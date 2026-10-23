#!/bin/sh
# Requires Docker, kind >= 0.30, kubectl 1.33-1.35 for the default node, and Nix.
# Run from any directory.
# KIND_CGROUP_DRIVER=systemd|cgroupfs; KIND_CLUSTER=igvano-kind.
# KIND_NODE_IMAGE=kindest/node:v1.34.0; KEEP_CLUSTER=1 skips teardown.
set -eu

for tool in docker kind kubectl nix; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing dependency: %s (must be on PATH)\n' "$tool" >&2
        exit 1
    fi
done

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
driver=${KIND_CGROUP_DRIVER:-systemd}
cluster=${KIND_CLUSTER:-igvano-kind}
node_image=${KIND_NODE_IMAGE:-kindest/node:v1.34.0}
case "$driver" in
    systemd|cgroupfs) ;;
    *) echo 'KIND_CGROUP_DRIVER must be systemd or cgroupfs' >&2; exit 1 ;;
esac
clusters=$(kind get clusters)
if printf '%s\n' "$clusters" | grep -Fx -e "$cluster" >/dev/null; then
    printf 'Cluster %s already exists; choose another KIND_CLUSTER\n' "$cluster" >&2
    exit 1
fi
case "$(docker info --format '{{.Architecture}}')" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo 'Unsupported Docker host architecture' >&2; exit 1 ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/igvano-kind.XXXXXX")
cluster_started=0
kube() {
    kubectl --kubeconfig "$work/kubeconfig" --namespace default "$@"
}
cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$status" -ne 0 ] && [ "$cluster_started" -eq 1 ]; then
        printf '\nKind smoke test failed (exit %s); diagnostics:\n' "$status" >&2
        kube --request-timeout=10s get pods -o wide || true
        kube --request-timeout=10s describe pods || true
        docker exec "$cluster-control-plane" journalctl -u containerd --no-pager | tail -100 || true
    fi
    if [ "$cluster_started" -eq 1 ]; then
        if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
            printf 'Keeping cluster %s; use: kind export kubeconfig --name %s\n' "$cluster" "$cluster"
        else
            kind delete cluster --name "$cluster" --kubeconfig "$work/kubeconfig" || {
                [ "$status" -ne 0 ] || status=1
            }
        fi
    fi
    if [ "${KEEP_CLUSTER:-0}" != 1 ] && [ -s "$work/image-id" ]; then
        docker image rm "$(cat "$work/image-id")" >/dev/null 2>&1 || true
    fi
    rm -rf "$work" || { [ "$status" -ne 0 ] || status=1; }
    exit "$status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Building igvano for %s-linux-musl (%s cgroups)\n' "$arch" "$driver"
cd "$repo"
nix develop -c zig build "-Dtarget=$arch-linux-musl" -Doptimize=ReleaseSafe
cp zig-out/bin/igvano "$work/igvano"
cp hack/kind/Dockerfile "$work/Dockerfile"
docker build --target "$driver" --build-arg "KIND_NODE_IMAGE=$node_image" \
    --iidfile "$work/image-id" "$work"
cat > "$work/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
kubeadmConfigPatches:
  - |
    kind: KubeletConfiguration
    cgroupDriver: $driver
EOF
cluster_started=1
kind create cluster --name "$cluster" --image "$(cat "$work/image-id")" \
    --config "$work/kind.yaml" --kubeconfig "$work/kubeconfig" --retain
kube apply -f "$repo/hack/kind/manifests.yaml"
kube wait deployment/nginx --for=condition=Available --timeout=180s
kube wait pods -l app=nginx --for=condition=Ready --timeout=180s
pod=$(kube get pods -l app=nginx -o jsonpath='{.items[0].metadata.name}')
kube exec "$pod" -- wget -qO- localhost > "$work/nginx.html"
grep -F '<title>Welcome to nginx!</title>' "$work/nginx.html"
kube logs "$pod" > "$work/nginx.log"
if [ ! -s "$work/nginx.log" ]; then
    echo 'nginx logs were empty' >&2
    exit 1
fi

# Mark existing pods so the waits below must observe a new, ready replacement.
kube label pods -l app=nginx igvano-smoke-original=true
kube delete pod "$pod" --wait=true --timeout=180s
deadline=$(($(date +%s) + 180))
replacement=
while [ "$(date +%s)" -lt "$deadline" ]; do
    replacement=$(kube --request-timeout=5s get pods -l 'app=nginx,!igvano-smoke-original' \
        -o jsonpath='{.items[*].metadata.name}') || replacement=
    if [ -n "$replacement" ]; then
        replacement=${replacement%% *}
        break
    fi
    sleep 1
done
if [ -z "$replacement" ]; then
    echo 'No replacement nginx pod appeared within 180s' >&2
    exit 1
fi
kube wait "pod/$replacement" --for=condition=Ready --timeout=180s
kube wait deployment/nginx --for=condition=Available --timeout=180s
kube apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: serviceaccount-smoke
spec:
  runtimeClassName: igvano
  restartPolicy: Never
  containers:
    - name: token
      image: busybox
      command: ["sh", "-c", "test -s /var/run/secrets/kubernetes.io/serviceaccount/token"]
EOF
kube wait pod/serviceaccount-smoke --for='jsonpath={.status.phase}=Succeeded' --timeout=180s
printf 'Kind smoke checks passed (%s).\n' "$driver"

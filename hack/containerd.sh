#!/bin/sh
# Runs containerd's integration/client suite with igvano installed as `runc`
# (under the stock containerd-shim-runc-v2), and compares the result with
# hack/containerd-expected-failures.txt.
# Run from any directory. Requires Nix and Docker; x86_64 only.
# CONTAINERD_LOG defaults to .zig-cache/containerd.log.
# CONTAINERD_REF pins the containerd commit; CONTAINERD_RUN limits the tests
# (a `go test -run` regex); CONTAINERD_TIMEOUT is the `go test -timeout`.
# CONTAINERD_RUNTIME=<static binary> runs the suite against e.g. runc instead.
# Exit status: 0 when the failures match the list exactly, 1 otherwise.
set -eu

# v2.2.10
CONTAINERD_REF_DEFAULT=991ca6a8ca58b47346a42093210099e090bc6c1f

if [ "${1-}" = "--inside" ]; then
    # Hand the Go caches back to the host user even when the build fails.
    trap 'chown -R "$HOST_UID:$HOST_GID" /cache' 0
    if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -f /.dockerenv ]; then
        # Empty Docker's cgroup namespace root so controllers can be enabled.
        mkdir -p /sys/fs/cgroup/init
        for pid in $(cat /sys/fs/cgroup/cgroup.procs); do
            printf '%s\n' "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
        done
    fi
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends jq iproute2 libbtrfs-dev btrfs-progs criu iptables >/dev/null
    # Copy, not bind-mount: a bind-mounted host binary may not be executable
    # through /proc/self/fd, which runc-style re-exec relies on.
    install -m 0755 /inputs/runtime /usr/local/sbin/runc
    sha256sum /usr/local/sbin/runc
    uname -a
    export GOMODCACHE=/cache/mod GOCACHE=/cache/build
    git init -q /containerd
    cd /containerd
    git remote add origin https://github.com/containerd/containerd.git
    git fetch -q --depth 1 origin "$CONTAINERD_REF"
    git checkout -q --detach FETCH_HEAD
    printf 'containerd %s\n' "$(git rev-parse HEAD)"
    make binaries install >/dev/null
    cd integration/client
    status=0
    go test -json -timeout "${CONTAINERD_TIMEOUT:-60m}" -parallel 8 ${CONTAINERD_RUN:+-run "$CONTAINERD_RUN"} . \
        -args -test.root > /tmp/test.json 2>&1 || status=$?
    jq -r 'select(.Action == "output") | .Output' /tmp/test.json 2>/dev/null | tr -d '\r' || cat /tmp/test.json
    printf '\nExit status: %s\n' "$status"
    echo client > /outputs/groups
    jq -r 'select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip"))
        | "client::\(.Test)\t\({"pass": "ok", "fail": "not ok", "skip": "skipped"}[.Action])"' /tmp/test.json > /outputs/results
    # A panic, a timeout or a build failure stops the package; count it once.
    if { [ "$status" -ne 0 ] && ! grep -q 'not ok' /outputs/results; } ||
        jq -e 'select(.Action == "output" and (.Output | test("^panic: ")))' /tmp/test.json > /dev/null; then
        printf 'client::*\tnot ok\n' >> /outputs/results
    fi
    exit 0
fi

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
log=${CONTAINERD_LOG:-"$repo/.zig-cache/containerd.log"}
cache="$repo/.zig-cache/containerd-go"
mkdir -p "$(dirname "$log")" "$cache"
printf 'Running containerd integration harness; full log: %s\n' "$log"
status=0
(
    cd "$repo"
    nix develop -c zig build -Dtarget=x86_64-linux-musl || exit "$?"
    # Snapshot inputs, so rebuilding cannot change a running container.
    snapshot=$(mktemp -d "$repo/.zig-cache/containerd.XXXXXX") || exit "$?"
    trap 'rm -rf "$snapshot"' 0
    mkdir "$snapshot/inputs" "$snapshot/outputs"
    cp "${CONTAINERD_RUNTIME:-$repo/zig-out/bin/igvano}" "$snapshot/inputs/runtime" || exit "$?"
    cp "$repo/hack/containerd.sh" "$snapshot/containerd.sh" || exit "$?"
    # containerd's overlayfs snapshotter cannot stack on the container's own overlay root.
    docker run --rm --init --privileged --platform linux/amd64 \
        --mount "type=bind,src=$snapshot/inputs,dst=/inputs,readonly" \
        --mount "type=bind,src=$snapshot/outputs,dst=/outputs" \
        --mount "type=bind,src=$snapshot/containerd.sh,dst=/containerd.sh,readonly" \
        --mount "type=bind,src=$cache,dst=/cache" \
        --tmpfs /var/lib/containerd-test:exec \
        --tmpfs /tmp:exec,mode=1777 \
        -e "CONTAINERD_REF=${CONTAINERD_REF:-$CONTAINERD_REF_DEFAULT}" \
        -e "CONTAINERD_RUN=${CONTAINERD_RUN:-}" \
        -e "CONTAINERD_TIMEOUT=${CONTAINERD_TIMEOUT:-60m}" \
        -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
        golang:1.25-trixie@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73 sh /containerd.sh --inside || exit "$?"
    expected="$repo/hack/containerd-expected-failures.txt"
    if [ -n "${CONTAINERD_RUN:-}" ]; then
        # A -run subset only checks listed tests that actually ran.
        cut -f 1 "$snapshot/outputs/results" | grep -Fx -f - "$expected" > "$snapshot/expected" || true
        expected="$snapshot/expected"
    fi
    sh "$repo/hack/gate.sh" "$snapshot/outputs/results" "$snapshot/outputs/groups" "$expected"
) > "$log" 2>&1 || status=$?
cat "$log"
printf '\nFull log: %s\n' "$log"
exit "$status"

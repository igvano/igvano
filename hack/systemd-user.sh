#!/bin/sh
# Rootless --systemd-cgroup check: boots systemd in a privileged container
# with a lingering user (UID 2000), then runs igvano as that user against the
# per-user manager, like runc's systemd driver when rootless.
# Run from any directory. Requires Nix and Docker; x86_64 only.
# SYSTEMD_USER_LOG defaults to .zig-cache/systemd-user.log.
# Exit status: 0 when every check passed.
set -eu

if [ "${1-}" = "--inside" ]; then
    # As the rootless user, with $XDG_RUNTIME_DIR pointing at its bus.
    # /tmp is a noexec tmpfs here.
    mkdir "$HOME/work"
    cd "$HOME/work"
    cp /inputs/igvano ./igvano
    mkdir rootfs
    tar -xf /inputs/rootfs.tar -C rootfs
    ./igvano spec --rootless
    jq '.process.terminal = false | .process.args = ["sleep", "100"] | .linux.resources = {"pids": {"limit": 42}}' \
        config.json > config.new
    mv config.new config.json
    scope=/sys/fs/cgroup/user.slice/user-2000.slice/user@2000.service/user.slice/igvano-c1.scope
    ./igvano --systemd-cgroup features | jq -e '.linux.cgroup.systemdUser' > /dev/null
    ./igvano --systemd-cgroup run -d c1 < /dev/null > /dev/null
    test "$(cat "$scope/pids.max")" = 42
    ./igvano --systemd-cgroup update --pids-limit 50 c1
    test "$(cat "$scope/pids.max")" = 50
    test "$(systemctl --user show -p TasksMax --value igvano-c1.scope)" = 50
    ./igvano --systemd-cgroup exec c1 true
    ./igvano --systemd-cgroup kill c1 KILL
    sleep 1
    ./igvano --systemd-cgroup delete c1
    ! systemctl --user is-active --quiet igvano-c1.scope
    test ! -e "$scope"
    echo "systemd-user: all checks passed"
    exit 0
fi

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
if [ "${1-}" = "--host" ]; then
    cd "$repo"
    nix develop -c zig build -Dtarget=x86_64-linux-musl
    snapshot=$(mktemp -d "$repo/.zig-cache/systemd-user.XXXXXX")
    name=igvano-systemd-user-$$
    trap 'docker rm -f "$name" > /dev/null 2>&1 || true; rm -rf "$snapshot"' 0
    cp zig-out/bin/igvano hack/systemd-user.sh "$snapshot/"
    busybox=$(docker create --platform linux/amd64 busybox:1.37)
    docker export "$busybox" > "$snapshot/rootfs.tar"
    docker rm "$busybox" > /dev/null
    chmod -R a+rX "$snapshot"
    docker build -q -t igvano-systemd-user - > /dev/null <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        systemd systemd-sysv dbus dbus-user-session libpam-systemd jq >/dev/null && \
    useradd -u2000 -m -s/bin/sh rootless && \
    mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/rootless
CMD ["/sbin/init"]
DOCKERFILE
    # systemd needs to be PID 1 in the container, so it runs detached.
    docker run --detach --name "$name" --privileged --cgroupns=private --platform linux/amd64 \
        --tmpfs /run --tmpfs /tmp \
        --mount "type=bind,src=$snapshot,dst=/inputs,readonly" igvano-systemd-user > /dev/null
    for _ in $(seq 60); do
        docker exec "$name" systemctl is-active --quiet user@2000.service 2> /dev/null && break
        sleep 1
    done
    docker exec "$name" systemctl is-active user@2000.service
    # The user manager joins the session bus only after the bus starts.
    for _ in $(seq 60); do
        docker exec "$name" su rootless -c 'XDG_RUNTIME_DIR=/run/user/2000 busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Peer Ping' > /dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$name" su rootless -c 'XDG_RUNTIME_DIR=/run/user/2000 sh /inputs/systemd-user.sh --inside'
    exit 0
fi

log=${SYSTEMD_USER_LOG:-"$repo/.zig-cache/systemd-user.log"}
mkdir -p "$(dirname "$log")"
printf 'Running rootless systemd check; full log: %s\n' "$log"
status=0
"$0" --host > "$log" 2>&1 || status=$?
cat "$log"
exit "$status"

#!/bin/sh
# Run from any directory. Requires Nix and Docker (or CONFORMANCE_VM with Lima).
# CONFORMANCE_LOG defaults to .zig-cache/conformance.log.
# CONFORMANCE_IMAGE and CONFORMANCE_TIMEOUT override the Go image and seconds/test.
# RUNTIME_TOOLS_REF overrides the runtime-tools branch, tag, or commit.
set -eu

KNOWN_UPSTREAM='linux_cgroups_*.t: cgroups/cgroups.go is v1-only ("cgroupv2 is not supported yet").
delete_resources.t: same v1-only cgroup validation.
delete_only_create_resources.t: same v1-only cgroup validation.
hooks.t: upstream compares against a string its own hooks never write.
misc_props.t: annotation case execs /runtimetest, which PrepareBundle never installs; runc fails it at create.
pidfile.t: expects kill of a stopped container to succeed, contradicting the spec and kill.t.
process_rlimits.t: soft-NOFILE; Go >= 1.21 runtimetest raises its own soft limit to hard-1.
start.t: step 7 asserts start succeeds for a container without process, inverting the spec'\''s MUST-error; step 8 then times out.'

if [ "${1-}" = "--inside" ]; then
    timeout_seconds=${CONFORMANCE_TIMEOUT:-120}
    case "$timeout_seconds" in
        ''|*[!0-9]*) echo "CONFORMANCE_TIMEOUT must be a positive integer" >&2; exit 1 ;;
    esac
    if [ "$timeout_seconds" -eq 0 ]; then
        echo "CONFORMANCE_TIMEOUT must be a positive integer (got 0); exiting" >&2
        exit 1
    fi

    if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -f /.dockerenv ]; then
        # Empty Docker's cgroup namespace root so controllers can be enabled.
        mkdir -p /sys/fs/cgroup/init
        # Snapshot the PIDs before moving them; short-lived processes may exit.
        cgroup_pids=$(cat /sys/fs/cgroup/cgroup.procs)
        for pid in $cgroup_pids; do
            printf '%s\n' "$pid" > /sys/fs/cgroup/init/cgroup.procs || true
        done
        if [ -n "$(cat /sys/fs/cgroup/cgroup.procs)" ]; then
            echo "Unable to empty the cgroup namespace root for conformance tests" >&2
            exit 1
        fi
    elif [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
        # Upstream's v1-only cgroup validations can pass on a v1 host.
        KNOWN_UPSTREAM=$(printf '%s\n' "$KNOWN_UPSTREAM" | sed '/v1-only/d')
        KNOWN_UPSTREAM="$KNOWN_UPSTREAM
linux_cgroups_pids.t: compares *int64 pointers (runtime-spec v1.3 made pids.limit a pointer); always false.
linux_cgroups_relative_pids.t: compares *int64 pointers (runtime-spec v1.3 made pids.limit a pointer); always false.
delete_resources.t: compares *int64 pointers (runtime-spec v1.3 made pids.limit a pointer); always false.
linux_cgroups_memory.t: kernel >= 5.16 rejects memory.kmem.limit_in_bytes writes.
linux_cgroups_relative_memory.t: kernel >= 5.16 rejects memory.kmem.limit_in_bytes writes.
linux_cgroups_blkio.t: reads blkio.weight, removed with CFQ in Linux 5.0 (BFQ exposes blkio.bfq.weight).
linux_cgroups_relative_blkio.t: reads blkio.weight, removed with CFQ in Linux 5.0 (BFQ exposes blkio.bfq.weight)."
    fi

    apt-get update
    apt-get install -y --no-install-recommends busybox-static
    if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true)" = Y ]; then
        apt-get install -y --no-install-recommends apparmor
        # Docker shares the Colima VM's kernel. Its privileged container can
        # load host profiles once securityfs is visible; Lima runs here as root.
        if [ ! -d /sys/kernel/security/apparmor ]; then
            mount -t securityfs securityfs /sys/kernel/security
        fi
        apparmor_parser -r <<'EOF'
profile acme_secure_profile flags=(attach_disconnected,mediate_deleted) {
    file,
    capability,
    network,
    mount,
    umount,
    pivot_root,
    ptrace,
    signal,
    unix,
    dbus,
}
EOF
        printf 'Loaded AppArmor conformance profile: acme_secure_profile\n'
    else
        KNOWN_UPSTREAM="$KNOWN_UPSTREAM
linux_process_apparmor_profile.t: environment limitation: AppArmor is not enabled on the host kernel."
    fi
    command -v timeout >/dev/null
    runtime_tools_ref=${RUNTIME_TOOLS_REF:-master}
    work=$(mktemp -d /tmp/igvano-conformance.XXXXXX)
    # User-namespace containers' mapped root must traverse the bundle path.
    chmod 0755 "$work"
    # Timed-out upstream suites can leave nested mounts busy. Detach the
    # task-owned tmpfs before removing the workspace, including its submounts.
    trap 'if ! mountpoint -q "$work/bundles" || umount -l "$work/bundles"; then rm -rf "$work"; fi' 0
    git init "$work/runtime-tools"
    cd "$work/runtime-tools"
    git remote add origin https://github.com/opencontainers/runtime-tools.git
    git fetch --depth 1 origin "$runtime_tools_ref"
    git checkout --detach FETCH_HEAD
    printf 'runtime-tools %s: %s\n' "$runtime_tools_ref" "$(git rev-parse HEAD)"
    go version
    uname -a
    make runtimetest validation-executables
    make tool

    mkdir -p bundle/rootfs/bin bundle/rootfs/etc bundle/rootfs/dev \
        bundle/rootfs/proc bundle/rootfs/sys bundle/rootfs/tmp bundle/rootfs/usr
    cp /bin/busybox bundle/rootfs/bin/busybox
    for applet in $(busybox --list); do
        [ "$applet" = busybox ] || ln -s busybox "bundle/rootfs/bin/$applet"
    done
    ln -s bin bundle/rootfs/sbin
    ln -s ../bin bundle/rootfs/usr/bin
    ln -s ../bin bundle/rootfs/usr/sbin
    chmod 1777 bundle/rootfs/tmp
    ./oci-runtime-tool generate --output bundle/config.json
    # Official executables generate their own configs and unpack this archive
    # into each bundle; they find both the archive and runtimetest in cwd.
    tar -czf "rootfs-$(go env GOARCH).tar.gz" -C bundle/rootfs .
    # PrepareBundle needs tmpfs for mknod of char 0:0; keep Go builds off tmpfs.
    mkdir "$work/bundles"
    mount -t tmpfs tmpfs "$work/bundles"
    export TMPDIR="$work/bundles"
    # Copy, not bind-mount: exeseal's overlayfs sees the directory under a
    # file bind mount, so a bind-mounted binary cannot run sealed.
    if [ -f /inputs/igvano ]; then install -m 0755 /inputs/igvano /usr/local/bin/igvano; fi
    export RUNTIME=/usr/local/bin/igvano
    sha256sum "$RUNTIME"
    find validation -type f -name '*.t' | LC_ALL=C sort > /tmp/conformance-tests
    [ -s /tmp/conformance-tests ] || { echo "No validation executables built" >&2; exit 1; }

    printf '%-64s %8s %8s %8s\n' TEST PASS FAIL SKIP > /tmp/conformance-summary
    total_pass=0 total_fail=0 total_skip=0
    while IFS= read -r test; do
        printf '\n===== %s =====\n' "$test"
        status=0
        timeout --kill-after=5 "$timeout_seconds" "./$test" < /dev/null > /tmp/conformance-tap 2>&1 || status=$?
        cat /tmp/conformance-tap
        printf '\nExit status: %s\n' "$status"
        # Some suites pass without assertions or a plan, and report failures only
        # as YAML diagnostics. Still count crashes, bailouts and incomplete plans.
        set -- $(awk -v status="$status" '
            /^ok([ \t]|$)/ {
                if (tolower($0) ~ /#[ \t]*(skip|todo)([ \t]|$)/) skip++; else pass++
                next
            }
            /^not ok([ \t]|$)/ {
                if (tolower($0) ~ /#[ \t]*(skip|todo)([ \t]|$)/) skip++; else fail++
                next
            }
            /^1\.\.[0-9]+/ {
                document_plan = $0; sub(/^1\.\./, "", document_plan); document_plan += 0
                plan += document_plan
                if (document_plan == 0 && tolower($0) ~ /#[ \t]*skip([ \t]|$)/) skip++
            }
            /^Bail out!/ { bailout = 1 }
            /^  ---$/ { diagnostic = 1 }
            END {
                if (bailout || (status != 0 && fail == 0) ||
                    (plan > 0 && plan != pass + fail + skip) ||
                    (fail == 0 && plan == 0 && skip == 0 && (status != 0 || diagnostic))) fail++
                print pass + 0, fail + 0, skip + 0
            }
        ' /tmp/conformance-tap)
        label="$test"
        while IFS=: read -r pattern reason; do
            case "${test##*/}" in
                $pattern) label="$test*"; break ;;
            esac
        done <<EOF
$KNOWN_UPSTREAM
EOF
        printf '%-64s %8s %8s %8s\n' "$label" "$1" "$2" "$3" >> /tmp/conformance-summary
        total_pass=$((total_pass + $1))
        total_fail=$((total_fail + $2))
        total_skip=$((total_skip + $3))
    done < /tmp/conformance-tests
    printf '%-64s %8s %8s %8s\n' TOTAL "$total_pass" "$total_fail" "$total_skip" >> /tmp/conformance-summary
    printf '\n'
    cat /tmp/conformance-summary
    printf '\n* Known upstream and environment limitations; failures remain in the FAIL count:\n%s\n' "$KNOWN_UPSTREAM"
    exit 0
fi

repo=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
log=${CONFORMANCE_LOG:-"$repo/.zig-cache/conformance.log"}
mkdir -p "$(dirname "$log")"
printf 'Running conformance harness; full log: %s\n' "$log"
status=0
(
    cd "$repo"
    if [ -n "${CONFORMANCE_VM:-}" ]; then
        vm=$CONFORMANCE_VM
        case "$(limactl shell "$vm" uname -m)" in
            aarch64) arch=aarch64 ;;
            x86_64) arch=x86_64 ;;
            *) echo "Unsupported VM architecture" >&2; exit 1 ;;
        esac
        nix develop -c zig build "-Dtarget=$arch-linux-musl" || exit "$?"
        # Lima mounts HOME, so keep immutable inputs there for the VM run.
        snapshot=$(mktemp -d "$HOME/.igvano-conformance.XXXXXX") || exit "$?"
        trap 'rm -rf "$snapshot"' 0
        cp "$repo/zig-out/bin/igvano" "$snapshot/igvano" || exit "$?"
        cp "$repo/hack/conformance.sh" "$snapshot/conformance.sh" || exit "$?"
        limactl shell "$vm" sudo install -m 0755 "$snapshot/igvano" /usr/local/bin/igvano || exit "$?"
        limactl shell "$vm" sudo env "PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            "CONFORMANCE_TIMEOUT=${CONFORMANCE_TIMEOUT:-120}" \
            "RUNTIME_TOOLS_REF=${RUNTIME_TOOLS_REF:-master}" \
            sh "$snapshot/conformance.sh" --inside
        exit "$?"
    fi
    nix develop -c zig build -Dtarget=x86_64-linux-musl || exit "$?"
    # Snapshot inputs under the shared repo, so rebuilding cannot change a
    # running validation container or reuse a previously mounted binary inode.
    snapshot=$(mktemp -d "$repo/.zig-cache/conformance.XXXXXX") || exit "$?"
    trap 'rm -rf "$snapshot"' 0
    cp "$repo/zig-out/bin/igvano" "$snapshot/igvano" || exit "$?"
    cp "$repo/hack/conformance.sh" "$snapshot/conformance.sh" || exit "$?"
    docker run --rm --init --privileged --platform linux/amd64 \
        --mount "type=bind,src=$snapshot/igvano,dst=/inputs/igvano,readonly" \
        --mount "type=bind,src=$snapshot/conformance.sh,dst=/conformance.sh,readonly" \
        -e "CONFORMANCE_TIMEOUT=${CONFORMANCE_TIMEOUT:-120}" \
        -e "RUNTIME_TOOLS_REF=${RUNTIME_TOOLS_REF:-master}" \
        "${CONFORMANCE_IMAGE:-golang:1.25-bookworm}" sh /conformance.sh --inside
) > "$log" 2>&1 || status=$?
cat "$log"
printf '\nFull log: %s\n' "$log"
if [ "$status" -ne 0 ]; then
    printf 'Harness failed to run (exit %s).\n' "$status" >&2
fi
exit "$status"

#!/bin/sh
# Run from any directory. Requires Nix and Docker on the host.
# CONFORMANCE_LOG defaults to .zig-cache/conformance.log.
# CONFORMANCE_IMAGE and CONFORMANCE_TIMEOUT override the Go image and seconds/test.
# RUNTIME_TOOLS_REF overrides the runtime-tools branch, tag, or commit.
set -eu

KNOWN_UPSTREAM='linux_cgroups_*.t: cgroups/cgroups.go is v1-only ("cgroupv2 is not supported yet").
delete_resources.t: same v1-only cgroup validation.
delete_only_create_resources.t: same v1-only cgroup validation.
hooks.t: upstream compares against a string its own hooks never write.
pidfile.t: expects kill of a stopped container to succeed, contradicting the spec and kill.t.
process_rlimits.t: soft-NOFILE; Go >= 1.21 runtimetest raises its own soft limit to hard-1.'

if [ "${1-}" = "--inside" ]; then
    timeout_seconds=${CONFORMANCE_TIMEOUT:-120}
    case "$timeout_seconds" in
        ''|*[!0-9]*) echo "CONFORMANCE_TIMEOUT must be a positive integer" >&2; exit 1 ;;
    esac
    if [ "$timeout_seconds" -eq 0 ]; then
        echo "CONFORMANCE_TIMEOUT must be a positive integer (got 0); exiting" >&2
        exit 1
    fi

    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
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
    fi

    apt-get update
    apt-get install -y --no-install-recommends busybox-static
    command -v timeout >/dev/null
    runtime_tools_ref=${RUNTIME_TOOLS_REF:-master}
    git init /tmp/runtime-tools
    cd /tmp/runtime-tools
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
    tar -czf rootfs-amd64.tar.gz -C bundle/rootfs .
    # PrepareBundle needs tmpfs for mknod of char 0:0; keep Go builds off tmpfs.
    mkdir /bundles
    mount -t tmpfs tmpfs /bundles
    export TMPDIR=/bundles
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
                plan = $0; sub(/^1\.\./, "", plan); plan += 0
                if (plan == 0 && tolower($0) ~ /#[ \t]*skip([ \t]|$)/) skip++
            }
            /^Bail out!/ { bailout = 1 }
            /^  ---$/ { diagnostic = 1 }
            END {
                if (bailout || (status != 0 && fail == 0) ||
                    (plan > 0 && plan != pass + fail + skip) ||
                    (plan == 0 && skip == 0 && (status != 0 || diagnostic))) fail++
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
    printf '\n* Known upstream limitations; failures remain in the FAIL count:\n%s\n' "$KNOWN_UPSTREAM"
    exit 0
fi

repo=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
log=${CONFORMANCE_LOG:-"$repo/.zig-cache/conformance.log"}
mkdir -p "$(dirname "$log")"
printf 'Running conformance harness; full log: %s\n' "$log"
status=0
(
    cd "$repo"
    nix develop -c zig build -Dtarget=x86_64-linux-musl || exit "$?"
    # Snapshot inputs under the shared repo, so rebuilding cannot change a
    # running validation container or reuse a previously mounted binary inode.
    snapshot=$(mktemp -d "$repo/.zig-cache/conformance.XXXXXX") || exit "$?"
    trap 'rm -rf "$snapshot"' 0
    cp "$repo/zig-out/bin/igvano" "$snapshot/igvano" || exit "$?"
    cp "$repo/hack/conformance.sh" "$snapshot/conformance.sh" || exit "$?"
    docker run --rm --init --privileged --platform linux/amd64 \
        --mount "type=bind,src=$snapshot/igvano,dst=/usr/local/bin/igvano,readonly" \
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

#!/bin/sh
# Runs runc's own bats integration suite (tests/integration) with igvano as
# $RUNC, one .bats file at a time, and compares the result with
# hack/runc-bats-expected-failures.txt.
# Run from any directory. Requires Nix and Docker; x86_64 only.
# RUNC_BATS_LOG defaults to .zig-cache/runc-bats.log.
# RUNC_REF pins the runc commit the suite comes from; RUNC_BATS_FILES limits
# the run to the listed files (space separated, without .bats);
# RUNC_BATS_TIMEOUT overrides the seconds allowed per file.
# RUNC_BATS_RUNTIME=<static binary> runs the suite against e.g. runc instead.
# Exit status: 0 when the failures match the list exactly, 1 otherwise.
set -eu

# v1.3.3
RUNC_REF_DEFAULT=d842d7719497cc3b774fd71620278ac9e17710e0
# v1.9.0
BATS_REF=6636e2c2ef5ffe361535cb45fc61682c5ef46b71

if [ "${1-}" = "--inside" ]; then
    timeout_seconds=${RUNC_BATS_TIMEOUT:-600}
    case "$timeout_seconds" in
        ''|0|*[!0-9]*) echo "RUNC_BATS_TIMEOUT must be a positive integer" >&2; exit 1 ;;
    esac
    if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -f /.dockerenv ]; then
        # Empty Docker's cgroup namespace root so controllers can be enabled.
        mkdir -p /sys/fs/cgroup/init
        for pid in $(cat /sys/fs/cgroup/cgroup.procs); do
            printf '%s\n' "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
        done
    fi
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends jq iproute2 uidmap libseccomp-dev xz-utils >/dev/null
    git init -q /tmp/bats-core
    git -C /tmp/bats-core fetch -q --depth 1 https://github.com/bats-core/bats-core.git "$BATS_REF"
    git -C /tmp/bats-core checkout -q --detach FETCH_HEAD
    /tmp/bats-core/install.sh /usr/local >/dev/null
    # Copy, not bind-mount: a bind-mounted host binary may not be executable
    # through /proc/self/fd, which runc-style re-exec relies on.
    install -m 0755 /inputs/runtime /usr/local/sbin/runc
    sha256sum /usr/local/sbin/runc
    uname -a
    git init -q /runc
    cd /runc
    git remote add origin https://github.com/opencontainers/runc.git
    git fetch -q --depth 1 origin "$RUNC_REF"
    git checkout -q --detach FETCH_HEAD
    printf 'runc tests %s\n' "$(git rev-parse HEAD)"
    make test-binaries >/dev/null
    export RUNC=/usr/local/sbin/runc
    all_files=$(cd tests/integration && ls ./*.bats | sed 's|^\./||; s|\.bats$||')
    files=${RUNC_BATS_FILES:-$all_files}
    for file in $files; do
        printf '%s\n' "$all_files" | grep -Fxq -e "$file" || { echo "Unknown bats file: $file" >&2; exit 1; }
    done
    printf '%s\n' $files > /outputs/groups
    : > /outputs/results
    for file in $files; do
        printf '\n===== %s =====\n' "$file"
        status=0
        # Some tests want a terminal; script(1) provides one, like youki's runner.
        timeout --kill-after=5 "$timeout_seconds" \
            script -qefc "bats -t tests/integration/$file.bats" /dev/null < /dev/null > /tmp/tap.raw 2>&1 || status=$?
        tr -d '\r' < /tmp/tap.raw > /tmp/tap
        cat /tmp/tap
        printf '\nExit status: %s\n' "$status"
        # TAP: "ok 3 name", "not ok 4 name", "ok 5 name # skip (reason)".
        sed -n "/^ok [0-9]* .* # skip/{s/^ok [0-9]* \(.*\) # skip.*/$file::\1	skipped/p;d}
                s/^ok [0-9]* \(.*\)/$file::\1	ok/p
                s/^not ok [0-9]* \(.*\)/$file::\1	not ok/p" /tmp/tap >> /outputs/results
        # A timeout, or a crash that reported no failing test, aborts the file; count it once.
        if [ "$status" -ge 124 ] || { [ "$status" -ne 0 ] && ! grep -q '^not ok ' /tmp/tap; }; then
            printf '%s::*\tnot ok\n' "$file" >> /outputs/results
        fi
    done
    exit 0
fi

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
log=${RUNC_BATS_LOG:-"$repo/.zig-cache/runc-bats.log"}
mkdir -p "$(dirname "$log")"
printf 'Running runc bats harness; full log: %s\n' "$log"
status=0
(
    cd "$repo"
    nix develop -c zig build -Dtarget=x86_64-linux-musl || exit "$?"
    # Snapshot inputs, so rebuilding cannot change a running container.
    snapshot=$(mktemp -d "$repo/.zig-cache/runc-bats.XXXXXX") || exit "$?"
    trap 'rm -rf "$snapshot"' 0
    mkdir "$snapshot/inputs" "$snapshot/outputs"
    cp "${RUNC_BATS_RUNTIME:-$repo/zig-out/bin/igvano}" "$snapshot/inputs/runtime" || exit "$?"
    cp "$repo/hack/runc-bats.sh" "$snapshot/runc-bats.sh" || exit "$?"
    docker run --rm --init --privileged --platform linux/amd64 \
        --mount "type=bind,src=$snapshot/inputs,dst=/inputs,readonly" \
        --mount "type=bind,src=$snapshot/outputs,dst=/outputs" \
        --mount "type=bind,src=$snapshot/runc-bats.sh,dst=/runc-bats.sh,readonly" \
        -e "RUNC_REF=${RUNC_REF:-$RUNC_REF_DEFAULT}" -e "BATS_REF=$BATS_REF" \
        -e "RUNC_BATS_FILES=${RUNC_BATS_FILES:-}" \
        -e "RUNC_BATS_TIMEOUT=${RUNC_BATS_TIMEOUT:-600}" \
        golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 sh /runc-bats.sh --inside || exit "$?"
    sh "$repo/hack/gate.sh" "$snapshot/outputs/results" "$snapshot/outputs/groups" "$repo/hack/runc-bats-expected-failures.txt"
) > "$log" 2>&1 || status=$?
cat "$log"
printf '\nFull log: %s\n' "$log"
exit "$status"

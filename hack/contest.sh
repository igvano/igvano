#!/bin/sh
# Runs youki's contest integration suite against igvano, one test group at a
# time, and compares the result with hack/contest-expected-failures.txt.
# Run from any directory. Requires Nix and Docker; x86_64 only.
# CONTEST_LOG defaults to .zig-cache/contest.log.
# YOUKI_REF pins the youki commit that contest and runtimetest are built from.
# CONTEST_TIMEOUT overrides the seconds allowed per group.
# CONTEST_GROUPS limits the run to the listed groups (space separated).
# Exit status: 0 when the failures match the list exactly, 1 otherwise.
set -eu

YOUKI_REF_DEFAULT=0e52d955914541b54dec33d82e3e3244307571d0

if [ "${1-}" = "--inside" ]; then
    timeout_seconds=${CONTEST_TIMEOUT:-300}
    case "$timeout_seconds" in
        ''|0|*[!0-9]*) echo "CONTEST_TIMEOUT must be a positive integer" >&2; exit 1 ;;
    esac
    if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -f /.dockerenv ]; then
        # Empty Docker's cgroup namespace root so controllers can be enabled.
        mkdir -p /sys/fs/cgroup/init
        for pid in $(cat /sys/fs/cgroup/cgroup.procs); do
            printf '%s\n' "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
        done
    fi
    work=$(mktemp -d /tmp/igvano-contest.XXXXXX)
    # User-namespace containers' mapped root must traverse the bundle path.
    chmod 0755 "$work"
    # Copy, not bind-mount: a bind-mounted host binary may not be executable
    # through /proc/self/fd, which runc-style re-exec relies on.
    install -m 0755 /inputs/igvano /usr/local/bin/igvano
    install -m 0755 /inputs/contest /inputs/runtimetest "$work/"
    cp /inputs/bundle.tar.gz "$work/"
    cd "$work"
    sha256sum /usr/local/bin/igvano
    uname -a
    all_groups=$(./contest list)
    groups=${CONTEST_GROUPS:-$all_groups}
    # contest itself ignores an unknown group, which would make a subset run green.
    for group in $groups; do
        printf '%s\n' "$all_groups" | grep -Fxq -e "$group" || { echo "Unknown contest group: $group" >&2; exit 1; }
    done
    printf '%s\n' $groups > /outputs/groups
    : > results
    for group in $groups; do
        printf '\n===== %s =====\n' "$group"
        status=0
        RUNTIME_KIND=runc timeout --kill-after=5 "$timeout_seconds" \
            ./contest run --runtime /usr/local/bin/igvano --runtimetest "$work/runtimetest" -t "$group" \
            < /dev/null > tap 2>&1 || status=$?
        cat tap
        printf '\nExit status: %s\n' "$status"
        # Result lines look like "3 / 14 : name : not ok".
        sed -n "s/^[0-9]* \/ [0-9]* : \(.*\) : \(ok\|not ok\|skipped\)\$/$group::\1	\2/p" tap >> results
        # A panic or timeout aborts the rest of the group; count it once.
        if [ "$status" -ne 0 ]; then
            printf '%s::*\tnot ok\n' "$group" >> results
        fi
    done
    cp results /outputs/results
    exit 0
fi

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
log=${CONTEST_LOG:-"$repo/.zig-cache/contest.log"}
youki_ref=${YOUKI_REF:-$YOUKI_REF_DEFAULT}
cache="$repo/.zig-cache/contest-$youki_ref"
expected="$repo/hack/contest-expected-failures.txt"
mkdir -p "$(dirname "$log")"
printf 'Running contest harness; full log: %s\n' "$log"
status=0
(
    cd "$repo"
    if [ ! -f "$cache/contest" ]; then
        src="$cache.src"
        rm -rf "$src"
        git init -q "$src"
        git -C "$src" remote add origin https://github.com/youki-dev/youki.git
        git -C "$src" fetch -q --depth 1 origin "$youki_ref"
        git -C "$src" checkout -q --detach FETCH_HEAD
        docker run --rm -v "$src:/youki" -w /youki rust:bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c sh -c '
            set -e
            git config --global --add safe.directory /youki
            apt-get update -qq
            apt-get install -y -qq pkg-config libseccomp-dev libsystemd-dev libdbus-1-dev libelf-dev >/dev/null
            ./scripts/build.sh -o /youki/out -r -c contest
            chown -R '"$(id -u):$(id -g)"' /youki' || exit "$?"
        mkdir -p "$cache"
        cp "$src/out/contest" "$src/out/runtimetest" "$src/tests/contest/contest/bundle.tar.gz" "$cache/" || exit "$?"
        rm -rf "$src"
    fi
    nix develop -c zig build -Dtarget=x86_64-linux-musl || exit "$?"
    # Snapshot inputs, so rebuilding cannot change a running container.
    snapshot=$(mktemp -d "$repo/.zig-cache/contest.XXXXXX") || exit "$?"
    trap 'rm -rf "$snapshot"' 0
    mkdir "$snapshot/inputs" "$snapshot/outputs"
    # CONTEST_RUNTIME=<static binary> runs the same suite against e.g. runc
    # to tell environment failures from igvano ones.
    cp "${CONTEST_RUNTIME:-$repo/zig-out/bin/igvano}" "$snapshot/inputs/igvano" || exit "$?"
    cp "$cache/contest" "$cache/runtimetest" "$cache/bundle.tar.gz" "$snapshot/inputs/" || exit "$?"
    cp "$repo/hack/contest.sh" "$snapshot/contest.sh" || exit "$?"
    docker run --rm --init --privileged --platform linux/amd64 \
        --mount "type=bind,src=$snapshot/inputs,dst=/inputs,readonly" \
        --mount "type=bind,src=$snapshot/outputs,dst=/outputs" \
        --mount "type=bind,src=$snapshot/contest.sh,dst=/contest.sh,readonly" \
        -e "CONTEST_TIMEOUT=${CONTEST_TIMEOUT:-300}" \
        -e "CONTEST_GROUPS=${CONTEST_GROUPS:-}" \
        debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc sh /contest.sh --inside || exit "$?"
    sh "$repo/hack/gate.sh" "$snapshot/outputs/results" "$snapshot/outputs/groups" "$expected"
) > "$log" 2>&1 || status=$?
cat "$log"
printf '\nFull log: %s\n' "$log"
exit "$status"

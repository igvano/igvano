#!/bin/sh
# Runs the Linux jobs of .github/workflows/ci.yml on this machine, one after
# another, and prints one line per job. Use it when GitHub Actions is not
# available. unit-macos needs a Mac and is not run here.
# Requires Nix and Docker; kind jobs also need kind and kubectl on PATH
# (CI pins kind v0.30.0 and kubectl v1.34.0).
# CI_JOBS limits the run (space separated, e.g. "lint unit-linux contest").
# CI_LOG_DIR keeps the logs (default .zig-cache/ci-local).
# Exit status: 0 when every job passed.
set -u

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
cd "$repo" || exit 1
logs=${CI_LOG_DIR:-"$repo/.zig-cache/ci-local"}
mkdir -p "$logs"
jobs=${CI_JOBS:-"lint unit-linux contest runc-bats runc-bats-rootless containerd runtime-tools kind-systemd kind-cgroupfs"}

lint() {
    nix develop -c zig fmt --check build.zig src examples &&
        nix develop -c cccc --table src/
}

unit_linux() {
    mkdir -p zig-out &&
        nix develop -c zig test src/libcontainer/root.zig --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/libcontainer-tests-linux &&
        nix develop -c zig test --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/lib-tests-linux \
            --dep libcontainer -Mroot=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig &&
        nix develop -c zig test --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/main-tests-linux \
            --dep igvano --dep libcontainer -Mroot=src/main.zig \
            --dep libcontainer -Migvano=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig &&
        nix develop -c zig build-exe src/test/seccomp-probe.zig -target x86_64-linux-musl -femit-bin=zig-out/seccomp-probe-x86_64 &&
        docker run --rm --init --privileged --platform linux/amd64 -v "$repo/zig-out:/bins:ro" debian:bookworm-slim sh -c \
            'set -e; apt-get update -qq && apt-get install -y -qq procps >/dev/null; cp /bins/*-tests-linux /bins/seccomp-probe-x86_64 /tmp/ &&
             mkdir -p /tmp/work && cd /tmp/work && /tmp/libcontainer-tests-linux && /tmp/lib-tests-linux &&
             IGVANO_SECCOMP_PROBE=/tmp/seccomp-probe-x86_64 /tmp/main-tests-linux'
}

run_job() {
    case "$1" in
        lint) lint ;;
        unit-linux) unit_linux ;;
        contest) ./hack/contest.sh ;;
        runc-bats) ./hack/runc-bats.sh ;;
        runc-bats-rootless) RUNC_BATS_ROOTLESS=1 ./hack/runc-bats.sh ;;
        containerd) ./hack/containerd.sh ;;
        # Report only in CI, like the job there.
        runtime-tools) ./hack/conformance.sh || true ;;
        kind-systemd) KIND_CGROUP_DRIVER=systemd ./hack/kind.sh ;;
        kind-cgroupfs) KIND_CGROUP_DRIVER=cgroupfs ./hack/kind.sh ;;
        *) printf 'unknown job: %s\n' "$1" >&2; return 2 ;;
    esac
}

failed=0
for job in $jobs; do
    if run_job "$job" > "$logs/$job.log" 2>&1; then
        printf '%s: pass\n' "$job"
    else
        printf '%s: fail (%s)\n' "$job" "$logs/$job.log"
        failed=1
    fi
done
exit "$failed"

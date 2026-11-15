# Testing

Pre-commit hooks run through [prek](https://github.com/j178/prek): `zig fmt --check`, and `cccc` enforcing the `cccc.toml` complexity limits (cognitive 25, cyclomatic 15 per function; `tests/` and `test/` exempt) on the staged files and on all of `src/`. Both tools come from the devShell. With a global `core.hooksPath` (e.g. a corporate hook that chains to local hooks), put `exec nix develop -c prek run --hook-stage pre-commit` in `.git/hooks/pre-commit` instead of `prek install`.

```sh
# unit tests (libcontainer + igvano library + CLI), run on any OS; Linux-only tests skip on macOS
nix develop -c zig build test

# one file's tests directly
# Doubled --dep libcontainer is intentional: one for root, one for igvano.
nix develop -c zig test --dep igvano --dep libcontainer -Mroot=src/main.zig \
  --dep libcontainer -Migvano=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig
```

After public API changes, build the independent consumer example to check the
library as an external dependency:

```sh
cd examples/consumer && nix develop ../.. -c zig build
nix develop ../.. -c zig build -Dtarget=x86_64-linux-musl
```

The Linux tests need root. Cross-compile the test binaries and run them in a
privileged container or a Linux VM:

```sh
mkdir -p zig-out
nix develop -c zig test src/libcontainer/root.zig --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/libcontainer-tests-linux
nix develop -c zig test --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/lib-tests-linux \
  --dep libcontainer -Mroot=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig
# Doubled --dep libcontainer is intentional: one for root, one for igvano.
nix develop -c zig test --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/main-tests-linux \
  --dep igvano --dep libcontainer -Mroot=src/main.zig \
  --dep libcontainer -Migvano=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig
nix develop -c zig build-exe src/test/seccomp-probe.zig -target x86_64-linux-musl -femit-bin=zig-out/seccomp-probe-x86_64
docker run --rm --init --privileged --platform linux/amd64 -v "$PWD/zig-out:/bins:ro" debian:bookworm-slim sh -c \
  'apt-get update -qq && apt-get install -y -qq procps >/dev/null; cp /bins/*-tests-linux /bins/seccomp-probe-x86_64 /tmp/ &&
   mkdir -p /tmp/work && cd /tmp/work && /tmp/libcontainer-tests-linux && /tmp/lib-tests-linux &&
   IGVANO_SECCOMP_PROBE=/tmp/seccomp-probe-x86_64 /tmp/main-tests-linux'
```

Run from a container-local directory (the tests create FIFOs and device
nodes). The seccomp lifecycle test needs the static probe named by
`IGVANO_SECCOMP_PROBE` (`zig build test` builds and passes it automatically).
cgroup v1, systemd and AppArmor tests skip unless the host provides them; the
project uses two Lima VMs (Ubuntu 24.04, arm64) for those: one booted into
pure cgroup v1, one on the default cgroup v2.

## OCI conformance

`hack/conformance.sh` runs the full runtime-tools validation suite and prints a
per-suite PASS/FAIL/SKIP table (full TAP log written next to it). By default it
runs inside a privileged `golang` container; `CONFORMANCE_VM=<lima instance>`
runs it as root in a Lima VM instead (needed for cgroup v1). It loads the
AppArmor profile the suite expects when the host has AppArmor.

```sh
./hack/conformance.sh
CONFORMANCE_VM=<v1 vm> ./hack/conformance.sh
```

Individual failures don't fail the script; the table is the tracking metric.
Failures caused by runtime-tools bugs or kernel limits are labelled in the
output. Pin the suite with `RUNTIME_TOOLS_REF=<ref>`. Run it from a checkout
under `$HOME` (Colima only shares `$HOME` with its VM).

## youki contest

`hack/contest.sh` builds youki's Rust integration suite
([contest](https://github.com/youki-dev/youki/tree/main/tests/contest)) at a
pinned commit (`YOUKI_REF`), then runs it against igvano with
`RUNTIME_KIND=runc` in a privileged `debian:bookworm-slim` container, one test
group at a time. It fails when a test outside
`hack/contest-expected-failures.txt` fails, or when a listed test stops failing, so
delete a line once its fix lands. `CONTEST_GROUPS="<group>..."` runs a subset;
`CONTEST_RUNTIME=<static runc>` runs the same suite against another runtime to
tell environment failures from igvano ones. x86_64 only.

```sh
./hack/contest.sh
CONTEST_GROUPS="lifecycle delete" ./hack/contest.sh
```

CI (`.github/workflows/ci.yml`) runs lint, `zig build test` on macOS, the
Linux unit tests as root, contest, runc's bats suite, containerd's
`integration/client` suite, runtime-tools (report only) and `hack/kind.sh`
with both cgroup drivers.

## containerd and CRI

`hack/containerd.sh` builds containerd v2.2 (pinned with `CONTAINERD_REF`),
installs igvano as `runc` under the stock `containerd-shim-runc-v2`, and runs
the `integration/client` suite (without CRIU) in a privileged `golang`
container. Like contest, it is gated by
`hack/containerd-expected-failures.txt`; today igvano fails exactly the tests
that runc v1.3.3 fails in the same container. `CONTAINERD_RUN=<regex>` runs a
subset and `CONTAINERD_RUNTIME=<static runc>` runs it against runc. x86_64 only.

```sh
./hack/containerd.sh
CONTAINERD_RUN='TestContainerExec' ./hack/containerd.sh
```

igvano has also been checked with
[cri-tools](https://github.com/kubernetes-sigs/cri-tools)' `critest` through
containerd's CRI plugin, by hand, on cgroup v1 and v2.

## runc compatibility (bats)

`hack/runc-bats.sh` runs runc's own bats suite (`tests/integration` at runc
v1.3.3, `RUNC_REF`) with igvano as `$RUNC`, one `.bats` file at a time, gated by
`hack/runc-bats-expected-failures.txt`. Leftover cgroups are removed between
files, so a hung test that kills its file cannot fail later files. `RUNC_BATS_FILES="<file>..."` runs a subset and
`RUNC_BATS_RUNTIME=<static runc>` runs it against runc. x86_64 only.

```sh
./hack/runc-bats.sh
RUNC_BATS_FILES="start kill" ./hack/runc-bats.sh
```

## Kubernetes (kind)

`hack/kind.sh` builds igvano for the Docker host's architecture and creates a
kind cluster with an igvano RuntimeClass. It checks a two-replica
`nginx:alpine` Deployment's readiness probes, exec, logs and pod replacement,
plus a one-shot BusyBox pod checking its mounted service-account token.
Docker, kind >= 0.30, kubectl and Nix must be on `PATH`. Use kubectl within one
minor version of the node's Kubernetes version (1.33–1.35 for the default 1.34
node). Pod replacement uses a bounded poll and does not need `wait --for=create`.

```sh
hack/kind.sh
KIND_CGROUP_DRIVER=cgroupfs hack/kind.sh
```

The default driver is systemd; the cgroupfs variant configures both kubelet
and every containerd runtime to use cgroupfs. `KIND_NODE_IMAGE` defaults to
`kindest/node:v1.34.0`, and `KIND_CLUSTER` defaults to `igvano-kind` (an
existing cluster with that name is refused). Failures print pod and containerd
diagnostics. The cluster and built node image are deleted on exit; set
`KEEP_CLUSTER=1` to retain them and use `kind export kubeconfig --name <cluster>`
to inspect it.

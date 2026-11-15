# igvano

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo/igvano-horizontal-dark.svg">
  <img alt="igvano logo: Ziggy the Ziguana standing on a shipping container" src="docs/logo/igvano-horizontal.svg" width="480">
</picture>

A toy OCI container runtime written in Zig. It started as an exercise in
conformance with the [OCI runtime spec](https://github.com/opencontainers/runtime-spec),
measured with [opencontainers/runtime-tools](https://github.com/opencontainers/runtime-tools),
and now also runs under containerd and Kubernetes' CRI the way runc does.

Linux only at runtime; the code builds and unit-tests on macOS (Linux-specific
paths are comptime-guarded). It is a single static binary with no C
dependencies (no libseccomp, no libsystemd).

## Features

runc-compatible CLI:

```
igvano [--root <dir>] [--log <file>] [--log-format text|json] [--systemd-cgroup] <command>

  create [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] <id>
  run [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] [--detach|-d] [--keep] <id>
  start <id>          state <id>          features
  spec [--bundle|-b <path>]
  list [--quiet|-q] [--format|-f table|json]
  events [--stats] [--interval <duration>] <id>
  kill [--all] <id> [signal]
  delete [--force|-f] <id>
  exec [--process <file>] [--detach] [--pid-file <file>] [--console-socket <path>]
       [--tty] [--cwd <dir>] [--env K=V]... [--user UID[:GID]] <id> [command...]
  ps [--format table|json] <id> [ps args...]
  pause <id>          resume <id>
  update [--resources <file|->] [--memory 64m] [--cpu-shares N] [--pids-limit N] ... <id>
```

Errors are also written to `--log` (JSON lines in `--log-format json`), which is
where containerd-shim-runc-v2 reads the failure reason.

Isolation and resources:

- Namespaces (including user namespaces, joining existing ones by path),
  pivot_root rootfs, default `/dev`, masked/read-only paths, sysctls, rlimits,
  capabilities, `noNewPrivileges`, `oomScoreAdj`, lifecycle hooks.
- cgroup v2 and cgroup v1, with the cgroupfs driver or the systemd driver
  (`--systemd-cgroup`, `linux.cgroupsPath` = `slice:prefix:name`; transient
  scopes over a minimal built-in D-Bus client; a rootless runtime uses the
  per-user manager on the session bus).
- Device rules on both versions: v1 `devices.*` via a port of runc's devices
  emulator; v2 via a `BPF_CGROUP_DEVICE` program.
- seccomp: a built-in classic-BPF compiler (native + compat arch, arg
  conditions, runc-compatible ENOSYS handling for newer syscalls).
- AppArmor profiles and SELinux labels (`process.selinuxLabel`,
  `linux.mountLabel`) for init and `exec`.
- `checkpoint` and `restore` through CRIU's RPC (`criu swrk`), like runc.
- Idmapped mounts (`uidMappings`/`gidMappings`, `idmap`/`ridmap`).
- `/proc` writes made inside the container (AppArmor, sysctls) go through a
  private procfs instance, failing closed if it cannot be verified.

Known limitations: no Intel RDT and no RDMA cgroup, systemd slice
units are not created (scopes only). In
joined mount namespaces, bind sources opened by the mount-source helper must
not contain symlinks.

## Using it with containerd

igvano runs under the stock `containerd-shim-runc-v2`; no shim of its own:

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.igvano]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.igvano.options]
    BinaryName = "/usr/local/bin/igvano"
    # SystemdCgroup = true   # optional
```

`ctr run --runc-binary /usr/local/bin/igvano ...` and
`nerdctl run --runtime /usr/local/bin/igvano ...` work too.

## Build

The Zig toolchain is pinned (ghostty-style): `minimum_zig_version` in
`build.zig.zon` is the single declared version, and the Nix flake devShell
provides exactly that compiler via [zig-overlay](https://github.com/mitchellh/zig-overlay).

```sh
# with Nix (recommended — exact pinned Zig)
nix develop -c zig build

# or once per clone, then plain zig commands work in this directory
direnv allow
zig build

# a Linux binary from macOS
nix develop -c zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe
```

Without Nix, install the Zig version named in `build.zig.zon` from
[ziglang.org](https://ziglang.org/download/); `build.zig` fails with a clear
`@compileError` on an older compiler.

Note: Nix flakes only see files tracked by git — `git add` new files before
`nix develop` or the build won't find them.

Other Zig projects can depend on the standalone `libcontainer` module:
fetch with `zig fetch --save git+https://github.com/igvano/igvano`, then import
`b.dependency("igvano", .{ .target = target, .optimize = optimize }).module("libcontainer")`.
See [src/libcontainer/README.md](src/libcontainer/README.md) for the API and caller contract,
and [examples/consumer](examples/consumer) for a complete build and usage example.

## Test

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

### OCI conformance

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

### youki contest

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

### containerd and CRI

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

### runc compatibility (bats)

`hack/runc-bats.sh` runs runc's own bats suite (`tests/integration` at runc
v1.3.3, `RUNC_REF`) with igvano as `$RUNC`, one `.bats` file at a time, gated by
`hack/runc-bats-expected-failures.txt`. Leftover cgroups are removed between
files, so a hung test that kills its file cannot fail later files. `RUNC_BATS_FILES="<file>..."` runs a subset and
`RUNC_BATS_RUNTIME=<static runc>` runs it against runc. x86_64 only.

```sh
./hack/runc-bats.sh
RUNC_BATS_FILES="start kill" ./hack/runc-bats.sh
```

### Kubernetes (kind)

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

## Layout

- `src/main.zig` — CLI entry point: dispatch and error reporting (stderr, `--log`)
- `src/cli/` — the runc-compatible commands: argument parsing (`args.zig`),
  `--log` writing, the state directory and locks (`state.zig`), one file per
  command (`create`, `start`, `exec`, `kill`, `delete`, `ps`, `pause`,
  `update`, `features`, ...); end-to-end CLI tests in `src/cli/tests/`
- `src/attached.zig` — attached `exec`: signal forwarding, pty proxy
- `src/oci.zig` + `src/oci/` — OCI spec types (config.json / state.json),
  validation, and translation to libcontainer types (resources, devices, mounts,
  process, seccomp, sysctls, systemd paths), `features`; fixture tests in
  `src/oci/tests/`
- `src/libcontainer/root.zig` — standalone `libcontainer` module: per-instance `Container` interface (vtable), persisted runtime `State`, and option/data types
- `src/libcontainer/linux.zig` + `src/libcontainer/linux/` — the namespace/cgroup implementation
  (the only one in scope): `linux.zig` holds `linux.Container`, constructed with
  `create(options)` or restored with `load(state)`, and adapters for its
  `container()` interface;
  the implementation is split by area (cgroup v1/v2, freezer, systemd, devices,
  mounts, rootfs, namespaces, process, procfs, console, create, exec);
  end-to-end tests in `src/libcontainer/linux/tests/`
- `src/libcontainer/seccomp.zig` — seccomp BPF compiler
- `src/libcontainer/devices.zig`, `devicefilter.zig` — device-cgroup emulator and v2 BPF device filter
- `src/libcontainer/dbus.zig` — minimal D-Bus client for the systemd driver
- `src/libcontainer/hooks.zig` — hook execution
- `hack/conformance.sh` — runtime-tools conformance harness

Small unit tests sit next to the code they test; tests that run real
containers live in the `tests/` directories and are pulled into the test
binaries with `test { _ = @import(...); }` blocks.

See `AGENTS.md` for architecture rules and development conventions.

## License

See [LICENSE](LICENSE).

The logo uses [Ziggy the Ziguana](https://codeberg.org/ziglang/logo#official-mascots)
by the Zig project, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See
[docs/logo](docs/logo/README.md) for details and changes.

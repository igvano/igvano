# igvano

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

  create [--bundle <path>] [--pid-file <file>] [--console-socket <path>] <id>
  start <id>          state <id>          features
  kill [--all] <id> [signal]
  delete [--force] <id>
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
  scopes over a minimal built-in D-Bus client).
- Device rules on both versions: v1 `devices.*` via a port of runc's devices
  emulator; v2 via a `BPF_CGROUP_DEVICE` program.
- seccomp: a built-in classic-BPF compiler (native + compat arch, arg
  conditions, runc-compatible ENOSYS handling for newer syscalls).
- AppArmor profiles for init and `exec`.
- Idmapped mounts (`uidMappings`/`gidMappings`, `idmap`/`ridmap`).
- `/proc` writes made inside the container (AppArmor, sysctls) go through a
  private procfs instance, failing closed if it cannot be verified.

Known limitations: no SELinux, no seccomp notify (`SCMP_ACT_NOTIFY`), no
checkpoint/restore, systemd slice units are not created (scopes only). In
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

## Test

```sh
# unit tests (library + CLI), run on any OS; Linux-only tests skip on macOS
nix develop -c zig build test

# one file's tests directly
nix develop -c zig test --dep igvano -Mroot=src/main.zig -Migvano=src/lib.zig
```

The Linux tests need root. Cross-compile the test binaries and run them in a
privileged container or a Linux VM:

```sh
nix develop -c zig test src/lib.zig --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/lib-tests-linux
nix develop -c zig test --test-no-exec -target x86_64-linux-musl -femit-bin=zig-out/main-tests-linux \
  --dep igvano -Mroot=src/main.zig -Migvano=src/lib.zig
nix develop -c zig build-exe src/test/seccomp-probe.zig -target x86_64-linux-musl -femit-bin=zig-out/seccomp-probe-x86_64
docker run --rm --init --privileged --platform linux/amd64 -v "$PWD/zig-out:/bins:ro" debian:bookworm-slim sh -c \
  'apt-get update -qq && apt-get install -y -qq procps >/dev/null; cp /bins/*-tests-linux /bins/seccomp-probe-x86_64 /tmp/ &&
   mkdir -p /tmp/work && cd /tmp/work && /tmp/lib-tests-linux &&
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

### containerd and CRI

igvano is also checked with containerd v2.2's integration suite
(`integration/client`, with igvano installed as `runc` on `PATH`) and with
[cri-tools](https://github.com/kubernetes-sigs/cri-tools)' `critest` through
containerd's CRI plugin. On both cgroup v1 and v2 the results match runc's.

## Layout

- `src/main.zig` — CLI entry point: dispatch and error reporting (stderr, `--log`)
- `src/cli/` — the runc-compatible commands: argument parsing (`args.zig`),
  `--log` writing, the state directory and locks (`state.zig`), one file per
  command (`create`, `start`, `exec`, `kill`, `delete`, `ps`, `pause`,
  `update`, `features`, ...); end-to-end CLI tests in `src/cli/tests/`
- `src/attached.zig` — attached `exec`: signal forwarding, pty proxy
- `src/oci.zig` + `src/oci/` — OCI spec types (config.json / state.json),
  validation, and translation to backend types (resources, devices, mounts,
  process, seccomp, sysctls, systemd paths), `features`; fixture tests in
  `src/oci/tests/`
- `src/backend.zig` — backend interface (vtable); isolation is pluggable by design
- `src/backend/linux.zig` + `src/backend/linux/` — the namespace/cgroup backend
  (the only one implemented): `linux.zig` holds `LinuxBackend` and its vtable;
  the implementation is split by area (cgroup v1/v2, freezer, systemd, devices,
  mounts, rootfs, namespaces, process, procfs, console, create, exec);
  end-to-end tests in `src/backend/linux/tests/`
- `src/backend/seccomp.zig` — seccomp BPF compiler
- `src/backend/devices.zig`, `devicefilter.zig` — device-cgroup emulator and v2 BPF device filter
- `src/backend/dbus.zig` — minimal D-Bus client for the systemd driver
- `src/backend/hooks.zig` — hook execution
- `hack/conformance.sh` — runtime-tools conformance harness

Small unit tests sit next to the code they test; tests that run real
containers live in the `tests/` directories and are pulled into the test
binaries with `test { _ = @import(...); }` blocks.

See `AGENTS.md` for architecture rules and development conventions.

## License

See [LICENSE](LICENSE).

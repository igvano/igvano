# AGENTS.md

Guidance for AI agents working in this repository.

## Project

igvano is a toy OCI container runtime written in Zig. It conforms to the OCI runtime spec (validated with opencontainers/runtime-tools) and runs as a runc replacement under containerd's stock `containerd-shim-runc-v2` (`BinaryName`), including CRI. The CLI is runc-compatible: `create`, `start`, `state`, `kill [--all]`, `delete [--force]`, `exec`, `ps`, `pause`, `resume`, `update`, `features`, with the global flags `--root`, `--log`, `--log-format`, `--systemd-cgroup`. runc's behaviour is the reference wherever the spec is silent.

## Architecture

Two layers, split so new isolation backends (wasm, VM-based, ...) can be added without touching the runtime frontend:

- **Runtime frontend** (`src/main.zig`, `src/oci.zig`): runc-compatible CLI, OCI spec types (config.json / state.json schemas), state persistence under `--root`, lifecycle state machine and exit codes. Knows nothing about HOW isolation happens.
- **Backend library** (`src/backend.zig`, `src/backend/`): libcontainer-like, exposed as its own Zig module importable without the CLI. `Backend` is a runtime-polymorphic interface (`std.mem.Allocator`-style ptr + vtable) with the ops `create`, `exec`, `alive`, `kill`, `killAll`, `update`, `pids`, `freeze`, `thaw`, `frozen`, `delete`, `diagnostic`. Supporting modules: `backend/seccomp.zig` (BPF compiler), `backend/devices.zig` + `devicefilter.zig` (device emulator, v2 BPF filter), `backend/dbus.zig` (systemd driver), `backend/hooks.zig`.

Scope: the ONLY backend in scope is `backend/linux.zig` (general container: namespaces + cgroups). wasm / VM-based isolation are future directions that justify the interface — do NOT scaffold stubs, enum variants, or config options for them.

Rules:
- OCI spec knowledge (JSON schemas, lifecycle semantics, CLI conventions) lives in the frontend only, never in backends. Backends receive parsed config, not config.json.
- Platform-specific code goes behind comptime `builtin.os.tag` guards; `zig build test` must pass on macOS (the dev machine) even though namespace isolation is Linux-only.
- No C dependencies (static musl binary): seccomp, D-Bus and BPF programs are generated in Zig.
- No allocation or std.Io calls in forked children before exec; prepare everything in the parent.
- Errors must carry a reason: frontend validation records a diagnostic, backend failures use `reportDiagnostic` (it crosses the fork boundary in the failure response) and reach stderr and `--log`.
- Security-sensitive paths fail closed (seccomp, device filter, AppArmor/procfs writes, mount locks for user-namespace containers).
- Inclusive naming: no master/slave/whitelist/blacklist identifiers (kernel API names such as `MS_SLAVE` excepted).

## Build and test

Zig is NOT installed system-wide. The toolchain comes from the Nix flake devShell (ghostty's scheme: `minimum_zig_version` in `build.zig.zon` is the single declared pin; `flake.nix` supplies exactly that compiler via `mitchellh/zig-overlay`).

```sh
nix develop -c zig build test   # build + run tests
nix develop -c zig build        # build only
direnv allow                    # once; then plain `zig build test` works in this dir
nix develop -c zig test --dep igvano -Mroot=src/main.zig -Migvano=src/lib.zig   # CLI tests directly
```

macOS skips every Linux-gated test, so a passing `zig build test` is not enough for backend changes. Linux checks (see README "Test"):
- x86_64 cgroup v2: cross-compile the lib/main test binaries for `x86_64-linux-musl` (`--test-no-exec`) and run them as root in privileged `debian:bookworm-slim` (install `procps`) from a container-local directory. The main tests need `IGVANO_SECCOMP_PROBE` pointing at `src/test/seccomp-probe.zig` built for the same target.
- arm64 cgroup v1 and v2, systemd, AppArmor: the same binaries built for `aarch64-linux-musl`, run as root in the Lima VMs (one pure cgroup v1, one cgroup v2).
- Conformance: `hack/conformance.sh` (cgroup v2, Colima) and `CONFORMANCE_VM=<vm> hack/conformance.sh` (cgroup v1), from a checkout under `$HOME`. Gate per suite: no previously clean suite may gain failures; known runtime-tools/kernel failures are labelled.
- containerd: v2.2 `integration/client` suite and `critest` via the CRI plugin, compared with runc on the same host.

Gotchas:
- Nix flakes ignore untracked files — `git add` new files before `nix develop` or the build won't see them.
- When bumping the Zig version, change it in both `build.zig.zon` (`minimum_zig_version`) and `flake.nix` (zig-overlay version string).

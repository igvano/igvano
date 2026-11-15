# AGENTS.md

Guidance for AI agents working in this repository.

## Project

igvano is a toy OCI container runtime written in Zig. It conforms to the OCI runtime spec (validated with opencontainers/runtime-tools) and runs as a runc replacement under containerd's stock `containerd-shim-runc-v2` (`BinaryName`), including CRI. The CLI is runc-compatible: `create`, `run [--detach] [--keep]`, `start`, `state`, `list`, `spec`, `events [--stats] [--interval]`, `kill [--all]`, `delete [--force]`, `exec`, `ps`, `pause`, `resume`, `update`, `features`, with the global flags `--root`, `--log`, `--log-format`, `--systemd-cgroup`. runc's behaviour is the reference wherever the spec is silent.

## Architecture

Two layers, split so future isolation implementations can be added without touching the runtime frontend:

- **Runtime frontend** (`src/main.zig`, `src/cli/`, `src/attached.zig`, `src/oci.zig` + `src/oci/`): runc-compatible CLI, OCI spec types (config.json / state.json schemas), state persistence under `--root`, lifecycle state machine and exit codes. Knows nothing about HOW isolation happens.
- **Container library** (`src/libcontainer/root.zig`, `src/libcontainer/`): exposed as the standalone `libcontainer` Zig module importable without the CLI. `Container` is a per-instance interface (`std.mem.Allocator`-style ptr + vtable) with the ops `exec`, `alive`, `kill`, `killAll`, `update`, `pids`, `stats`, `freeze`, `thaw`, `frozen`, `delete`, `diagnostic`. `State` holds the per-container runtime data persisted by the frontend; option and data types are module-level declarations. Supporting modules: `libcontainer/seccomp.zig` (BPF compiler), `libcontainer/devices.zig` + `devicefilter.zig` (device emulator, v2 BPF filter), `libcontainer/dbus.zig` (systemd driver), `libcontainer/hooks.zig`.

`libcontainer/linux.zig` is a thin facade: `linux.Container.create(options)` constructs an instance, `load(state)` restores one from borrowed runtime data, and `container()` exposes its interface. Its vtable adapters read the instance's `State`; the Linux implementation lives in `libcontainer/linux/` by area. `linux.diagnostic()` also exposes failure detail when construction fails before an instance exists.

Scope: the ONLY implementation in scope is `libcontainer/linux.zig` (general container: namespaces + cgroups). wasm / VM-based isolation are future directions that justify the interface — do NOT scaffold stubs, enum variants, or config options for them.

Rules:
- OCI spec knowledge (JSON schemas, lifecycle semantics, CLI conventions) lives in the frontend only, never in the library. The library receives parsed config, not config.json.
- Platform-specific code goes behind comptime `builtin.os.tag` guards; `zig build test` must pass on macOS (the dev machine) even though namespace isolation is Linux-only.
- No C dependencies (static musl binary): seccomp, D-Bus and BPF programs are generated in Zig.
- No allocation or std.Io calls in forked children before exec; prepare everything in the parent.
- Errors must carry a reason: frontend validation records a diagnostic, library failures use `reportDiagnostic` (it crosses the fork boundary in the failure response) and reach stderr and `--log`.
- Security-sensitive paths fail closed (seccomp, device filter, AppArmor/procfs writes, mount locks for user-namespace containers).
- File layout: keep files roughly under 1,000–1,500 lines; small unit tests next to the code, container-running end-to-end tests in the area's `tests/` directory. Every new file must be reachable from test discovery (`test { _ = @import("x.zig"); }`); a refactor must not change test names or counts.
- Inclusive naming: no master/slave/whitelist/blacklist identifiers (kernel API names such as `MS_SLAVE` excepted).

## Build and test

Pre-commit hooks run through [prek](https://github.com/j178/prek): `zig fmt --check`, and `cccc` enforcing the `cccc.toml` complexity limits (cognitive 25, cyclomatic 15 per function; `tests/` and `test/` exempt) on the staged files and on all of `src/`. Both tools come from the devShell. With a global `core.hooksPath` (e.g. a corporate hook that chains to local hooks), put `exec nix develop -c prek run --hook-stage pre-commit` in `.git/hooks/pre-commit` instead of `prek install`.

Zig is NOT installed system-wide. The toolchain comes from the Nix flake devShell (ghostty's scheme: `minimum_zig_version` in `build.zig.zon` is the single declared pin; `flake.nix` supplies exactly that compiler via `mitchellh/zig-overlay`).

```sh
nix develop -c zig build test   # build + run tests
nix develop -c zig build        # build only
direnv allow                    # once; then plain `zig build test` works in this dir
nix develop -c mdbook build docs  # docs (user and developer guide in docs/src)
# Doubled --dep libcontainer is intentional: one for root, one for igvano.
nix develop -c zig test --dep igvano --dep libcontainer -Mroot=src/main.zig \
  --dep libcontainer -Migvano=src/lib.zig -Mlibcontainer=src/libcontainer/root.zig   # CLI tests directly
```

After public API changes, check the library as an external dependency with the
independent `examples/consumer` project:
`cd examples/consumer && nix develop ../.. -c zig build`, then
`nix develop ../.. -c zig build -Dtarget=x86_64-linux-musl` for the Linux check.

macOS skips every Linux-gated test, so a passing `zig build test` is not enough for Linux implementation changes. Linux checks (see docs/src/testing.md):
- x86_64 cgroup v2: cross-compile the libcontainer/lib/main test binaries for `x86_64-linux-musl` (`--test-no-exec`) and run them as root in privileged `debian:bookworm-slim` (install `procps`) from a container-local directory. The main tests need `IGVANO_SECCOMP_PROBE` pointing at `src/test/seccomp-probe.zig` built for the same target.
- arm64 cgroup v1 and v2, systemd, AppArmor: the same binaries built for `aarch64-linux-musl`, run as root in the Lima VMs (one pure cgroup v1, one cgroup v2).
- Conformance: `hack/conformance.sh` (cgroup v2, Colima) and `CONFORMANCE_VM=<vm> hack/conformance.sh` (cgroup v1), from a checkout under `$HOME`. Gate per suite: no previously clean suite may gain failures; known runtime-tools/kernel failures are labelled.
- contest: `hack/contest.sh` (youki's suite, `RUNTIME_KIND=runc`, x86_64, cgroup v2). Gate: the failures must match `hack/contest-expected-failures.txt` exactly; delete a line when a fix makes it pass, and add one only with a reason (check runc first with `CONTEST_RUNTIME`). A `? ` prefix marks a host-dependent test that may pass or fail; GitHub's ubuntu-24.04 runner is the reference host.
- Unit tests on an xfs filesystem fail `linux dangling mount destinations bound symlink loops and expanded paths` with `NameTooLong` (xfs rejects symlink targets of 1 KiB or more); run from ext4 or tmpfs.
- runc bats: `hack/runc-bats.sh` (runc v1.3.3 `tests/integration`, x86_64, cgroup v2), gated by `hack/runc-bats-expected-failures.txt` the same way (check runc first with `RUNC_BATS_RUNTIME`).
- containerd: `hack/containerd.sh` (v2.2 `integration/client`, x86_64, cgroup v2), gated by `hack/containerd-expected-failures.txt` the same way (`CONTAINERD_RUNTIME` for runc). `critest` via the CRI plugin is still a manual check, compared with runc on the same host.
- Kubernetes (kind): `hack/kind.sh` (systemd driver) and `KIND_CGROUP_DRIVER=cgroupfs hack/kind.sh` (cgroupfs driver for kubelet and all containerd runtimes). Requires Docker, kind >= 0.30, kubectl within one minor version of the node's Kubernetes version (1.33–1.35 for the default 1.34 node), and Nix; builds for the Docker host architecture. Pod replacement uses a bounded poll without `kubectl wait --for=create`. Checks nginx readiness/exec/logs/pod replacement and the default service-account token mount. `KIND_CLUSTER` defaults to `igvano-kind` (must not already exist), `KIND_NODE_IMAGE` to `kindest/node:v1.34.0`; `KEEP_CLUSTER=1` retains the cluster and built node image, otherwise the exit trap removes both after failure diagnostics.

Gotchas:
- Nix flakes ignore untracked files — `git add` new files before `nix develop` or the build won't see them.
- When bumping the Zig version, change it in both `build.zig.zon` (`minimum_zig_version`) and `flake.nix` (zig-overlay version string).

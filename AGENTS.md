# AGENTS.md

Guidance for AI agents working in this repository.

## Project

igvano is a toy OCI container runtime written in Zig. First goal: conform to the OCI runtime spec, validated with opencontainers/runtime-tools. The binary exposes the standard lifecycle subcommands (`state`, `create`, `start`, `kill`, `delete`); runtime-tools calls them as `create --bundle <path> <id>`, `start <id>`, etc., and expects state JSON on stdout.

## Architecture

Two layers, split so new isolation backends (wasm, VM-based, ...) can be added without touching the runtime frontend:

- **Runtime frontend** (`src/main.zig`, `src/oci.zig`): runc-compatible CLI, OCI spec types (config.json / state.json schemas), state persistence under `--root`, lifecycle state machine and exit codes. Knows nothing about HOW isolation happens.
- **Backend library** (`src/backend.zig`, `src/backend/`): libcontainer-like, exposed as its own Zig module importable without the CLI. `Backend` is a runtime-polymorphic interface (`std.mem.Allocator`-style ptr + vtable) with the lifecycle ops: `create`, `start`, `kill`, `delete`.

Scope: the ONLY backend in scope is `backend/linux.zig` (general container: namespaces + cgroups). wasm / VM-based isolation are future directions that justify the interface — do NOT scaffold stubs, enum variants, or config options for them.

Rules:
- OCI spec knowledge (JSON schemas, lifecycle semantics, CLI conventions) lives in the frontend only, never in backends. Backends receive parsed config, not config.json.
- Platform-specific code goes behind comptime `builtin.os.tag` guards; `zig build test` must pass on macOS (the dev machine) even though namespace isolation is Linux-only.

## Build and test

Zig is NOT installed system-wide. The toolchain comes from the Nix flake devShell (ghostty's scheme: `minimum_zig_version` in `build.zig.zon` is the single declared pin; `flake.nix` supplies exactly that compiler via `mitchellh/zig-overlay`).

```sh
nix develop -c zig build test   # build + run tests
nix develop -c zig build        # build only
direnv allow                    # once; then plain `zig build test` works in this dir
nix develop -c zig test src/main.zig   # run one file's tests directly
```

Gotchas:
- Nix flakes ignore untracked files — `git add` new files before `nix develop` or the build won't see them.
- When bumping the Zig version, change it in both `build.zig.zon` (`minimum_zig_version`) and `flake.nix` (zig-overlay version string).

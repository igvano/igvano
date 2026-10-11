# AGENTS.md

Guidance for AI agents working in this repository.

## Project

igvano is a toy OCI container runtime written in Zig. First goal: conform to the OCI runtime spec, validated with opencontainers/runtime-tools. The binary exposes the standard lifecycle subcommands (`state`, `create`, `start`, `kill`, `delete`); runtime-tools calls them as `create --bundle <path> <id>`, `start <id>`, etc., and expects state JSON on stdout.

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

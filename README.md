# igvano

A toy OCI container runtime written in Zig. The first goal is conformance with the
[OCI runtime spec](https://github.com/opencontainers/runtime-spec), measured with
[opencontainers/runtime-tools](https://github.com/opencontainers/runtime-tools).

It is runc-compatible in shape: `igvano [--root <dir>] create|start|state|kill|delete`,
double-fork + namespace isolation, pivot_root rootfs, cgroup v2, user namespaces,
default `/dev` population, and lifecycle hooks. Linux only at runtime; the code
builds and unit-tests on macOS (Linux-specific paths are comptime-guarded).

`--systemd-cgroup` selects systemd scopes without a libsystemd dependency.
Set `linux.cgroupsPath` to `slice:prefix:name`; an empty path defaults to
`system.slice:igvano:<id>`. Later commands use the saved driver and resolved
path. Transient slice units are currently rejected with a diagnostic.

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
```

Without Nix, install the Zig version named in `build.zig.zon` from
[ziglang.org](https://ziglang.org/download/); `build.zig` fails with a clear
`@compileError` on an older compiler.

Note: Nix flakes only see files tracked by git — `git add` new files before
`nix develop` or the build won't find them.

## Test

```sh
# unit tests (library + CLI), run on any OS
nix develop -c zig build test

# one file's tests directly
nix develop -c zig test --dep igvano -Mroot=src/main.zig -Migvano=src/lib.zig
```

The systemd lifecycle tests require root and `/run/systemd/private`; they skip
on hosts without systemd and exercise both the private socket and system bus
fallback on the v1/v2 Lima hosts.

The Linux seccomp lifecycle test needs a static probe. `zig build test` builds
it in the build cache and passes its path through `IGVANO_SECCOMP_PROBE`;
the probe is not installed in `zig-out/bin`. For direct or cross-compiled test
runs, build `src/test/seccomp-probe.zig` with `zig build-exe` for the same target
and set `IGVANO_SECCOMP_PROBE` to its path on the test host.

Running real containers needs Linux. On macOS, cross-compile and use a
privileged container (Docker/colima work):

```sh
nix develop -c zig build -Dtarget=x86_64-linux-musl
docker run --rm --privileged -v $PWD/zig-out/bin/igvano:/igvano:ro busybox:musl sh
# inside: /igvano --root /r create --bundle /b <id> && /igvano --root /r start <id> ...
```

### OCI conformance

`hack/conformance.sh` runs the full runtime-tools validation suite against
igvano inside a privileged `golang` container and prints a per-suite
PASS/FAIL/SKIP table (full TAP log written next to it):

```sh
./hack/conformance.sh
```

Individual conformance failures don't fail the script; the table is the
tracking metric. Pin the suite with `RUNTIME_TOOLS_REF=<ref>`.

## Layout

- `src/main.zig` — CLI frontend: arg parsing, lifecycle state machine, state dir
- `src/oci.zig` — OCI spec types (config.json / state.json) and validation
- `src/backend.zig` — backend interface (vtable); isolation is pluggable by design
- `src/backend/linux.zig` — the namespace/cgroup backend (the only one implemented)

See `AGENTS.md` for architecture rules and development conventions.

## License

See [LICENSE](LICENSE).

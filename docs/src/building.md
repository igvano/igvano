# Building

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
See [src/libcontainer/README.md](https://github.com/igvano/igvano/blob/main/src/libcontainer/README.md) for the API and caller contract,
and [examples/consumer](https://github.com/igvano/igvano/tree/main/examples/consumer) for a complete build and usage example.

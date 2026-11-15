# igvano

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/src/logo/igvano-horizontal-dark.svg">
  <img alt="igvano logo: Ziggy the Ziguana standing on a shipping container" src="docs/src/logo/igvano-horizontal.svg" width="480">
</picture>

A toy OCI container runtime written in Zig. It aims at runc compatibility and
runs under containerd and Kubernetes' CRI the way runc does. It is a single
static Linux binary with no C dependencies.

## Quick start

```sh
nix develop -c zig build        # zig-out/bin/igvano
nix develop -c zig build test   # unit tests
```

## Documentation

The docs live in [docs/](docs/src/SUMMARY.md) as an mdBook. Preview them with
`nix develop -c mdbook serve docs`.

| Page | Covers |
|---|---|
| [Features](docs/src/features.md) | CLI and what is supported |
| [Using it with containerd](docs/src/containerd.md) | containerd and CRI setup |
| [Building](docs/src/building.md) | toolchain, cross builds, using `libcontainer` |
| [Testing](docs/src/testing.md) | unit tests and the Linux test suites |
| [Source layout](docs/src/layout.md) | where the code lives |

See [AGENTS.md](AGENTS.md) for architecture rules and conventions.

## License

See [LICENSE](LICENSE).

The logo uses [Ziggy the Ziguana](https://codeberg.org/ziglang/logo#official-mascots)
by the Zig project, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See
[docs/src/logo](docs/src/logo/README.md) for details and changes.

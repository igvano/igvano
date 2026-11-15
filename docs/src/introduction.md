# igvano

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo/igvano-horizontal-dark.svg">
  <img alt="igvano logo: Ziggy the Ziguana standing on a shipping container" src="logo/igvano-horizontal.svg" width="480">
</picture>

A toy OCI container runtime written in Zig. It started as an exercise in
conformance with the [OCI runtime spec](https://github.com/opencontainers/runtime-spec),
measured with [opencontainers/runtime-tools](https://github.com/opencontainers/runtime-tools),
and now also runs under containerd and Kubernetes' CRI the way runc does.

Linux only at runtime; the code builds and unit-tests on macOS (Linux-specific
paths are comptime-guarded). It is a single static binary with no C
dependencies (no libseccomp, no libsystemd).


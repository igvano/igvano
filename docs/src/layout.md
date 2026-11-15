# Source layout

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
- `docs/` — this documentation (mdBook); preview with `nix develop -c mdbook serve docs`

Small unit tests sit next to the code they test; tests that run real
containers live in the `tests/` directories and are pulled into the test
binaries with `test { _ = @import(...); }` blocks.

See [AGENTS.md](https://github.com/igvano/igvano/blob/main/AGENTS.md) for architecture rules and development conventions.

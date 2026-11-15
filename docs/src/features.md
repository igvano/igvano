# Features

runc-compatible CLI:

```
igvano [--root <dir>] [--log <file>] [--log-format text|json] [--systemd-cgroup] <command>

  create [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] <id>
  run [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] [--detach|-d] [--keep] <id>
  start <id>          state <id>          features
  spec [--bundle|-b <path>]
  list [--quiet|-q] [--format|-f table|json]
  events [--stats] [--interval <duration>] <id>
  kill [--all] <id> [signal]
  delete [--force|-f] <id>
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
  scopes over a minimal built-in D-Bus client; a rootless runtime uses the
  per-user manager on the session bus).
- Device rules on both versions: v1 `devices.*` via a port of runc's devices
  emulator; v2 via a `BPF_CGROUP_DEVICE` program.
- seccomp: a built-in classic-BPF compiler (native + compat arch, arg
  conditions, runc-compatible ENOSYS handling for newer syscalls).
- AppArmor profiles and SELinux labels (`process.selinuxLabel`,
  `linux.mountLabel`) for init and `exec`.
- `checkpoint` and `restore` through CRIU's RPC (`criu swrk`), like runc.
- Idmapped mounts (`uidMappings`/`gidMappings`, `idmap`/`ridmap`).
- `/proc` writes made inside the container (AppArmor, sysctls) go through a
  private procfs instance, failing closed if it cannot be verified.

Known limitations: no Intel RDT and no RDMA cgroup, systemd slice
units are not created (scopes only). In
joined mount namespaces, bind sources opened by the mount-source helper must
not contain symlinks.

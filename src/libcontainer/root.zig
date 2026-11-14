//! A runc-style libcontainer for Zig, using Linux namespaces and cgroups.
//! Linux-only at runtime; it compiles elsewhere, where operations return
//! NotImplemented and Linux tests skip. Callers need root or a user namespace
//! and a writable cgroup hierarchy or systemd.
//!
//! ```zig
//! var instance = try libcontainer.linux.Container.create(options);
//! defer instance.deinit(options.allocator);
//! const container = instance.container();
//! _ = try container.alive();
//! // Persist instance.state, then borrow the restored state:
//! var restored = libcontainer.linux.Container.load(state);
//! defer restored.deinit(options.allocator); // Borrowed state: no-op.
//! _ = try restored.container().alive();
//! ```
//!
//! All option strings and slices are borrowed. Keep state-referenced data alive
//! while using the instance. State is caller-persisted; its strings are borrowed
//! except starttime allocated by create and freed by deinit with the same allocator.
//! load borrows all state; adopt transfers ownership of an allocated starttime.
//! Interface handles borrow their instance, which must remain at a stable address.
//! Diagnostics are thread-local borrowed slices: copy them immediately after a
//! failed call, before another container operation or cleanup overwrites them.
//! create forks; keep caller-owned descriptors CLOEXEC-safe, including passed
//! descriptors as documented on CreateOptions.

const std = @import("std");
const builtin = @import("builtin");

pub const linux = @import("linux.zig");
pub const hooks = @import("hooks.zig");

pub const testing = if (builtin.is_test) struct {
    pub const seccomp = @import("test/seccomp.zig");
} else struct {};

pub const seccomp = @import("seccomp.zig");

/// Strings and slices are borrowed; the caller owns their memory.
/// create forks: caller-owned descriptors must be CLOEXEC to avoid leaking
/// into init or hooks. Passed console_fds follow the contract below.
pub const CreateOptions = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    /// Absolute rootfs path resolved by the frontend.
    rootfs: []const u8,
    /// Absolute path to the FIFO created by the frontend.
    exec_fifo: []const u8,
    process: ?Process = null,
    namespaces: []const Namespace = &.{},
    /// Clock offsets for a new time namespace (CLOCK_MONOTONIC, CLOCK_BOOTTIME).
    time_offsets: ?TimeOffsets = null,
    uid_mappings: []const IDMapping = &.{},
    gid_mappings: []const IDMapping = &.{},
    hostname: ?[]const u8 = null,
    domainname: ?[]const u8 = null,
    readonly_rootfs: bool = false,
    /// Borrowed socketpair: init sends its PTY controller on [1]; the caller
    /// receives on [0]. Both ends are CLOEXEC and remain caller-owned.
    console_fds: ?[2]std.posix.fd_t = null,
    mounts: []const Mount = &.{},
    /// Normalized path relative to each cgroup hierarchy's mount root.
    cgroup_path: []const u8 = "",
    systemd: bool = false,
    systemd_slice: []const u8 = "system.slice",
    systemd_unit: []const u8 = "",
    resources: Resources = .{},
    capabilities: ?Capabilities = null,
    rlimits: []const Rlimit = &.{},
    oom_score_adj: ?i32 = null,
    devices: []const Device = &.{},
    device_symlinks: []const Symlink = &.{},
    create_hooks: []const Hook = &.{},
    start_hooks: []const Hook = &.{},
    /// Opaque serialized input, split where the host PID is inserted.
    /// Only the frontend knows its JSON schema and lifecycle status.
    create_hook_state: HookState = .{},
    start_hook_state: HookState = .{},
    /// Called in the parent after mounts are ready, before child hooks and
    /// pivot_root. Returning an error aborts create and cleans up init.
    on_create: ?CreateCallback = null,
    masked_paths: []const []const u8 = &.{},
    readonly_paths: []const []const u8 = &.{},
    sysctls: []const Sysctl = &.{},
    /// runc --preserve-fds: fds 3..3+N-1 reach the container process.
    preserve_fds: u32 = 0,
    /// runc --no-pivot: move the rootfs onto / and chroot, not pivot_root.
    no_pivot: bool = false,
    /// Host interfaces to move into the container's network namespace.
    net_devices: []const NetDevice = &.{},
    /// Null means runc's default, rslave, in a private mount namespace.
    rootfs_propagation: ?u32 = null,
    apparmor_profile: ?[]const u8 = null,
    seccomp: ?seccomp.Config = null,
    /// Required when the seccomp config has notify rules.
    on_seccomp_listener: ?SeccompListenerCallback = null,
    /// linux.cgroupsPath was omitted, so cgroup_path is igvano's default.
    cgroup_path_default: bool = false,
    /// runc's rootless cgroup manager: with no permission to create a
    /// default cgroup and no limits, run without one; device rules are
    /// best effort.
    rootless_cgroups: bool = false,
    /// Absolute newuidmap/newgidmap paths; a non-root runtime uses them for
    /// maps beyond its own IDs, like runc.
    newuidmap: ?[]const u8 = null,
    newgidmap: ?[]const u8 = null,
    debug: ?DebugLog = null,
};

pub const Process = struct {
    args: []const []const u8,
    env: []const []const u8 = &.{},
    cwd: []const u8,
    terminal: bool = false,
    /// process.consoleSize; applied like runc only when both are non-zero.
    console_size: ?ConsoleSize = null,
    uid: u32,
    gid: u32,
    additional_gids: []const u32 = &.{},
    /// process.user.umask; init falls back to 0o022, like runc.
    umask: ?u32 = null,
    no_new_privileges: bool = false,
    scheduler: ?Scheduler = null,
    io_priority: ?IOPriority = null,
    /// linux.memoryPolicy and linux.personality, applied before exec.
    memory_policy: ?MemoryPolicy = null,
    personality: ?u32 = null,
};

/// sched_setattr(2) values; the frontend has validated them like runc.
/// set_mempolicy(2) arguments; the frontend has validated them like youki.
pub const MemoryPolicy = struct {
    /// MPOL_* mode with MPOL_F_* flags.
    mode: i32,
    nodemask: [max_numa_nodes / @bitSizeOf(usize)]usize = @splat(0),
    /// Bits in nodemask plus one: the kernel ignores the last bit.
    maxnode: usize = 0,

    pub const max_numa_nodes = 1024;
};

pub const ConsoleSize = struct { height: u16, width: u16 };

pub const Scheduler = struct {
    policy: u32,
    flags: u64 = 0,
    nice: i32 = 0,
    priority: u32 = 0,
    runtime: u64 = 0,
    deadline: u64 = 0,
    period: u64 = 0,
};

/// ioprio_set(2) class (1 rt, 2 be, 3 idle) and level 0..7, like runc.
pub const IOPriority = struct {
    class: u2,
    priority: u3,
};

pub const TimeOffsets = struct {
    monotonic: ?TimeOffset = null,
    boottime: ?TimeOffset = null,
};
pub const TimeOffset = struct { secs: i64, nanosecs: u32 };

pub const Namespace = struct {
    kind: Kind,
    path: ?[]const u8 = null,

    pub const Kind = enum { pid, network, mount, ipc, uts, user, cgroup, time };
};

pub const Hook = hooks.Hook;
/// Process settings translated by the frontend; all memory is caller-owned.
pub const ExecOptions = struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    envp: []const []const u8 = &.{},
    cwd: []const u8,
    uid: u32,
    gid: u32,
    additional_gids: []const u32 = &.{},
    capabilities: ?Capabilities = null,
    rlimits: []const Rlimit = &.{},
    no_new_privileges: bool = false,
    apparmor_profile: ?[]const u8 = null,
    oom_score_adj: ?i32 = null,
    console_fds: ?[2]std.posix.fd_t = null,
    cgroup_path: []const u8 = "",
    seccomp: ?seccomp.Config = null,
    /// Required when the seccomp config has notify rules.
    on_seccomp_listener: ?SeccompListenerCallback = null,
    /// Null resets the affinity to every CPU the cgroup allows, like runc.
    cpu_affinity: ?CPUAffinity = null,
    scheduler: ?Scheduler = null,
    io_priority: ?IOPriority = null,
    /// linux.memoryPolicy and linux.personality, applied before exec.
    memory_policy: ?MemoryPolicy = null,
    personality: ?u32 = null,
    debug: ?DebugLog = null,
    /// runc exec --cgroup: paths below the container's cgroup to join.
    /// One entry with no controller applies to every controller.
    sub_cgroups: []const SubCgroup = &.{},
    console_size: ?ConsoleSize = null,
    /// runc exec --pidfd-socket: a connected socket; the process sends a
    /// pidfd of itself on it before exec, like runc's setupPidfd.
    pidfd_socket: ?std.posix.fd_t = null,
    /// The container's process.user.umask, which runc exec also applies.
    umask: ?u32 = null,
    /// runc exec --preserve-fds: fds 3..3+N-1 reach the process.
    preserve_fds: u32 = 0,
};

pub const SubCgroup = struct { controller: []const u8 = "", path: []const u8 };

/// Where --debug lines go: an O_APPEND log file or stderr.
pub const DebugLog = struct {
    fd: std.posix.fd_t,
    json: bool = false,
};

/// A sched_setaffinity(2) mask of 1024 CPUs, the size of glibc's cpu_set_t.
pub const CpuSet = [16]u64;

/// runtime-spec execCPUAffinity: initial is set before the process joins the
/// container cgroup, final right after.
pub const CPUAffinity = struct {
    initial: ?CpuSet = null,
    final: ?CpuSet = null,
};

/// Receives the runtime's copy of a seccomp notify fd (borrowed; closed after
/// return) and the host PID of the process that installed the filter.
pub const SeccompListenerCallback = struct {
    ptr: *anyopaque,
    run: *const fn (*anyopaque, std.posix.fd_t, i32) Error!void,
};

pub const CreateCallback = struct {
    ptr: *anyopaque,
    run: *const fn (*anyopaque, State) Error!void,
};
pub const HookState = struct {
    prefix: []const u8 = "",
    suffix: []const u8 = "",
};

/// Device types, defaults and paths have been translated by the frontend.
pub const Device = struct {
    path: []const u8,
    kind: Kind,
    major: u32 = 0,
    minor: u32 = 0,
    mode: u32 = 0o666,
    uid: u32 = 0,
    gid: u32 = 0,
    /// Explicit devices cannot be skipped when /dev is bind-mounted.
    required: bool = true,
    pub const Kind = enum { character, block, fifo };
};

pub const Symlink = struct {
    path: [:0]const u8,
    target: [:0]const u8,
};

/// The new UTS namespace's names.
pub const Uts = struct { hostname: ?[]const u8 = null, domainname: ?[]const u8 = null };
pub const Sysctl = struct { key: []const u8, value: []const u8 };
/// An empty name keeps the host name.
pub const NetDevice = struct { host_name: []const u8, name: []const u8 = "" };

/// Capability names and rlimit types have been translated by the frontend.
pub const Capabilities = struct {
    bounding: u64 = 0,
    effective: u64 = 0,
    inheritable: u64 = 0,
    permitted: u64 = 0,
    ambient: u64 = 0,
};

pub const Rlimit = struct {
    resource: std.os.linux.rlimit_resource,
    hard: u64,
    soft: u64,
};

/// Hierarchy-independent resource settings. All slices are caller-owned.
pub const Resources = struct {
    memory: ?Memory = null,
    cpu: ?Cpu = null,
    pids: ?Pids = null,
    block_io: ?BlockIO = null,
    hugepage_limits: []const HugepageLimit = &.{},
    network: ?Network = null,
    devices: []const DeviceRule = &.{},
    unified: []const Unified = &.{},

    pub const Memory = struct {
        /// -1 represents unlimited for signed memory limits.
        limit: ?i64 = null,
        reservation: ?i64 = null,
        swap: ?i64 = null,
        kernel: ?i64 = null,
        kernel_tcp: ?i64 = null,
        swappiness: ?u64 = null,
        disable_oom_killer: ?bool = null,
        /// cgroup v2: refuse a limit at or below current usage, like runc.
        check_before_update: bool = false,
    };
    pub const Cpu = struct {
        shares: ?u64 = null,
        quota: ?i64 = null,
        period: ?u64 = null,
        realtime_runtime: ?i64 = null,
        realtime_period: ?u64 = null,
        /// cgroup cpu.idle (SCHED_IDLE group); the kernel accepts only 0 or 1.
        idle: ?i64 = null,
        /// cpu.max.burst (v2) or cpu.cfs_burst_us (v1); 0 is written.
        burst: ?u64 = null,
        cpus: ?[]const u8 = null,
        mems: ?[]const u8 = null,
    };
    pub const Pids = struct { limit: ?i64 = null };
    pub const BlockIO = struct {
        weight: ?u16 = null,
        leaf_weight: ?u16 = null,
        weight_device: []const WeightDevice = &.{},
        throttle_read_bps: []const ThrottleDevice = &.{},
        throttle_write_bps: []const ThrottleDevice = &.{},
        throttle_read_iops: []const ThrottleDevice = &.{},
        throttle_write_iops: []const ThrottleDevice = &.{},
    };
    pub const WeightDevice = struct {
        major: i64,
        minor: i64,
        weight: ?u16 = null,
        leaf_weight: ?u16 = null,
    };
    pub const ThrottleDevice = struct { major: i64, minor: i64, rate: u64 };
    pub const HugepageLimit = struct { page_size: []const u8, limit: u64 };
    pub const Network = struct {
        class_id: ?u32 = null,
        priorities: []const Priority = &.{},
    };
    pub const Priority = struct { name: []const u8, priority: u32 };
    pub const DeviceRule = struct {
        allow: bool,
        kind: enum { all, block, char } = .all,
        /// Null represents a wildcard device number.
        major: ?i64 = null,
        minor: ?i64 = null,
        access: []const u8 = "rwm",
    };
    pub const Unified = struct { key: []const u8, value: []const u8 };
};

/// MOUNT_ATTR_* bits to set and clear on a mount and every submount.
pub const RecursiveAttr = struct {
    set: u64 = 0,
    clear: u64 = 0,
};

/// Mount options and destinations have already been translated by the frontend.
// ponytail: MS_* flags tie this neutral interface to Linux; acceptable while
// Linux is the only implementation. Translate to neutral options when another is added.
pub const Mount = struct {
    destination: []const u8,
    source: ?[]const u8,
    type: ?[]const u8,
    flags: u32,
    propagation: u32,
    data: []const u8,
    /// mount_setattr(AT_RECURSIVE) change from runc's "r*" options.
    recursive_attr: ?RecursiveAttr = null,
    mappings: ?MountMappings = null,
    /// For tmpfs: copy the directory it covers into it first (runc's tmpcopyup).
    copy_up: bool = false,
    /// Flags the options asked to clear ("dev", "rw", ...), like runc's
    /// ClearedFlags; a bind mount is remounted when any are set.
    cleared_flags: u32 = 0,
};

pub const IDMapping = struct {
    container_id: u32,
    host_id: u32,
    size: u32,
};

/// Borrowed mappings, or an existing namespace whose mappings should be used.
pub const MountMappings = struct {
    uid: []const IDMapping = &.{},
    gid: []const IDMapping = &.{},
    userns_path: ?[]const u8 = null,
    recursive: bool = false,
};

/// The id is borrowed. create() allocates starttime with the supplied allocator;
/// loaded handles borrow starttime from the caller.
pub const State = struct {
    id: []const u8,
    pid: i32,
    /// Opaque process identity, required to detect PID reuse.
    starttime: []const u8,
    /// Borrowed from create options, or loaded from the runtime state directory.
    cgroup_path: ?[]const u8 = null,
    systemd: bool = false,
    /// Include the named v1 hierarchy after verified systemd cleanup falls back.
    systemd_cleanup: bool = false,
    /// Set only when the container shares the runtime's mount namespace.
    rootfs_mount: ?[]const u8 = null,
    /// STATX_MNT_ID_UNIQUE of the self-bind; null for old handles.
    rootfs_mount_id: ?u64 = null,
    /// Kernel boot ID, since unique mount IDs reset on reboot.
    rootfs_mount_boot_id: ?[36]u8 = null,
    /// Create-time device nodes, restored by the frontend for updates.
    /// Borrowed; only their type and numbers enter the device policy.
    device_nodes: []const Device = &.{},
};

/// A cgroup resource snapshot. Times are nanoseconds and sizes bytes; a limit
/// of maxInt(u64) means unlimited. `raw` is allocated by the caller's allocator.
pub const Stats = struct {
    cpu: Cpu = .{},
    memory: Memory = .{},
    pids: Pids = .{},
    /// Cumulative OOM kills in the cgroup, for OOM notification by polling.
    oom_kills: u64 = 0,

    pub const Cpu = struct {
        total: u64 = 0,
        user: u64 = 0,
        kernel: u64 = 0,
        periods: u64 = 0,
        throttled_periods: u64 = 0,
        throttled_time: u64 = 0,
        psi: ?Psi = null,
    };

    pub const Memory = struct {
        usage: u64 = 0,
        limit: u64 = 0,
        max_usage: u64 = 0,
        failcnt: u64 = 0,
        cache: u64 = 0,
        raw: []const Raw = &.{},
        psi: ?Psi = null,
    };

    pub const Pids = struct {
        current: u64 = 0,
        limit: u64 = 0,
    };

    pub const Raw = struct { name: []const u8, value: u64 };

    pub const Psi = struct {
        some: Data = .{},
        full: Data = .{},

        pub const Data = struct { avg10: f64 = 0, avg60: f64 = 0, avg300: f64 = 0, total: u64 = 0 };
    };
};

pub const Error = error{
    NotImplemented,
    Unsupported,
    InvalidConfig,
    AmbientCapabilitiesRequirePermittedAndInheritable,
    InvalidProcess,
    InvalidPath,
    PermissionDenied,
    SystemResources,
    ResolveRetryExhausted,
    CreateFailed,
    ExecFailed,
    KillFailed,
    LivenessFailed,
    ProcessNotFound,
    CgroupWriteFailed,
    CgroupReadFailed,
    CgroupDeleteFailed,
    HookFailed,
    HookTimeout,
    ConsoleFailed,
    MissingDevpts,
    MissingProcfs,
} || std.mem.Allocator.Error;

pub const Container = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// A per-container interface; construction belongs to each implementation.
    /// The frontend manages the FIFO ready exchange, so there is no start operation.
    pub const VTable = struct {
        exec: *const fn (ptr: *anyopaque, options: ExecOptions) Error!i32 = noExec,
        alive: *const fn (ptr: *anyopaque) Error!bool,
        /// Validate the process identity before signaling its host PID.
        kill: *const fn (ptr: *anyopaque, signal: i32) Error!void,
        /// Signal every cgroup member, even after init exits.
        killAll: *const fn (ptr: *anyopaque, signal: i32) Error!void,
        update: *const fn (ptr: *anyopaque, resources: Resources) Error!void = noUpdate,
        /// The caller owns the returned host PIDs, including descendant cgroups.
        pids: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) Error![]i32 = noPids,
        /// Raw entries are allocated with allocator; an arena suits callers.
        stats: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) Error!Stats = noStats,
        freeze: *const fn (ptr: *anyopaque) Error!void = noFreeze,
        thaw: *const fn (ptr: *anyopaque) Error!void = noFreeze,
        frozen: *const fn (ptr: *anyopaque) Error!bool = noFrozen,
        /// The id identifies resources after the container stops and its pid is gone.
        delete: *const fn (ptr: *anyopaque) Error!void,
        /// Human-readable detail for the most recent failed operation.
        diagnostic: *const fn (ptr: *anyopaque) ?[]const u8 = noDiagnostic,

        fn noDiagnostic(_: *anyopaque) ?[]const u8 {
            return null;
        }

        fn noExec(_: *anyopaque, _: ExecOptions) Error!i32 {
            return error.NotImplemented;
        }

        fn noPids(_: *anyopaque, _: std.mem.Allocator) Error![]i32 {
            return error.NotImplemented;
        }

        fn noStats(_: *anyopaque, _: std.mem.Allocator) Error!Stats {
            return error.NotImplemented;
        }

        fn noUpdate(_: *anyopaque, _: Resources) Error!void {
            return error.NotImplemented;
        }

        fn noFreeze(_: *anyopaque) Error!void {
            return error.NotImplemented;
        }

        fn noFrozen(_: *anyopaque) Error!bool {
            return false;
        }
    };

    /// Returns the host PID after successful exec. A caller that intends to
    /// waitpid must enable child subreaping before this call; otherwise the
    /// process is adopted by the outer shim's subreaper (or host init).
    pub fn exec(self: Container, options: ExecOptions) Error!i32 {
        return self.vtable.exec(self.ptr, options);
    }

    /// Checks whether init is alive and its saved process identity still matches.
    pub fn alive(self: Container) Error!bool {
        return self.vtable.alive(self.ptr);
    }

    /// Signals init after validating its saved process identity.
    pub fn kill(self: Container, signal: i32) Error!void {
        return self.vtable.kill(self.ptr, signal);
    }

    /// Signals every cgroup member, including descendants, even after init exits.
    pub fn killAll(self: Container, signal: i32) Error!void {
        return self.vtable.killAll(self.ptr, signal);
    }

    /// Applies resource limits to the container's cgroup.
    pub fn update(self: Container, resources: Resources) Error!void {
        return self.vtable.update(self.ptr, resources);
    }

    /// Returns host PIDs, including descendant cgroups; free with allocator.
    pub fn pids(self: Container, allocator: std.mem.Allocator) Error![]i32 {
        return self.vtable.pids(self.ptr, allocator);
    }

    /// Reads the cgroup's CPU, memory and pids counters and its OOM kill count.
    pub fn stats(self: Container, allocator: std.mem.Allocator) Error!Stats {
        return self.vtable.stats(self.ptr, allocator);
    }

    /// Freezes the container's cgroup and waits for the requested state.
    pub fn freeze(self: Container) Error!void {
        return self.vtable.freeze(self.ptr);
    }

    /// Thaws the container's cgroup and waits for the requested state.
    pub fn thaw(self: Container) Error!void {
        return self.vtable.thaw(self.ptr);
    }

    /// Reports whether the container's cgroup is frozen.
    pub fn frozen(self: Container) Error!bool {
        return self.vtable.frozen(self.ptr);
    }

    /// Removes the stopped container's resources; instance memory remains owned.
    pub fn delete(self: Container) Error!void {
        return self.vtable.delete(self.ptr);
    }

    /// Borrowed detail for the most recent failed operation; copy before cleanup.
    pub fn diagnostic(self: Container) ?[]const u8 {
        return self.vtable.diagnostic(self.ptr);
    }
};

test {
    std.testing.refAllDecls(@This());
}

// Keep this test name stable across the per-instance Container refactor.
test "backend dispatches lifecycle operations through its vtable" {
    const TestContainer = struct {
        state: State = undefined,
        options: ?CreateOptions = null,
        checked: ?State = null,
        killed: ?State = null,
        killed_all: ?State = null,
        signal: ?i32 = null,
        deleted: ?State = null,
        fail_create: bool = false,

        const vtable: Container.VTable = .{
            .alive = alive,
            .kill = kill,
            .killAll = killAll,
            .delete = delete,
            .diagnostic = diagnostic,
        };

        fn create(self: *@This(), options: CreateOptions) Error!State {
            self.options = options;
            if (self.fail_create) return error.NotImplemented;
            self.state = .{ .id = options.id, .pid = 1234, .starttime = "12345" };
            return self.state;
        }

        fn alive(ptr: *anyopaque) Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.checked = self.state;
            return true;
        }

        fn kill(ptr: *anyopaque, signal: i32) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = self.state;
            self.signal = signal;
        }

        fn killAll(ptr: *anyopaque, signal: i32) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed_all = self.state;
            self.signal = signal;
        }

        fn delete(ptr: *anyopaque) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = self.state;
        }

        fn diagnostic(ptr: *anyopaque) ?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return if (self.fail_create) "test create is unavailable" else null;
        }
    };

    const options: CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/tmp/bundle/rootfs",
        .exec_fifo = "/tmp/containers/example/exec.fifo",
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .uid = 0, .gid = 0 },
    };
    var implementation: TestContainer = .{};
    const container: Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    try std.testing.expect(container.diagnostic() == null);
    const handle = try implementation.create(options);
    try std.testing.expectEqualStrings("example", handle.id);
    try std.testing.expectEqual(@as(i32, 1234), handle.pid);
    try std.testing.expectEqualStrings("example", implementation.options.?.id);
    try std.testing.expectEqualStrings("/tmp/bundle/rootfs", implementation.options.?.rootfs);
    try std.testing.expectEqualStrings("/tmp/containers/example/exec.fifo", implementation.options.?.exec_fifo);
    try std.testing.expectEqualDeep(options.process, implementation.options.?.process);
    try std.testing.expect(try container.alive());
    try std.testing.expectEqualStrings("example", implementation.checked.?.id);
    try std.testing.expectEqual(@as(i32, 1234), implementation.checked.?.pid);
    implementation.state = .{ .id = "other", .pid = 1235, .starttime = "12346" };
    try container.kill(15);
    try std.testing.expectEqualStrings("other", implementation.killed.?.id);
    try std.testing.expectEqual(@as(i32, 1235), implementation.killed.?.pid);
    try std.testing.expectEqual(@as(?i32, 15), implementation.signal);
    implementation.state = .{ .id = "all", .pid = 1236, .starttime = "12347", .cgroup_path = "test/all" };
    try container.killAll(9);
    try std.testing.expectEqualStrings("all", implementation.killed_all.?.id);
    try std.testing.expectEqualStrings("test/all", implementation.killed_all.?.cgroup_path.?);
    try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
    implementation.state = .{ .id = "example", .pid = 0, .starttime = "" };
    try container.delete();
    try std.testing.expectEqualStrings("example", implementation.deleted.?.id);
    try std.testing.expectEqual(@as(i32, 0), implementation.deleted.?.pid);

    implementation.fail_create = true;
    try std.testing.expectError(error.NotImplemented, implementation.create(options));
    try std.testing.expectEqualStrings("test create is unavailable", container.diagnostic().?);
}

const std = @import("std");
const oci = @import("oci.zig");

pub const LinuxBackend = @import("backend/linux.zig").LinuxBackend;
pub const apparmorEnabled = @import("backend/linux.zig").apparmorEnabled;
pub const console = @import("backend/linux.zig").console;
pub const hooks = @import("backend/hooks.zig");

pub const Backend = struct {
    pub const seccomp = @import("backend/seccomp.zig");
    ptr: *anyopaque,
    vtable: *const VTable,

    /// Strings and the parsed spec are borrowed; the frontend owns their memory.
    pub const CreateOptions = struct {
        allocator: std.mem.Allocator,
        id: []const u8,
        /// Absolute rootfs path resolved by the frontend.
        rootfs: []const u8,
        /// Absolute path to the FIFO created by the frontend.
        exec_fifo: []const u8,
        spec: *const oci.Spec,
        /// Borrowed socketpair: init sends its PTY master on [1]; the caller
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
        /// Null preserves the default propagation in a private mount namespace.
        rootfs_propagation: ?u32 = null,
        apparmor_profile: ?[]const u8 = null,
        seccomp: ?Backend.seccomp.Config = null,
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
        seccomp: ?Backend.seccomp.Config = null,
    };

    pub const CreateCallback = struct {
        ptr: *anyopaque,
        run: *const fn (*anyopaque, Handle) Error!void,
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

    pub const Sysctl = struct { key: []const u8, value: []const u8 };

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
        };
        pub const Cpu = struct {
            shares: ?u64 = null,
            quota: ?i64 = null,
            period: ?u64 = null,
            realtime_runtime: ?i64 = null,
            realtime_period: ?u64 = null,
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

    /// Mount options and destinations have already been translated by the frontend.
    // ponytail: MS_* flags tie this neutral interface to Linux; acceptable while
    // Linux is the only backend. Translate to neutral options when another is added.
    pub const Mount = struct {
        destination: []const u8,
        source: ?[]const u8,
        type: ?[]const u8,
        flags: u32,
        propagation: u32,
        data: []const u8,
        recursive_readonly: ?bool = null,
        mappings: ?MountMappings = null,
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
    /// loaded handles borrow starttime from the frontend.
    pub const Handle = struct {
        id: []const u8,
        pid: i32,
        /// Opaque process identity, required to detect PID reuse.
        starttime: []const u8,
        /// Borrowed from create options, or loaded from the runtime state directory.
        cgroup_path: ?[]const u8 = null,
        systemd: bool = false,
        /// Set only when the container shares the runtime's mount namespace.
        rootfs_mount: ?[]const u8 = null,
        /// STATX_MNT_ID_UNIQUE of the self-bind; null for old handles.
        rootfs_mount_id: ?u64 = null,
        /// Kernel boot ID, since unique mount IDs reset on reboot.
        rootfs_mount_boot_id: ?[36]u8 = null,
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
        CreateFailed,
        ExecFailed,
        KillFailed,
        LivenessFailed,
        ProcessNotFound,
        CgroupWriteFailed,
        CgroupDeleteFailed,
        HookFailed,
        HookTimeout,
        ConsoleFailed,
        MissingDevpts,
        MissingProcfs,
    } || std.mem.Allocator.Error;

    /// Backends receive parsed values only; the frontend loads config.json and resolves paths.
    pub const VTable = struct {
        create: *const fn (ptr: *anyopaque, options: CreateOptions) Error!Handle,
        exec: *const fn (ptr: *anyopaque, handle: Handle, options: ExecOptions) Error!i32 = noExec,
        /// The FIFO ready exchange is runtime state machinery, not isolation.
        /// A backend start hook can be added when an isolation mechanism needs it.
        alive: *const fn (ptr: *anyopaque, handle: Handle) Error!bool,
        /// Validate the process identity before signaling its host PID.
        kill: *const fn (ptr: *anyopaque, handle: Handle, signal: i32) Error!void,
        /// Signal every cgroup member, even after init exits.
        killAll: *const fn (ptr: *anyopaque, handle: Handle, signal: i32) Error!void,
        update: *const fn (ptr: *anyopaque, handle: Handle, resources: Resources) Error!void = noUpdate,
        /// The caller owns the returned host PIDs, including descendant cgroups.
        pids: *const fn (ptr: *anyopaque, handle: Handle, allocator: std.mem.Allocator) Error![]i32 = noPids,
        freeze: *const fn (ptr: *anyopaque, handle: Handle) Error!void = noFreeze,
        thaw: *const fn (ptr: *anyopaque, handle: Handle) Error!void = noFreeze,
        frozen: *const fn (ptr: *anyopaque, handle: Handle) Error!bool = noFrozen,
        /// The id identifies resources after the container stops and its pid is gone.
        delete: *const fn (ptr: *anyopaque, handle: Handle) Error!void,
        /// Human-readable detail for the most recent failed operation.
        diagnostic: *const fn (ptr: *anyopaque) ?[]const u8 = noDiagnostic,

        fn noDiagnostic(_: *anyopaque) ?[]const u8 {
            return null;
        }

        fn noExec(_: *anyopaque, _: Handle, _: ExecOptions) Error!i32 {
            return error.NotImplemented;
        }

        fn noPids(_: *anyopaque, _: Handle, _: std.mem.Allocator) Error![]i32 {
            return error.NotImplemented;
        }

        fn noUpdate(_: *anyopaque, _: Handle, _: Resources) Error!void {
            return error.NotImplemented;
        }

        fn noFreeze(_: *anyopaque, _: Handle) Error!void {
            return error.NotImplemented;
        }

        fn noFrozen(_: *anyopaque, _: Handle) Error!bool {
            return false;
        }
    };

    pub fn create(self: Backend, options: CreateOptions) Error!Handle {
        return self.vtable.create(self.ptr, options);
    }

    /// Returns the host PID after successful exec. A caller that intends to
    /// waitpid must enable child subreaping before this call; otherwise the
    /// process is adopted by the outer shim's subreaper (or host init).
    pub fn exec(self: Backend, handle: Handle, options: ExecOptions) Error!i32 {
        return self.vtable.exec(self.ptr, handle, options);
    }

    pub fn alive(self: Backend, handle: Handle) Error!bool {
        return self.vtable.alive(self.ptr, handle);
    }

    pub fn kill(self: Backend, handle: Handle, signal: i32) Error!void {
        return self.vtable.kill(self.ptr, handle, signal);
    }

    pub fn killAll(self: Backend, handle: Handle, signal: i32) Error!void {
        return self.vtable.killAll(self.ptr, handle, signal);
    }

    pub fn update(self: Backend, handle: Handle, resources: Resources) Error!void {
        return self.vtable.update(self.ptr, handle, resources);
    }

    pub fn pids(self: Backend, handle: Handle, allocator: std.mem.Allocator) Error![]i32 {
        return self.vtable.pids(self.ptr, handle, allocator);
    }

    pub fn freeze(self: Backend, handle: Handle) Error!void {
        return self.vtable.freeze(self.ptr, handle);
    }

    pub fn thaw(self: Backend, handle: Handle) Error!void {
        return self.vtable.thaw(self.ptr, handle);
    }

    pub fn frozen(self: Backend, handle: Handle) Error!bool {
        return self.vtable.frozen(self.ptr, handle);
    }

    pub fn delete(self: Backend, handle: Handle) Error!void {
        return self.vtable.delete(self.ptr, handle);
    }

    /// Human-readable detail for the most recent failed operation.
    pub fn diagnostic(self: Backend) ?[]const u8 {
        return self.vtable.diagnostic(self.ptr);
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "backend dispatches lifecycle operations through its vtable" {
    const TestBackend = struct {
        options: ?Backend.CreateOptions = null,
        checked: ?Backend.Handle = null,
        killed: ?Backend.Handle = null,
        killed_all: ?Backend.Handle = null,
        signal: ?i32 = null,
        deleted: ?Backend.Handle = null,
        fail_create: bool = false,

        const vtable: Backend.VTable = .{
            .create = create,
            .alive = alive,
            .kill = kill,
            .killAll = killAll,
            .delete = delete,
            .diagnostic = diagnostic,
        };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.options = options;
            if (self.fail_create) return error.NotImplemented;
            return .{ .id = options.id, .pid = 1234, .starttime = "12345" };
        }

        fn alive(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.checked = handle;
            return true;
        }

        fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = handle;
            self.signal = signal;
        }

        fn killAll(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed_all = handle;
            self.signal = signal;
        }

        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = handle;
        }

        fn diagnostic(ptr: *anyopaque) ?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return if (self.fail_create) "test create is unavailable" else null;
        }
    };

    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/tmp/bundle/rootfs",
        .exec_fifo = "/tmp/containers/example/exec.fifo",
        .spec = &spec,
    };
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    try std.testing.expect(backend.diagnostic() == null);
    const handle = try backend.create(options);
    try std.testing.expectEqualStrings("example", handle.id);
    try std.testing.expectEqual(@as(i32, 1234), handle.pid);
    try std.testing.expectEqualStrings("example", implementation.options.?.id);
    try std.testing.expectEqualStrings("/tmp/bundle/rootfs", implementation.options.?.rootfs);
    try std.testing.expectEqualStrings("/tmp/containers/example/exec.fifo", implementation.options.?.exec_fifo);
    try std.testing.expect(implementation.options.?.spec == &spec);
    try std.testing.expect(try backend.alive(handle));
    try std.testing.expectEqualStrings("example", implementation.checked.?.id);
    try std.testing.expectEqual(@as(i32, 1234), implementation.checked.?.pid);
    try backend.kill(.{ .id = "other", .pid = 1235, .starttime = "12346" }, 15);
    try std.testing.expectEqualStrings("other", implementation.killed.?.id);
    try std.testing.expectEqual(@as(i32, 1235), implementation.killed.?.pid);
    try std.testing.expectEqual(@as(?i32, 15), implementation.signal);
    try backend.killAll(.{ .id = "all", .pid = 1236, .starttime = "12347", .cgroup_path = "test/all" }, 9);
    try std.testing.expectEqualStrings("all", implementation.killed_all.?.id);
    try std.testing.expectEqualStrings("test/all", implementation.killed_all.?.cgroup_path.?);
    try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
    try backend.delete(.{ .id = "example", .pid = 0, .starttime = "" });
    try std.testing.expectEqualStrings("example", implementation.deleted.?.id);
    try std.testing.expectEqual(@as(i32, 0), implementation.deleted.?.pid);

    implementation.fail_create = true;
    try std.testing.expectError(error.NotImplemented, backend.create(options));
    try std.testing.expectEqualStrings("test create is unavailable", backend.diagnostic().?);
}

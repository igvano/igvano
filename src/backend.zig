const std = @import("std");
const oci = @import("oci.zig");

pub const LinuxBackend = @import("backend/linux.zig").LinuxBackend;

pub const Backend = struct {
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
        mounts: []const Mount = &.{},
        /// Normalized path relative to the cgroup2 mount root.
        cgroup_path: []const u8 = "",
        cgroup_writes: []const CgroupWrite = &.{},
        capabilities: ?Capabilities = null,
        rlimits: []const Rlimit = &.{},
    };

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

    pub const CgroupWrite = struct {
        name: []const u8,
        value: []const u8,
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
    };

    pub const Error = error{
        NotImplemented,
        Unsupported,
        InvalidConfig,
        InvalidProcess,
        InvalidPath,
        MissingMountNamespace,
        PermissionDenied,
        SystemResources,
        CreateFailed,
        KillFailed,
        LivenessFailed,
        ProcessNotFound,
        CgroupWriteFailed,
        CgroupDeleteFailed,
    } || std.mem.Allocator.Error;

    /// Backends receive parsed values only; the frontend loads config.json and resolves paths.
    pub const VTable = struct {
        create: *const fn (ptr: *anyopaque, options: CreateOptions) Error!Handle,
        /// The FIFO ready exchange is runtime state machinery, not isolation.
        /// A backend start hook can be added when an isolation mechanism needs it.
        alive: *const fn (ptr: *anyopaque, handle: Handle) Error!bool,
        /// Validate the process identity before signaling its host PID.
        /// Whole-cgroup termination happens at delete, not kill.
        kill: *const fn (ptr: *anyopaque, handle: Handle, signal: i32) Error!void,
        /// The id identifies resources after the container stops and its pid is gone.
        delete: *const fn (ptr: *anyopaque, handle: Handle) Error!void,
    };

    pub fn create(self: Backend, options: CreateOptions) Error!Handle {
        return self.vtable.create(self.ptr, options);
    }

    pub fn alive(self: Backend, handle: Handle) Error!bool {
        return self.vtable.alive(self.ptr, handle);
    }

    pub fn kill(self: Backend, handle: Handle, signal: i32) Error!void {
        return self.vtable.kill(self.ptr, handle, signal);
    }

    pub fn delete(self: Backend, handle: Handle) Error!void {
        return self.vtable.delete(self.ptr, handle);
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
        signal: ?i32 = null,
        deleted: ?Backend.Handle = null,
        fail_create: bool = false,

        const vtable: Backend.VTable = .{
            .create = create,
            .alive = alive,
            .kill = kill,
            .delete = delete,
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

        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = handle;
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
    try backend.delete(.{ .id = "example", .pid = 0, .starttime = "" });
    try std.testing.expectEqualStrings("example", implementation.deleted.?.id);
    try std.testing.expectEqual(@as(i32, 0), implementation.deleted.?.pid);

    implementation.fail_create = true;
    try std.testing.expectError(error.NotImplemented, backend.create(options));
}

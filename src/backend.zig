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
    };

    /// Container identity with a borrowed id owned by the frontend.
    pub const Handle = struct {
        id: []const u8,
        pid: i32,
    };

    pub const Error = error{
        NotImplemented,
        Unsupported,
        InvalidConfig,
        InvalidProcess,
        InvalidPath,
        PermissionDenied,
        SystemResources,
        CreateFailed,
        KillFailed,
        LivenessFailed,
        ProcessNotFound,
    } || std.mem.Allocator.Error;

    /// Backends receive parsed values only; the frontend loads config.json and resolves paths.
    pub const VTable = struct {
        create: *const fn (ptr: *anyopaque, options: CreateOptions) Error!Handle,
        /// The FIFO ready exchange is runtime state machinery, not isolation.
        /// A backend start hook can be added when an isolation mechanism needs it.
        alive: *const fn (ptr: *anyopaque, handle: Handle) Error!bool,
        /// Handles currently identify processes by host PID.
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
            return .{ .id = options.id, .pid = 1234 };
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
    try backend.kill(.{ .id = "other", .pid = 1235 }, 15);
    try std.testing.expectEqualStrings("other", implementation.killed.?.id);
    try std.testing.expectEqual(@as(i32, 1235), implementation.killed.?.pid);
    try std.testing.expectEqual(@as(?i32, 15), implementation.signal);
    try backend.delete(.{ .id = "example", .pid = 0 });
    try std.testing.expectEqualStrings("example", implementation.deleted.?.id);
    try std.testing.expectEqual(@as(i32, 0), implementation.deleted.?.pid);

    implementation.fail_create = true;
    try std.testing.expectError(error.NotImplemented, backend.create(options));
}

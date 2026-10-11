const std = @import("std");

pub const LinuxBackend = @import("backend/linux.zig").LinuxBackend;

pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const CreateOptions = struct {
        id: []const u8,
        bundle: []const u8,
    };

    pub const Error = error{NotImplemented};

    pub const VTable = struct {
        create: *const fn (ptr: *anyopaque, options: CreateOptions) Error!i32,
        start: *const fn (ptr: *anyopaque, pid: i32) Error!void,
        kill: *const fn (ptr: *anyopaque, pid: i32, signal: u8) Error!void,
        delete: *const fn (ptr: *anyopaque, pid: i32) Error!void,
    };

    pub fn create(self: Backend, options: CreateOptions) Error!i32 {
        return self.vtable.create(self.ptr, options);
    }

    pub fn start(self: Backend, pid: i32) Error!void {
        return self.vtable.start(self.ptr, pid);
    }

    pub fn kill(self: Backend, pid: i32, signal: u8) Error!void {
        return self.vtable.kill(self.ptr, pid, signal);
    }

    pub fn delete(self: Backend, pid: i32) Error!void {
        return self.vtable.delete(self.ptr, pid);
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "backend dispatches lifecycle operations through its vtable" {
    const TestBackend = struct {
        options: ?Backend.CreateOptions = null,
        started_pid: ?i32 = null,
        killed_pid: ?i32 = null,
        signal: ?u8 = null,
        deleted_pid: ?i32 = null,
        fail_create: bool = false,

        const vtable: Backend.VTable = .{
            .create = create,
            .start = start,
            .kill = kill,
            .delete = delete,
        };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!i32 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.options = options;
            if (self.fail_create) return error.NotImplemented;
            return 1234;
        }

        fn start(ptr: *anyopaque, pid: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.started_pid = pid;
        }

        fn kill(ptr: *anyopaque, pid: i32, signal: u8) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed_pid = pid;
            self.signal = signal;
        }

        fn delete(ptr: *anyopaque, pid: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted_pid = pid;
        }
    };

    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    try std.testing.expectEqual(@as(i32, 1234), try backend.create(.{ .id = "example", .bundle = "/tmp/bundle" }));
    try std.testing.expectEqualStrings("example", implementation.options.?.id);
    try std.testing.expectEqualStrings("/tmp/bundle", implementation.options.?.bundle);
    try backend.start(1234);
    try std.testing.expectEqual(@as(?i32, 1234), implementation.started_pid);
    try backend.kill(1235, 15);
    try std.testing.expectEqual(@as(?i32, 1235), implementation.killed_pid);
    try std.testing.expectEqual(@as(?u8, 15), implementation.signal);
    try backend.delete(1236);
    try std.testing.expectEqual(@as(?i32, 1236), implementation.deleted_pid);

    implementation.fail_create = true;
    try std.testing.expectError(error.NotImplemented, backend.create(.{ .id = "example", .bundle = "/tmp/bundle" }));
}

const std = @import("std");
const Backend = @import("../backend.zig").Backend;

pub const LinuxBackend = struct {
    pub fn backend(self: *LinuxBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .create = create,
        .start = start,
        .kill = kill,
        .delete = delete,
    };

    fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!i32 {
        return error.NotImplemented;
    }

    fn start(_: *anyopaque, _: i32) Backend.Error!void {
        return error.NotImplemented;
    }

    fn kill(_: *anyopaque, _: i32, _: u8) Backend.Error!void {
        return error.NotImplemented;
    }

    fn delete(_: *anyopaque, _: i32) Backend.Error!void {
        return error.NotImplemented;
    }
};

test "linux backend lifecycle operations are not implemented" {
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    try std.testing.expectError(error.NotImplemented, backend.create(.{ .id = "example", .bundle = "/tmp/bundle" }));
    try std.testing.expectError(error.NotImplemented, backend.start(1234));
    try std.testing.expectError(error.NotImplemented, backend.kill(1234, 15));
    try std.testing.expectError(error.NotImplemented, backend.delete(1234));
}

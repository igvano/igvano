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

    fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
        return error.NotImplemented;
    }

    fn start(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
        return error.NotImplemented;
    }

    fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
        return error.NotImplemented;
    }

    fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
        return error.NotImplemented;
    }
};

test "linux backend lifecycle operations are not implemented" {
    const spec: @import("../oci.zig").Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234 };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    try std.testing.expectError(error.NotImplemented, backend.create(.{ .id = "example", .rootfs = "/tmp/bundle/rootfs", .spec = &spec }));
    try std.testing.expectError(error.NotImplemented, backend.start(handle));
    try std.testing.expectError(error.NotImplemented, backend.kill(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.delete(handle));
}

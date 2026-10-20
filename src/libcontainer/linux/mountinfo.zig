const std = @import("std");
const linux = std.os.linux;
const Backend = @import("../root.zig").Backend;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;

pub fn readMountinfo(allocator: std.mem.Allocator) Backend.Error![]u8 {
    const fd = try openPath(linux.AT.FDCWD, "/proc/self/mountinfo", .{ .CLOEXEC = true });
    defer closeFd(fd);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.read(fd, &buffer, buffer.len);
        if (linux.errno(result) == .INTR) continue;
        try checkResult(result);
        if (result == 0) return text.toOwnedSlice(allocator);
        try text.appendSlice(allocator, buffer[0..result]);
    }
}

pub const MountInfo = struct {
    id: u64,
    parent: u64,
    device: []const u8,
    root: []const u8,
    mountpoint: []const u8,

    pub fn parse(line: []const u8) Backend.Error!MountInfo {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        return .{
            .id = std.fmt.parseInt(u64, fields.next() orelse return error.CreateFailed, 10) catch return error.CreateFailed,
            .parent = std.fmt.parseInt(u64, fields.next() orelse return error.CreateFailed, 10) catch return error.CreateFailed,
            .device = fields.next() orelse return error.CreateFailed,
            .root = fields.next() orelse return error.CreateFailed,
            .mountpoint = fields.next() orelse return error.CreateFailed,
        };
    }
};

pub fn mountinfoPath(buffer: []u8, escaped: []const u8) Backend.Error![]const u8 {
    var used: usize = 0;
    var i: usize = 0;
    while (i < escaped.len) : (i += 1) {
        if (used == buffer.len) return error.InvalidPath;
        if (escaped[i] == '\\') {
            if (escaped.len - i < 4) return error.InvalidPath;
            buffer[used] = std.fmt.parseInt(u8, escaped[i + 1 .. i + 4], 8) catch return error.InvalidPath;
            i += 3;
        } else {
            buffer[used] = escaped[i];
        }
        used += 1;
    }
    return buffer[0..used];
}

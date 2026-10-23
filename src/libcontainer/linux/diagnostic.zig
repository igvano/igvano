const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const writeAll = @import("syscall.zig").writeAll;

// Borrowed diagnostic detail for this thread; no allocation after fork.
// ponytail: one container operation at a time per thread; copy detail before the next.
pub threadlocal var last_diagnostic: [512]u8 = @splat(0);
pub threadlocal var last_diagnostic_len: usize = 0;

fn diagnosticWrite(bytes: []const u8) void {
    const len = @min(bytes.len, last_diagnostic.len - last_diagnostic_len);
    @memcpy(last_diagnostic[last_diagnostic_len..][0..len], bytes[0..len]);
    last_diagnostic_len += len;
    _ = writeAll(2, bytes);
}

fn diagnosticDrain(_: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    for (data[0 .. data.len - 1]) |bytes| diagnosticWrite(bytes);
    for (0..splat) |_| diagnosticWrite(data[data.len - 1]);
    return std.Io.Writer.countSplat(data, splat);
}

/// Formatting and raw writes need neither allocator nor inherited debug locks.
pub fn reportDiagnostic(comptime fmt: []const u8, args: anytype) void {
    last_diagnostic_len = 0;
    _ = writeAll(2, "igvano: ");
    var writer: std.Io.Writer = .{ .vtable = &.{ .drain = diagnosticDrain }, .buffer = &.{} };
    writer.print(fmt, args) catch {};
    _ = writeAll(2, "\n");
    if (last_diagnostic_len == last_diagnostic.len) {
        // Avoid ending a truncated JSON diagnostic halfway through a codepoint.
        var start = last_diagnostic_len - 1;
        while (start > 0 and last_diagnostic[start] & 0xc0 == 0x80) start -= 1;
        const len = std.unicode.utf8ByteSequenceLength(last_diagnostic[start]) catch 1;
        if (len > last_diagnostic_len - start) last_diagnostic_len = start;
    }
}

pub fn diagnostic() ?[]const u8 {
    return if (last_diagnostic_len == 0) null else last_diagnostic[0..last_diagnostic_len];
}

pub const CreateResponse = extern struct {
    pid: i32 = 0,
    failure: u32 = 0,
    starttime: u64 = 0,
    rootfs_mount_id: u64 = 0,
    message: [512]u8 = @splat(0),
    message_len: u32 = 0,

    pub fn failureError(self: *const CreateResponse) ?libcontainer.Error {
        if (self.failure == 0) return null;
        last_diagnostic_len = @min(self.message_len, last_diagnostic.len);
        @memcpy(last_diagnostic[0..last_diagnostic_len], self.message[0..last_diagnostic_len]);
        return @errorCast(@errorFromInt(@as(u16, @intCast(self.failure))));
    }
};

pub fn childError(message: []const u8, err: anyerror) void {
    reportDiagnostic("{s}{s}", .{ message, @errorName(err) });
}

pub fn failCreate(fd: posix.fd_t, err: libcontainer.Error) noreturn {
    var response: CreateResponse = .{ .failure = @intFromError(err), .message_len = @intCast(last_diagnostic_len) };
    @memcpy(response.message[0..last_diagnostic_len], last_diagnostic[0..last_diagnostic_len]);
    _ = writeAll(fd, std.mem.asBytes(&response));
    linux.exit_group(1);
}

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
}

fn diagnosticDrain(_: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    for (data[0 .. data.len - 1]) |bytes| diagnosticWrite(bytes);
    for (0..splat) |_| diagnosticWrite(data[data.len - 1]);
    return std.Io.Writer.countSplat(data, splat);
}

/// Formatting and raw writes need neither allocator nor inherited debug locks.
/// Records the reason for the next error; the frontend shows it once, with
/// the error, like runc (forked children's stderr is often the container's).
pub fn reportDiagnostic(comptime fmt: []const u8, args: anytype) void {
    last_diagnostic_len = 0;
    var writer: std.Io.Writer = .{ .vtable = &.{ .drain = diagnosticDrain }, .buffer = &.{} };
    writer.print(fmt, args) catch {};
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
    /// Set by a process that installed a seccomp notify filter: the listener
    /// fd number in that process, for the runtime to copy with pidfd_getfd.
    seccomp_fd: i32 = -1,

    pub fn failureError(self: *const CreateResponse) ?libcontainer.Error {
        if (self.failure == 0) return null;
        last_diagnostic_len = @min(self.message_len, last_diagnostic.len);
        @memcpy(last_diagnostic[0..last_diagnostic_len], self.message[0..last_diagnostic_len]);
        return @errorCast(@errorFromInt(@as(u16, @intCast(self.failure))));
    }
};

/// For a child with nobody to report to: print the diagnostic on stderr.
pub fn printDiagnostic() void {
    if (last_diagnostic_len == 0) return;
    _ = writeAll(2, "igvano: ");
    _ = writeAll(2, last_diagnostic[0..last_diagnostic_len]);
    _ = writeAll(2, "\n");
}

pub fn childError(message: []const u8, err: anyerror) void {
    reportDiagnostic("{s}{s}", .{ message, @errorName(err) });
}

pub fn failCreate(fd: posix.fd_t, err: libcontainer.Error) noreturn {
    var response: CreateResponse = .{ .failure = @intFromError(err), .message_len = @intCast(last_diagnostic_len) };
    @memcpy(response.message[0..last_diagnostic_len], last_diagnostic[0..last_diagnostic_len]);
    _ = writeAll(fd, std.mem.asBytes(&response));
    linux.exit_group(1);
}

/// One --debug line without allocation, so forked children can log too.
/// Messages are fixed text and numbers, so neither format needs escaping.
/// They reuse runc's nsexec and init wording, which tools and tests grep for.
pub fn debugLog(debug: ?libcontainer.DebugLog, comptime fmt: []const u8, args: anytype) void {
    const log = debug orelse return;
    var buffer: [256]u8 = undefined;
    const line = (if (log.json)
        std.fmt.bufPrint(&buffer, "{{\"level\":\"debug\",\"msg\":\"" ++ fmt ++ "\"}}\n", args)
    else
        std.fmt.bufPrint(&buffer, "level=debug msg=\"" ++ fmt ++ "\"\n", args)) catch return;
    _ = writeAll(log.fd, line);
}

const std = @import("std");

// One command per process. Keep validation detail alive after parsed data is freed.
var diagnostic_buffer: [512]u8 = @splat(0);

var diagnostic_len: usize = 0;

var diagnostic_error: u16 = 0;

pub fn clearDiagnostic() void {
    diagnostic_len = 0;
    diagnostic_error = 0;
}

pub fn diagnostic() ?[]const u8 {
    return if (diagnostic_len == 0) null else diagnostic_buffer[0..diagnostic_len];
}

pub fn diagnosticFor(err: anyerror) ?[]const u8 {
    return if (diagnostic_error == @intFromError(err)) diagnostic() else null;
}

pub fn validationError(err: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(err) {
    recordDiagnostic(err, fmt, args);
    return err;
}

pub fn recordDiagnostic(err: anyerror, comptime fmt: []const u8, args: anytype) void {
    diagnostic_error = @intFromError(err);
    const text = std.fmt.bufPrint(&diagnostic_buffer, fmt, args) catch &diagnostic_buffer;
    diagnostic_len = completeUTF8Prefix(text).len;
}

// Trim a partial trailing codepoint from either a detail or a context prefix.
fn completeUTF8Prefix(text: []const u8) []const u8 {
    if (text.len == 0) return text;
    var start = text.len - 1;
    while (start > 0 and text[start] & 0xc0 == 0x80) start -= 1;
    const len = std.unicode.utf8ByteSequenceLength(text[start]) catch 1;
    return if (len > text.len - start) text[0..start] else text;
}

pub fn invalidConfig(comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
    return validationError(error.InvalidConfig, fmt, args);
}

pub fn diagnosticContext(comptime fmt: []const u8, args: anytype) void {
    const previous = diagnostic_buffer;
    const len = diagnostic_len;
    const err = diagnostic_error;
    var prefix_buffer: [256]u8 = undefined;
    const prefix = completeUTF8Prefix(std.fmt.bufPrint(&prefix_buffer, fmt, args) catch &prefix_buffer);
    recordDiagnostic(error.InvalidConfig, "{s}: {s}", .{ prefix, previous[0..len] });
    diagnostic_error = err;
}

test "frontend diagnostics truncate at UTF-8 boundaries and clear" {
    defer clearDiagnostic();
    recordDiagnostic(error.InvalidConfig, "{s}", .{"x" ** 511 ++ "é"});
    try std.testing.expectEqual(@as(usize, 511), diagnostic().?.len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(diagnostic().?));
    diagnosticContext("mounts[3]", .{});
    try std.testing.expect(std.mem.startsWith(u8, diagnostic().?, "mounts[3]: "));
    recordDiagnostic(error.InvalidConfig, "reason", .{});
    diagnosticContext("{s}", .{"x" ** 255 ++ "é"});
    try std.testing.expect(std.unicode.utf8ValidateSlice(diagnostic().?));
    clearDiagnostic();
    try std.testing.expect(diagnostic() == null);
}

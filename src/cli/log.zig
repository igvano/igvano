const std = @import("std");
const oci = @import("igvano").oci;

pub const LogFormat = enum { text, json };

/// --debug lines go to --log when set, else stderr, like runc. The fd stays
/// open until exit; like runc, a log that cannot be opened is an error.
pub fn openDebugLog(path: ?[]const u8, log_format: LogFormat) !@import("libcontainer").DebugLog {
    const fd = if (path) |value| try std.posix.openat(std.posix.AT.FDCWD, value, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600) else 2;
    return .{ .fd = fd, .json = log_format == .json };
}

/// RFC3339 UTC with seconds, as logrus prints it.
fn logTime(io: std.Io, buffer: *[20]u8) ![]const u8 {
    const seconds = std.math.cast(u64, std.Io.Clock.real.now(io).toSeconds()) orelse return oci.validationError(error.InvalidTimestamp, "log timestamp: predates the Unix epoch", .{});
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        @as(u8, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

fn writeJsonError(io: std.Io, writer: *std.Io.Writer, message: []const u8) !void {
    var time_buffer: [20]u8 = undefined;
    const time = try logTime(io, &time_buffer);
    try std.json.Stringify.value(.{ .level = "error", .msg = message, .time = time }, .{}, writer);
}

/// runc's error on stderr when there is no --log: one logrus line,
/// `time="..." level=error msg="..."` (or JSON), without a trailing newline.
pub fn stderrErrorLine(allocator: std.mem.Allocator, io: std.Io, log_format: LogFormat, message: []const u8) ![]u8 {
    var line: std.Io.Writer.Allocating = .init(allocator);
    errdefer line.deinit();
    if (log_format == .json) {
        try writeJsonError(io, &line.writer, message);
    } else {
        var time_buffer: [20]u8 = undefined;
        try line.writer.print("time=\"{s}\" level=error msg=", .{try logTime(io, &time_buffer)});
        try writeQuoted(&line.writer, message);
    }
    return line.toOwnedSlice();
}

/// Go's strconv.Quote, as logrus writes text values: \\, \", ASCII
/// controls, invalid UTF-8 as \xNN and non-printable runes as \uNNNN.
// ponytail: the non-printable set covers C1 controls, line/paragraph
// separators and invisible format runes, not all of Go's unicode.IsPrint.
fn writeQuoted(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    var i: usize = 0;
    while (i < text.len) {
        const byte = text[i];
        if (byte < 0x80) {
            try writeQuotedAscii(writer, byte);
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(byte) catch 0;
        const rune: ?u21 = if (len != 0 and i + len <= text.len) std.unicode.utf8Decode(text[i .. i + len]) catch null else null;
        if (rune) |value| {
            if (printableRune(value)) try writer.writeAll(text[i .. i + len]) else try writer.print("\\u{x:0>4}", .{value});
            i += len;
        } else {
            try writer.print("\\x{x:0>2}", .{byte});
            i += 1;
        }
    }
    try writer.writeByte('"');
}

fn writeQuotedAscii(writer: *std.Io.Writer, byte: u8) !void {
    switch (byte) {
        '"', '\\' => try writer.print("\\{c}", .{byte}),
        '\n' => try writer.writeAll("\\n"),
        '\t' => try writer.writeAll("\\t"),
        '\r' => try writer.writeAll("\\r"),
        0...8, 11, 12, 14...31, 127 => try writer.print("\\x{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    }
}

fn printableRune(rune: u21) bool {
    return switch (rune) {
        0x80...0x9f, 0xad, 0x200b...0x200f, 0x2028...0x202e, 0x2060...0x2064, 0xfeff => false,
        else => true,
    };
}

pub fn appendErrorLog(allocator: std.mem.Allocator, io: std.Io, path: []const u8, log_format: LogFormat, message: []const u8) !void {
    var line: std.Io.Writer.Allocating = .init(allocator);
    defer line.deinit();
    if (log_format == .json) {
        try writeJsonError(io, &line.writer, message);
    } else {
        try line.writer.writeAll(message);
    }
    try line.writer.writeByte('\n');
    // Dir.createFile has no append flag; use O_APPEND for concurrent callers.
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer file.close(io);
    try file.writeStreamingAll(io, line.written());
}

test "json error logs append escaped messages and RFC3339 UTC timestamps" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "runtime.log" });
    defer std.testing.allocator.free(path);
    const messages = [_][]const u8{ "igvano: \"quoted\" \\ slash\nnewline\t\x01", "igvano: another error" };
    const before = std.Io.Clock.real.now(std.testing.io).toSeconds();
    for (messages) |message| try appendErrorLog(std.testing.allocator, std.testing.io, path, .json, message);
    const after = std.Io.Clock.real.now(std.testing.io).toSeconds();
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(bytes.len > 0 and bytes[bytes.len - 1] == '\n');
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    for (messages) |message| {
        const parsed = try std.json.parseFromSlice(struct { level: []const u8, msg: []const u8, time: []const u8 }, std.testing.allocator, lines.next().?, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings("error", parsed.value.level);
        try std.testing.expectEqualStrings(message, parsed.value.msg);
        try expectLogTimestamp(parsed.value.time, before, after);
    }
    try std.testing.expectEqualStrings("", lines.next().?);
    try std.testing.expect(lines.next() == null);
    const stat = try tmp.dir.statFile(std.testing.io, "runtime.log", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
}

fn expectLogTimeFormat(time: []const u8) !void {
    // Parse the UTC RFC3339 form and validate its calendar and clock fields.
    try std.testing.expectEqual(@as(usize, 20), time.len);
    try std.testing.expectEqualStrings("-", time[4..5]);
    try std.testing.expectEqualStrings("-", time[7..8]);
    try std.testing.expectEqualStrings("T", time[10..11]);
    try std.testing.expectEqualStrings(":", time[13..14]);
    try std.testing.expectEqualStrings(":", time[16..17]);
    try std.testing.expectEqualStrings("Z", time[19..20]);
    for (time, 0..) |byte, index| {
        if (index == 4 or index == 7 or index == 10 or index == 13 or index == 16 or index == 19) continue;
        try std.testing.expect(std.ascii.isDigit(byte));
    }
}

fn expectLogTimestamp(time: []const u8, before: i128, after: i128) !void {
    try expectLogTimeFormat(time);
    const year = try std.fmt.parseInt(std.time.epoch.Year, time[0..4], 10);
    const month = try std.fmt.parseInt(u8, time[5..7], 10);
    const day = try std.fmt.parseInt(u8, time[8..10], 10);
    const hour = try std.fmt.parseInt(u8, time[11..13], 10);
    const minute = try std.fmt.parseInt(u8, time[14..16], 10);
    const second = try std.fmt.parseInt(u8, time[17..19], 10);
    try std.testing.expect(year >= 1970 and month >= 1 and month <= 12);
    try std.testing.expect(day >= 1 and day <= std.time.epoch.getDaysInMonth(year, @enumFromInt(month)));
    try std.testing.expect(hour < 24 and minute < 60 and second < 60);
    var days: u64 = day - 1;
    for (1970..year) |y| days += std.time.epoch.getDaysInYear(@intCast(y));
    for (1..month) |m| days += std.time.epoch.getDaysInMonth(year, @enumFromInt(m));
    const timestamp = days * 86400 + @as(u64, hour) * 3600 + @as(u64, minute) * 60 + second;
    try std.testing.expect(timestamp >= before and timestamp <= after);
}

test "text error logs append the stderr line without changing existing permissions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "runtime.log", .{ .permissions = .fromMode(0o640) });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, "existing\n");
    const permissions = (try file.stat(std.testing.io)).permissions;
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "runtime.log" });
    defer std.testing.allocator.free(path);
    try appendErrorLog(std.testing.allocator, std.testing.io, path, .text, "igvano: an error");
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("existing\nigvano: an error\n", bytes);
    try std.testing.expectEqual(permissions, (try file.stat(std.testing.io)).permissions);
}

test "text quoting escapes invalid UTF-8 and line separators like Go" {
    var buffer: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeQuoted(&writer, "a\xffb\u{2028}c\u{85}d\u{e9}");
    try std.testing.expectEqualStrings("\"a\\xffb\\u2028c\\u0085d\u{e9}\"", writer.buffered());
}

test "stderr errors use logrus's text line with Go quoting" {
    const line = try stderrErrorLine(std.testing.allocator, std.testing.io, .text, "kill: \"x\"\n\x01");
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.startsWith(u8, line, "time=\""));
    try std.testing.expect(std.mem.endsWith(u8, line, "\" level=error msg=\"kill: \\\"x\\\"\\n\\x01\""));
    try expectLogTimeFormat(line[6..26]);
}

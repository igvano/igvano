const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("state.zig").ContainerInstance;
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const bindContainer = @import("state.zig").bindContainer;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const readLiveState = @import("state.zig").readLiveState;

fn filterPsOutput(allocator: std.mem.Allocator, text: []const u8, pids: []const i32) ![]u8 {
    // ponytail: whitespace in columns before PID is mis-tokenized, as in runc;
    // parse fixed-width columns if those ps formats need to be supported.
    var lines = std.mem.splitScalar(u8, text, '\n');
    const header = lines.next() orelse return error.PsMissingPidColumn;
    var titles = std.mem.tokenizeAny(u8, header, " \t\r");
    const pid_column = column: {
        var index: usize = 0;
        while (titles.next()) |title| : (index += 1) {
            if (std.mem.eql(u8, title, "PID")) break :column index;
        }
        return error.PsMissingPidColumn;
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.writer.print("{s}\n", .{header});
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        for (0..pid_column) |_| _ = fields.next() orelse return error.PsInvalidPid;
        const pid_text = fields.next() orelse return error.PsInvalidPid;
        const pid = std.fmt.parseInt(i32, pid_text, 10) catch return error.PsInvalidPid;
        if (std.mem.indexOfScalar(i32, pids, pid) != null)
            try output.writer.print("{s}\n", .{line});
    }
    return output.toOwnedSlice();
}

pub fn psContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, output: std.Io.File) !void {
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const locked = if (lock) |file| try lockContainer(file, false) else true;
    if (locked) {
        if (lock) |file| try requireLinkedLock(io, file);
    }
    const state = try readLiveState(allocator, io, injected, config, locked);
    defer state.deinit();
    var instance: ContainerInstance = undefined;
    const container = if (state.container_state) |value| bindContainer(&instance, injected, value) else null;
    // Like runc, a stopped container has no processes, which is not an error.
    const pids = if (state.parsed.value.status == .stopped)
        try allocator.alloc(i32, 0)
    else
        try containerResult(container.?, container.?.pids(allocator));
    defer allocator.free(pids);
    if (config.ps_format == .json) {
        const json = try std.json.Stringify.valueAlloc(allocator, pids, .{});
        defer allocator.free(json);
        try output.writeStreamingAll(io, json);
        try output.writeStreamingAll(io, "\n");
    } else {
        const ps_args: []const []const u8 = if (config.ps_args.len == 0) &.{"-ef"} else config.ps_args;
        const argv = try allocator.alloc([]const u8, ps_args.len + 1);
        defer allocator.free(argv);
        argv[0] = "ps";
        @memcpy(argv[1..], ps_args);
        const result = try std.process.run(allocator, io, .{ .argv = argv, .expand_arg0 = .expand });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) {
            return oci.validationError(error.PsFailed, "ps: {s}", .{std.mem.trim(u8, result.stderr, "\n")});
        }
        const filtered = try filterPsOutput(allocator, result.stdout, pids);
        defer allocator.free(filtered);
        try output.writeStreamingAll(io, filtered);
    }
}

test "ps table filters host rows by the header PID column and preserves formatting" {
    const sample =
        "UID          PID    PPID  C STIME TTY          TIME CMD\n" ++
        "root          12       1  0 10:00 ?        00:00:00 sleep 100\n" ++
        "user          99      12  0 10:01 ?        00:00:00 sh -c echo 12\n" ++
        "root         123       1  0 10:02 ?        00:00:00 echo 99\n";
    const filtered = try filterPsOutput(std.testing.allocator, sample, &.{ 12, 123 });
    defer std.testing.allocator.free(filtered);
    try std.testing.expectEqualStrings(
        "UID          PID    PPID  C STIME TTY          TIME CMD\n" ++
            "root          12       1  0 10:00 ?        00:00:00 sleep 100\n" ++
            "root         123       1  0 10:02 ?        00:00:00 echo 99\n",
        filtered,
    );
    const custom = try filterPsOutput(std.testing.allocator, "    PID COMMAND\n     12 sh\n     99 sleep\n", &.{99});
    defer std.testing.allocator.free(custom);
    try std.testing.expectEqualStrings("    PID COMMAND\n     99 sleep\n", custom);
    const last = try filterPsOutput(std.testing.allocator, "COMMAND PID\nsh 12", &.{12});
    defer std.testing.allocator.free(last);
    try std.testing.expectEqualStrings("COMMAND PID\nsh 12\n", last);
    const empty = try filterPsOutput(std.testing.allocator, "PID COMMAND\n12 sh\n", &.{});
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqualStrings("PID COMMAND\n", empty);
    try std.testing.expectError(error.PsMissingPidColumn, filterPsOutput(std.testing.allocator, "COMMAND\nsh\n", &.{12}));
    try std.testing.expectError(error.PsInvalidPid, filterPsOutput(std.testing.allocator, "UID PID COMMAND\nroot\n", &.{12}));
    try std.testing.expectError(error.PsInvalidPid, filterPsOutput(std.testing.allocator, "PID COMMAND\nabc sh\n", &.{12}));
}

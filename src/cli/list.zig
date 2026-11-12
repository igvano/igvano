const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const Config = @import("args.zig").Config;
const ContainerOverride = @import("state.zig").ContainerOverride;
const readLiveState = @import("state.zig").readLiveState;

/// One `runc list --format json` entry; field order matches runc.
const Entry = struct {
    ociVersion: []const u8,
    id: []const u8,
    pid: i32,
    status: []const u8,
    bundle: []const u8,
    rootfs: []const u8,
    created: []const u8,
    owner: []const u8,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,
};

/// runc list: every container under --root, sorted by id. Unreadable entries
/// are skipped with a warning, like runc.
pub fn listContainers(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const entries = try collectEntries(scratch, io, injected, config);
    const out = std.Io.File.stdout();
    if (config.quiet) {
        for (entries) |entry| try out.writeStreamingAll(io, try std.fmt.allocPrint(scratch, "{s}\n", .{entry.id}));
    } else if (config.ps_format == .json) {
        const json = try std.json.Stringify.valueAlloc(scratch, entries, .{ .emit_null_optional_fields = false });
        try out.writeStreamingAll(io, try std.fmt.allocPrint(scratch, "{s}\n", .{json}));
    } else {
        try out.writeStreamingAll(io, try formatTable(scratch, entries));
    }
}

fn collectEntries(scratch: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) ![]Entry {
    var directory = std.Io.Dir.cwd().openDir(io, config.root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer directory.close(io);
    var entries: std.ArrayList(Entry) = .empty;
    var names = directory.iterate();
    while (try names.next(io)) |name| {
        if (name.kind != .directory) continue;
        const id = try scratch.dupe(u8, name.name);
        const entry = loadEntry(scratch, io, injected, config, id) catch |err| {
            if (err == error.OutOfMemory) return err;
            std.debug.print("igvano: warning: cannot list container '{s}': {s}\n", .{ id, @errorName(err) });
            continue;
        };
        try entries.append(scratch, entry);
    }
    std.mem.sortUnstable(Entry, entries.items, {}, struct {
        fn lessThan(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.id, b.id);
        }
    }.lessThan);
    return entries.items;
}

fn loadEntry(scratch: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, id: []const u8) !Entry {
    var lookup = config;
    lookup.id = id;
    // Read-only: list never persists recovered states, unlike state/kill/delete.
    const live = try readLiveState(scratch, io, injected, lookup, false);
    const state = live.parsed.value;
    const saved = try std.fs.path.join(scratch, &.{ config.root, id });
    const spec = oci.loadSpec(scratch, io, saved) catch null;
    const rootfs = if (spec) |value| try oci.resolveRootfs(scratch, state.bundle, value.value.root.path) else "";
    const stat = try statPath(scratch, try std.fs.path.join(scratch, &.{ saved, "config.json" }));
    return .{
        .ociVersion = state.ociVersion,
        .id = id,
        .pid = if (state.status == .stopped) 0 else state.pid orelse 0,
        .status = @tagName(state.status),
        .bundle = state.bundle,
        .rootfs = rootfs,
        .created = try formatTime(scratch, stat.seconds, stat.nanoseconds),
        .owner = if (stat.uid == 0) "root" else try std.fmt.allocPrint(scratch, "#{d}", .{stat.uid}),
        .annotations = state.annotations,
    };
}

const PathStat = struct { seconds: i64, nanoseconds: u32, uid: u32 };

fn statPath(scratch: std.mem.Allocator, path: []const u8) !PathStat {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    const path_z = try scratch.dupeZ(u8, path);
    var result: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path_z, 0, .{ .MTIME = true, .UID = true }, &result)) != .SUCCESS)
        return error.FileNotFound;
    return .{ .seconds = result.mtime.sec, .nanoseconds = result.mtime.nsec, .uid = result.uid };
}

/// RFC 3339 with nanoseconds in UTC, as runc prints Go's time.Time.
fn formatTime(scratch: std.mem.Allocator, seconds: i64, nanoseconds: u32) ![]u8 {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(seconds, 0)) };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.allocPrint(scratch, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}Z", .{
        year_day.year,                 month_day.month.numeric(),        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
        nanoseconds,
    });
}

fn formatTable(scratch: std.mem.Allocator, entries: []const Entry) ![]u8 {
    const header = [_][]const u8{ "ID", "PID", "STATUS", "BUNDLE", "CREATED", "OWNER" };
    var rows: std.ArrayList([6][]const u8) = .empty;
    try rows.append(scratch, header);
    for (entries) |entry| try rows.append(scratch, .{
        entry.id,     try std.fmt.allocPrint(scratch, "{d}", .{entry.pid}), entry.status,
        entry.bundle, entry.created,                                        entry.owner,
    });
    var widths: [6]usize = @splat(0);
    for (rows.items) |row| for (row, &widths) |cell, *width| {
        width.* = @max(width.*, cell.len);
    };
    // Columns padded by at least one space, like Go's tabwriter(minwidth 12, padding 1).
    var output: std.ArrayList(u8) = .empty;
    for (rows.items) |row| {
        for (row, widths, 0..) |cell, width, column| {
            try output.appendSlice(scratch, cell);
            if (column + 1 < row.len) try output.appendNTimes(scratch, ' ', @max(width, 11) + 1 - cell.len);
        }
        try output.append(scratch, '\n');
    }
    return output.items;
}

test "list formats times and pads table columns" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("2026-11-12T01:02:03.000000042Z", try formatTime(arena.allocator(), 1794445323, 42));
    const table = try formatTable(arena.allocator(), &.{.{
        .ociVersion = "1.0.2",
        .id = "a",
        .pid = 7,
        .status = "running",
        .bundle = "/b",
        .rootfs = "/b/rootfs",
        .created = "t",
        .owner = "root",
    }});
    var lines = std.mem.splitScalar(u8, table, '\n');
    try std.testing.expect(std.mem.startsWith(u8, lines.next().?, "ID          PID         STATUS      BUNDLE"));
    try std.testing.expect(std.mem.startsWith(u8, lines.next().?, "a           7           running     /b"));
}

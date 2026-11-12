//! Cgroup counters for `Container.stats`, in runc's units (ns, bytes).
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const libcontainer = @import("../root.zig");
const Stats = libcontainer.Stats;
const diagnostics = @import("diagnostic.zig");
const closeFd = @import("syscall.zig").closeFd;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const openV1Hierarchies = @import("cgroup_v1.zig").openV1Hierarchies;
const freeV1Hierarchies = @import("cgroup_v1.zig").freeV1Hierarchies;
const walkV1Cgroup = @import("cgroup_v1.zig").walkV1Cgroup;

const unlimited = std.math.maxInt(u64);
/// cpuacct.stat counts USER_HZ ticks, which Linux fixes at 100 per second.
const ns_per_tick = std.time.ns_per_s / 100;

/// Missing files (a controller not enabled) read as zero, like runc.
pub fn stats(handle: libcontainer.State, allocator: std.mem.Allocator) libcontainer.Error!Stats {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const path = handle.cgroup_path orelse return error.NotImplemented;
    try validateCgroupPath(path);
    const root = try openCgroupRoot();
    defer closeFd(root.fd);
    if (root.mode == .legacy) return statsV1(allocator, handle.systemd, path);
    const fd = (try walkCgroup(root.fd, path, false, &.{})) orelse return error.ProcessNotFound;
    defer closeFd(fd);
    return statsV2(allocator, fd);
}

fn statsV2(allocator: std.mem.Allocator, fd: posix.fd_t) libcontainer.Error!Stats {
    var result: Stats = .{};
    if (try optionalFile(allocator, fd, "cpu.stat")) |text| {
        defer allocator.free(text);
        const us = std.time.ns_per_us;
        result.cpu.total = ((try keyed(text, "usage_usec")) orelse 0) * us;
        result.cpu.user = ((try keyed(text, "user_usec")) orelse 0) * us;
        result.cpu.kernel = ((try keyed(text, "system_usec")) orelse 0) * us;
        result.cpu.periods = (try keyed(text, "nr_periods")) orelse 0;
        result.cpu.throttled_periods = (try keyed(text, "nr_throttled")) orelse 0;
        result.cpu.throttled_time = ((try keyed(text, "throttled_usec")) orelse 0) * us;
    }
    result.cpu.psi = try psiFile(allocator, fd, "cpu.pressure");
    result.memory.usage = try valueFile(allocator, fd, "memory.current");
    result.memory.limit = try valueFile(allocator, fd, "memory.max");
    result.memory.max_usage = try valueFile(allocator, fd, "memory.peak");
    if (try optionalFile(allocator, fd, "memory.events")) |text| {
        defer allocator.free(text);
        result.memory.failcnt = (try keyed(text, "max")) orelse 0;
        result.oom_kills = (try keyed(text, "oom_kill")) orelse 0;
    }
    if (try optionalFile(allocator, fd, "memory.stat")) |text| {
        defer allocator.free(text);
        result.memory.raw = try rawEntries(allocator, text);
        result.memory.cache = (try keyed(text, "file")) orelse 0;
    }
    result.memory.psi = try psiFile(allocator, fd, "memory.pressure");
    result.pids.current = try valueFile(allocator, fd, "pids.current");
    result.pids.limit = try valueFile(allocator, fd, "pids.max");
    return result;
}

fn statsV1(allocator: std.mem.Allocator, systemd: bool, path: []const u8) libcontainer.Error!Stats {
    const hierarchies = try openV1Hierarchies(allocator, systemd);
    defer freeV1Hierarchies(allocator, hierarchies);
    var result: Stats = .{};
    for (hierarchies) |hierarchy| {
        const fd = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false)) orelse continue;
        defer closeFd(fd);
        if (hierarchy.has("cpuacct")) try cpuacctV1(allocator, fd, &result.cpu);
        if (hierarchy.has("cpu")) {
            if (try optionalFile(allocator, fd, "cpu.stat")) |text| {
                defer allocator.free(text);
                result.cpu.periods = (try keyed(text, "nr_periods")) orelse 0;
                result.cpu.throttled_periods = (try keyed(text, "nr_throttled")) orelse 0;
                result.cpu.throttled_time = (try keyed(text, "throttled_time")) orelse 0;
            }
        }
        if (hierarchy.has("memory")) try memoryV1(allocator, fd, &result);
        if (hierarchy.has("pids")) {
            result.pids.current = try valueFile(allocator, fd, "pids.current");
            result.pids.limit = try valueFile(allocator, fd, "pids.max");
        }
    }
    return result;
}

fn cpuacctV1(allocator: std.mem.Allocator, fd: posix.fd_t, cpu: *Stats.Cpu) libcontainer.Error!void {
    cpu.total = try valueFile(allocator, fd, "cpuacct.usage");
    if (try optionalFile(allocator, fd, "cpuacct.stat")) |text| {
        defer allocator.free(text);
        cpu.user = ((try keyed(text, "user")) orelse 0) * ns_per_tick;
        cpu.kernel = ((try keyed(text, "system")) orelse 0) * ns_per_tick;
    }
}

fn memoryV1(allocator: std.mem.Allocator, fd: posix.fd_t, result: *Stats) libcontainer.Error!void {
    result.memory.usage = try valueFile(allocator, fd, "memory.usage_in_bytes");
    result.memory.limit = try valueFile(allocator, fd, "memory.limit_in_bytes");
    result.memory.max_usage = try valueFile(allocator, fd, "memory.max_usage_in_bytes");
    result.memory.failcnt = try valueFile(allocator, fd, "memory.failcnt");
    if (try optionalFile(allocator, fd, "memory.stat")) |text| {
        defer allocator.free(text);
        result.memory.raw = try rawEntries(allocator, text);
        result.memory.cache = (try keyed(text, "cache")) orelse 0;
    }
    if (try optionalFile(allocator, fd, "memory.oom_control")) |text| {
        defer allocator.free(text);
        result.oom_kills = (try keyed(text, "oom_kill")) orelse 0;
    }
}

/// Only a missing file (a controller that is not enabled) reads as absent;
/// any other failure is an error that names the file and errno.
fn optionalFile(allocator: std.mem.Allocator, dir: posix.fd_t, name: [:0]const u8) libcontainer.Error!?[]u8 {
    const opened = linux.openat(dir, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        .NOENT => return null,
        else => |errno| return readFailed(name, errno),
    }
    const fd: posix.fd_t = @intCast(opened);
    defer closeFd(fd);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(count)) {
            .SUCCESS => if (count == 0) return try text.toOwnedSlice(allocator),
            .INTR => continue,
            // The cgroup was removed while reading: the container stopped.
            .NODEV => return error.ProcessNotFound,
            else => |errno| return readFailed(name, errno),
        }
        try text.appendSlice(allocator, buffer[0..count]);
    }
}

fn readFailed(name: []const u8, errno: linux.E) libcontainer.Error {
    reportDiagnostic("cannot read cgroup file {s}: {s}", .{ name, @tagName(errno) });
    return error.CgroupReadFailed;
}

fn malformed(text: []const u8) libcontainer.Error {
    reportDiagnostic("malformed cgroup value '{s}'", .{std.mem.trim(u8, text[0..@min(text.len, 64)], " \t\n")});
    return error.CgroupReadFailed;
}

fn valueFile(allocator: std.mem.Allocator, fd: posix.fd_t, name: [:0]const u8) libcontainer.Error!u64 {
    const text = (try optionalFile(allocator, fd, name)) orelse return 0;
    defer allocator.free(text);
    return parseValue(text);
}

fn psiFile(allocator: std.mem.Allocator, fd: posix.fd_t, name: [:0]const u8) libcontainer.Error!?Stats.Psi {
    const text = (try optionalFile(allocator, fd, name)) orelse return null;
    defer allocator.free(text);
    return try parsePsi(text);
}

/// A single number, or "max" for unlimited.
fn parseValue(text: []const u8) libcontainer.Error!u64 {
    const trimmed = std.mem.trim(u8, text, " \t\n");
    if (std.mem.eql(u8, trimmed, "max")) return unlimited;
    return std.fmt.parseInt(u64, trimmed, 10) catch malformed(text);
}

/// The value of `key` in "key value" lines; null when the key is absent.
fn keyed(text: []const u8, key: []const u8) libcontainer.Error!?u64 {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        if (!std.mem.eql(u8, fields.next() orelse continue, key)) continue;
        const value = fields.next() orelse return malformed(line);
        return std.fmt.parseInt(u64, value, 10) catch malformed(line);
    }
    return null;
}

fn rawEntries(allocator: std.mem.Allocator, text: []const u8) libcontainer.Error![]const Stats.Raw {
    var entries: std.ArrayList(Stats.Raw) = .empty;
    errdefer {
        for (entries.items) |entry| allocator.free(entry.name);
        entries.deinit(allocator);
    }
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const name = fields.next() orelse continue;
        const value = std.fmt.parseInt(u64, fields.next() orelse return malformed(line), 10) catch return malformed(line);
        const owned = try allocator.dupe(u8, name);
        errdefer allocator.free(owned);
        try entries.append(allocator, .{ .name = owned, .value = value });
    }
    return entries.toOwnedSlice(allocator);
}

/// "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" and an optional "full" line.
fn parsePsi(text: []const u8) libcontainer.Error!Stats.Psi {
    var result: Stats.Psi = .{};
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next() orelse continue;
        const data = if (std.mem.eql(u8, kind, "some")) &result.some else if (std.mem.eql(u8, kind, "full")) &result.full else continue;
        while (fields.next()) |field| try parsePsiField(data, field);
    }
    return result;
}

fn parsePsiField(data: *Stats.Psi.Data, field: []const u8) libcontainer.Error!void {
    const equals = std.mem.indexOfScalar(u8, field, '=') orelse return malformed(field);
    const key = field[0..equals];
    const value = field[equals + 1 ..];
    if (std.mem.eql(u8, key, "total")) {
        data.total = std.fmt.parseInt(u64, value, 10) catch return malformed(field);
        return;
    }
    inline for (.{ "avg10", "avg60", "avg300" }) |name| {
        if (std.mem.eql(u8, key, name)) @field(data, name) = std.fmt.parseFloat(f64, value) catch return malformed(field);
    }
}

test "stats parsers read cgroup value, keyed, raw and PSI files" {
    try std.testing.expectEqual(@as(u64, unlimited), try parseValue("max\n"));
    try std.testing.expectEqual(@as(u64, 4096), try parseValue("4096\n"));
    const cpu = "usage_usec 12\nuser_usec 7\nsystem_usec 5\nnr_periods 3\n";
    try std.testing.expectEqual(@as(?u64, 7), try keyed(cpu, "user_usec"));
    try std.testing.expectEqual(@as(?u64, null), try keyed(cpu, "usage"));
    try std.testing.expectEqual(@as(?u64, 1), try keyed("oom 2\noom_kill 1\n", "oom_kill"));
    const raw = try rawEntries(std.testing.allocator, "anon 10\nfile 20\n");
    defer {
        for (raw) |entry| std.testing.allocator.free(entry.name);
        std.testing.allocator.free(raw);
    }
    try std.testing.expectEqual(@as(usize, 2), raw.len);
    try std.testing.expectEqualStrings("file", raw[1].name);
    const psi = try parsePsi("some avg10=1.50 avg60=0.25 avg300=0.00 total=42\nfull avg10=0.10 avg60=0.00 avg300=0.00 total=7\n");
    try std.testing.expectEqual(@as(f64, 1.5), psi.some.avg10);
    try std.testing.expectEqual(@as(u64, 42), psi.some.total);
    try std.testing.expectEqual(@as(u64, 7), psi.full.total);
}

test "stats parsers fail on malformed cgroup values instead of reading zero" {
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectError(error.CgroupReadFailed, parseValue("bogus"));
    try std.testing.expectError(error.CgroupReadFailed, keyed("usage_usec x\n", "usage_usec"));
    try std.testing.expectError(error.CgroupReadFailed, keyed("usage_usec\n", "usage_usec"));
    try std.testing.expectError(error.CgroupReadFailed, rawEntries(std.testing.allocator, "anon 10\nbad x\n"));
    try std.testing.expectError(error.CgroupReadFailed, parsePsi("some avg10=nope total=1\n"));
}

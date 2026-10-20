const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../root.zig").Backend;
const diagnostics = @import("diagnostic.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const CgroupMode = @import("cgroup.zig").CgroupMode;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const readCgroupFile = @import("cgroup.zig").readCgroupFile;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const freeV1Hierarchies = @import("cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("cgroup_v1.zig").openV1Hierarchies;
const walkV1Cgroup = @import("cgroup_v1.zig").walkV1Cgroup;

pub fn openFreezerCgroup(handle: Backend.Handle) Backend.Error!?struct { fd: posix.fd_t, mode: CgroupMode } {
    const path = handle.cgroup_path orelse return null;
    try validateCgroupPath(path);
    const root = openCgroupRoot() catch |err| switch (err) {
        error.Unsupported => return null,
        else => return err,
    };
    defer closeFd(root.fd);
    const fd = if (root.mode == .legacy) freezer: {
        const allocator = std.heap.page_allocator;
        const hierarchies = try openV1Hierarchies(allocator, handle.systemd);
        defer freeV1Hierarchies(allocator, hierarchies);
        for (hierarchies) |hierarchy| {
            if (hierarchy.has("freezer"))
                break :freezer (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false)) orelse return null;
        }
        return null;
    } else (try walkCgroup(root.fd, path, false, &.{})) orelse return null;
    errdefer closeFd(fd);
    const name: [:0]const u8 = if (root.mode == .unified) "cgroup.freeze" else "freezer.state";
    const probe = linux.openat(fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(probe) == .NOENT) {
        closeFd(fd);
        return null;
    }
    try checkResult(probe);
    closeFd(@intCast(probe));
    return .{ .fd = fd, .mode = root.mode };
}

pub fn cgroupFrozen(dir: posix.fd_t, mode: CgroupMode) Backend.Error!bool {
    const fd = try openPath(dir, if (mode == .unified) "cgroup.freeze" else "freezer.state", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var buffer: [4096]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const count = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) break;
        used += count;
    }
    const state = std.mem.trim(u8, buffer[0..used], " \t\n");
    // v2 paused reflects our own freeze request, not an ancestor's freeze,
    // matching runc's v2 freezer GetState.
    if (mode == .unified) return std.mem.eql(u8, state, "1");
    return std.mem.eql(u8, state, "FROZEN") or std.mem.eql(u8, state, "FREEZING");
}

/// Both freezer implementations are asynchronous; poll every ten milliseconds.
pub fn waitFrozen(dir: posix.fd_t, mode: CgroupMode, wanted: bool, attempts: usize) Backend.Error!bool {
    const allocator = std.heap.page_allocator;
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..attempts) |_| {
        if (mode == .legacy) {
            const state = try readCgroupFile(allocator, dir, "freezer.state");
            defer allocator.free(state);
            if (std.mem.eql(u8, std.mem.trim(u8, state, " \t\n"), if (wanted) "FROZEN" else "THAWED"))
                return true;
        } else {
            const events = try readCgroupFile(allocator, dir, "cgroup.events");
            defer allocator.free(events);
            var lines = std.mem.tokenizeScalar(u8, events, '\n');
            const frozen = while (lines.next()) |line| {
                if (std.mem.eql(u8, line, "frozen 1")) break true;
                if (std.mem.eql(u8, line, "frozen 0")) break false;
            } else {
                reportDiagnostic("cgroup.events has no freezer state", .{});
                return error.Unsupported;
            };
            if (frozen == wanted) return true;
        }
        _ = linux.nanosleep(&delay, null);
    }
    return false;
}

pub fn setFrozen(handle: Backend.Handle, wanted: bool) Backend.Error!void {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const cgroup = (try openFreezerCgroup(handle)) orelse {
        reportDiagnostic("container '{s}' has no cgroup freezer; pause/resume is unsupported", .{handle.id});
        return error.Unsupported;
    };
    defer closeFd(cgroup.fd);
    // Explicit pause allows ten seconds for busy containers to freeze.
    try setCgroupFrozen(cgroup.fd, cgroup.mode, wanted, handle.cgroup_path.?, if (wanted) 1000 else 50);
}

pub fn setCgroupFrozen(dir: posix.fd_t, mode: CgroupMode, wanted: bool, path: []const u8, attempts: usize) Backend.Error!void {
    const name: []const u8 = if (mode == .unified) "cgroup.freeze" else "freezer.state";
    const value: []const u8 = if (mode == .unified)
        (if (wanted) "1" else "0")
    else
        (if (wanted) "FROZEN" else "THAWED");
    try writeCgroupFile(dir, name, value, path);
    errdefer if (wanted) {
        const saved_diagnostic = diagnostics.last_diagnostic;
        const saved_len = diagnostics.last_diagnostic_len;
        writeCgroupFile(dir, name, if (mode == .unified) "0" else "THAWED", path) catch {};
        diagnostics.last_diagnostic = saved_diagnostic;
        diagnostics.last_diagnostic_len = saved_len;
    };
    if (!try waitFrozen(dir, mode, wanted, attempts)) {
        reportDiagnostic("cgroup '{s}' did not reach freezer state {s}", .{ path, value });
        return error.CgroupWriteFailed;
    }
}

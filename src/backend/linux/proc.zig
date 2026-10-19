const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const diagnostics = @import("diagnostic.zig");
const closeFd = @import("syscall.zig").closeFd;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const openFreezerCgroup = @import("freezer.zig").openFreezerCgroup;
const cgroupFrozen = @import("freezer.zig").cgroupFrozen;

pub fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        if (handle.pid <= 0) return error.InvalidProcess;
        switch (linux.errno(linux.kill(handle.pid, @enumFromInt(0)))) {
            .SUCCESS, .PERM => {},
            .SRCH => return false,
            else => return error.LivenessFailed,
        }
        var buffer: [4096]u8 = undefined;
        // ponytail: /proc mounted with hidepid can conceal a live process.
        // Require a readable host /proc; kill(0) alone cannot verify identity.
        const stat = readProcStat(handle.pid, &buffer) catch |err| switch (err) {
            error.ProcessNotFound => return false,
            else => return err,
        };
        return stat.matches(handle.starttime);
    } else {
        return error.NotImplemented;
    }
}

pub fn kill(_: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        if (handle.pid <= 0) return error.InvalidProcess;
        if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
        const pidfd = try openPidfd(handle.pid);
        defer if (pidfd) |fd| closeFd(fd);
        var buffer: [4096]u8 = undefined;
        const stat = try readProcStat(handle.pid, &buffer);
        if (!stat.matches(handle.starttime)) return error.ProcessNotFound;
        try signalPid(handle.pid, pidfd, signal);
        if (signal == @intFromEnum(linux.SIG.KILL)) thawKilledV1Cgroup(handle);
    } else {
        return error.NotImplemented;
    }
}

fn thawKilledV1Cgroup(handle: Backend.Handle) void {
    // A v1 freezer holds SIGKILL until the paused cgroup is thawed.
    const root = openCgroupRoot() catch return;
    defer closeFd(root.fd);
    if (root.mode == .unified) return;
    const cgroup = (openFreezerCgroup(handle) catch null) orelse return;
    defer closeFd(cgroup.fd);
    if (cgroupFrozen(cgroup.fd, .legacy) catch false)
        writeCgroupFile(cgroup.fd, "freezer.state", "THAWED", handle.cgroup_path.?) catch {};
}

const ProcStat = struct {
    state: u8,
    starttime: []const u8,

    pub fn matches(self: ProcStat, starttime: []const u8) bool {
        if (self.state == 'Z' or self.state == 'X') return false;
        return std.mem.eql(u8, starttime, self.starttime);
    }
};

fn parseProcStat(bytes: []const u8) Backend.Error!ProcStat {
    // comm can contain spaces and parentheses; only its final ')' delimits it.
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.LivenessFailed;
    var fields = std.mem.tokenizeAny(u8, bytes[end + 1 ..], " \t\n");
    const state = fields.next() orelse return error.LivenessFailed;
    if (state.len != 1) return error.LivenessFailed;
    // State is field 3; skip fields 4 through 21 to reach starttime.
    for (4..22) |_| _ = fields.next() orelse return error.LivenessFailed;
    const starttime = fields.next() orelse return error.LivenessFailed;
    _ = std.fmt.parseInt(u64, starttime, 10) catch return error.LivenessFailed;
    return .{ .state = state[0], .starttime = starttime };
}

pub fn readProcStat(pid: i32, buffer: []u8) Backend.Error!ProcStat {
    return readProcStatAt(linux.AT.FDCWD, pid, buffer);
}

pub fn readProcStatAt(proc_dir: posix.fd_t, pid: i32, buffer: []u8) Backend.Error!ProcStat {
    return parseProcStat(try readProcFileAt(proc_dir, pid, "stat", buffer));
}

pub fn readProcFileAt(proc_dir: posix.fd_t, pid: i32, comptime filename: []const u8, buffer: []u8) Backend.Error![]const u8 {
    var path_buffer: [64]u8 = undefined;
    const path = if (proc_dir == linux.AT.FDCWD)
        std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/" ++ filename, .{pid}) catch unreachable
    else
        std.fmt.bufPrintZ(&path_buffer, "{d}/" ++ filename, .{pid}) catch unreachable;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(proc_dir, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            .NOENT, .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    };
    defer closeFd(fd);
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return buffer[0..used];
                used += result;
            },
            .INTR => continue,
            .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    }
    return error.LivenessFailed;
}

pub fn openPidfd(pid: i32) Backend.Error!?posix.fd_t {
    while (true) {
        const opened = linux.pidfd_open(pid, 0);
        switch (linux.errno(opened)) {
            .SUCCESS => return @intCast(opened),
            .INTR => continue,
            .NOSYS, .PERM, .ACCES => return null,
            .SRCH => return error.ProcessNotFound,
            else => return error.KillFailed,
        }
    }
}

pub fn signalPid(pid: i32, pidfd: ?posix.fd_t, signal: i32) Backend.Error!void {
    const sig: linux.SIG = @enumFromInt(@as(u32, @intCast(signal)));
    if (pidfd) |fd| {
        while (true) {
            switch (linux.errno(linux.pidfd_send_signal(fd, sig, null, 0))) {
                .SUCCESS => return,
                .INTR => continue,
                .NOSYS => break,
                .SRCH => return error.ProcessNotFound,
                .PERM => return error.PermissionDenied,
                else => return error.KillFailed,
            }
        }
    }
    // ponytail: when pidfds are unavailable or denied by seccomp, the PID can
    // be reused between the identity check and kill().
    switch (linux.errno(linux.kill(pid, sig))) {
        .SUCCESS => {},
        .SRCH => return error.ProcessNotFound,
        .PERM => return error.PermissionDenied,
        else => return error.KillFailed,
    }
}

test "proc stat parses field 22 after comm containing spaces and closing parentheses" {
    const stat = try parseProcStat(
        "1234 (init) name (x)) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 987654321 23 24\n",
    );
    try std.testing.expectEqual(@as(u8, 'S'), stat.state);
    try std.testing.expectEqualStrings("987654321", stat.starttime);
}

test "proc stat treats zombie and dead states as not alive" {
    for ([_]u8{ 'Z', 'X', 'S', 'R', 'T' }) |state| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "1234 (init) ) {c} 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345\n", .{state});
        defer std.testing.allocator.free(line);
        const stat = try parseProcStat(line);
        try std.testing.expectEqual(state != 'Z' and state != 'X', stat.matches("12345"));
        try std.testing.expect(!stat.matches("54321"));
    }
}

test "proc stat rejects missing fields and malformed starttime" {
    for ([_][]const u8{
        "1234 init S 4",
        "1234 (init)",
        "1234 (init) SS 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 invalid",
    }) |line| {
        try std.testing.expectError(error.LivenessFailed, parseProcStat(line));
    }
}

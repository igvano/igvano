const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const diagnostics = @import("diagnostic.zig");
const RESOLVE_NO_XDEV = @import("syscall.zig").RESOLVE_NO_XDEV;
const RESOLVE_NO_MAGICLINKS = @import("syscall.zig").RESOLVE_NO_MAGICLINKS;
const RESOLVE_NO_SYMLINKS = @import("syscall.zig").RESOLVE_NO_SYMLINKS;
const RESOLVE_BENEATH = @import("syscall.zig").RESOLVE_BENEATH;
const OpenHow = @import("syscall.zig").OpenHow;
const statfsType = @import("syscall.zig").statfsType;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const readAll = @import("syscall.zig").readAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;

/// Created by the init/exec child after entering its PID and mount namespaces,
/// before dropping credentials. A detached procfs cannot be overmounted by the
/// container. All buffers and syscalls here are safe to use after fork.
pub const Procfs = struct {
    fd: posix.fd_t,
    /// Only the fallback uses a visible mount, requiring statx verification.
    mount_id: ?u64 = null,

    pub fn open(subset_pid: bool) libcontainer.Error!Procfs {
        if (try privateProcfs(subset_pid)) |fd| return .{ .fd = fd };
        const opened = linux.openat(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) {
            reportDiagnostic("cannot open fallback /proc: {s}", .{@tagName(linux.errno(opened))});
            return error.MissingProcfs;
        }
        const fd: posix.fd_t = @intCast(opened);
        errdefer closeFd(fd);
        return fallback(fd);
    }

    pub fn fallback(fd: posix.fd_t) libcontainer.Error!Procfs {
        var fs: [32]usize = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&fs)));
        if (statfsType(&fs) != 0x9fa0) {
            reportDiagnostic("unsafe fallback /proc: requires the root of a procfs mount", .{});
            return error.MissingProcfs;
        }
        var stat: linux.Statx = undefined;
        const result = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .INO = true, .MNT_ID = true }, &stat);
        if (linux.errno(result) != .SUCCESS or !stat.mask.INO or !stat.mask.MNT_ID or stat.ino != 1) {
            reportDiagnostic("unsafe fallback /proc: cannot verify procfs root and STATX_MNT_ID", .{});
            return error.MissingProcfs;
        }
        return .{ .fd = fd, .mount_id = stat.mnt_id };
    }

    pub fn openWrite(self: Procfs, path: [:0]const u8) libcontainer.Error!?posix.fd_t {
        // Fallback allows procfs's own self/thread-self symlinks, but never
        // crosses a mount. Numeric paths on the private mount need no symlinks.
        const how: OpenHow = .{
            .flags = @as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CLOEXEC = true })),
            .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                (if (self.mount_id != null) RESOLVE_NO_XDEV else RESOLVE_NO_SYMLINKS),
        };
        const opened = linux.syscall4(.openat2, @intCast(self.fd), @intFromPtr(path.ptr), @intFromPtr(&how), @sizeOf(OpenHow));
        switch (linux.errno(opened)) {
            .SUCCESS => {},
            .NOENT => return null,
            .LOOP, .XDEV => {
                reportDiagnostic("cannot safely open procfs path '{s}': {s} (symlinks or overmounts are forbidden)", .{ path, @tagName(linux.errno(opened)) });
                return error.MissingProcfs;
            },
            else => try checkResult(opened),
        }
        const fd: posix.fd_t = @intCast(opened);
        errdefer closeFd(fd);
        if (self.mount_id) |expected| {
            var stat: linux.Statx = undefined;
            const result = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .MNT_ID = true }, &stat);
            if (linux.errno(result) != .SUCCESS or !stat.mask.MNT_ID or stat.mnt_id != expected) {
                reportDiagnostic("unsafe procfs path '{s}': mount differs from /proc or STATX_MNT_ID is unavailable", .{path});
                return error.MissingProcfs;
            }
        }
        return fd;
    }
};

/// EPERM is possible in user namespaces even when container /proc is usable.
/// EACCES may likewise result from LSM mount mediation.
/// Old kernels may lack the new mount API or subset=pid; fail closed on other
/// errors and let the caller verify the visible procfs if mounting is denied.
fn privateProcfs(subset_pid: bool) libcontainer.Error!?posix.fd_t {
    const opened = linux.fsopen("proc", .{ .CLOEXEC = true });
    if (linux.errno(opened) == .PERM or linux.errno(opened) == .ACCES or linux.errno(opened) == .NOSYS) return null;
    try checkResult(opened);
    const context: posix.fd_t = @intCast(opened);
    defer closeFd(context);
    if (subset_pid) {
        const result = linux.fsconfig(context, .SET_STRING, "subset", "pid", 0);
        if (linux.errno(result) == .PERM or linux.errno(result) == .ACCES or linux.errno(result) == .NOSYS) return null;
        if (linux.errno(result) != .INVAL) try checkResult(result);
    }
    const created = linux.fsconfig(context, .CREATE, null, null, 0);
    if (linux.errno(created) == .PERM or linux.errno(created) == .ACCES or linux.errno(created) == .NOSYS) return null;
    try checkResult(created);
    const mounted = linux.fsmount(context, .{ .CLOEXEC = true }, .{
        .RELATIME = 0,
        .RDONLY = false,
        .NOSUID = true,
        .NODEV = true,
        .NOEXEC = true,
        .NOATIME = false,
        .STRICTATIME = false,
        .NODIRATIME = false,
        .IDMAP = false,
        .NOSYMFOLLOW = false,
    });
    if (linux.errno(mounted) == .PERM or linux.errno(mounted) == .ACCES or linux.errno(mounted) == .NOSYS) return null;
    try checkResult(mounted);
    return @intCast(mounted);
}

fn sysctlPath(buffer: []u8, key: []const u8) libcontainer.Error![:0]const u8 {
    if (std.mem.indexOfAny(u8, key, "/\x00") != null) return error.InvalidConfig;
    var components = std.mem.splitScalar(u8, key, '.');
    while (components.next()) |component| {
        if (component.len == 0) return error.InvalidConfig;
        if (component.len > 255) return error.InvalidPath;
    }
    const path = std.fmt.bufPrintZ(buffer, "sys/{s}", .{key}) catch return error.InvalidPath;
    std.mem.replaceScalar(u8, path["sys/".len..], '.', '/');
    return path;
}

test "sysctl paths are relative to procfs and reject traversal and overflow" {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("sys/kernel/hostname", try sysctlPath(&buffer, "kernel.hostname"));
    try std.testing.expectEqualStrings("sys/net/ipv4/ip_forward", try sysctlPath(&buffer, "net.ipv4.ip_forward"));
    for ([_][]const u8{ "", ".kernel", "kernel.", "net..ipv4", "../kernel", "kernel/name", "kernel\x00name" }) |key|
        try std.testing.expectError(error.InvalidConfig, sysctlPath(&buffer, key));
    try std.testing.expectError(error.InvalidPath, sysctlPath(&buffer, "x" ** 256));
    try std.testing.expectError(error.InvalidPath, sysctlPath(buffer[0..8], "kernel.hostname"));
}

/// Namespace policy belongs to the frontend; only translate and write here.
pub fn writeSysctl(proc: Procfs, setting: libcontainer.Sysctl) libcontainer.Error!void {
    if (std.mem.indexOfAny(u8, setting.value, "\x00\n") != null) return error.InvalidConfig;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try sysctlPath(&buffer, setting.key);
    const fd = (try proc.openWrite(path)) orelse return error.CreateFailed;
    defer closeFd(fd);
    var offset: usize = 0;
    while (offset < setting.value.len) {
        const result = linux.write(fd, setting.value[offset..].ptr, setting.value.len - offset);
        if (linux.errno(result) == .INTR) continue;
        try checkResult(result);
        if (result == 0) return error.CreateFailed;
        offset += result;
    }
}

pub fn applySysctls(settings: []const libcontainer.Sysctl) libcontainer.Error!void {
    if (settings.len == 0) return;
    var key = settings[0].key;
    errdefer |err| if (err != error.MissingProcfs or diagnostics.last_diagnostic_len == 0)
        reportDiagnostic("cannot set sysctl {s}: {s}", .{ key, @errorName(err) });
    const proc = try Procfs.open(false);
    defer closeFd(proc.fd);
    for (settings) |setting| {
        key = setting.key;
        try writeSysctl(proc, setting);
    }
}

pub fn apparmorEnabled() bool {
    if (comptime builtin.os.tag != .linux) return false;
    // Match runc's host probe, before the container hides /sys.
    if (linux.errno(linux.access("/sys/kernel/security/apparmor", linux.F_OK)) != .SUCCESS) return false;
    const fd = openPath(linux.AT.FDCWD, "/sys/module/apparmor/parameters/enabled", .{ .CLOEXEC = true }) catch return false;
    defer closeFd(fd);
    var enabled: [1]u8 = undefined;
    return readAll(fd, &enabled) and enabled[0] == 'Y';
}

test "AppArmor profile preparation ignores empty profiles and rejects unavailable enforcement" {
    try std.testing.expect(try prepareAppArmor(std.testing.allocator, null) == null);
    try std.testing.expect(try prepareAppArmor(std.testing.allocator, "") == null);
    try std.testing.expectError(error.InvalidProcess, prepareAppArmor(std.testing.allocator, "bad\x00profile"));
    if (!apparmorEnabled()) {
        defer diagnostics.last_diagnostic_len = 0;
        try std.testing.expectError(error.Unsupported, prepareAppArmor(std.testing.allocator, "igvano-deny-write"));
        try std.testing.expectEqualStrings("apparmor profile specified but apparmor is not enabled", diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
    } else {
        const command = (try prepareAppArmor(std.testing.allocator, "igvano-deny-write")).?;
        defer std.testing.allocator.free(command);
        try std.testing.expectEqualStrings("exec igvano-deny-write", command);
    }
}

pub fn prepareAppArmor(allocator: std.mem.Allocator, profile: ?[]const u8) libcontainer.Error!?[]const u8 {
    const name = profile orelse return null;
    if (name.len == 0) return null;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidProcess;
    if (!apparmorEnabled()) {
        reportDiagnostic("apparmor profile specified but apparmor is not enabled", .{});
        return error.Unsupported;
    }
    // One write is one AppArmor command; prepare the entire buffer before fork.
    return try std.fmt.allocPrint(allocator, "exec {s}", .{name});
}

pub fn applyAppArmor(command: ?[]const u8) libcontainer.Error!void {
    const text = command orelse return;
    const profile = text["exec ".len..];
    var unknown_profile = false;
    errdefer |err| if (err != error.MissingProcfs or diagnostics.last_diagnostic_len == 0)
        reportDiagnostic("unable to apply apparmor profile {s}: {s}", .{
            profile, if (unknown_profile) "profile not loaded" else @errorName(err),
        });
    const proc = try Procfs.open(true);
    defer closeFd(proc.fd);
    for ([_][:0]const u8{ "thread-self/attr/apparmor/exec", "self/attr/apparmor/exec", "self/attr/exec" }, 0..) |fallback_path, i| {
        var buffer: [96]u8 = undefined;
        // A private subset mount need not expose thread-self. Numeric IDs
        // refer to this child in the PID namespace that created the mount.
        // The visible fallback may use an ancestor PID namespace, so use its
        // verified self links rather than interpreting getpid() there.
        const path = if (proc.mount_id != null)
            fallback_path
        else
            std.fmt.bufPrintZ(&buffer, "{d}/task/{d}/attr/{s}exec", .{
                linux.getpid(), linux.gettid(), if (i < 2) "apparmor/" else "",
            }) catch unreachable;
        const fd = (try proc.openWrite(path)) orelse continue;
        defer closeFd(fd);
        return writeAppArmorCommand(fd, text, &unknown_profile);
    }
    reportDiagnostic("no apparmor exec attr in procfs", .{});
    return error.MissingProcfs;
}

fn writeAppArmorCommand(fd: posix.fd_t, text: []const u8, unknown_profile: *bool) libcontainer.Error!void {
    while (true) {
        const result = linux.write(fd, text.ptr, text.len);
        if (linux.errno(result) == .INTR) continue;
        unknown_profile.* = linux.errno(result) == .NOENT;
        try checkResult(result);
        if (result != text.len) return error.CreateFailed;
        return;
    }
}

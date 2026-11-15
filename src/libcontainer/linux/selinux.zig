//! SELinux process and mount labels, like runc with go-selinux: the process
//! label is the exec attribute set just before execve, and mount labels are
//! a context= option (see the frontend) or, for mqueue, an xattr.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const statfsType = @import("syscall.zig").statfsType;
const fdPath = @import("syscall.zig").fdPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const procfs = @import("procfs.zig");
const Procfs = procfs.Procfs;

const SELINUX_MAGIC = 0xf97cff8c;

/// go-selinux's GetEnabled: selinuxfs is mounted and we are not "kernel".
pub fn enabled() bool {
    if (comptime builtin.os.tag != .linux) return false;
    const fs_fd = openPath(linux.AT.FDCWD, "/sys/fs/selinux", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch return false;
    defer closeFd(fs_fd);
    var fs: [32]usize = undefined;
    if (linux.errno(linux.syscall2(.fstatfs, @intCast(fs_fd), @intFromPtr(&fs))) != .SUCCESS) return false;
    if (statfsType(&fs) != SELINUX_MAGIC) return false;
    const fd = openPath(linux.AT.FDCWD, "/proc/self/attr/current", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return false;
    defer closeFd(fd);
    var buffer: [256]u8 = undefined;
    const size = linux.read(fd, &buffer, buffer.len);
    if (linux.errno(size) != .SUCCESS) return false;
    return !std.mem.eql(u8, std.mem.trim(u8, buffer[0..size], "\x00\n"), "kernel");
}

/// runc's validator: a process label needs SELinux. Before fork.
pub fn requireLabelSupport(label: ?[]const u8) libcontainer.Error!void {
    const value = label orelse return;
    if (value.len == 0) return;
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidProcess;
    if (!enabled()) {
        reportDiagnostic("selinux label is specified in config, but selinux is disabled or not supported", .{});
        return error.InvalidConfig;
    }
}

/// go-selinux's SetExecLabel through a verified procfs. After fork.
pub fn applyExecLabel(label: ?[]const u8) libcontainer.Error!void {
    const value = label orelse return;
    if (value.len == 0) return;
    const proc = try Procfs.open(true);
    defer closeFd(proc.fd);
    for ([_]bool{ true, false }) |thread| {
        const fd = (try procfs.openAttr(proc, "exec", thread)) orelse continue;
        defer closeFd(fd);
        const result = linux.write(fd, value.ptr, value.len);
        checkResult(result) catch |err| {
            reportDiagnostic("unable to set selinux label {s}: {s}", .{ value, @tagName(linux.errno(result)) });
            return err;
        };
        return;
    }
    reportDiagnostic("no selinux exec attr in procfs", .{});
    return error.MissingProcfs;
}

/// label.SetFileLabel: the security.selinux xattr, as runc labels mqueue.
pub fn labelFile(fd: posix.fd_t, label: ?[]const u8) libcontainer.Error!void {
    const value = label orelse return;
    if (value.len == 0 or !enabled()) return;
    var buffer: [64]u8 = undefined;
    const result = linux.setxattr(fdPath(&buffer, fd), "security.selinux", value.ptr, value.len, 0);
    checkResult(result) catch |err| {
        reportDiagnostic("setxattr(label={s}): {s}", .{ value, @tagName(linux.errno(result)) });
        return err;
    };
}

/// The data for runc's masked-path tmpfs: context="<label>", or none.
pub fn maskData(buffer: []u8, label: ?[]const u8) ?[*:0]const u8 {
    const value = label orelse return null;
    if (value.len == 0) return null;
    return (std.fmt.bufPrintZ(buffer, "context=\"{s}\"", .{value}) catch return null).ptr;
}

test "a process label without SELinux fails like runc" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer @import("diagnostic.zig").last_diagnostic_len = 0;
    try requireLabelSupport(null);
    try requireLabelSupport("");
    try std.testing.expectError(error.InvalidProcess, requireLabelSupport("a\x00b"));
    if (!enabled()) try std.testing.expectError(error.InvalidConfig, requireLabelSupport("system_u:system_r:container_t:s0"));
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("context=\"l\"", std.mem.span(maskData(&buffer, "l").?));
    try std.testing.expect(maskData(&buffer, null) == null);
}

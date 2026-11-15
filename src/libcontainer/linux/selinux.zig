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

/// go-selinux's FormatMountLabel option: context= and the label quoted
/// like Go's %q; null without a label. Owned by `allocator`.
// ponytail: bytes >= 0x80 pass through; Go also escapes invalid UTF-8 and
// non-printable runes, which SELinux contexts never contain.
pub fn mountLabelOption(allocator: std.mem.Allocator, label: ?[]const u8) libcontainer.Error!?[:0]const u8 {
    const value = label orelse return null;
    if (value.len == 0) return null;
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.appendSlice(allocator, "context=\"");
    for (value) |byte| {
        if (byte == 0) {
            reportDiagnostic("linux.mountLabel: must not contain NUL", .{});
            return error.InvalidConfig;
        }
        if (goEscape(byte)) |sequence| {
            try text.appendSlice(allocator, sequence);
        } else if (byte < 0x20 or byte == 0x7f) {
            try text.print(allocator, "\\x{x:0>2}", .{byte});
        } else try text.append(allocator, byte);
    }
    try text.append(allocator, '"');
    return try text.toOwnedSliceSentinel(allocator, 0);
}

/// Go's strconv.Quote short escapes.
fn goEscape(byte: u8) ?[]const u8 {
    return switch (byte) {
        '"' => "\\\"",
        '\\' => "\\\\",
        0x07 => "\\a",
        0x08 => "\\b",
        0x0c => "\\f",
        '\n' => "\\n",
        '\r' => "\\r",
        '\t' => "\\t",
        0x0b => "\\v",
        else => null,
    };
}

test "a process label without SELinux fails like runc" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer @import("diagnostic.zig").last_diagnostic_len = 0;
    try requireLabelSupport(null);
    try requireLabelSupport("");
    try std.testing.expectError(error.InvalidProcess, requireLabelSupport("a\x00b"));
    if (!enabled()) try std.testing.expectError(error.InvalidConfig, requireLabelSupport("system_u:system_r:container_t:s0"));
    const option = (try mountLabelOption(std.testing.allocator, "a\"b,c\\\n")).?;
    defer std.testing.allocator.free(option);
    try std.testing.expectEqualStrings("context=\"a\\\"b,c\\\\\\n\"", option);
    try std.testing.expect(try mountLabelOption(std.testing.allocator, null) == null);
    try std.testing.expectError(error.InvalidConfig, mountLabelOption(std.testing.allocator, "a\x00"));
}

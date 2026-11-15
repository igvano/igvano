// SPDX-License-Identifier: Apache-2.0
// Portions derived from runc (https://github.com/opencontainers/runc), Copyright The runc Authors, Apache-2.0:
// libcontainer/exeseal (sealedOverlayfs, escapeOverlayLowerDir, CloneSelfExe).
// Translated to Zig and modified. See NOTICE.
//! runc's exeseal (CVE-2019-5736): processes that enter a container must
//! not have /proc/self/exe point at the writable host binary, or the
//! container could reopen and overwrite it. igvano forks rather than
//! re-executing itself, so it re-executes once, early, from a sealed
//! clone: a read-only private overlayfs view of the binary (no copy), or a
//! sealed memfd copy when overlayfs is not available (rootless).
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const statfsType = @import("syscall.zig").statfsType;
const statfsFlags = @import("syscall.zig").statfsFlags;
const debugLog = @import("diagnostic.zig").debugLog;

/// Set on the re-executed process. It is only trusted together with a
/// sealed /proc/self/exe (see isSealed), so it cannot skip sealing.
pub const marker = "_IGVANO_EXESEAL=1";

const OVERLAYFS_SUPER_MAGIC = 0x794c7630;
const ST_RDONLY = 1;
const F_SEAL_SEAL = 0x1;
const F_SEAL_SHRINK = 0x2;
const F_SEAL_GROW = 0x4;
const F_SEAL_WRITE = 0x8;
const F_SEAL_EXEC = 0x20;
const MFD_EXEC = 0x10;
const base_seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

/// Returns when /proc/self/exe is already a sealed clone. Otherwise
/// re-executes from one, or returns an error. `state_dir` must be an
/// existing directory; it is the second, empty overlayfs lower layer.
pub fn ensureSealed(argv: [*:null]const ?[*:0]const u8, envp: []const ?[*:0]const u8, state_dir: [:0]const u8, debug: ?libcontainer.DebugLog) libcontainer.Error!void {
    if (hasMarker(envp) and isSealed()) return;
    const exe = sealedOverlay(state_dir) catch |err| overlay: {
        debugLog(debug, "could not use overlayfs for /proc/self/exe sealing -- falling back to making a temporary copy: {s}", .{@errorName(err)});
        break :overlay null;
    };
    if (exe != null) debugLog(debug, "runc exeseal: using overlayfs for sealed /proc/self/exe", .{});
    const fd = exe orelse try sealedMemfd();
    defer closeFd(fd);
    debugLog(debug, "runc exeseal: using /proc/self/exe clone", .{});
    const env = std.heap.page_allocator.alloc(?[*:0]const u8, envp.len + 2) catch return error.OutOfMemory;
    var count: usize = 0;
    for (envp) |entry| {
        const value = entry orelse continue;
        if (std.mem.eql(u8, std.mem.span(value), marker)) continue;
        env[count] = value;
        count += 1;
    }
    env[count] = marker;
    env[count + 1] = null;
    const result = linux.execveat(fd, "", argv, @ptrCast(env.ptr), @bitCast(@as(u32, linux.AT.EMPTY_PATH)));
    try checkResult(result);
    unreachable;
}

fn hasMarker(envp: []const ?[*:0]const u8) bool {
    for (envp) |entry| {
        if (entry) |value| if (std.mem.eql(u8, std.mem.span(value), marker)) return true;
    }
    return false;
}

/// A memfd with runc's base seals, or a read-only overlayfs file. A host
/// binary on a writable overlayfs (a Docker container root) is not sealed.
fn isSealed() bool {
    const fd = openPath(linux.AT.FDCWD, "/proc/self/exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return false;
    defer closeFd(fd);
    const seals = linux.fcntl(fd, linux.F.GET_SEALS, 0);
    if (linux.errno(seals) == .SUCCESS) return seals & base_seals == base_seals;
    var fs: [32]usize = undefined;
    if (linux.errno(linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&fs))) != .SUCCESS) return false;
    return statfsType(&fs) == OVERLAYFS_SUPER_MAGIC and statfsFlags(&fs) & ST_RDONLY != 0;
}

/// overlayfs escapes ':' and '\' in lowerdir paths.
fn escapeLowerDir(buffer: []u8, path: []const u8) error{NameTooLong}![]const u8 {
    var used: usize = 0;
    for (path) |byte| {
        if (byte == ':' or byte == '\\') {
            if (used == buffer.len) return error.NameTooLong;
            buffer[used] = '\\';
            used += 1;
        }
        if (used == buffer.len) return error.NameTooLong;
        buffer[used] = byte;
        used += 1;
    }
    return buffer[0..used];
}

/// runc's sealedOverlayfs: a private, read-only overlayfs whose top layer
/// is the binary's directory. It cannot be unwrapped to the host file.
fn sealedOverlay(state_dir: [:0]const u8) libcontainer.Error!posix.fd_t {
    const opened = linux.fsopen("overlay", .{ .CLOEXEC = true });
    try checkResult(opened);
    const context: posix.fd_t = @intCast(opened);
    defer closeFd(context);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const size = linux.readlink("/proc/self/exe", &path_buffer, path_buffer.len);
    try checkResult(size);
    const path = path_buffer[0..size];
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidPath;
    var name_buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&name_buffer, "{s}", .{path[slash + 1 ..]}) catch return error.InvalidPath;
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var dummy_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = escapeLowerDir(&dir_buffer, if (slash == 0) "/" else path[0..slash]) catch return error.InvalidPath;
    const dummy = escapeLowerDir(&dummy_buffer, state_dir) catch return error.InvalidPath;
    var lower_buffer: [2 * std.fs.max_path_bytes + 2]u8 = undefined;
    const lower = std.fmt.bufPrintZ(&lower_buffer, "{s}:{s}", .{ dir, dummy }) catch return error.InvalidPath;
    try checkResult(linux.fsconfig(context, .SET_STRING, "lowerdir", lower, 0));
    // Only quiets spurious dmesg lines; older kernels lack it.
    _ = linux.fsconfig(context, .SET_STRING, "xino", "off", 0);
    try checkResult(linux.fsconfig(context, .CREATE, null, null, 0));
    const mounted = linux.fsmount(context, .{ .CLOEXEC = true }, @bitCast(@as(u32, 0x1 | 0x2 | 0x4))); // RDONLY, NOSUID, NODEV;
    try checkResult(mounted);
    const mount_fd: posix.fd_t = @intCast(mounted);
    defer closeFd(mount_fd);
    return openPath(mount_fd, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
}

/// runc's CloneBinary with a memfd: copy, make it 0511, then seal it.
fn sealedMemfd() libcontainer.Error!posix.fd_t {
    const flags = linux.MFD.ALLOW_SEALING | linux.MFD.CLOEXEC;
    var created = linux.memfd_create("igvano_cloned:/proc/self/exe", flags | MFD_EXEC);
    // MFD_EXEC is Linux 6.3+.
    if (linux.errno(created) == .INVAL) created = linux.memfd_create("igvano_cloned:/proc/self/exe", flags);
    try checkResult(created);
    const memfd: posix.fd_t = @intCast(created);
    errdefer closeFd(memfd);
    const source = try openPath(linux.AT.FDCWD, "/proc/self/exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(source);
    while (true) {
        const copied = linux.sendfile(memfd, source, null, 1 << 30);
        if (linux.errno(copied) == .INTR) continue;
        try checkResult(copied);
        if (copied == 0) break;
    }
    try checkResult(linux.fchmod(memfd, 0o511));
    _ = linux.fcntl(memfd, linux.F.ADD_SEALS, F_SEAL_EXEC);
    try checkResult(linux.fcntl(memfd, linux.F.ADD_SEALS, base_seals));
    return memfd;
}

test "overlayfs lowerdir paths escape colons and backslashes" {
    var buffer: [32]u8 = undefined;
    try std.testing.expectEqualStrings("/a\\:b\\\\c", try escapeLowerDir(&buffer, "/a:b\\c"));
    try std.testing.expectError(error.NameTooLong, escapeLowerDir(buffer[0..3], "a:b"));
}

test "statfs flags come from the f_flags field" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    // procfs is mounted nosuid,nodev,noexec on hosts and in containers.
    const fd = try openPath(linux.AT.FDCWD, "/proc/self", .{ .PATH = true, .CLOEXEC = true });
    defer closeFd(fd);
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&fs)));
    try std.testing.expectEqual(@as(usize, 0x9fa0), statfsType(&fs)); // PROC_SUPER_MAGIC
    const ST_NOSUID = 2;
    try std.testing.expect(statfsFlags(&fs) & ST_NOSUID != 0);
    try std.testing.expect(statfsFlags(&fs) & ST_RDONLY == 0);
}

test "the marker alone does not count as sealed" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    // This test binary runs from a plain file, never a sealed clone.
    try std.testing.expect(!isSealed());
    try std.testing.expect(hasMarker(&.{ "A=1", marker }));
    try std.testing.expect(!hasMarker(&.{"A=1"}));
}

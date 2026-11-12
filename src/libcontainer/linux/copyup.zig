//! tmpfs "tmpcopyup": copy the directory a tmpfs covers into the new tmpfs.
//! Runs in the forked init: no allocation, only stack buffers and syscalls.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;

/// Deeper trees fail closed instead of exhausting init's stack.
const max_depth = 64;

/// Copies every entry of `from` into `to`, like runc's fileutils.CopyDirectory:
/// directories, regular files, symlinks and device or FIFO nodes, keeping
/// mode (setuid bits included) and owner. Sockets are skipped, hard links
/// become separate files, and `to` itself keeps the tmpfs mount's mode.
pub fn copyTree(from: posix.fd_t, to: posix.fd_t) libcontainer.Error!void {
    return copyDirectory(from, to, 0);
}

fn copyDirectory(from: posix.fd_t, to: posix.fd_t, depth: usize) libcontainer.Error!void {
    if (depth >= max_depth) return error.InvalidPath;
    var buffer: [4096]u8 align(8) = undefined;
    while (true) {
        const count = linux.getdents64(from, &buffer, buffer.len);
        try checkResult(count);
        if (count == 0) return;
        var offset: usize = 0;
        while (offset < count) {
            // struct linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
            const reclen = std.mem.readInt(u16, buffer[offset + 16 ..][0..2], .little);
            const name: [*:0]const u8 = @ptrCast(&buffer[offset + 19]);
            offset += reclen;
            const text = std.mem.span(name);
            if (std.mem.eql(u8, text, ".") or std.mem.eql(u8, text, "..")) continue;
            try copyEntry(from, to, name, depth);
        }
    }
}

fn copyEntry(from: posix.fd_t, to: posix.fd_t, name: [*:0]const u8, depth: usize) libcontainer.Error!void {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(from, name, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true }, &stat));
    const kind = stat.mode & linux.S.IFMT;
    const mode: u32 = stat.mode & 0o7777;
    switch (kind) {
        linux.S.IFDIR => {
            try checkResult(linux.mkdirat(to, name, 0o700));
            const source = try openEntry(from, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
            defer closeFd(source);
            const target = try openEntry(to, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
            defer closeFd(target);
            try copyDirectory(source, target, depth + 1);
            // After the children, so a read-only directory can still be filled.
            try setOwnerAndMode(target, stat.uid, stat.gid, mode);
        },
        linux.S.IFREG => {
            const source = try openEntry(from, name, .{ .ACCMODE = .RDONLY });
            defer closeFd(source);
            const target = try openEntry(to, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true });
            defer closeFd(target);
            try copyFile(source, target);
            try setOwnerAndMode(target, stat.uid, stat.gid, mode);
        },
        linux.S.IFLNK => {
            var link: [linux.PATH_MAX + 1]u8 = undefined;
            const length = linux.readlinkat(from, name, &link, linux.PATH_MAX);
            try checkResult(length);
            link[length] = 0;
            try checkResult(linux.symlinkat(link[0..length :0], to, name));
            try checkResult(linux.fchownat(to, name, stat.uid, stat.gid, linux.AT.SYMLINK_NOFOLLOW));
        },
        linux.S.IFCHR, linux.S.IFBLK, linux.S.IFIFO => {
            const dev = deviceNumber(stat.rdev_major, stat.rdev_minor);
            try checkResult(linux.mknodat(to, name, kind | 0o600, dev));
            try checkResult(linux.fchownat(to, name, stat.uid, stat.gid, linux.AT.SYMLINK_NOFOLLOW));
            try checkResult(linux.fchmodat(to, name, mode));
        },
        else => {}, // Sockets belong to the process that bound them.
    }
}

fn openEntry(dir: posix.fd_t, name: [*:0]const u8, flags: linux.O) libcontainer.Error!posix.fd_t {
    var with = flags;
    with.NOFOLLOW = true;
    with.CLOEXEC = true;
    const result = linux.openat(dir, name, with, 0o600);
    try checkResult(result);
    return @intCast(result);
}

/// Owner first: chown clears setuid and setgid bits.
fn setOwnerAndMode(fd: posix.fd_t, uid: u32, gid: u32, mode: u32) libcontainer.Error!void {
    try checkResult(linux.fchown(fd, uid, gid));
    try checkResult(linux.fchmod(fd, @intCast(mode)));
}

fn copyFile(source: posix.fd_t, target: posix.fd_t) libcontainer.Error!void {
    var buffer: [16384]u8 = undefined;
    while (true) {
        const count = linux.read(source, &buffer, buffer.len);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) return;
        var written: usize = 0;
        while (written < count) {
            const result = linux.write(target, buffer[written..count].ptr, count - written);
            if (linux.errno(result) == .INTR) continue;
            try checkResult(result);
            written += result;
        }
    }
}

/// The kernel's 32-bit dev_t encoding (new_encode_dev).
fn deviceNumber(major: u32, minor: u32) u32 {
    return (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ~@as(u32, 0xff)) << 12);
}

test "copy-up copies files, directories, symlinks and modes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "from/a/b");
    try tmp.dir.createDir(io, "to", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "from/a/file", .data = "hello" });
    try tmp.dir.symLink(io, "a/file", "from/link", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const dir = try openEntry(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
    defer closeFd(dir);
    try checkResult(linux.fchmodat(dir, "from/a/b", 0o777));
    try checkResult(linux.fchmodat(dir, "from/a", 0o555));
    defer _ = linux.fchmodat(dir, "from/a", 0o755);
    defer _ = linux.fchmodat(dir, "to/a", 0o755);
    const from = try openEntry(dir, "from", .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
    defer closeFd(from);
    const to = try openEntry(dir, "to", .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
    defer closeFd(to);
    try copyTree(from, to);
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(dir, "to/a/b", 0, .{ .MODE = true }, &stat));
    try std.testing.expectEqual(@as(u16, linux.S.IFDIR | 0o777), stat.mode);
    try checkResult(linux.statx(dir, "to/a", 0, .{ .MODE = true }, &stat));
    try std.testing.expectEqual(@as(u16, 0o555), stat.mode & 0o7777);
    const text = try tmp.dir.readFileAlloc(io, "to/a/file", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("hello", text);
    var link: [64]u8 = undefined;
    const length = linux.readlinkat(dir, "to/link", &link, link.len);
    try checkResult(length);
    try std.testing.expectEqualStrings("a/file", link[0..length]);
    try std.testing.expectEqual(@as(u32, 0x0801), deviceNumber(8, 1));
    try std.testing.expectEqual(@as(u32, 0x10_0001), deviceNumber(0, 0x101));
}

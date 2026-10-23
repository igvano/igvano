const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;

pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;
pub const OpenHow = extern struct {
    flags: u64,
    mode: u64 = 0,
    resolve: u64,
};

/// statfs starts with native words, except s390x's packed u32 type/bsize.
pub fn statfsType(fs: *const [32]usize) usize {
    if (comptime builtin.cpu.arch == .s390x) {
        const words: *const [64]u32 = @ptrCast(fs);
        return words[0];
    }
    return fs[0];
}

test "statfs type excludes the adjacent block size on s390x" {
    var fs: [32]usize = @splat(0);
    if (comptime builtin.cpu.arch == .s390x) {
        const words: *[64]u32 = @ptrCast(&fs);
        words[0] = 0x9fa0;
        words[1] = 4096;
    } else {
        fs[0] = 0x9fa0;
        fs[1] = 4096;
    }
    try std.testing.expectEqual(@as(usize, 0x9fa0), statfsType(&fs));
}

pub fn processString(allocator: std.mem.Allocator, value: []const u8) libcontainer.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidProcess;
    return allocator.dupeZ(u8, value);
}

pub fn pathString(allocator: std.mem.Allocator, value: []const u8) libcontainer.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidPath;
    return allocator.dupeZ(u8, value);
}

pub fn preparePaths(allocator: std.mem.Allocator, paths: []const []const u8) libcontainer.Error![]const [:0]const u8 {
    const prepared = try allocator.alloc([:0]const u8, paths.len);
    for (paths, prepared) |path, *value| {
        if (!std.mem.startsWith(u8, path, "/")) return error.InvalidPath;
        value.* = try pathString(allocator, path);
    }
    return prepared;
}

pub fn checkResult(result: usize) libcontainer.Error!void {
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .AGAIN, .MFILE, .NFILE => return error.SystemResources,
        .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

// Zig 0.16 exposes fork/pipe/waitpid through std.posix.system.
pub fn forkProcess() libcontainer.Error!i32 {
    const result = posix.system.fork();
    switch (posix.errno(result)) {
        .SUCCESS => return @intCast(result),
        .NOMEM, .AGAIN => return error.SystemResources,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

pub fn makePipe() libcontainer.Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    switch (posix.errno(posix.system.pipe2(&fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => return fds,
        .MFILE, .NFILE => return error.SystemResources,
        else => return error.CreateFailed,
    }
}

pub fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

pub fn waitChild(pid: i32) libcontainer.Error!u32 {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => return @bitCast(status),
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

pub fn readAll(fd: posix.fd_t, bytes: []u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

pub fn writeAll(fd: posix.fd_t, bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

pub fn openPath(dir_fd: posix.fd_t, path: [*:0]const u8, flags: linux.O) libcontainer.Error!posix.fd_t {
    const result = linux.openat(dir_fd, path, flags, 0);
    try checkResult(result);
    return @intCast(result);
}

fn openResolved(dir_fd: posix.fd_t, path: [*:0]const u8, flags: linux.O, resolve: u64) libcontainer.Error!posix.fd_t {
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve };
    const result = try openat2(dir_fd, path, how);
    try checkResult(result);
    return @intCast(result);
}

/// Preserve ordinary errno values for callers with path-specific semantics.
/// Never fall back to openat when the kernel cannot enforce resolve flags.
pub fn openat2(dir_fd: posix.fd_t, path: [*:0]const u8, how: OpenHow) libcontainer.Error!usize {
    // Scoped lookups can race with mount or rename changes elsewhere.
    for (0..32) |_| {
        const result = linux.syscall4(.openat2, @bitCast(@as(isize, dir_fd)), @intFromPtr(path), @intFromPtr(&how), @sizeOf(OpenHow));
        switch (linux.errno(result)) {
            .AGAIN => continue,
            .NOSYS, .@"2BIG" => {
                reportDiagnostic("openat2 is required for confined path resolution (Linux 5.6+): {s}", .{@tagName(linux.errno(result))});
                return error.Unsupported;
            },
            else => return result,
        }
    }
    reportDiagnostic("resolve confined path (openat2 EAGAIN after 32 attempts)", .{});
    return error.ResolveRetryExhausted;
}

pub fn fileType(fd: posix.fd_t) libcontainer.Error!u16 {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    return stat.mode & linux.S.IFMT;
}

pub fn fdPath(buffer: []u8, fd: posix.fd_t) [:0]u8 {
    return std.fmt.bufPrintZ(buffer, "/proc/self/fd/{d}", .{fd}) catch unreachable;
}

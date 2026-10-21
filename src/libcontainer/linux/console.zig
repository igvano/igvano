const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const OPEN_TREE_CLONE = @import("mount.zig").OPEN_TREE_CLONE;
const OPEN_TREE_CLOEXEC = @import("mount.zig").OPEN_TREE_CLOEXEC;
const mountDestination = @import("mount.zig").mountDestination;
const statfsType = @import("syscall.zig").statfsType;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const fdPath = @import("syscall.zig").fdPath;

/// Linux descriptor passing, shared by init and the frontend. No allocation
/// or std.Io machinery: these helpers also run after fork.
pub const console = struct {
    pub const Rights = extern struct {
        header: linux.cmsghdr,
        fd: posix.fd_t,
    };
    pub const rights_len = @sizeOf(linux.cmsghdr) + @sizeOf(posix.fd_t);

    pub fn socketpair() libcontainer.Error![2]posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var fds: [2]posix.fd_t = undefined;
        try checkResult(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
        errdefer for (fds) |fd| closeFd(fd);
        for (&fds) |*fd| {
            if (fd.* <= 2) {
                const moved = linux.fcntl(fd.*, linux.F.DUPFD_CLOEXEC, 3);
                try checkResult(moved);
                closeFd(fd.*);
                fd.* = @intCast(moved);
            }
        }
        return fds;
    }

    pub fn sendFd(socket: posix.fd_t, fd: posix.fd_t) libcontainer.Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        rights.header = .{ .len = rights_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
        rights.fd = fd;
        const data = "ptmx";
        const iov = [_]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
        const message: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        while (true) {
            const result = linux.sendmsg(socket, &message, linux.MSG.NOSIGNAL);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.ConsoleFailed;
                    // Ancillary data is attached to the first byte, even when
                    // a stream write is short. Do not send the rights twice.
                    if (result < data.len and !writeAll(socket, data[result..])) return error.ConsoleFailed;
                    return;
                },
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        }
    }

    pub fn receiveFd(socket: posix.fd_t) libcontainer.Error!posix.fd_t {
        return (try receiveFdOrEof(socket)) orelse error.ConsoleFailed;
    }

    pub fn receiveFdOrEof(socket: posix.fd_t) libcontainer.Error!?posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        var data: [4]u8 = undefined;
        var iov = [_]posix.iovec{.{ .base = &data, .len = data.len }};
        var message: linux.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        const count = while (true) {
            const result = linux.recvmsg(socket, &message, linux.MSG.CMSG_CLOEXEC | linux.MSG.WAITALL);
            switch (linux.errno(result)) {
                .SUCCESS => break result,
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        };
        if (count == 0) return null;
        if (message.controllen < rights_len or rights.header.level != linux.SOL.SOCKET or
            rights.header.type != linux.SCM.RIGHTS or rights.header.len < rights_len)
            return error.ConsoleFailed;
        closeExtraRights(&rights, message.controllen);
        errdefer closeFd(rights.fd);
        if (rights.header.len != rights_len or message.flags & linux.MSG.CTRUNC != 0)
            return error.ConsoleFailed;
        if (count < data.len and !readAll(socket, data[count..])) {
            closeFd(rights.fd);
            return null;
        }
        if (!std.mem.eql(u8, &data, "ptmx")) return error.ConsoleFailed;
        return rights.fd;
    }

    fn closeExtraRights(rights: *const Rights, controllen: usize) void {
        // The aligned control buffer can hold a second fd in its padding.
        // Close all delivered rights, including on truncated/malformed input.
        const bytes = std.mem.asBytes(rights);
        const control_end = @min(controllen, @min(rights.header.len, bytes.len));
        var offset: usize = rights_len;
        while (offset + @sizeOf(posix.fd_t) <= control_end) : (offset += @sizeOf(posix.fd_t)) {
            const extra = std.mem.bytesToValue(posix.fd_t, bytes[offset..][0..@sizeOf(posix.fd_t)]);
            closeFd(extra);
        }
    }
};

pub fn setupConsole(socket: posix.fd_t, mount_console: bool) libcontainer.Error!void {
    const pts = consolePath("/dev/pts", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch
        return error.MissingDevpts;
    defer closeFd(pts);
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(pts), @intFromPtr(&fs)));
    if (statfsType(&fs) != 0x1cd1) return error.MissingDevpts; // DEVPTS_SUPER_MAGIC
    const controller = try consolePath("/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    defer closeFd(controller);
    var unlock: i32 = 0;
    try checkResult(linux.ioctl(controller, linux.T.IOCSPTLCK, @intFromPtr(&unlock)));
    const replica_flags: linux.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
    var replica_path_buffer: [32]u8 = undefined;
    var replica_path: ?[:0]const u8 = null;
    const opened_replica: posix.fd_t = peer: {
        const result = linux.ioctl(controller, linux.T.IOCGPTPEER, @as(u32, @bitCast(replica_flags)));
        switch (linux.errno(result)) {
            .SUCCESS => break :peer @intCast(result),
            .NOTTY, .INVAL, .NOSYS => {
                var number: u32 = undefined;
                try checkResult(linux.ioctl(controller, linux.T.IOCGPTN, @intFromPtr(&number)));
                const path = std.fmt.bufPrintZ(&replica_path_buffer, "/dev/pts/{d}", .{number}) catch return error.ConsoleFailed;
                replica_path = path;
                break :peer try openPath(linux.AT.FDCWD, path, replica_flags);
            },
            else => return error.ConsoleFailed,
        }
    };
    const replica = try consoleAboveStdio(opened_replica);
    defer closeFd(replica);
    if (mount_console) {
        const root = try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root);
        const target = try consoleAboveStdio(try mountDestination(root, "/dev/console", true, true));
        defer closeFd(target);
        bind: {
            const cloned = linux.syscall3(.open_tree, @intCast(replica), @intFromPtr(""), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | linux.AT.EMPTY_PATH);
            if (linux.errno(cloned) != .NOSYS and linux.errno(cloned) != .PERM) {
                try checkResult(cloned);
                const tree: posix.fd_t = @intCast(cloned);
                defer closeFd(tree);
                var flags = std.mem.zeroes(linux.MOVE_MOUNT);
                flags.F_EMPTY_PATH = true;
                flags.T_EMPTY_PATH = true;
                const moved = linux.move_mount(tree, "", target, "", flags);
                if (linux.errno(moved) != .NOSYS and linux.errno(moved) != .PERM) {
                    try checkResult(moved);
                    break :bind;
                }
            }
            // Older kernels and seccomp policies still need procfs for the descriptor paths.
            var source_buffer: [64]u8 = undefined;
            var target_buffer: [64]u8 = undefined;
            try checkResult(linux.mount(replica_path orelse fdPath(&source_buffer, replica), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
        }
    }
    try checkResult(linux.setsid());
    try checkResult(linux.ioctl(replica, linux.T.IOCSCTTY, 0));
    for (0..3) |fd| {
        try checkResult(linux.dup2(replica, @intCast(fd)));
        // dup2(fd, fd) preserves CLOEXEC when stdio was initially closed.
        try checkResult(linux.fcntl(@intCast(fd), linux.F.SETFD, 0));
    }
    try console.sendFd(socket, controller);
}

fn consoleAboveStdio(fd: posix.fd_t) libcontainer.Error!posix.fd_t {
    if (fd > 2) return fd;
    defer closeFd(fd);
    const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
    try checkResult(moved);
    return @intCast(moved);
}

pub fn consolePath(path: [*:0]const u8, flags: linux.O) libcontainer.Error!posix.fd_t {
    return consoleAboveStdio(try openPath(linux.AT.FDCWD, path, flags));
}

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const writeAll = @import("../syscall.zig").writeAll;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const console = @import("../console.zig").console;
const setupConsole = @import("../console.zig").setupConsole;

test "linux SCM_RIGHTS roundtrip preserves a descriptor across forwarding" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer for (sockets) |fd| closeFd(fd);
    const forwarded = try console.socketpair();
    defer for (forwarded) |fd| closeFd(fd);
    const pipe = try makePipe();
    defer for (pipe) |fd| closeFd(fd);
    try console.sendFd(sockets[0], pipe[0]);
    const received = try console.receiveFd(sockets[1]);
    defer closeFd(received);
    try std.testing.expect(linux.fcntl(received, linux.F.GETFD, 0) & linux.FD_CLOEXEC != 0);
    try console.sendFd(forwarded[0], received);
    const final = try console.receiveFd(forwarded[1]);
    defer closeFd(final);
    try std.testing.expect(writeAll(pipe[1], "x"));
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(final, &byte));
    try std.testing.expectEqualStrings("x", &byte);
}

test "linux console receiver rejects a message without descriptor rights and EOF" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer closeFd(sockets[0]);
    try std.testing.expect(writeAll(sockets[1], "ptmx"));
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
    closeFd(sockets[1]);
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
}

test "linux console setup binds its replica to dev console and sends its controller" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const sockets = try console.socketpair();
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(sockets[0]);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        checkResult(linux.mount("tmpfs", "/dev", "tmpfs", linux.MS.NOSUID, 0)) catch linux.exit_group(1);
        checkResult(linux.mkdir("/dev/pts", 0o755)) catch linux.exit_group(1);
        checkResult(linux.mount("devpts", "/dev/pts", "devpts", linux.MS.NOSUID | linux.MS.NOEXEC, @intFromPtr("newinstance,ptmxmode=666,mode=620"))) catch linux.exit_group(1);
        checkResult(linux.symlink("pts/ptmx", "/dev/ptmx")) catch linux.exit_group(1);
        setupConsole(sockets[1], true, null) catch linux.exit_group(1);
        closeFd(sockets[1]);
        var console_stat: linux.Statx = undefined;
        var replica_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(1);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &replica_stat)) catch linux.exit_group(1);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != replica_stat.ino or
            console_stat.dev_major != replica_stat.dev_major or console_stat.dev_minor != replica_stat.dev_minor)
            linux.exit_group(1);
        var session: i32 = undefined;
        for (0..3) |fd| {
            checkResult(linux.ioctl(@intCast(fd), linux.T.IOCGSID, @intFromPtr(&session))) catch linux.exit_group(1);
            if (session != linux.getpid()) linux.exit_group(1);
            if (linux.fcntl(@intCast(fd), linux.F.GETFD, 0) != 0) linux.exit_group(1);
        }
        if (!writeAll(1, "console\n")) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(1);
        linux.exit_group(0);
    }
    closeFd(sockets[1]);
    defer closeFd(sockets[0]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    const controller = try console.receiveFd(sockets[0]);
    defer closeFd(controller);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(controller, &output));
    try std.testing.expectEqualStrings("console\r\n", &output);
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
}

// Static process used by the create/start integration test. Raw syscalls keep
// the checks independent of libc, shell applets, and test-runner initialization.
const std = @import("std");
const builtin = @import("builtin");

pub fn main(init: std.process.Init.Minimal) void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    const expected_nnp = args.next() orelse linux.exit_group(10);
    const mode = args.next() orelse "";
    const docker = std.mem.eql(u8, mode, "docker");
    const nnp = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
    if (linux.errno(nnp) != .SUCCESS or nnp != @as(usize, if (std.mem.eql(u8, expected_nnp, "true")) 1 else 0))
        linux.exit_group(11);
    if (std.mem.eql(u8, mode, "hook")) {
        // The NNP=true filter must wait until startContainer hooks finish.
        const result = linux.syscall3(.mkdirat, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(@as([*:0]const u8, "/tmp/hook")), 0o755);
        const expected: linux.E = if (nnp == 1) .SUCCESS else .PERM;
        linux.exit_group(if (linux.errno(result) == expected) 0 else 18);
    }
    if (linux.errno(linux.syscall1(.personality, 0)) != .SUCCESS) linux.exit_group(12);
    if (linux.errno(linux.syscall1(.personality, 1)) != .PERM) linux.exit_group(13);
    if (!docker) {
        if (linux.errno(linux.syscall3(.mkdirat, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(@as([*:0]const u8, "/tmp/x")), 0o755)) != .PERM)
            linux.exit_group(14);
        if (comptime @hasField(linux.SYS, "mkdir")) {
            if (linux.errno(linux.syscall2(.mkdir, @intFromPtr(@as([*:0]const u8, "/tmp/y")), 0o755)) != .PERM)
                linux.exit_group(15);
        }
    }
    const fd = linux.openat(linux.AT.FDCWD, "/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) linux.exit_group(16);
    var bytes: [4096]u8 = undefined;
    const size = linux.read(@intCast(fd), &bytes, bytes.len);
    if (linux.errno(size) != .SUCCESS or std.mem.indexOf(u8, bytes[0..size], "Seccomp:\t2\n") == null)
        linux.exit_group(17);
    _ = linux.close(@intCast(fd));
    linux.exit_group(0);
}

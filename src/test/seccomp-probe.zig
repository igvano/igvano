// Static process used by lifecycle security tests. Raw syscalls keep
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
    if (std.mem.eql(u8, mode, "runtime-tools") or std.mem.eql(u8, mode, "runtime-tools-hook")) {
        // faccessat2 is above the fixture's native maximum. An unpatched
        // ERRNO filter returns EPERM before the kernel sees this syscall.
        // Like runc, startContainer hooks run filtered whatever NNP is.
        {
            const result = linux.syscall4(.faccessat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(@as([*:0]const u8, "/")), linux.F_OK, 0);
            if (linux.errno(result) != .NOSYS) linux.exit_group(28);
        }
        if (std.mem.eql(u8, mode, "runtime-tools"))
            linux.exit_group(0);
        // A filtered hook cannot call close_range; the hook runner must not
        // need this call.
        const sweep = linux.syscall3(.close_range, 3, 2, 1 << 2);
        linux.exit_group(if (linux.errno(sweep) == .NOSYS) 0 else 29);
    }
    if (std.mem.eql(u8, mode, "apparmor")) {
        const profile = args.next() orelse linux.exit_group(20);
        if (linux.errno(linux.openat(linux.AT.FDCWD, "/tmp/denied", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(21);
        const allowed = linux.openat(linux.AT.FDCWD, "/tmp/allowed", .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(allowed) != .SUCCESS) linux.exit_group(22);
        _ = linux.close(@intCast(allowed));
        const current = linux.openat(linux.AT.FDCWD, "/proc/self/attr/current", .{ .CLOEXEC = true }, 0);
        if (linux.errno(current) != .SUCCESS) linux.exit_group(23);
        var bytes: [512]u8 = undefined;
        const size = linux.read(@intCast(current), &bytes, bytes.len);
        if (linux.errno(size) != .SUCCESS or !std.mem.startsWith(u8, bytes[0..size], profile) or
            !std.mem.eql(u8, bytes[profile.len..size], " (enforce)\n"))
            linux.exit_group(24);
        linux.exit_group(0);
    }
    if (std.mem.eql(u8, mode, "propagation-init")) {
        const delay: linux.timespec = .{ .sec = 1, .nsec = 0 };
        while (true) _ = linux.nanosleep(&delay, null);
    }
    if (std.mem.eql(u8, mode, "propagation-host"))
        linux.exit_group(if (linux.errno(linux.access("/volume/from-host/flag", linux.F_OK)) == .SUCCESS) 0 else 25);
    if (std.mem.eql(u8, mode, "propagation-container")) {
        if (linux.errno(linux.mount("tmpfs", "/volume/from-container", "tmpfs", 0, 0)) != .SUCCESS)
            linux.exit_group(26);
        const flag = linux.openat(linux.AT.FDCWD, "/volume/from-container/flag", .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
        linux.exit_group(if (linux.errno(flag) == .SUCCESS) 0 else 27);
    }
    if (std.mem.eql(u8, mode, "hook")) {
        // Like runc, the filter is on before startContainer hooks, with or
        // without NNP.
        const result = linux.syscall3(.mkdirat, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(@as([*:0]const u8, "/tmp/hook")), 0o755);
        linux.exit_group(if (linux.errno(result) == .PERM) 0 else 18);
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

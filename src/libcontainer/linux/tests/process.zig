const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../../root.zig");
const seccomp = @import("../../seccomp.zig");
const diagnostics = @import("../diagnostic.zig");
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const openPath = @import("../syscall.zig").openPath;
const reportDiagnostic = @import("../diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("../diagnostic.zig").CreateResponse;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const closeExecFrom = @import("../process.zig").closeExecFrom;
const closeFdRange = @import("../process.zig").closeFdRange;
const kernelCapabilities = @import("../process.zig").kernelCapabilities;
const CapabilityHeader = @import("../process.zig").CapabilityHeader;
const runProcess = @import("../process.zig").runProcess;
const applyOomScoreAdj = @import("../process.zig").applyOomScoreAdj;
const applyProcess = @import("../process.zig").applyProcess;
const resolveExecutable = @import("../process.zig").resolveExecutable;
const execResolved = @import("../process.zig").execResolved;
const execProcess = @import("../process.zig").execProcess;
const runInit = @import("../create.zig").runInit;

test "linux capability preparation skips bits unsupported by the running kernel" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), 63, 0, 0, 0)) != .INVAL)
        return error.SkipZigTest;
    const future = @as(u64, 1) << 63;
    try std.testing.expectEqual(libcontainer.Capabilities{
        .bounding = 1,
        .effective = 1,
        .permitted = 1,
        .inheritable = 1,
        .ambient = 1,
    }, try kernelCapabilities(.{
        .bounding = future | 1,
        .effective = future | 1,
        .permitted = future | 1,
        .inheritable = future | 1,
        .ambient = future | 1,
    }));
}

test "linux exec searches the process PATH and preserves explicit paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct {
        executable: [*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        cwd: [:0]const u8 = "/",
        status: u32 = 0,
    }{
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:/bin:/usr/bin"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"}, .status = 1 << 8 },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{} },
        .{ .executable = "/bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH="}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=:/does-not-exist"}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:"}, .cwd = "/bin" },
    };
    for (cases) |case| {
        const argv = [_:null]?[*:0]const u8{ case.executable, "-c", "exit 0" };
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.chdir(case.cwd)) catch linux.exit_group(2);
            execProcess(&argv, case.envp) catch linux.exit_group(1);
        }
        try std.testing.expectEqual(case.status, try waitChild(pid));
    }
}

test "linux exec failure diagnostics name the errno" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const cases = [_]struct { name: []const u8, data: []const u8, mode: posix.mode_t, expected: []const u8 }{
        .{ .name = "denied", .data = "exit 0\n", .mode = 0o644, .expected = "permission denied" },
        .{ .name = "bad-format", .data = "not an executable\n", .mode = 0o755, .expected = "exec format error" },
        .{ .name = "missing-interpreter", .data = "#!/igvano-no-such-interpreter\n", .mode = 0o755, .expected = "no such file or directory" },
    };
    const envp = [_:null]?[*:0]const u8{};
    for (cases) |case| {
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = case.name, .data = case.data, .flags = .{ .permissions = .fromMode(case.mode) } });
        const path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/{s}", .{ base, case.name }, 0);
        defer std.testing.allocator.free(path);
        const argv = [_:null]?[*:0]const u8{path};
        try std.testing.expectError(error.ExecFailed, execResolved(path, &argv, &envp));
        const expected = try std.fmt.allocPrint(std.testing.allocator, "exec {s}: {s}", .{ path, case.expected });
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
    }
}

test "linux init rejects missing directory and non-executable args before create readiness" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "no-execute", .data = "exit 0\n", .flags = .{ .permissions = .fromMode(0o644) } });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    const rootfs_z = try std.testing.allocator.dupeZ(u8, rootfs);
    defer std.testing.allocator.free(rootfs_z);
    for ([_][*:0]const u8{ "igvano-no-such-binary", "/igvano-no-such-binary", "/directory", "/no-execute" }) |arg0| {
        const process: libcontainer.Process = .{ .args = &.{std.mem.span(arg0)}, .cwd = "/", .uid = 0, .gid = 0 };
        const argv = [_:null]?[*:0]const u8{arg0};
        const envp = [_:null]?[*:0]const u8{"PATH=/bin:/usr/bin"};
        const ready = try makePipe();
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(ready[0]);
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(2);
            runInit(process, .{}, false, null, &.{}, linux.CLONE.NEWNS, rootfs_z, &.{}, &.{}, &.{}, "/", -1, -1, &argv, &envp, ready[1], .{}, &.{}, "", null, null);
        }
        closeFd(ready[1]);
        var response: CreateResponse = .{};
        const received = readAll(ready[0], std.mem.asBytes(&response));
        const status = try waitChild(pid);
        try std.testing.expect(received);
        try std.testing.expectEqual(@as(u32, 1 << 8), status);
        try std.testing.expectEqual(error.ExecFailed, response.failureError().?);
        const expected = try std.fmt.allocPrint(std.testing.allocator, "exec: \"{s}\": executable file not found in $PATH", .{std.mem.span(arg0)});
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
    }
}

test "linux init applies uid gid and optional supplementary groups before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const cases = [_]struct { process: libcontainer.Process, expected: []const u8 }{
        .{ .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .uid = 1000, .gid = 1000 }, .expected = "1000\n1000\n1000\n" },
        .{ .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .uid = 1000, .gid = 1000, .additional_gids = &.{} }, .expected = "1000\n1000\n1000\n" },
        .{ .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .uid = 1000, .gid = 1000, .additional_gids = &.{ 1001, 1002 } }, .expected = "1000\n1000\n1000 1001 1002\n" },
    };
    for (cases) |case| {
        const argv = [_:null]?[*:0]const u8{ "sh", "-c", "id -u; id -g; id -G" };
        const envp = [_:null]?[*:0]const u8{"PATH=/does-not-exist:/usr/bin:/bin"};
        const output = try makePipe();
        defer closeFd(output[0]);
        const ready = makePipe() catch |err| {
            closeFd(output[1]);
            return err;
        };
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(output[1]);
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(output[0]);
            closeFd(ready[0]);
            checkResult(linux.setgroups(1, &.{42})) catch linux.exit_group(1);
            checkResult(linux.dup2(output[1], posix.STDOUT_FILENO)) catch linux.exit_group(1);
            closeFd(output[1]);
            applyProcess(case.process, null, &.{}) catch linux.exit_group(1);
            var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const executable = resolveExecutable(&argv, &envp, &executable_buffer) catch linux.exit_group(1);
            runProcess(case.process, executable, &argv, &envp, null) catch linux.exit_group(1);
        }
        closeFd(output[1]);
        closeFd(ready[1]);
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        var bytes: [64]u8 = undefined;
        const result = bytes[0..case.expected.len];
        try std.testing.expect(readAll(output[0], result));
        try std.testing.expectEqualStrings(case.expected, result);
    }
}

test "linux init applies oomScoreAdj before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(1);
        execProcess(&argv, &envp) catch linux.exit_group(1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init preserves inherited oomScoreAdj when unset" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(2);
        const child = forkProcess() catch linux.exit_group(2);
        if (child == 0) {
            applyOomScoreAdj(proc_dir, null) catch linux.exit_group(1);
            execProcess(&argv, &envp) catch linux.exit_group(1);
        }
        const status = waitChild(child) catch linux.exit_group(2);
        linux.exit_group(if (status == 0) 0 else 1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init exits nonzero instead of exec for out of range oomScoreAdj" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    for ([_]i32{ 1001, -1001 }) |value| {
        const pid = try forkProcess();
        if (pid == 0) {
            applyOomScoreAdj(proc_dir, value) catch linux.exit_group(1);
            execProcess(&argv, &envp) catch linux.exit_group(1);
        }
        try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
    }
}

test "linux init exits nonzero instead of exec when it cannot apply process user" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const process: libcontainer.Process = .{ .args = &.{ "/bin/sh", "-c", "exit 0" }, .cwd = "/", .uid = 0, .gid = 0 };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        if (linux.geteuid() == 0) {
            checkResult(linux.setgid(1000)) catch linux.exit_group(2);
            checkResult(linux.setuid(1000)) catch linux.exit_group(2);
        }
        applyProcess(process, null, &.{}) catch linux.exit_group(1);
        runProcess(process, argv[0], &argv, &envp, null) catch linux.exit_group(1);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
}

test "linux init marks inherited descriptors CLOEXEC and sets noNewPrivileges" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const command = "test ! -e /proc/self/fd/200 && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status";
    const process: libcontainer.Process = .{
        .args = &.{ "/bin/sh", "-c", command },
        .cwd = "/",
        .uid = 0,
        .gid = 0,
        .no_new_privileges = true,
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        checkResult(linux.dup2(ready[1], 200)) catch linux.exit_group(2);
        closeExecFrom(3, null) catch linux.exit_group(1);
        applyProcess(process, null, &.{}) catch linux.exit_group(1);
        runProcess(process, argv[0], &argv, &envp, null) catch linux.exit_group(1);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux descriptor sweep falls back when close_range returns ENOSYS EPERM or EINVAL" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const arch = seccomp.Arch.native() orelse return error.SkipZigTest;
    const pipe = try makePipe();
    defer for (pipe) |fd| closeFd(fd);
    for ([_]linux.E{ .NOSYS, .PERM, .INVAL }) |denied| {
        const program = try seccomp.compile(std.testing.allocator, .{
            .default_action = .allow,
            .architectures = &.{arch},
            .rules = &.{.{ .arch = arch, .number = @intFromEnum(linux.SYS.close_range), .action = .errno, .errno_ret = @intCast(@intFromEnum(denied)) }},
        }, arch);
        defer std.testing.allocator.free(program.filters);
        for ([_]bool{ false, true }) |pinned| {
            const pid = try forkProcess();
            if (pid == 0) {
                // self/fd captures the calling task, so pin it after fork.
                const directory: ?posix.fd_t = if (pinned)
                    openPath(linux.AT.FDCWD, "/proc/self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1)
                else
                    null;
                checkResult(linux.dup2(pipe[1], 99)) catch linux.exit_group(1);
                checkResult(linux.dup2(pipe[1], 200)) catch linux.exit_group(1);
                checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(2);
                if (seccomp.install(program) != .SUCCESS) linux.exit_group(3);
                closeExecFrom(100, directory) catch linux.exit_group(4);
                const low_flags = linux.fcntl(99, linux.F.GETFD, 0);
                const high_flags = linux.fcntl(200, linux.F.GETFD, 0);
                if (low_flags != 0 or high_flags != linux.FD_CLOEXEC) {
                    reportDiagnostic("fallback {s}, pinned={}: fd99={d}, fd200={d}", .{ @tagName(denied), directory != null, low_flags, high_flags });
                    linux.exit_group(5);
                }
                // Exec's host-descriptor closing must also work on old kernels.
                closeFdRange(200, 200, false, directory) catch linux.exit_group(6);
                if (linux.errno(linux.fcntl(200, linux.F.GETFD, 0)) != .BADF) linux.exit_group(7);
                linux.exit_group(0);
            }
            try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        }
    }
}

test "linux process settings apply rlimits without changing inherited capabilities" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    var original: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.NOFILE, &original));
    const hard = @min(original.max, 1024);
    const soft = @min(hard, 512);
    const process: libcontainer.Process = .{
        .args = &.{"/bin/true"},
        .cwd = "/",
        .uid = linux.geteuid(),
        .gid = linux.getegid(),
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, null, &.{.{ .resource = .NOFILE, .hard = hard, .soft = soft }}) catch linux.exit_group(1);
        var actual: linux.rlimit = undefined;
        checkResult(linux.getrlimit(.NOFILE, &actual)) catch linux.exit_group(2);
        if (actual.cur != soft or actual.max != hard) linux.exit_group(3);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(4);
        for (inherited, caps) |before, after| {
            if (before.effective != after.effective or before.permitted != after.permitted or
                before.inheritable != after.inheritable) linux.exit_group(5);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux process settings retain configured capabilities across nonzero uid and exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) | (@as(u32, 1) << linux.CAP.SETPCAP) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (inherited[0].effective & required != required) return error.SkipZigTest;
    if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.CHOWN, 0, 0, 0) != 1)
        return error.SkipZigTest;
    const command = "test \"$(id -u)\" = 1000 && grep -q '^CapAmb:[[:space:]]*0000000000000001$' /proc/self/status";
    const process: libcontainer.Process = .{
        .args = &.{ "/bin/sh", "-c", command },
        .cwd = "/",
        .uid = 1000,
        .gid = 1000,
        .no_new_privileges = true,
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, .{
            .bounding = 1,
            .permitted = 1,
            .effective = 1,
            .inheritable = 1,
            .ambient = 1,
        }, &.{}) catch linux.exit_group(1);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(2);
        if (caps[0].effective != 1 or caps[0].permitted != 1 or caps[0].inheritable != 1 or
            caps[1].effective != 0 or caps[1].permitted != 0 or caps[1].inheritable != 0) linux.exit_group(3);
        if (linux.prctl(@intFromEnum(linux.PR.GET_KEEPCAPS), 0, 0, 0, 0) != 0) linux.exit_group(4);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SETUID, 0, 0, 0) != 0) linux.exit_group(5);
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_IS_SET, linux.CAP.CHOWN, 0, 0) != 1)
            linux.exit_group(6);
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
        const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
        execProcess(&argv, &envp) catch linux.exit_group(1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

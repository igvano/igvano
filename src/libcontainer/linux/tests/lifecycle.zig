const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../root.zig").Backend;
const diagnostics = @import("../diagnostic.zig");
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const writeAll = @import("../syscall.zig").writeAll;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const readProcStat = @import("../proc.zig").readProcStat;
const applyProcess = @import("../process.zig").applyProcess;
const LinuxBackend = @import("../../linux.zig").LinuxBackend;

test "linux update requires a persisted cgroup path" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    try std.testing.expectError(error.Unsupported, backend.update(.{
        .id = "example",
        .pid = 1,
        .starttime = "1",
    }, .{ .memory = .{ .limit = 67108864 } }));
    try std.testing.expect(std.mem.indexOf(u8, backend.diagnostic().?, "no cgroup") != null);
}

test "linux backend is unavailable on other platforms" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234, .starttime = "12345" };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.NotImplemented, backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = "/tmp/bundle/rootfs",
            .exec_fifo = "/tmp/containers/example/exec.fifo",
            .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .uid = 0, .gid = 0 },
        }));
    }
    try std.testing.expectError(error.NotImplemented, backend.alive(handle));
    try std.testing.expectError(error.NotImplemented, backend.kill(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.killAll(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.pids(handle, std.testing.allocator));
    try std.testing.expectError(error.NotImplemented, backend.freeze(handle));
    try std.testing.expectError(error.NotImplemented, backend.thaw(handle));
    try std.testing.expectError(error.NotImplemented, backend.frozen(handle));
    try std.testing.expectError(error.NotImplemented, backend.delete(handle));
}

test "linux liveness and signaling work with a handle loaded by a new backend" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    defer closeFd(pipe[1]);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(pipe[1]);
        var byte: [1]u8 = undefined;
        _ = readAll(pipe[0], &byte);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var stat_buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &stat_buffer);
    const handle: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(try backend.alive(handle));
    const reused: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = "mismatched" };
    try std.testing.expect(!try backend.alive(reused));
    const reused_pids = try backend.pids(reused, std.testing.allocator);
    defer std.testing.allocator.free(reused_pids);
    try std.testing.expectEqual(@as(usize, 0), reused_pids.len);
    const pids = try backend.pids(handle, std.testing.allocator);
    defer std.testing.allocator.free(pids);
    try std.testing.expectEqualSlices(i32, &.{pid}, pids);
    try std.testing.expect(!try backend.frozen(handle));
    try std.testing.expectError(error.Unsupported, backend.freeze(handle));
    try std.testing.expect(std.mem.indexOf(u8, backend.diagnostic().?, "no cgroup freezer") != null);
    try std.testing.expectError(error.Unsupported, backend.thaw(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(reused, 9));
    try backend.killAll(reused, 9);
    try std.testing.expect(try backend.alive(handle));
    try backend.kill(handle, 0);
    try backend.killAll(handle, 0);
    try std.testing.expectError(error.InvalidProcess, backend.kill(.{ .id = "invalid", .pid = 0, .starttime = "" }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.killAll(.{ .id = "invalid", .pid = 0, .starttime = "" }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.alive(.{ .id = "invalid", .pid = -1, .starttime = "" }));
    try std.testing.expectError(error.KillFailed, backend.kill(handle, 65));
    try std.testing.expectError(error.KillFailed, backend.killAll(handle, 65));
    try backend.killAll(handle, 9);
    _ = try waitChild(pid);
    reaped = true;
    try std.testing.expect(!try backend.alive(handle));
    const stopped_pids = try backend.pids(handle, std.testing.allocator);
    defer std.testing.allocator.free(stopped_pids);
    try std.testing.expectEqual(@as(usize, 0), stopped_pids.len);
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
    try backend.killAll(handle, 15);
    try backend.delete(handle);
}

test "linux liveness rejects an unreaped zombie even though kill zero succeeds" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pid = try forkProcess();
    if (pid == 0) linux.exit_group(0);
    defer _ = waitChild(pid) catch {};
    var info: linux.siginfo_t = undefined;
    while (true) {
        switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT, null))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, @enumFromInt(0))));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &buffer);
    const handle: Backend.Handle = .{ .id = "zombie", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(!try backend.alive(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
}

test "linux create rejects hostname without UTS isolation and terminals without a console" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .hostname = "must-not-change-the-host",
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    options.hostname = null;
    options.process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .terminal = true, .uid = 0, .gid = 0 };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
}

test "linux create rejects propagation without mount isolation before acquiring resources" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .rootfs_propagation = linux.MS.PRIVATE | linux.MS.REC,
    }));
}

test "linux inherited mount namespace rejects the runtime root before any mount" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    for ([_][]const u8{ "/", "/./", "/proc/self/root" }) |rootfs| {
        try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            // An invalid cgroup path prevents mount setup if this guard regresses.
            .cgroup_path = "",
        }));
    }
}

test "linux create rejects joining the runtime's own mount namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .namespaces = &.{.{ .kind = .mount, .path = "/proc/self/ns/mnt" }},
        // An invalid cgroup path prevents mount setup if the guard regresses.
        .cgroup_path = "",
    }));
}

test "linux create rejects relative process cwd" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // These paths exist under rootfs, so existence alone cannot validate cwd.
    for ([_][]const u8{ "rootfs", ".", "" }) |cwd| {
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const result = backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            .process = .{ .args = &.{"/bin/sh"}, .cwd = cwd, .uid = 0, .gid = 0 },
        });
        if (result) |handle| {
            defer std.testing.allocator.free(handle.starttime);
            // Clean up if a regression incorrectly creates an init.
            backend.kill(handle, 9) catch {};
        } else |_| {}
        try std.testing.expectError(
            if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
            result,
        );
    }
}

test "linux create rejects empty process args" {
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .process = .{ .args = &.{}, .cwd = "/", .uid = 0, .gid = 0 },
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
        result,
    );
}

test "linux create rejects a cwd missing from the resolved rootfs" {
    if (comptime builtin.os.tag == .linux) {
        try requireTestMountNamespace();
        const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
        if (cgroup_root.mode != .unified) {
            closeFd(cgroup_root.fd);
            return error.SkipZigTest;
        }
        closeFd(cgroup_root.fd);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // /proc exists on the Linux host, but not inside this empty rootfs.
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = rootfs,
        .exec_fifo = "/dev/null",
        .namespaces = &.{.{ .kind = .mount }},
        .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/proc", .uid = 0, .gid = 0 },
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        // Clean up if a regression incorrectly creates an init.
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.CreateFailed else error.NotImplemented,
        result,
    );
}

test "linux create reports the frontend ambient capability validation error" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.AmbientCapabilitiesRequirePermittedAndInheritable, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .capabilities = .{ .ambient = 1 },
    }));
}

test "linux init reopens its root-owned pinned FIFO only for writing after dropping uid" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fifo_fd);
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
        closeFd(proc_dir);
        var buffer: [32]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{d}", .{fifo_fd}) catch unreachable;
        checkResult(linux.fchmodat(fd_dir, name, 0o622)) catch linux.exit_group(2);
        applyProcess(.{
            .args = &.{"/bin/true"},
            .cwd = "/",
            .uid = 1000,
            .gid = 1000,
        }, null, &.{}) catch linux.exit_group(3);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(7);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(8);
        if (!writeAll(ready[1], &.{1})) linux.exit_group(4);
        const fd = openPath(fd_dir, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch linux.exit_group(5);
        if (!writeAll(fd, &.{1})) linux.exit_group(6);
        linux.exit_group(0);
    }
    closeFd(ready[1]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(ready[0], &byte));
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    const status = try waitChild(pid);
    reaped = true;
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "linux create reports child setup failures without leaving an init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const missing_cwd = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "missing" });
    defer std.testing.allocator.free(missing_cwd);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    var implementation: LinuxBackend = .{};
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = fifo,
        .namespaces = &.{.{ .kind = .mount }},
        .process = .{ .args = &.{"/bin/sh"}, .cwd = missing_cwd, .uid = 0, .gid = 0 },
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    options.process.?.cwd = "/";
    // Linux rejects NOFILE above fs.nr_open even with CAP_SYS_RESOURCE.
    options.rlimits = &.{.{ .resource = .NOFILE, .hard = std.math.maxInt(u64), .soft = 0 }};
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    options.rlimits = &.{};
    for ([_]i32{ 1001, -1001 }) |value| {
        options.oom_score_adj = value;
        try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    }
    options.oom_score_adj = null;
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    options.rootfs = rootfs;
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/no-execute",
        .data = "exit 0\n",
        .flags = .{ .permissions = .fromMode(0o644) },
    });
    for ([_][]const u8{ "igvano-no-such-binary", "/igvano-no-such-binary", "/", "/no-execute" }) |arg0| {
        options.process.?.args = &.{arg0};
        try std.testing.expectError(error.ExecFailed, implementation.backend().create(options));
        const expected = try std.fmt.allocPrint(std.testing.allocator, "exec: \"{s}\": executable file not found in $PATH", .{arg0});
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, implementation.backend().diagnostic().?);
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    }
}

test "linux create retains the init child's rootfs diagnostic" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(allocator, "igvano-diagnostic-test-{d}", .{linux.getpid()});
    defer allocator.free(cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fs.path.join(allocator, &.{ absolute, "rootfs" });
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    defer diagnostics.last_diagnostic_len = 0;
    defer backend.delete(.{ .id = "diagnostic", .pid = 0, .starttime = "", .cgroup_path = cgroup_path }) catch {};
    var options: Backend.CreateOptions = .{
        .allocator = allocator,
        .id = "diagnostic",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .namespaces = &.{.{ .kind = .mount }},
        .cgroup_path = cgroup_path,
        .mounts = &.{.{
            .destination = "/proc",
            .source = "proc",
            .type = "igvano-missing-filesystem",
            .flags = 0,
            .propagation = 0,
            .data = "",
        }},
    };
    try std.testing.expectError(error.CreateFailed, backend.create(options));
    try std.testing.expectEqualStrings(
        "cannot prepare rootfs: mount /proc (igvano-missing-filesystem): CreateFailed",
        backend.diagnostic().?,
    );
    // Hooks run after the first ready response; failure must survive cleanup
    // after the runtime has already received the init's PID.
    options.mounts = &.{};
    options.create_hooks = &.{.{ .path = "/igvano-missing-create-hook" }};
    try std.testing.expectError(error.HookFailed, backend.create(options));
    try std.testing.expectEqualStrings("error running hook #0: exit status 1, stdout: , stderr: ", backend.diagnostic().?);
}

test "linux create accepts a prepared executable or process-less rootfs and returns a live blocked init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    const parent_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/parent-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(parent_marker);
    const child_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/child-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(child_marker);
    const Callback = struct {
        parent_marker: [:0]const u8,
        child_marker: [:0]const u8,
        pid: i32 = 0,
        fail: bool = false,

        fn run(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.pid = handle.pid;
            if (linux.errno(linux.access(self.child_marker, linux.F_OK)) != .NOENT)
                return error.InvalidConfig;
            if (self.fail) return error.HookFailed;
            const fd = try openPath(linux.AT.FDCWD, self.parent_marker, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true });
            defer closeFd(fd);
        }
    };
    const processes = [_]?Backend.Process{
        .{ .args = &.{"/init"}, .cwd = "/", .uid = 0, .gid = 0 },
        null,
    };
    for (processes) |process| {
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        var callback: Callback = .{ .parent_marker = parent_marker, .child_marker = child_marker, .fail = true };
        const options: Backend.CreateOptions = .{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .process = process,
            .namespaces = if (process != null) &.{ .{ .kind = .mount }, .{ .kind = .cgroup } } else &.{.{ .kind = .mount }},
            .cgroup_path = cgroup_path,
            .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
            .device_symlinks = &.{
                .{ .path = "/dev/fd", .target = "/proc/self/fd" },
                .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
                .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
                .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
            },
            .on_create = .{ .ptr = &callback, .run = Callback.run },
            .create_hooks = &.{.{
                .path = "/bin/sh",
                // The host shell must remain reachable until this hook finishes.
                .args = &.{ "sh", "-c", "test -e \"$1\" && printf child > \"$2\"", "sh", parent_marker, child_marker },
                .timeout_seconds = 2,
            }},
        };
        try std.testing.expectError(error.HookFailed, backend.create(options));
        try std.testing.expectEqual(linux.E.SRCH, linux.errno(linux.kill(callback.pid, @enumFromInt(0))));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "child-hook", .{}));
        callback.fail = false;
        const handle = try backend.create(options);
        defer std.testing.allocator.free(handle.starttime);
        defer {
            backend.kill(handle, 9) catch {};
            backend.delete(handle) catch {};
        }
        try std.testing.expect(handle.pid > 0);
        try std.testing.expectEqual(handle.pid, callback.pid);
        const child_output = try tmp.dir.readFileAlloc(std.testing.io, "child-hook", std.testing.allocator, .limited(16));
        defer std.testing.allocator.free(child_output);
        try std.testing.expectEqualStrings("child", child_output);
        try tmp.dir.deleteFile(std.testing.io, "parent-hook");
        try tmp.dir.deleteFile(std.testing.io, "child-hook");
        try std.testing.expectEqualStrings("example", handle.id);
        try std.testing.expect(handle.starttime.len != 0);
        try std.testing.expect(try backend.alive(handle));
        const null_device = try tmp.dir.statFile(std.testing.io, "rootfs/dev/null", .{});
        try std.testing.expectEqual(std.Io.File.Kind.character_device, null_device.kind);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(handle.pid, @enumFromInt(0))));
        const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
        try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
        if (process != null) {
            var path_buffer: [64]u8 = undefined;
            const namespace_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/cgroup", .{handle.pid}) catch unreachable;
            const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
            defer closeFd(namespace);
            const membership_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/cgroup", .{handle.pid}) catch unreachable;
            // Read init's membership from its cgroup namespace without changing
            // the test runner's namespace or needing /proc in the empty rootfs.
            const checker = try forkProcess();
            if (checker == 0) {
                checkResult(linux.setns(namespace, linux.CLONE.NEWCGROUP)) catch linux.exit_group(1);
                const membership = openPath(linux.AT.FDCWD, membership_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(1);
                var bytes: [5]u8 = undefined;
                if (!readAll(membership, &bytes)) linux.exit_group(1);
                linux.exit_group(if (std.mem.eql(u8, &bytes, "0::/\n")) 0 else 1);
            }
            try std.testing.expectEqual(@as(u32, 0), try waitChild(checker));
        }
        try backend.kill(handle, 9);
        try backend.delete(handle);
        try backend.delete(handle);
    }
}

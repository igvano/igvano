const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../../backend.zig").Backend;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const validateNamespaceFd = @import("../namespaces.zig").validateNamespaceFd;
const mappedRootID = @import("../namespaces.zig").mappedRootID;
const validateJoinedMappings = @import("../namespaces.zig").validateJoinedMappings;
const joinedUserNamespaceMappings = @import("../namespaces.zig").joinedUserNamespaceMappings;
const createMountUserNamespace = @import("../namespaces.zig").createMountUserNamespace;
const CapabilityHeader = @import("../process.zig").CapabilityHeader;
const LinuxBackend = @import("../../linux.zig").LinuxBackend;

test "linux namespace descriptors reject a mismatched configured type" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const fd = try openPath(linux.AT.FDCWD, "/proc/self/ns/net", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(fd);
    // Kernels without NS_GET_NSTYPE cannot exercise the type comparison.
    if (linux.errno(linux.ioctl(fd, linux.IOCTL.IO(0xb7, 3), 0)) == .NOTTY) return error.SkipZigTest;
    try validateNamespaceFd(fd, linux.CLONE.NEWNET);
    try std.testing.expectError(error.InvalidConfig, validateNamespaceFd(fd, linux.CLONE.NEWUTS));
}

test "linux joined user namespace helper reads host mappings from a pinned namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const uid: []const Backend.IDMapping = &.{
        .{ .container_id = 20, .host_id = 200000, .size = 2 },
        .{ .container_id = 0, .host_id = 100000, .size = 10 },
    };
    const gid: []const Backend.IDMapping = &.{
        .{ .container_id = 0, .host_id = 300000, .size = 10 },
        .{ .container_id = 20, .host_id = 400000, .size = 2 },
    };
    const fd = createMountUserNamespace(std.testing.allocator, .{ .uid = uid, .gid = gid }) catch |err| switch (err) {
        error.PermissionDenied, error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    defer closeFd(fd);
    const actual = try joinedUserNamespaceMappings(std.testing.allocator, fd);
    defer std.testing.allocator.free(actual.uid);
    defer std.testing.allocator.free(actual.gid);
    try validateJoinedMappings(std.testing.allocator, actual, .{ .uid = uid, .gid = gid });
    try std.testing.expectEqual(@as(u32, 100000), try mappedRootID(actual.uid));
    try std.testing.expectEqual(@as(u32, 300000), try mappedRootID(actual.gid));
}

test "linux mapped init acknowledges start without path access to its private state directory" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var caps: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (caps[0].effective & required != required) return error.SkipZigTest;
    const namespace_probe = try forkProcess();
    if (namespace_probe == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(namespace_probe) != 0) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-private-fifo-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "state", .fromMode(0o700));
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/state/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = std.testing.allocator,
        .id = "private",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .namespaces = &.{ .{ .kind = .user }, .{ .kind = .mount }, .{ .kind = .pid } },
        .uid_mappings = &.{.{ .container_id = 0, .host_id = 100000, .size = 2 }},
        .gid_mappings = &.{.{ .container_id = 0, .host_id = 200000, .size = 2 }},
        .process = .{ .args = &.{"/init"}, .cwd = "/", .uid = 1, .gid = 1 },
        .cgroup_path = cgroup_path,
    });
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    const stat = try tmp.dir.statFile(std.testing.io, "state", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o700), stat.permissions.toMode() & 0o7777);
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll_fds = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll_fds, 1, 2000));
    try std.testing.expect(poll_fds[0].revents & linux.POLL.IN != 0);
    var acknowledgement: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &acknowledgement));
    try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
}

test "linux mapped create installs maps outside init and cleans up rejected maps" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const ProcFile = struct {
        fn read(path: []const u8, limit: std.Io.Limit) ![]u8 {
            const file = try std.Io.Dir.cwd().openFile(std.testing.io, path, .{});
            defer file.close(std.testing.io);
            // Proc files report size zero; force reads through EOF.
            var reader = file.readerStreaming(std.testing.io, &.{});
            return reader.interface.allocRemaining(std.testing.allocator, limit);
        }
    };
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var caps: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (caps[0].effective & required != required) return error.SkipZigTest;
    const namespace_probe = try forkProcess();
    if (namespace_probe == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(namespace_probe) != 0) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-mapped-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "rootfs/dev", .default_dir);
    // Mapped root can read the sources, but cannot search their host-only ancestor.
    try tmp.dir.createDir(std.testing.io, "priv", .fromMode(0o700));
    try checkResult(linux.fchownat(tmp.dir.handle, "priv", 0, 0, 0));
    try tmp.dir.createDir(std.testing.io, "priv/dir", .fromMode(0o755));
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "priv/dir/content",
        .data = "private bind source\n",
        .flags = .{ .permissions = .fromMode(0o644) },
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const bind_dir = try std.fs.path.join(std.testing.allocator, &.{ absolute, "priv/dir" });
    defer std.testing.allocator.free(bind_dir);
    const bind_file = try std.fs.path.join(std.testing.allocator, &.{ bind_dir, "content" });
    defer std.testing.allocator.free(bind_file);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "mapped",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .readonly_rootfs = true,
        .namespaces = &.{ .{ .kind = .user }, .{ .kind = .mount }, .{ .kind = .pid } },
        // Distinct container ranges with overlapping host ranges: the
        // kernel rejects uid_map after gid_map is written.
        .uid_mappings = &.{
            .{ .container_id = 0, .host_id = 100000, .size = 2 },
            .{ .container_id = 2, .host_id = 100001, .size = 1 },
        },
        .gid_mappings = &.{.{ .container_id = 0, .host_id = 200000, .size = 10 }},
        .process = .{ .args = &.{"/init"}, .cwd = "/", .uid = 0, .gid = 0, .additional_gids = &.{ 1, 2 } },
        // Creating /dev/pts on the namespace-owned tmpfs needs mapped
        // fsuid/fsgid; unmapped host-root would fail mkdirat with EOVERFLOW.
        .mounts = &.{
            .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/pts", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/host-null", .source = "/dev/null", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
            .{ .destination = "/dev/bind-file", .source = bind_file, .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" },
            .{ .destination = "/dev/bind-dir", .source = bind_dir, .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" },
        },
        .devices = &.{
            .{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 },
            .{ .path = "/dev/zero", .kind = .character, .major = 1, .minor = 5 },
            .{ .path = "/dev/pipe", .kind = .fifo, .mode = 0o620, .uid = 1, .gid = 2 },
        },
        .oom_score_adj = 500,
        .device_symlinks = &.{
            .{ .path = "/dev/fd", .target = "/proc/self/fd" },
            .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
            .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
            .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
        },
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    options.uid_mappings = &.{.{ .container_id = 0, .host_id = 100000, .size = 10 }};
    const handle = try backend.create(options);
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    try std.testing.expect(try backend.alive(handle));
    for ([_][]const u8{ "dev/bind-file", "dev/bind-dir/content" }) |destination| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/root/{s}", .{ handle.pid, destination });
        defer std.testing.allocator.free(path);
        const content = try ProcFile.read(path, .limited(64));
        defer std.testing.allocator.free(content);
        try std.testing.expectEqualStrings("private bind source\n", content);
    }
    const oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{handle.pid});
    defer std.testing.allocator.free(oom_path);
    const oom_score_adj = try ProcFile.read(oom_path, .limited(32));
    defer std.testing.allocator.free(oom_score_adj);
    try std.testing.expectEqualStrings("500\n", oom_score_adj);
    for ([_]struct { name: []const u8, tokens: []const []const u8 }{
        .{ .name = "uid_map", .tokens = &.{ "0", "100000", "10" } },
        .{ .name = "gid_map", .tokens = &.{ "0", "200000", "10" } },
        .{ .name = "setgroups", .tokens = &.{"allow"} },
    }) |expected| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/{s}", .{ handle.pid, expected.name });
        defer std.testing.allocator.free(path);
        const text = try ProcFile.read(path, .limited(4096));
        defer std.testing.allocator.free(text);
        var tokens = std.mem.tokenizeAny(u8, text, " \t\n");
        for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
        try std.testing.expect(tokens.next() == null);
    }
    const status_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/status", .{handle.pid});
    defer std.testing.allocator.free(status_path);
    const status = try ProcFile.read(status_path, .limited(16384));
    defer std.testing.allocator.free(status);
    for ([_]struct { prefix: []const u8, tokens: []const []const u8 }{
        .{ .prefix = "Uid:", .tokens = &.{ "100000", "100000", "100000", "100000" } },
        .{ .prefix = "Gid:", .tokens = &.{ "200000", "200000", "200000", "200000" } },
        .{ .prefix = "Groups:", .tokens = &.{ "200001", "200002" } },
    }) |expected| {
        var lines = std.mem.tokenizeScalar(u8, status, '\n');
        var found = false;
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, expected.prefix)) continue;
            var tokens = std.mem.tokenizeAny(u8, line[expected.prefix.len..], " \t");
            for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
            try std.testing.expect(tokens.next() == null);
            found = true;
            break;
        }
        try std.testing.expect(found);
    }
    const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
    for ([_]struct { with_mappings: bool, uid: u32 }{
        .{ .with_mappings = true, .uid = 0 },
        .{ .with_mappings = false, .uid = 0 },
        .{ .with_mappings = true, .uid = 1 },
        .{ .with_mappings = false, .uid = 1 },
    }) |case| {
        const with_mappings = case.with_mappings;
        // Reuse this mapped user namespace while creating fresh mount/PID
        // namespaces. Root's host UID differs from the runtime's UID.
        const user_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/ns/user", .{handle.pid});
        defer std.testing.allocator.free(user_path);
        const joined_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/joined-{s}-{d}.fifo", .{ absolute, if (with_mappings) "mapped" else "unmapped", case.uid }, 0);
        defer std.testing.allocator.free(joined_fifo);
        try checkResult(linux.mknod(joined_fifo, linux.S.IFIFO | 0o600, 0));
        const joined_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-joined-{s}-{d}", .{ cgroup_path, if (with_mappings) "mapped" else "unmapped", case.uid });
        defer std.testing.allocator.free(joined_cgroup);
        var joined_options = options;
        joined_options.namespaces = &.{ .{ .kind = .mount }, .{ .kind = .user, .path = user_path }, .{ .kind = .pid } };
        joined_options.process.?.uid = case.uid;
        if (!with_mappings) {
            joined_options.uid_mappings = &.{};
            joined_options.gid_mappings = &.{};
        }
        joined_options.id = "joined";
        joined_options.exec_fifo = joined_fifo;
        joined_options.cgroup_path = joined_cgroup;
        if (with_mappings) {
            joined_options.uid_mappings = &.{.{ .container_id = 0, .host_id = 100001, .size = 10 }};
            try std.testing.expectError(error.InvalidConfig, backend.create(joined_options));
            try std.testing.expectEqualStrings("user namespace mappings do not match the joined namespace", backend.diagnostic().?);
            joined_options.uid_mappings = options.uid_mappings;
            joined_options.gid_mappings = &.{.{ .container_id = 0, .host_id = 200001, .size = 10 }};
            try std.testing.expectError(error.InvalidConfig, backend.create(joined_options));
            try std.testing.expectEqualStrings("user namespace mappings do not match the joined namespace", backend.diagnostic().?);
            joined_options.gid_mappings = options.gid_mappings;
            try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, joined_cgroup, false, &.{}));
        }
        // Lowering requires host CAP_SYS_RESOURCE even when joining a user
        // namespace whose root maps to a different host UID.
        if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0)
            joined_options.oom_score_adj = -500;
        const joined = try backend.create(joined_options);
        defer std.testing.allocator.free(joined.starttime);
        defer {
            backend.kill(joined, 9) catch {};
            backend.delete(joined) catch {};
        }
        try std.testing.expect(try backend.alive(joined));
        for ([_][]const u8{ "dev/bind-file", "dev/bind-dir/content" }) |destination| {
            const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/root/{s}", .{ joined.pid, destination });
            defer std.testing.allocator.free(path);
            const content = try ProcFile.read(path, .limited(64));
            defer std.testing.allocator.free(content);
            try std.testing.expectEqualStrings("private bind source\n", content);
        }
        var joined_fifo_stat: linux.Statx = undefined;
        try checkResult(linux.statx(linux.AT.FDCWD, joined_fifo, 0, .{ .UID = true, .GID = true, .MODE = true }, &joined_fifo_stat));
        try std.testing.expectEqual(@as(u32, 100000), joined_fifo_stat.uid);
        try std.testing.expectEqual(@as(u32, 200000), joined_fifo_stat.gid);
        try std.testing.expectEqual(@as(u16, if (case.uid == 0) 0o600 else 0o622), joined_fifo_stat.mode & 0o7777);
        const joined_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{joined.pid});
        defer std.testing.allocator.free(joined_oom_path);
        const joined_oom_score_adj = try ProcFile.read(joined_oom_path, .limited(32));
        defer std.testing.allocator.free(joined_oom_score_adj);
        try std.testing.expectEqualStrings(if (joined_options.oom_score_adj == -500) "-500\n" else "500\n", joined_oom_score_adj);
        const joined_reader = try openPath(linux.AT.FDCWD, joined_fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        defer closeFd(joined_reader);
        var joined_poll = [_]linux.pollfd{.{ .fd = joined_reader, .events = linux.POLL.IN, .revents = 0 }};
        try checkResult(linux.poll(&joined_poll, 1, 2000));
        try std.testing.expect(joined_poll[0].revents & linux.POLL.IN != 0);
        var acknowledgement: [1]u8 = undefined;
        try std.testing.expect(readAll(joined_reader, &acknowledgement));
        try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
    }
    if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0) {
        // Identity maps isolate loss of host CAP_SYS_RESOURCE from the proc
        // ownership failure exercised by the nonidentity maps above.
        const lowered_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/lowered.fifo", .{absolute}, 0);
        defer std.testing.allocator.free(lowered_fifo);
        try checkResult(linux.mknod(lowered_fifo, linux.S.IFIFO | 0o600, 0));
        const lowered_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-lowered", .{cgroup_path});
        defer std.testing.allocator.free(lowered_cgroup);
        var lowered_options = options;
        lowered_options.uid_mappings = &.{.{ .container_id = 0, .host_id = 0, .size = 10 }};
        lowered_options.gid_mappings = &.{.{ .container_id = 0, .host_id = 0, .size = 10 }};
        lowered_options.exec_fifo = lowered_fifo;
        lowered_options.cgroup_path = lowered_cgroup;
        lowered_options.oom_score_adj = -500;
        const lowered = try backend.create(lowered_options);
        defer std.testing.allocator.free(lowered.starttime);
        defer {
            backend.kill(lowered, 9) catch {};
            backend.delete(lowered) catch {};
        }
        const lowered_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{lowered.pid});
        defer std.testing.allocator.free(lowered_oom_path);
        const lowered_oom_score_adj = try ProcFile.read(lowered_oom_path, .limited(32));
        defer std.testing.allocator.free(lowered_oom_score_adj);
        try std.testing.expectEqualStrings("-500\n", lowered_oom_score_adj);
    }
    // Mapped root (host UID 100000) must still acknowledge start on the FIFO.
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll, 1, 2000));
    try std.testing.expect(poll[0].revents & linux.POLL.IN != 0);
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../root.zig").Backend;
const Resources = Backend.Resources;
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
const readCgroupFile = @import("../cgroup.zig").readCgroupFile;
const writeCgroupFile = @import("../cgroup.zig").writeCgroupFile;
const freeV1Writes = @import("../cgroup_v1.zig").freeV1Writes;
const v1Writes = @import("../cgroup_v1.zig").v1Writes;
const V1Hierarchy = @import("../cgroup_v1.zig").V1Hierarchy;
const freeV1Hierarchies = @import("../cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("../cgroup_v1.zig").openV1Hierarchies;
const walkV1Cgroup = @import("../cgroup_v1.zig").walkV1Cgroup;
const applyV1Writes = @import("../cgroup_v1.zig").applyV1Writes;
const killV1Members = @import("../cgroup_v1.zig").killV1Members;
const removeV1Cgroups = @import("../cgroup_v1.zig").removeV1Cgroups;
const removeV1Cgroup = @import("../cgroup_v1.zig").removeV1Cgroup;
const cleanupV1TestHierarchies = @import("helpers.zig").cleanupV1TestHierarchies;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const LinuxBackend = @import("../../linux.zig").LinuxBackend;

test "linux v1 create exposes readonly controller leaves containing init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator, false);
    defer freeV1Hierarchies(allocator, hierarchies);
    if (hierarchies.len == 0) return error.SkipZigTest;
    var selected = hierarchies[0];
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("memory")) selected = hierarchy;
    }
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-mount-test-{d}", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    // Probe delegation before create, so a failure in mount expansion is fatal.
    for (hierarchies) |hierarchy| {
        const leaf = (walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        defer closeFd(leaf);
        try removeV1Cgroup(hierarchy.root.?, hierarchy.mount_root, path, leaf, null, null);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fs.path.join(allocator, &.{ absolute, "rootfs" });
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const controller_path = try std.fmt.allocPrintSentinel(allocator, "/sys/fs/cgroup/{s}", .{std.fs.path.basename(selected.mountpoint)}, 0);
    defer allocator.free(controller_path);
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = "v1-mount",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .namespaces = &.{ .{ .kind = .mount }, .{ .kind = .cgroup } },
        .cgroup_path = path,
        .mounts = &.{.{
            .destination = "/sys/fs/cgroup",
            .source = "cgroup",
            .type = "cgroup",
            .flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV,
            .propagation = 0,
            .data = "",
        }},
    });
    defer allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    var buffer: [64]u8 = undefined;
    const namespace_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/ns/mnt", .{handle.pid});
    const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    const init_root_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/root", .{handle.pid});
    const init_root = try openPath(linux.AT.FDCWD, init_root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(init_root);
    const checker = try forkProcess();
    if (checker == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.fchdir(init_root)) catch linux.exit_group(2);
        checkResult(linux.chroot(".")) catch linux.exit_group(3);
        checkResult(linux.chdir("/")) catch linux.exit_group(4);
        for (hierarchies) |hierarchy| {
            const basename = std.fs.path.basename(hierarchy.mountpoint);
            if (std.mem.indexOfScalar(u8, basename, ',') == null) continue;
            var names = std.mem.tokenizeScalar(u8, basename, ',');
            while (names.next()) |name| {
                var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const link = std.fmt.bufPrintZ(&path_buffer, "/sys/fs/cgroup/{s}", .{name}) catch linux.exit_group(12);
                var target: [256]u8 = undefined;
                const len = linux.readlink(link, &target, target.len);
                checkResult(len) catch linux.exit_group(13);
                if (!std.mem.eql(u8, target[0..len], basename)) linux.exit_group(14);
            }
        }
        const controller = openPath(linux.AT.FDCWD, controller_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(5);
        if (linux.errno(linux.mkdirat(controller, "readonly-probe", 0o755)) != .ROFS) linux.exit_group(6);
        // The tmpfs itself must be readonly after controller binds and links.
        if (linux.errno(linux.mkdir("/sys/fs/cgroup/readonly-probe", 0o755)) != .ROFS) linux.exit_group(7);
        const procs = openPath(controller, "cgroup.procs", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(8);
        var members: [4096]u8 = undefined;
        const count = linux.read(procs, &members, members.len);
        checkResult(count) catch linux.exit_group(9);
        var pids = std.mem.tokenizeAny(u8, members[0..count], " \t\n");
        while (pids.next()) |pid| {
            if ((std.fmt.parseInt(i32, pid, 10) catch linux.exit_group(10)) == handle.pid)
                linux.exit_group(0);
        }
        linux.exit_group(11);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(checker));
}

test "linux v1 creates seeds writes joins and deletes each hierarchy" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator, false);
    defer freeV1Hierarchies(allocator, hierarchies);
    if (hierarchies.len == 0) return error.SkipZigTest;
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-test-{d}/leaf", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    for (hierarchies) |*hierarchy| {
        hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        try std.testing.expectError(error.CreateFailed, walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, true, hierarchy.has("cpuset")));
        if (hierarchy.has("cpuset")) {
            const parent = (try walkCgroup(hierarchy.root.?, std.fs.path.dirname(path).?, false, &.{})).?;
            defer closeFd(parent);
            for ([_][:0]const u8{ "cpuset.cpus", "cpuset.mems" }) |name| {
                const inherited = try readCgroupFile(allocator, hierarchy.root.?, name);
                defer allocator.free(inherited);
                const intermediate = try readCgroupFile(allocator, parent, name);
                defer allocator.free(intermediate);
                const leaf = try readCgroupFile(allocator, hierarchy.leaf.?, name);
                defer allocator.free(leaf);
                try std.testing.expect(std.mem.trim(u8, leaf, "\n").len != 0);
                try std.testing.expectEqualStrings(inherited, intermediate);
                try std.testing.expectEqualStrings(inherited, leaf);
            }
        }
    }
    // A forced concurrent delete/recreate must not make cleanup remove the
    // replacement. Hold the old descriptor so its inode cannot be reused.
    const first = &hierarchies[0];
    const original = first.leaf.?;
    try removeV1Cgroup(first.root.?, first.mount_root, path, original, null, null);
    first.leaf = (try walkV1Cgroup(allocator, first.root.?, first.mount_root, path, true, first.has("cpuset"))).?;
    defer closeFd(original);
    try removeV1Cgroup(first.root.?, first.mount_root, path, original, null, null);
    const replacement = (try walkCgroup(first.root.?, path, false, &.{})).?;
    closeFd(replacement);

    var resources: Resources = .{
        .memory = .{ .limit = 67108864, .reservation = 33554432, .swap = 134217728, .swappiness = 50 },
        .cpu = .{ .shares = 1024, .period = 100000, .quota = 50000 },
        .pids = .{ .limit = 32 },
        .block_io = .{ .weight = 100 },
        .hugepage_limits = &.{.{ .page_size = "2MB", .limit = 4194304 }},
        .network = .{ .class_id = 1048577, .priorities = &.{.{ .name = "lo", .priority = 2 }} },
        .devices = &.{.{ .allow = false }},
    };
    // blkio.weight and blkio.bfq.weight depend on the I/O scheduler.
    for (hierarchies) |hierarchy| {
        if (!hierarchy.has("blkio")) continue;
        var has_weight = false;
        for ([_][:0]const u8{ "blkio.weight", "blkio.bfq.weight" }) |name| {
            const result = linux.faccessat(hierarchy.leaf.?, name, linux.F_OK, 0);
            switch (linux.errno(result)) {
                .SUCCESS => has_weight = true,
                .NOENT => {},
                else => try checkResult(result),
            }
        }
        if (!has_weight) resources.block_io.?.weight = null;
    }
    const writes = try v1Writes(allocator, resources);
    defer freeV1Writes(allocator, writes);
    try applyV1Writes(allocator, hierarchies, writes, resources, &.{}, path, true);
    for (hierarchies) |hierarchy| {
        const cases = [_]struct { controller: []const u8, name: [:0]const u8, value: []const u8 }{
            .{ .controller = "memory", .name = "memory.limit_in_bytes", .value = "67108864" },
            .{ .controller = "memory", .name = "memory.memsw.limit_in_bytes", .value = "134217728" },
            .{ .controller = "cpu", .name = "cpu.shares", .value = "1024" },
            .{ .controller = "cpu", .name = "cpu.cfs_period_us", .value = "100000" },
            .{ .controller = "cpu", .name = "cpu.cfs_quota_us", .value = "50000" },
            .{ .controller = "pids", .name = "pids.max", .value = "32" },
            .{ .controller = "hugetlb", .name = "hugetlb.2MB.limit_in_bytes", .value = "4194304" },
        };
        for (cases) |case| {
            if (!hierarchy.has(case.controller)) continue;
            const value = try readCgroupFile(allocator, hierarchy.leaf.?, case.name);
            defer allocator.free(value);
            try std.testing.expectEqualStrings(case.value, std.mem.trim(u8, value, "\n"));
        }
        if (hierarchy.has("memory")) {
            // Exercise both orders against a real kernel constraint: lower
            // limit+memsw, then raise limit beyond the current memsw.
            const lower: Resources = .{ .memory = .{ .limit = 33554432, .swap = 67108864 } };
            const lower_writes = try v1Writes(allocator, lower);
            defer freeV1Writes(allocator, lower_writes);
            try applyV1Writes(allocator, hierarchies, lower_writes, lower, &.{}, path, false);
            const higher: Resources = .{ .memory = .{ .limit = 100663296, .swap = 134217728 } };
            const higher_writes = try v1Writes(allocator, higher);
            defer freeV1Writes(allocator, higher_writes);
            try applyV1Writes(allocator, hierarchies, higher_writes, higher, &.{}, path, false);
        }
    }
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    var writer: ?posix.fd_t = pipe[1];
    defer if (writer) |fd| closeFd(fd);
    const child = try forkProcess();
    if (child == 0) {
        closeFd(pipe[0]);
        for (hierarchies) |hierarchy|
            writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", path) catch linux.exit_group(1);
        if (!writeAll(pipe[1], &.{1})) linux.exit_group(2);
        const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
        while (true) _ = linux.nanosleep(&delay, null);
    }
    closeFd(pipe[1]);
    writer = null;
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(child, .KILL);
        _ = waitChild(child) catch {};
    };
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(pipe[0], &byte));
    var pid_buffer: [24]u8 = undefined;
    const pid_line = try std.fmt.bufPrint(&pid_buffer, "{d}\n", .{child});
    for (hierarchies) |hierarchy| {
        const members = try readCgroupFile(allocator, hierarchy.leaf.?, "cgroup.procs");
        defer allocator.free(members);
        try std.testing.expect(std.mem.indexOf(u8, members, pid_line) != null);
        if (hierarchy.has("freezer")) {
            // Failed enumeration must thaw the real cgroup, leaving its
            // member alive for delete's subsequent freeze/kill/thaw cycle.
            try std.testing.expectError(error.CreateFailed, killV1Members(-1, hierarchy.leaf, 9, hierarchy.mount_root, path, null));
            const state = try readCgroupFile(allocator, hierarchy.leaf.?, "freezer.state");
            defer allocator.free(state);
            try std.testing.expectEqualStrings("THAWED", std.mem.trim(u8, state, " \t\n"));
            try checkResult(linux.kill(child, @enumFromInt(0)));
        }
    }
    var backend: LinuxBackend = .{};
    try backend.backend().delete(.{ .id = "v1-test", .pid = child, .starttime = "", .cgroup_path = path });
    try std.testing.expectEqual(@as(u32, 9), try waitChild(child));
    reaped = true;
    for (hierarchies) |hierarchy|
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(hierarchy.root.?, path, false, &.{}));
    try backend.backend().delete(.{ .id = "v1-test", .pid = 0, .starttime = "", .cgroup_path = path });
}

test "linux v1 cleanup attempts later hierarchies after the first removal fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator, false);
    defer freeV1Hierarchies(allocator, hierarchies);
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-cleanup-{d}", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    var selected: [2]V1Hierarchy = undefined;
    var count: usize = 0;
    for (hierarchies) |*hierarchy| {
        if (hierarchy.has("freezer")) continue;
        hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        selected[count] = hierarchy.*;
        count += 1;
        if (count == selected.len) break;
    }
    if (count < selected.len) return error.SkipZigTest;
    const first_root = selected[0].root.?;
    selected[0].root = -1; // Fail before removing the first owned leaf.
    try std.testing.expectError(error.CreateFailed, removeV1Cgroups(&selected, path));
    const first = (try walkCgroup(first_root, path, false, &.{})) orelse return error.TestUnexpectedResult;
    closeFd(first);
    const second = try walkCgroup(selected[1].root.?, path, false, &.{});
    defer if (second) |fd| closeFd(fd);
    try std.testing.expectEqual(@as(?posix.fd_t, null), second);
}

test "linux v1 missing optional controllers are ignored and required limits fail" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    for ([_]Resources{
        .{ .memory = .{ .limit = 64 } }, .{ .pids = .{ .limit = 32 } }, .{ .devices = &.{.{ .allow = false }} },
    }) |resources| {
        const writes = try v1Writes(allocator, resources);
        defer freeV1Writes(allocator, writes);
        try std.testing.expectError(error.CgroupWriteFailed, applyV1Writes(allocator, &.{}, writes, resources, &.{}, "missing", true));
    }
    const resources: Resources = .{ .cpu = .{ .shares = 1024 }, .block_io = .{ .weight = 100 } };
    const writes = try v1Writes(allocator, resources);
    defer freeV1Writes(allocator, writes);
    try applyV1Writes(allocator, &.{}, writes, resources, &.{}, "missing", true);
}

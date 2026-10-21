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
const writeAll = @import("../syscall.zig").writeAll;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const readCgroupFile = @import("../cgroup.zig").readCgroupFile;
const collectCgroupPids = @import("../cgroup.zig").collectCgroupPids;
const writeCgroupFile = @import("../cgroup.zig").writeCgroupFile;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const V1Hierarchy = @import("../cgroup_v1.zig").V1Hierarchy;
const freeV1Hierarchies = @import("../cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("../cgroup_v1.zig").openV1Hierarchies;
const walkV1Cgroup = @import("../cgroup_v1.zig").walkV1Cgroup;
const writeV1Resource = @import("../cgroup_v1.zig").writeV1Resource;
const killV1Members = @import("../cgroup_v1.zig").killV1Members;
const removeV1Cgroup = @import("../cgroup_v1.zig").removeV1Cgroup;
const cleanupV1TestHierarchies = @import("helpers.zig").cleanupV1TestHierarchies;
const readProcStat = @import("../proc.zig").readProcStat;
const readProcFileAt = @import("../proc.zig").readProcFileAt;
const openPidfd = @import("../proc.zig").openPidfd;
const signalPid = @import("../proc.zig").signalPid;
const LinuxContainer = @import("../../linux.zig").Container;

test "linux v1 ignores missing deprecated kmem files but requires other memory files" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    var kmem_warned = false;
    for ([_][]const u8{ "memory.kmem.limit_in_bytes", "memory.kmem.tcp.limit_in_bytes" }) |name| {
        try writeV1Resource(root, .{ .controller = "memory", .name = name, .value = "64" }, "test", &kmem_warned);
        try std.testing.expect(kmem_warned);
    }
    try std.testing.expectError(error.CgroupWriteFailed, writeV1Resource(root, .{
        .controller = "memory",
        .name = "memory.limit_in_bytes",
        .value = "64",
    }, "test", &kmem_warned));
}

test "linux cgroup member signaling distinguishes kill failures from deletion failures" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "leaf", .fromMode(0o755));
    const members = try std.fmt.allocPrint(std.testing.allocator, "{d}\n", .{linux.getpid()});
    defer std.testing.allocator.free(members);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf/cgroup.procs", .data = members });
    const leaf = try openPath(tmp.dir.handle, "leaf", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(leaf);
    try std.testing.expectError(error.KillFailed, killV1Members(leaf, null, linux.NSIG, "/", "leaf", null));
    // A populated leaf without a verified member must not report success.
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectError(error.KillFailed, killV1Members(leaf, null, 0, "/", "igvano/unrelated", null));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "no member could be verified") != null);
    try std.testing.expectError(error.CgroupDeleteFailed, removeV1Cgroup(tmp.dir.handle, "/", "leaf", leaf, null, null));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "no member could be verified") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "still busy") == null);
    var proc_buffer: [64 * 1024]u8 = undefined;
    const cgroups = try readProcFileAt(linux.AT.FDCWD, linux.getpid(), "cgroup", &proc_buffer);
    const first = std.mem.indexOfScalar(u8, cgroups, ':').?;
    const second = std.mem.indexOfScalarPos(u8, cgroups, first + 1, ':').?;
    const end = std.mem.indexOfScalarPos(u8, cgroups, second + 1, '\n') orelse cgroups.len;
    const member_path = cgroups[second + 2 .. end];
    if (linux.geteuid() != 0) return;
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try checkResult(linux.fchmod(root, 0o755));
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setuid(65534)) catch linux.exit_group(1);
        killV1Members(leaf, null, 0, "/", member_path, null) catch |err| {
            if (err != error.PermissionDenied) linux.exit_group(2);
            removeV1Cgroup(root, "/", "leaf", leaf, null, null) catch |delete_err|
                linux.exit_group(if (delete_err == error.CgroupDeleteFailed) 0 else 3);
            linux.exit_group(4);
        };
        linux.exit_group(5);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux pidfds signal the held process and cgroup checks reject stale members" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var children = [_]i32{ 0, 0 };
    defer for (children) |pid| {
        if (pid > 0) {
            _ = linux.kill(pid, .KILL);
            _ = waitChild(pid) catch {};
        }
    };
    for (&children) |*child| {
        child.* = try forkProcess();
        if (child.* == 0) {
            const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
            while (true) _ = linux.nanosleep(&delay, null);
        }
    }
    const pidfd = (try openPidfd(children[0])) orelse return error.SkipZigTest;
    defer closeFd(pidfd);
    // Even a different numeric PID cannot redirect signalling through this fd.
    try signalPid(children[1], pidfd, 9);
    try std.testing.expectEqual(@as(u32, 9), try waitChild(children[0]));
    children[0] = 0;
    var buffer: [4096]u8 = undefined;
    const stat = try readProcStat(children[1], &buffer);
    const starttime = try std.testing.allocator.dupe(u8, stat.starttime);
    defer std.testing.allocator.free(starttime);
    const handle: libcontainer.State = .{ .id = "survivor", .pid = children[1], .starttime = starttime };
    var handle_instance = LinuxContainer.load(handle);
    const handle_container = handle_instance.container();
    try std.testing.expect(try handle_container.alive());
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const members = try std.fmt.allocPrint(std.testing.allocator, "{d}\n", .{children[1]});
    defer std.testing.allocator.free(members);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = members });
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectError(error.KillFailed, killV1Members(tmp.dir.handle, null, 9, "/", "igvano/unrelated", null));
    try std.testing.expect(try handle_container.alive());
}

test "linux pidfd_open denied by seccomp falls back to kill" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]linux.E{ .PERM, .ACCES }) |denied| {
        const pid = try forkProcess();
        if (pid == 0) {
            const filters = [_]seccomp.Filter{
                .{ .code = 0x20, .k = 0 },
                .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.pidfd_open) },
                .{ .code = 0x06, .k = 0x00050000 | @as(u32, @intFromEnum(denied)) },
                .{ .code = 0x06, .k = 0x7fff0000 },
            };
            checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(1);
            if (seccomp.install(.{ .filters = &filters, .flags = 0 }) != .SUCCESS) linux.exit_group(2);
            const pidfd = openPidfd(linux.getpid()) catch linux.exit_group(3);
            if (pidfd != null) linux.exit_group(4);
            var buffer: [4096]u8 = undefined;
            const stat = readProcStat(linux.getpid(), &buffer) catch linux.exit_group(5);
            var self_instance = LinuxContainer.load(.{ .id = "pidfd-denied", .pid = linux.getpid(), .starttime = stat.starttime });
            const self_container = self_instance.container();
            self_container.kill(0) catch linux.exit_group(6);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

test "linux populated v2 cgroup without visible PIDs fails member signaling" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    defer diagnostics.last_diagnostic_len = 0;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = "populated 1\n" });
    try std.testing.expectError(error.KillFailed, killV1Members(tmp.dir.handle, null, 0, "/", "igvano/hidden", ""));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "igvano/hidden") != null);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = "populated 0\n" });
    try killV1Members(tmp.dir.handle, null, 0, "/", "igvano/hidden", "");
}

test "linux pid enumeration includes nested descendants and ignores control files and symlinks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "child/grandchild");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = "1234\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "child/cgroup.procs", .data = "1235\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "child/grandchild/cgroup.procs", .data = "1236\n1234\n" });
    try tmp.dir.symLink(std.testing.io, "child", "linked-child", .{ .is_directory = true });
    const dir = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    var pids: std.ArrayList(i32) = .empty;
    defer pids.deinit(allocator);
    try collectCgroupPids(allocator, dir, &pids);
    try std.testing.expectEqualSlices(i32, &.{ 1234, 1235, 1236 }, pids.items);
    pids.clearRetainingCapacity();
    try collectCgroupPids(allocator, dir, &pids);
    try std.testing.expectEqualSlices(i32, &.{ 1234, 1235, 1236 }, pids.items);
}

test "linux kill all signals every cgroup member and plain SIGKILL thaws paused v1" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(root.fd);
    const path = try std.fmt.allocPrint(allocator, "igvano-kill-all-test-{d}", .{linux.getpid()});
    defer allocator.free(path);
    const hierarchies: []V1Hierarchy = if (root.mode == .legacy) try openV1Hierarchies(allocator, false) else &.{};
    defer freeV1Hierarchies(allocator, hierarchies);
    var cgroup: ?posix.fd_t = null;
    defer if (cgroup) |fd| closeFd(fd);
    defer if (root.mode == .legacy) {
        cleanupV1TestHierarchies(hierarchies, path);
    } else {
        removeCgroup(root.fd, path) catch {};
    };
    if (root.mode == .legacy) {
        if (hierarchies.len == 0) return error.SkipZigTest;
        for (hierarchies) |*hierarchy|
            hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, true, hierarchy.has("cpuset")) catch return error.SkipZigTest).?;
    } else {
        cgroup = (walkCgroup(root.fd, path, true, &.{}) catch return error.SkipZigTest).?;
    }
    const nested_path = try std.fmt.allocPrint(allocator, "{s}/child/grandchild", .{path});
    defer allocator.free(nested_path);
    var nested: std.ArrayList(posix.fd_t) = .empty;
    defer {
        for (nested.items) |fd| closeFd(fd);
        nested.deinit(allocator);
    }
    if (root.mode == .legacy) {
        for (hierarchies) |hierarchy| {
            const fd = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, nested_path, true, hierarchy.has("cpuset"))).?;
            errdefer closeFd(fd);
            try nested.append(allocator, fd);
        }
    } else {
        const fd = (try walkCgroup(root.fd, nested_path, true, &.{})).?;
        errdefer closeFd(fd);
        try nested.append(allocator, fd);
    }
    for ([_]struct { signal: i32, paused: bool, all: bool = true }{
        .{ .signal = 9, .paused = false },
        .{ .signal = 15, .paused = false },
        .{ .signal = 9, .paused = true },
        .{ .signal = 15, .paused = true },
        .{ .signal = 9, .paused = true, .all = false },
    }) |case| {
        const signal = case.signal;
        if (case.paused and root.mode == .legacy) {
            var has_freezer = false;
            for (hierarchies) |hierarchy| {
                if (hierarchy.has("freezer")) has_freezer = true;
            }
            if (!has_freezer) continue;
        }
        const ready = try makePipe();
        defer closeFd(ready[0]);
        var writer: ?posix.fd_t = ready[1];
        defer if (writer) |fd| closeFd(fd);
        var children = [_]i32{ 0, 0 };
        defer {
            var cleanup_instance = LinuxContainer.load(.{ .id = "kill-all", .pid = 0, .starttime = "", .cgroup_path = path });
            const cleanup_container = cleanup_instance.container();
            if (case.paused) cleanup_container.thaw() catch {};
            for (children) |pid| {
                if (pid > 0) {
                    _ = linux.kill(pid, .KILL);
                    _ = waitChild(pid) catch {};
                }
            }
        }
        for (&children, 0..) |*child, index| {
            child.* = try forkProcess();
            if (child.* == 0) {
                closeFd(ready[0]);
                if (index != 0) {
                    for (nested.items) |fd|
                        writeCgroupFile(fd, "cgroup.procs", "0", nested_path) catch linux.exit_group(1);
                } else if (cgroup) |fd| {
                    writeCgroupFile(fd, "cgroup.procs", "0", path) catch linux.exit_group(1);
                } else {
                    for (hierarchies) |hierarchy|
                        writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", path) catch linux.exit_group(1);
                }
                if (!writeAll(ready[1], &.{1})) linux.exit_group(2);
                const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
                while (true) _ = linux.nanosleep(&delay, null);
            }
        }
        closeFd(ready[1]);
        writer = null;
        var bytes: [2]u8 = undefined;
        try std.testing.expect(readAll(ready[0], &bytes));
        try std.testing.expectEqualSlices(u8, &.{ 1, 1 }, &bytes);
        var buffer: [4096]u8 = undefined;
        const stat = try readProcStat(children[0], &buffer);
        const handle: libcontainer.State = .{ .id = "kill-all", .pid = children[0], .starttime = stat.starttime, .cgroup_path = path };
        var handle_instance = LinuxContainer.load(handle);
        const handle_container = handle_instance.container();
        const subtree_pids = try handle_container.pids(allocator);
        defer allocator.free(subtree_pids);
        for (children) |pid| try std.testing.expect(std.mem.indexOfScalar(i32, subtree_pids, pid) != null);
        try handle_container.killAll(0);
        try std.testing.expect(try handle_container.alive());
        if (signal == 15) {
            // Init can exit while another member remains in its cgroup.
            try handle_container.kill(9);
            const status = try waitChild(children[0]);
            children[0] = 0;
            try std.testing.expectEqual(@as(u32, 9), status);
        }
        if (case.paused) try handle_container.freeze();
        if (case.all) {
            try handle_container.killAll(signal);
        } else {
            try handle_container.kill(signal);
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(children[1], @enumFromInt(0))));
        }
        const stays_frozen = case.paused and (root.mode == .unified or signal != 9);
        if (case.paused and root.mode == .unified) {
            // Exiting tasks can clear the events bit, but kill must retain the user's freeze request.
            const requested = try readCgroupFile(allocator, cgroup.?, "cgroup.freeze");
            defer allocator.free(requested);
            try std.testing.expectEqualStrings("1", std.mem.trim(u8, requested, " \t\n"));
        } else {
            try std.testing.expectEqual(stays_frozen, try handle_container.frozen());
        }
        // Finish SIGKILL exits before thawing so the kernel has updated
        // the subtree's freezer counters.
        if (case.paused and case.all and signal == 9) {
            for (&children) |*child| {
                const status = try waitChild(child.*);
                child.* = 0;
                try std.testing.expectEqual(@as(u32, 9), status);
            }
        }
        if (stays_frozen) try handle_container.thaw();
        if (!case.all) try handle_container.killAll(signal);
        if (cgroup) |fd| {
            const thawed = try readCgroupFile(allocator, fd, "cgroup.freeze");
            defer allocator.free(thawed);
            try std.testing.expectEqualStrings("0", std.mem.trim(u8, thawed, " \t\n"));
        } else {
            for (hierarchies) |hierarchy| {
                if (!hierarchy.has("freezer")) continue;
                const thawed = try readCgroupFile(allocator, hierarchy.leaf.?, "freezer.state");
                defer allocator.free(thawed);
                try std.testing.expectEqualStrings("THAWED", std.mem.trim(u8, thawed, " \t\n"));
            }
        }
        for (&children) |*child| {
            if (child.* == 0) continue;
            const status = try waitChild(child.*);
            child.* = 0;
            try std.testing.expectEqual(@as(u32, @intCast(signal)), status);
        }
        const members = try readCgroupFile(allocator, cgroup orelse hierarchies[0].leaf.?, "cgroup.procs");
        defer allocator.free(members);
        try std.testing.expectEqualStrings("", std.mem.trim(u8, members, " \t\n"));
        try handle_container.killAll(signal);
    }
    const handle: libcontainer.State = .{ .id = "kill-all", .pid = 0, .starttime = "", .cgroup_path = path };
    var handle_instance = LinuxContainer.load(handle);
    const handle_container = handle_instance.container();
    try handle_container.delete();
    try handle_container.killAll(9);
}

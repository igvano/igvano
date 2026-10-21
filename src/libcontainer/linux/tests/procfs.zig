const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../../root.zig");
const diagnostics = @import("../diagnostic.zig");
const PreparedMount = @import("../mount.zig").PreparedMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const writeAll = @import("../syscall.zig").writeAll;
const openPath = @import("../syscall.zig").openPath;
const readCgroupFile = @import("../cgroup.zig").readCgroupFile;
const setupRootfs = @import("../rootfs.zig").setupRootfs;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const Procfs = @import("../procfs.zig").Procfs;
const writeSysctl = @import("../procfs.zig").writeSysctl;
const applySysctls = @import("../procfs.zig").applySysctls;
const namespaceFlag = @import("../namespaces.zig").namespaceFlag;
const validateNamespaceFd = @import("../namespaces.zig").validateNamespaceFd;

test "linux private subset procfs resolves the child in its PID namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const helper = try forkProcess();
    if (helper == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        const child = forkProcess() catch linux.exit_group(2);
        if (child == 0) {
            if (linux.getpid() != 1 or linux.gettid() != 1) linux.exit_group(3);
            const proc = Procfs.open(true) catch linux.exit_group(4);
            if (proc.mount_id != null) linux.exit_group(77);
            const fd = (proc.openWrite("1/task/1/oom_score_adj") catch linux.exit_group(5)) orelse linux.exit_group(6);
            // Change only this child's score, through the same numeric task
            // addressing used for AppArmor on a detached subset mount.
            if (!writeAll(fd, "0")) linux.exit_group(7);
            closeFd(fd);
            closeFd(proc.fd);
            linux.exit_group(0);
        }
        const status = waitChild(child) catch linux.exit_group(8);
        linux.exit_group(if (status == 0) 0 else if (status == 77 << 8) 77 else 9);
    }
    const status = try waitChild(helper);
    if (status == 77 << 8) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), status);
}

test "linux sysctls precede readonly restrictions and preserve the runtime network namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const host = try openPath(linux.AT.FDCWD, "/proc/sys/net/ipv4", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(host);
    const before = try readCgroupFile(allocator, host, "ip_forward");
    defer allocator.free(before);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/rootfs", .{absolute}, 0);
    defer allocator.free(rootfs);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    var ready_writer: ?posix.fd_t = ready[1];
    defer if (ready_writer) |fd| closeFd(fd);
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(ready[0]);
        closeFd(go[1]);
        closeFd(host);
        checkResult(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWNET | linux.CLONE.NEWIPC)) catch linux.exit_group(77);
        if (!writeAll(ready[1], &.{1})) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(2);
        const mounts = [_]PreparedMount{
            .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
        };
        setupRootfs(rootfs, &mounts, &.{}, &.{}, true, .{
            .sysctls = &.{.{ .key = "net.ipv4.ip_forward", .value = "1" }},
            .readonly_paths = &.{"/proc/sys"},
        }) catch linux.exit_group(3);
        const fd = openPath(linux.AT.FDCWD, "/proc/sys/net/ipv4/ip_forward", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(4);
        var value: [2]u8 = undefined;
        if (!readAll(fd, &value) or !std.mem.eql(u8, &value, "1\n")) linux.exit_group(5);
        closeFd(fd);
        if (linux.errno(linux.open("/proc/sys/net/ipv4/ip_forward", .{ .ACCMODE = .WRONLY }, 0)) != .ROFS)
            linux.exit_group(6);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    closeFd(ready[1]);
    ready_writer = null;
    var byte: [1]u8 = undefined;
    if (!readAll(ready[0], &byte)) {
        const status = try waitChild(pid);
        reaped = true;
        if (status == 77) return error.SkipZigTest;
        return error.TestUnexpectedResult;
    }
    // Joined namespaces also validate when their inode differs from ours.
    for ([_]struct { kind: libcontainer.Namespace.Kind, name: []const u8 }{
        .{ .kind = .network, .name = "net" },
        .{ .kind = .ipc, .name = "ipc" },
    }) |case| {
        const path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/ns/{s}", .{ pid, case.name }, 0);
        defer allocator.free(path);
        const fd = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
        defer closeFd(fd);
        try validateNamespaceFd(fd, namespaceFlag(case.kind));
    }
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
    const after = try readCgroupFile(allocator, host, "ip_forward");
    defer allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
}

test "linux sysctl writes reject symlinks in every path component" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "sys/net/ipv4");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "unchanged" });
    try tmp.dir.symLink(std.testing.io, "../../../outside", "sys/net/ipv4/ip_forward", .{});
    try tmp.dir.symLink(std.testing.io, "net", "sys/alias", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_][]const u8{ "net.ipv4.ip_forward", "alias.ipv4.ip_forward", "net..outside" }) |key| {
        if (writeSysctl(.{ .fd = root }, .{ .key = key, .value = "1" })) return error.TestUnexpectedResult else |_| {}
    }
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "outside", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("unchanged", contents);
}

test "linux procfs writes bypass bind overmounts and the fallback fails closed" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "marker", .data = "unchanged" });
    const allocator = std.testing.allocator;
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/rootfs", .{absolute}, 0);
    defer allocator.free(rootfs);
    const marker = try std.fmt.allocPrintSentinel(allocator, "{s}/marker", .{absolute}, 0);
    defer allocator.free(marker);
    for ([_][:0]const u8{ marker, "/proc/sys/kernel/domainname" }) |source| {
        const child = try forkProcess();
        if (child == 0) {
            // Only this UTS namespace can be affected by either sysctl.
            checkResult(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWUTS)) catch linux.exit_group(1);
            var before: linux.utsname = undefined;
            checkResult(linux.uname(&before)) catch linux.exit_group(2);
            const mounts = [_]PreparedMount{
                .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
                .{ .destination = "/proc/sys/kernel/hostname", .source = source, .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" },
            };
            // Prepared mounts are the parsed backend config; install the
            // attack exactly as a configured bind, then write after pivot_root.
            setupRootfs(rootfs, &mounts, &.{}, &.{}, false, .{}) catch linux.exit_group(3);
            const root = openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(4);
            const fallback = Procfs.fallback(root) catch linux.exit_group(5);
            if (writeSysctl(fallback, .{ .key = "kernel.hostname", .value = "redirected" })) {
                linux.exit_group(6);
            } else |err| {
                if (err != error.MissingProcfs or diagnostics.last_diagnostic_len == 0) linux.exit_group(7);
            }
            // Exercise statx verification even when lookup stays on procfs.
            var wrong_mount = fallback;
            wrong_mount.mount_id = fallback.mount_id.? + 1;
            if (writeSysctl(wrong_mount, .{ .key = "kernel.domainname", .value = "redirected" })) {
                linux.exit_group(8);
            } else |err| {
                if (err != error.MissingProcfs) linux.exit_group(9);
            }
            closeFd(root);
            applySysctls(&.{.{ .key = "kernel.hostname", .value = "igvano-private-proc" }}) catch |err| {
                if (err != error.MissingProcfs) linux.exit_group(10);
                // Mounting procfs can be forbidden in some user namespaces.
                // A verified failure is acceptable; neither target may change.
                var after: linux.utsname = undefined;
                checkResult(linux.uname(&after)) catch linux.exit_group(11);
                if (!std.mem.eql(u8, &before.nodename, &after.nodename) or
                    !std.mem.eql(u8, &before.domainname, &after.domainname)) linux.exit_group(12);
                linux.exit_group(0);
            };
            var after: linux.utsname = undefined;
            checkResult(linux.uname(&after)) catch linux.exit_group(13);
            if (!std.mem.eql(u8, std.mem.sliceTo(&after.nodename, 0), "igvano-private-proc") or
                !std.mem.eql(u8, &before.domainname, &after.domainname)) linux.exit_group(14);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(child));
        const contents = try tmp.dir.readFileAlloc(std.testing.io, "marker", allocator, .limited(32));
        defer allocator.free(contents);
        try std.testing.expectEqualStrings("unchanged", contents);
    }
}

test "linux sysctls use private procfs when container proc is absent or covered" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/proc/sys");
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
        .{ .destination = "/proc/sys", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" },
    };
    for ([_]bool{ false, true }) |overmount_sys| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWNET)) catch linux.exit_group(1);
            setupRootfs(rootfs, if (overmount_sys) &mounts else &.{}, &.{}, &.{}, false, .{
                .sysctls = &.{.{ .key = "net.ipv4.ip_forward", .value = "1" }},
            }) catch |err| linux.exit_group(if (err == error.MissingProcfs) 0 else 2);
            // Success requires the private mount; the fallback cannot use the
            // missing /proc or cross the tmpfs mounted over /proc/sys.
            const proc = Procfs.open(false) catch linux.exit_group(3);
            const fd = (proc.openWrite("sys/net/ipv4/ip_forward") catch linux.exit_group(4)) orelse linux.exit_group(5);
            closeFd(fd);
            closeFd(proc.fd);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

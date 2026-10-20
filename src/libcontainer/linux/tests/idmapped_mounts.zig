const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Backend = @import("../../root.zig").Backend;
const PreparedMount = @import("../mount.zig").PreparedMount;
const applyMount = @import("../mount.zig").applyMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const writeAll = @import("../syscall.zig").writeAll;
const openPath = @import("../syscall.zig").openPath;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const createMountUserNamespace = @import("../namespaces.zig").createMountUserNamespace;
const RootfsStep = @import("../rootfs.zig").RootfsStep;
const testIDMappedBindOwnership = @import("helpers.zig").testIDMappedBindOwnership;
const requireTestIDMappedMounts = @import("helpers.zig").requireTestIDMappedMounts;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const cloneIDMappedMount = @import("../mount_sources.zig").cloneIDMappedMount;

test "linux idmapped binds translate ownership and writes with and without a container user namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "probe", .default_dir);
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const probe_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/probe", .{absolute}, 0);
    defer std.testing.allocator.free(probe_path);
    try requireTestIDMappedMounts(probe_path);
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-idmap-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const runtime = try forkProcess();
    if (runtime == 0) {
        // Keep the real bind source and rootfs on tmpfs, private to this worker.
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(2);
        checkResult(linux.mount("tmpfs", probe_path, "tmpfs", 0, @intFromPtr("mode=0755"))) catch linux.exit_group(3);
        testIDMappedBindOwnership(probe_path, cgroup_path) catch |err| {
            std.debug.print("idmapped bind ownership test: {s}\n", .{@errorName(err)});
            linux.exit_group(4);
        };
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(runtime));
}

test "linux idmapped binds isolate shared source propagation recursively" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    const source = try std.fmt.allocPrintSentinel(allocator, "{s}/source", .{absolute}, 0);
    const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/rootfs", .{absolute}, 0);
    try requireTestIDMappedMounts(source);
    const mapping: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 1 }};
    const userns = try createMountUserNamespace(allocator, .{ .uid = mapping, .gid = mapping });
    defer closeFd(userns);
    for ([_]bool{ false, true }) |recursive_bind| {
        const worker = try forkProcess();
        if (worker == 0) {
            const ms = linux.MS;
            // Isolate the test from the real host, then explicitly make its
            // source and submount shared, as on a systemd host.
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            checkResult(linux.chdir(source)) catch linux.exit_group(4);
            checkResult(linux.mkdir("sub", 0o755)) catch linux.exit_group(5);
            checkResult(linux.mount("tmpfs", "sub", "tmpfs", 0, 0)) catch linux.exit_group(6);
            inline for (.{ "from-container", "from-host", "sub/from-container", "sub/from-host" }) |path| {
                checkResult(linux.mkdir(path, 0o755)) catch linux.exit_group(7);
                const file = linux.open(path ++ "/marker", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
                checkResult(file) catch linux.exit_group(8);
                closeFd(@intCast(file));
            }
            checkResult(linux.mount(null, source, null, ms.SHARED | ms.REC, 0)) catch linux.exit_group(9);
            var mount: PreparedMount = .{
                .destination = "/data",
                .source = source,
                .type = null,
                .flags = ms.BIND | (if (recursive_bind) @as(u32, ms.REC) else 0),
                .propagation = 0,
                .data = "",
                // rbind must privatize submounts even with a nonrecursive idmap.
                .mappings = .{ .recursive = false },
            };
            const ready = makePipe() catch linux.exit_group(12);
            const go = makePipe() catch linux.exit_group(13);
            const container = forkProcess() catch linux.exit_group(14);
            if (container == 0) {
                closeFd(ready[0]);
                closeFd(go[1]);
                // The source helper clones inside the container namespace,
                // with host credentials, before setupRootfs makes '/' rprivate.
                checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(15);
                mount.mount_fd = cloneIDMappedMount(mount, userns) catch linux.exit_group(10);
                checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(16);
                const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(11);
                var step: RootfsStep = .{};
                applyMount(rootfs, root_fd, mount, true, ms.PRIVATE | ms.REC, &step) catch |err| {
                    step.report(err);
                    linux.exit_group(17);
                };
                closeFd(mount.mount_fd.?);
                checkResult(linux.fchdir(root_fd)) catch linux.exit_group(18);
                checkResult(linux.chdir("data")) catch linux.exit_group(19);
                checkResult(linux.mount("tmpfs", "from-container", "tmpfs", 0, 0)) catch linux.exit_group(20);
                if (recursive_bind)
                    checkResult(linux.mount("tmpfs", "sub/from-container", "tmpfs", 0, 0)) catch linux.exit_group(21);
                if (!writeAll(ready[1], &.{1})) linux.exit_group(22);
                var byte: [1]u8 = undefined;
                if (!readAll(go[0], &byte)) linux.exit_group(23);
                if (linux.errno(linux.access("from-host/marker", linux.F_OK)) != .SUCCESS) linux.exit_group(24);
                if (recursive_bind and linux.errno(linux.access("sub/from-host/marker", linux.F_OK)) != .SUCCESS)
                    linux.exit_group(25);
                linux.exit_group(0);
            }
            closeFd(ready[1]);
            closeFd(go[0]);
            var byte: [1]u8 = undefined;
            if (!readAll(ready[0], &byte)) linux.exit_group(26);
            // Mounts from the container must not cover the host's markers.
            if (linux.errno(linux.access("from-container/marker", linux.F_OK)) != .SUCCESS) linux.exit_group(27);
            if (recursive_bind and linux.errno(linux.access("sub/from-container/marker", linux.F_OK)) != .SUCCESS)
                linux.exit_group(28);
            checkResult(linux.mount("tmpfs", "from-host", "tmpfs", 0, 0)) catch linux.exit_group(29);
            if (recursive_bind)
                checkResult(linux.mount("tmpfs", "sub/from-host", "tmpfs", 0, 0)) catch linux.exit_group(30);
            // Host mounts must likewise leave the container's markers visible.
            if (!writeAll(go[1], &.{1})) linux.exit_group(31);
            const status = waitChild(container) catch linux.exit_group(32);
            if (status != 0) {
                std.debug.print("idmapped mount propagation container status: {d}\n", .{status});
                linux.exit_group(33);
            }
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(worker));
    }
}

test "linux rbind clones submounts and ridmap alone maps them recursively" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    const source = try std.fmt.allocPrintSentinel(allocator, "{s}/source", .{absolute}, 0);
    const submount = try std.fmt.allocPrintSentinel(allocator, "{s}/source/sub", .{absolute}, 0);
    const marker = try std.fmt.allocPrintSentinel(allocator, "{s}/source/sub/marker", .{absolute}, 0);
    const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/rootfs", .{absolute}, 0);
    try requireTestIDMappedMounts(source);
    const mapping: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 1 }};
    const userns = try createMountUserNamespace(allocator, .{ .uid = mapping, .gid = mapping });
    defer closeFd(userns);
    for ([_]bool{ false, true }) |recursive| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            checkResult(linux.mkdir(submount, 0o755)) catch linux.exit_group(4);
            checkResult(linux.mount("tmpfs", submount, "tmpfs", 0, 0)) catch linux.exit_group(5);
            const file = linux.open(marker, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
            checkResult(file) catch linux.exit_group(6);
            closeFd(@intCast(file));
            var mount: PreparedMount = .{
                .destination = "/data",
                .source = source,
                .type = null,
                .flags = linux.MS.BIND | linux.MS.REC,
                .propagation = 0,
                .data = "",
                .mappings = .{ .recursive = recursive },
            };
            mount.mount_fd = cloneIDMappedMount(mount, userns) catch linux.exit_group(7);
            const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(8);
            var step: RootfsStep = .{};
            applyMount(rootfs, root_fd, mount, true, linux.MS.PRIVATE | linux.MS.REC, &step) catch |err| {
                step.report(err);
                linux.exit_group(9);
            };
            closeFd(mount.mount_fd.?);
            var stat: linux.Statx = undefined;
            checkResult(linux.statx(root_fd, "data", 0, .BASIC_STATS, &stat)) catch linux.exit_group(10);
            if (stat.uid != 100000 or stat.gid != 100000) linux.exit_group(11);
            // The marker proves rbind cloned the mounted subtree in both cases.
            checkResult(linux.statx(root_fd, "data/sub/marker", 0, .BASIC_STATS, &stat)) catch linux.exit_group(12);
            const expected: u32 = if (recursive) 100000 else 0;
            if (stat.uid != expected or stat.gid != expected) linux.exit_group(13);
            checkResult(linux.statx(linux.AT.FDCWD, marker, 0, .BASIC_STATS, &stat)) catch linux.exit_group(14);
            if (stat.uid != 0 or stat.gid != 0) linux.exit_group(15);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Backend = @import("../../root.zig").Backend;
const PreparedMount = @import("../mount.zig").PreparedMount;
const mountDestination = @import("../mount.zig").mountDestination;
const remountFlags = @import("../mount.zig").remountFlags;
const applyMount = @import("../mount.zig").applyMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const openPath = @import("../syscall.zig").openPath;
const createMountUserNamespace = @import("../namespaces.zig").createMountUserNamespace;
const RootfsStep = @import("../rootfs.zig").RootfsStep;
const testPrivateUserNamespaceBindLocks = @import("helpers.zig").testPrivateUserNamespaceBindLocks;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const startMountSourceHelper = @import("../mount_sources.zig").startMountSourceHelper;
const receiveMountSources = @import("../mount_sources.zig").receiveMountSources;
const createDevice = @import("../device_nodes.zig").createDevice;

test "linux mount destinations reject symlinks without creating host paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "outside", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const outside = try std.fs.path.join(std.testing.allocator, &.{ absolute, "outside" });
    defer std.testing.allocator.free(outside);
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/escape", .{});
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/file", .{});
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const rootfs_z = try std.testing.allocator.dupeZ(u8, rootfs);
    defer std.testing.allocator.free(rootfs_z);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    if (mountDestination(root_fd, "/escape/new", false, true)) |fd| {
        closeFd(fd);
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/file", true, true));
    var step: RootfsStep = .{};
    if (createDevice(root_fd, .{ .path = "/escape/new", .mode = linux.S.IFIFO | 0o600, .dev = 0 }, true, &step)) {
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/new", .{}));
}

test "linux privileged bind remount honors atime changes and clears unrequested flags" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source);
    const ms = linux.MS;
    const cases = [_]struct { source_atime: u32, requested: u32 }{
        .{ .source_atime = ms.RELATIME, .requested = ms.STRICTATIME },
        .{ .source_atime = ms.STRICTATIME, .requested = ms.NOATIME },
        .{ .source_atime = ms.NOATIME, .requested = ms.RELATIME },
    };
    for (cases) |case| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            // Set per-mount readonly without making the superblock readonly.
            checkResult(linux.mount(null, source, null, ms.BIND | ms.REMOUNT | ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC | case.source_atime, 0)) catch linux.exit_group(4);
            const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(5);
            var step: RootfsStep = .{};
            applyMount(rootfs, root_fd, .{
                .destination = "/bound",
                .source = source,
                .type = null,
                .flags = ms.BIND | case.requested,
                .propagation = 0,
                .data = "",
            }, true, ms.PRIVATE | ms.REC, &step) catch linux.exit_group(6);
            const target = mountDestination(root_fd, "/bound", false, false) catch linux.exit_group(7);
            const actual = remountFlags(target, 0) catch linux.exit_group(8);
            if (actual != case.requested) linux.exit_group(9);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

test "linux accessible user namespace binds retain locked host mount restrictions" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    try requireTestMountNamespace();
    const ranges: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 10 }};
    const mappings: Backend.MountMappings = .{ .uid = ranges, .gid = ranges };
    const userns = createMountUserNamespace(std.testing.allocator, mappings) catch |err| switch (err) {
        error.PermissionDenied, error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    defer closeFd(userns);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/bound");
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source);
    const child = try forkProcess();
    if (child == 0) {
        const ms = linux.MS;
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
        checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
        const restrictions = ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC;
        checkResult(linux.mount(null, source, null, ms.BIND | ms.REMOUNT | restrictions, 0)) catch linux.exit_group(4);
        var mounts = [_]PreparedMount{.{
            .destination = "/bound",
            .source = source,
            .type = null,
            .flags = ms.BIND,
            .propagation = 0,
            .data = "",
        }};
        const helper = startMountSourceHelper(&mounts) catch linux.exit_group(5);
        checkResult(linux.setns(userns, linux.CLONE.NEWUSER)) catch linux.exit_group(7);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(8);
        checkResult(linux.setgid(0)) catch linux.exit_group(9);
        checkResult(linux.setuid(0)) catch linux.exit_group(10);
        const namespace = openPath(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(6);
        receiveMountSources(&mounts, helper.socket, namespace) catch linux.exit_group(15);
        closeFd(namespace);
        closeFd(helper.socket);
        if ((waitChild(helper.pid) catch linux.exit_group(16)) != 0) linux.exit_group(17);
        const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(11);
        var step: RootfsStep = .{};
        applyMount(rootfs, root_fd, mounts[0], true, ms.PRIVATE | ms.REC, &step) catch linux.exit_group(12);
        const target = mountDestination(root_fd, "/bound", false, false) catch linux.exit_group(13);
        const actual = remountFlags(target, 0) catch linux.exit_group(18);
        checkResult(linux.fchdir(root_fd)) catch linux.exit_group(19);
        checkResult(linux.chroot(".")) catch linux.exit_group(20);
        checkResult(linux.chdir("/")) catch linux.exit_group(21);
        for ([_]u32{ ms.RDONLY, ms.NOSUID, ms.NODEV, ms.NOEXEC }) |flag| {
            const result = linux.mount(null, "/bound", null, ms.BIND | ms.REMOUNT | (actual & ~flag), 0);
            if (linux.errno(result) != .PERM) linux.exit_group(14);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(child));
}

test "linux host-private user namespace binds lock host mount restrictions" {
    try testPrivateUserNamespaceBindLocks(false);
}

test "linux host-private idmapped user namespace binds lock host mount restrictions" {
    try testPrivateUserNamespaceBindLocks(true);
}

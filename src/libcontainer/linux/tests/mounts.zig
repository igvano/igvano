const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const libcontainer = @import("../../root.zig");
const LinuxContainer = @import("../../linux.zig").Container;
const diagnostics = @import("../diagnostic.zig");
const seccomp = libcontainer.seccomp;
const PreparedMount = @import("../mount.zig").PreparedMount;
const mountDestination = @import("../mount.zig").mountDestination;
const remountFlags = @import("../mount.zig").remountFlags;
const applyMount = @import("../mount.zig").applyMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const openPath = @import("../syscall.zig").openPath;
const readAll = @import("../syscall.zig").readAll;
const fileType = @import("../syscall.zig").fileType;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
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
    // Absolute symlink targets are interpreted relative to rootfs.
    const scoped_outside = try std.fmt.allocPrint(std.testing.allocator, "rootfs{s}", .{outside});
    defer std.testing.allocator.free(scoped_outside);
    try tmp.dir.createDirPath(std.testing.io, scoped_outside);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    const destination = try mountDestination(root_fd, "/escape/new", false, true);
    closeFd(destination);
    const scoped_new = try std.fmt.allocPrint(std.testing.allocator, "{s}/new", .{scoped_outside});
    defer std.testing.allocator.free(scoped_new);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try tmp.dir.statFile(std.testing.io, scoped_new, .{})).kind);
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/file", true, true));
    var step: RootfsStep = .{};
    if (createDevice(root_fd, .{ .path = "/escape/new", .mode = linux.S.IFIFO | 0o600, .dev = 0 }, true, &step)) {
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/new", .{}));
}

test "linux mount destinations follow relative and final symlinks within rootfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/var");
    try tmp.dir.createDir(std.testing.io, "rootfs/run", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "rootfs/run/token", .data = "token" });
    try tmp.dir.symLink(std.testing.io, "../run", "rootfs/var/run", .{});
    try tmp.dir.symLink(std.testing.io, "/run/token", "rootfs/file", .{});
    try tmp.dir.symLink(std.testing.io, "/run", "rootfs/directory", .{});
    try tmp.dir.symLink(std.testing.io, "../../../", "rootfs/above", .{});
    try tmp.dir.symLink(std.testing.io, "loop", "rootfs/loop", .{});
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/rootfs", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(rootfs);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    const directory = try mountDestination(root_fd, "/var/run/secrets/token-dir", false, true);
    closeFd(directory);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try tmp.dir.statFile(std.testing.io, "rootfs/run/secrets/token-dir", .{})).kind);
    const above = try mountDestination(root_fd, "/above/inside", false, true);
    closeFd(above);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try tmp.dir.statFile(std.testing.io, "rootfs/inside", .{})).kind);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "inside", .{}));
    for ([_]bool{ false, true }) |create| {
        const file = try mountDestination(root_fd, "/file", true, create);
        defer closeFd(file);
        try std.testing.expectEqual(@as(u16, linux.S.IFREG), try fileType(file));
        const dir = try mountDestination(root_fd, "/directory", false, create);
        defer closeFd(dir);
        try std.testing.expectEqual(@as(u16, linux.S.IFDIR), try fileType(dir));
        try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/directory", true, create));
        if (mountDestination(root_fd, "/file", false, create)) |fd| {
            closeFd(fd);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    for ([_][]const u8{ "/var/../run", "/var/./run", "/loop/new" }) |path| {
        if (mountDestination(root_fd, path, false, true)) |fd| {
            closeFd(fd);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "linux mount destinations reject procfs magic links" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root_fd = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    var buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buffer, "/proc/self/fd/{d}", .{root_fd});
    if (mountDestination(root_fd, path, false, false)) |fd| {
        closeFd(fd);
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "linux create bind mounts through var run symlink" {
    try testCreateSymlinkMount(false);
}

test "linux create confines absolute mount destination symlinks to rootfs" {
    try testCreateSymlinkMount(true);
}

fn testCreateSymlinkMount(absolute_symlink: bool) !void {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-symlink-mount-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    if (cgroup_root.mode == .unified) {
        const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
        closeFd(probe);
        try removeCgroup(cgroup_root.fd, cgroup_path);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/var");
    try tmp.dir.createDir(std.testing.io, "rootfs/run", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.createDir(std.testing.io, "outside", .default_dir);
    const contents = "service account token";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/item", .data = contents });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source);
    const outside = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/outside", .{absolute}, 0);
    defer std.testing.allocator.free(outside);
    const outside_fd = try openPath(linux.AT.FDCWD, outside, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(outside_fd);
    const resolved = if (absolute_symlink)
        try std.fmt.allocPrint(std.testing.allocator, "{s}/token-dir", .{outside})
    else
        try std.testing.allocator.dupe(u8, "/run/secrets/token-dir");
    defer std.testing.allocator.free(resolved);
    if (absolute_symlink) {
        const scoped_outside = try std.fmt.allocPrint(std.testing.allocator, "rootfs{s}", .{outside});
        defer std.testing.allocator.free(scoped_outside);
        try tmp.dir.createDirPath(std.testing.io, scoped_outside);
    }
    try tmp.dir.symLink(std.testing.io, if (absolute_symlink) outside else "../run", if (absolute_symlink) "rootfs/escape" else "rootfs/var/run", .{});
    const destination = if (absolute_symlink) "/escape/token-dir" else "/var/run/secrets/token-dir";
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var instance = try LinuxContainer.create(.{
        .allocator = std.testing.allocator,
        .id = "symlink-mount",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .namespaces = &.{.{ .kind = .mount }},
        .cgroup_path = cgroup_path,
        .mounts = &.{.{
            .destination = destination,
            .source = source,
            .type = null,
            .flags = linux.MS.BIND | linux.MS.RDONLY,
            .propagation = 0,
            .data = "",
        }},
    });
    defer instance.deinit(std.testing.allocator);
    const container = instance.container();
    defer {
        container.kill(9) catch {};
        container.delete() catch {};
    }
    try std.testing.expect(try container.alive());
    const namespace_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "/proc/{d}/ns/mnt", .{instance.state.pid}, 0);
    defer std.testing.allocator.free(namespace_path);
    const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    const root_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "/proc/{d}/root", .{instance.state.pid}, 0);
    defer std.testing.allocator.free(root_path);
    const root_fd = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    const resolved_item = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/item", .{resolved}, 0);
    defer std.testing.allocator.free(resolved_item);
    const destination_item = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/item", .{destination}, 0);
    defer std.testing.allocator.free(destination_item);
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        // Pin the host directory: setns may change the checker's filesystem root.
        if (linux.errno(linux.openat(outside_fd, "token-dir/item", .{ .PATH = true, .CLOEXEC = true }, 0)) != .NOENT)
            linux.exit_group(2);
        checkResult(linux.fchdir(root_fd)) catch linux.exit_group(3);
        checkResult(linux.chroot(".")) catch linux.exit_group(4);
        checkResult(linux.chdir("/")) catch linux.exit_group(5);
        for ([_][:0]const u8{ resolved_item, destination_item }) |path| {
            const fd = openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(6);
            var buffer: [contents.len]u8 = undefined;
            if (!readAll(fd, &buffer) or !std.mem.eql(u8, &buffer, contents)) linux.exit_group(7);
            closeFd(fd);
            if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0)) != .ROFS) linux.exit_group(8);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/token-dir", .{}));
}

test "linux mount destinations fail closed when openat2 is unavailable" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const arch = seccomp.Arch.native() orelse return error.SkipZigTest;
    for ([_]linux.E{ .NOSYS, .@"2BIG" }) |denied| {
        const program = try seccomp.compile(std.testing.allocator, .{
            .default_action = .allow,
            .architectures = &.{arch},
            .rules = &.{.{ .arch = arch, .number = @intFromEnum(linux.SYS.openat2), .action = .errno, .errno_ret = @intCast(@intFromEnum(denied)) }},
        }, arch);
        defer std.testing.allocator.free(program.filters);
        const pid = try forkProcess();
        if (pid == 0) {
            const root_fd = openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
            checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(2);
            if (seccomp.install(program) != .SUCCESS) linux.exit_group(3);
            if (mountDestination(root_fd, "/", false, false)) |fd| {
                closeFd(fd);
                linux.exit_group(4);
            } else |err| {
                if (err != error.Unsupported) linux.exit_group(5);
                const message = diagnostics.diagnostic() orelse linux.exit_group(6);
                if (std.mem.indexOf(u8, message, "openat2") == null or std.mem.indexOf(u8, message, "required") == null)
                    linux.exit_group(7);
            }
            var step: RootfsStep = .{};
            if (applyMount("/", root_fd, .{
                .destination = "/",
                .source = "tmpfs",
                .type = "tmpfs",
                .flags = 0,
                .propagation = 0,
                .data = "",
            }, true, linux.MS.PRIVATE | linux.MS.REC, &step)) {
                linux.exit_group(8);
            } else |err| {
                if (err != error.Unsupported) linux.exit_group(9);
                step.report(err);
                const message = diagnostics.diagnostic() orelse linux.exit_group(10);
                if (std.mem.indexOf(u8, message, "openat2") == null or std.mem.indexOf(u8, message, "required") == null)
                    linux.exit_group(11);
            }
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

test "linux mount destinations report exhausted openat2 EAGAIN retries" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const arch = seccomp.Arch.native() orelse return error.SkipZigTest;
    const program = try seccomp.compile(std.testing.allocator, .{
        .default_action = .allow,
        .architectures = &.{arch},
        .rules = &.{.{ .arch = arch, .number = @intFromEnum(linux.SYS.openat2), .action = .errno, .errno_ret = @intCast(@intFromEnum(linux.E.AGAIN)) }},
    }, arch);
    defer std.testing.allocator.free(program.filters);
    const pid = try forkProcess();
    if (pid == 0) {
        const root_fd = openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
        checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(2);
        if (seccomp.install(program) != .SUCCESS) linux.exit_group(3);
        if (mountDestination(root_fd, "/", false, false)) |fd| {
            closeFd(fd);
            linux.exit_group(4);
        } else |err| {
            if (err != error.SystemResources) linux.exit_group(5);
            const message = diagnostics.diagnostic() orelse linux.exit_group(6);
            if (std.mem.indexOf(u8, message, "EAGAIN after 32 attempts") == null) linux.exit_group(7);
        }
        var step: RootfsStep = .{};
        if (applyMount("/", root_fd, .{
            .destination = "/",
            .source = "tmpfs",
            .type = "tmpfs",
            .flags = 0,
            .propagation = 0,
            .data = "",
        }, true, linux.MS.PRIVATE | linux.MS.REC, &step)) {
            linux.exit_group(8);
        } else |err| {
            if (err != error.SystemResources) linux.exit_group(9);
            step.report(err);
            const message = diagnostics.diagnostic() orelse linux.exit_group(10);
            if (std.mem.indexOf(u8, message, "EAGAIN after 32 attempts") == null) linux.exit_group(11);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
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
    const ranges: []const libcontainer.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 10 }};
    const mappings: libcontainer.MountMappings = .{ .uid = ranges, .gid = ranges };
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

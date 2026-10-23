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

test "linux mount destinations confine symlinks to rootfs without creating host paths" {
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

test "linux dangling mount destinations reject procfs links during expansion" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/proc");
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/rootfs", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(rootfs);
    const proc = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/proc", .{rootfs}, 0);
    defer std.testing.allocator.free(proc);
    const host_root = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(host_root);
    var target_buffer: [128]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buffer, "/proc/self/igvano-missing-{d}", .{linux.getpid()});
    try tmp.dir.symLink(std.testing.io, target, "rootfs/entry", .{});
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(2);
        checkResult(linux.mount("/proc", proc, null, linux.MS.BIND, 0)) catch linux.exit_group(3);
        // A fd opened before unshare pins the old mount and cannot see this proc bind.
        const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(8);
        if (mountDestination(root_fd, "/entry/escaped", false, true)) |fd| {
            closeFd(fd);
            linux.exit_group(4);
        } else |err| {
            const diagnostic = diagnostics.diagnostic() orelse linux.exit_group(5);
            if (err != error.InvalidPath or std.mem.indexOf(u8, diagnostic, "procfs") == null) linux.exit_group(5);
        }
        if (linux.errno(linux.openat(root_fd, "escaped", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0)) != .NOENT)
            linux.exit_group(6);
        if (linux.errno(linux.openat(host_root, "escaped", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0)) != .NOENT)
            linux.exit_group(7);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux create bind mounts through var run symlink" {
    try testCreateSymlinkMount(false);
}

test "linux create confines absolute mount destination symlinks to rootfs" {
    try testCreateSymlinkMount(true);
}

test "linux create file bind follows dangling resolv conf symlink" {
    try testCreateDanglingMount("/etc/resolv.conf", "etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/stub-resolv.conf", true);
}

test "linux create directory bind follows dangling var run symlink" {
    try testCreateDanglingMount("/var/run/secrets/x", "var/run", "/run", "/run/secrets/x", false);
}

test "linux create dangling mount targets clamp parent traversal and absolute root" {
    try testCreateDanglingMount("/entry/item", "entry", "../../../../host-escape", "/host-escape/item", false);
    try testCreateDanglingMount("/entry/missing/item", "entry", "/", "/missing/item", false);
}

fn testCreateDanglingMount(destination: [:0]const u8, link: []const u8, target: []const u8, resolved: [:0]const u8, is_file: bool) !void {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-dangling-mount-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    if (cgroup_root.mode == .unified) {
        const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch |err| switch (err) {
            error.PermissionDenied, error.Unsupported => return error.SkipZigTest,
            else => return err,
        }).?;
        closeFd(probe);
        try removeCgroup(cgroup_root.fd, cgroup_path);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/etc");
    try tmp.dir.createDir(std.testing.io, "rootfs/var", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    const contents = "bound through a dangling symlink";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/item", .data = contents });
    const link_path = try std.fmt.allocPrint(std.testing.allocator, "rootfs/{s}", .{link});
    defer std.testing.allocator.free(link_path);
    try tmp.dir.symLink(std.testing.io, target, link_path, .{});
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source{s}", .{ absolute, if (is_file) "/item" else "" }, 0);
    defer std.testing.allocator.free(source);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const host_root = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(host_root);
    var missing_buffer: [128]u8 = undefined;
    const missing = try std.fmt.bufPrintZ(&missing_buffer, "{s}/igvano-missing-{d}", .{ destination, linux.getpid() });
    // Pin the host root before joining init's namespace, then check both
    // fixtures which would create host paths if resolution were unconfined.
    const host_path: ?[:0]const u8 = if (std.mem.startsWith(u8, resolved, "/host-escape/"))
        "host-escape/item"
    else if (std.mem.eql(u8, target, "/"))
        "missing/item"
    else
        null;
    if (host_path) |path| try expectMissingMountHostPath(host_root, path);
    var instance = try LinuxContainer.create(.{
        .allocator = std.testing.allocator,
        .id = "dangling-mount",
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
    const created = try std.fmt.allocPrint(std.testing.allocator, "rootfs{s}", .{resolved});
    defer std.testing.allocator.free(created);
    try std.testing.expectEqual(if (is_file) std.Io.File.Kind.file else .directory, (try tmp.dir.statFile(std.testing.io, created, .{})).kind);
    const namespace_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "/proc/{d}/ns/mnt", .{instance.state.pid}, 0);
    defer std.testing.allocator.free(namespace_path);
    const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    const root_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "/proc/{d}/root", .{instance.state.pid}, 0);
    defer std.testing.allocator.free(root_path);
    const root_fd = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    const resolved_item = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}{s}", .{ resolved, if (is_file) "" else "/item" }, 0);
    defer std.testing.allocator.free(resolved_item);
    const destination_item = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}{s}", .{ destination, if (is_file) "" else "/item" }, 0);
    defer std.testing.allocator.free(destination_item);
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        if (host_path) |path| {
            if (linux.errno(linux.openat(host_root, path, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0)) != .NOENT)
                linux.exit_group(2);
        }
        checkResult(linux.fchdir(root_fd)) catch linux.exit_group(3);
        checkResult(linux.chroot(".")) catch linux.exit_group(4);
        checkResult(linux.chdir("/")) catch linux.exit_group(5);
        for ([_][:0]const u8{ resolved_item, destination_item }) |path| {
            const fd = openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(6);
            var buffer: [contents.len]u8 = undefined;
            if (!readAll(fd, &buffer) or !std.mem.eql(u8, &buffer, contents)) linux.exit_group(7);
            closeFd(fd);
            // Verify an actual readonly bind mount, not merely a created path.
            if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0)) != .ROFS) linux.exit_group(8);
        }
        if (!is_file and linux.errno(linux.open(missing, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o600)) != .ROFS)
            linux.exit_group(9);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

fn expectMissingMountHostPath(fd: std.posix.fd_t, path: [:0]const u8) !void {
    const result = linux.openat(fd, path, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(result) == .SUCCESS) closeFd(@intCast(result));
    try std.testing.expectEqual(linux.E.NOENT, linux.errno(result));
}

test "linux dangling mount destinations resolve relative targets after symlinked parents" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/nested/parent");
    try tmp.dir.symLink(std.testing.io, "/nested/parent", "rootfs/alias", .{});
    try tmp.dir.symLink(std.testing.io, "../missing/./child", "rootfs/nested/parent/link", .{});
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/rootfs", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(rootfs);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    try std.testing.expectError(error.CreateFailed, mountDestination(root_fd, "/alias/link/file", true, false));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/nested/missing", .{}));
    const fd = try mountDestination(root_fd, "/alias/link/file", true, true);
    closeFd(fd);
    try std.testing.expectEqual(std.Io.File.Kind.file, (try tmp.dir.statFile(std.testing.io, "rootfs/nested/missing/child/file", .{})).kind);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/missing", .{}));
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/alias/link/../bad", false, true));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/nested/missing/child/bad", .{}));
}

test "linux dangling mount destinations reject parent traversal after missing components" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.symLink(std.testing.io, "/missing/../proc", "rootfs/entry", .{});
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/rootfs", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(rootfs);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    diagnostics.last_diagnostic_len = 0;
    if (mountDestination(root_fd, "/entry", false, true)) |fd| {
        closeFd(fd);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.InvalidPath, err);
    }
    try std.testing.expect(diagnostics.diagnostic() != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/missing", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/proc", .{}));
}

test "linux dangling mount destinations bound symlink loops and expanded paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.symLink(std.testing.io, "b", "rootfs/a", .{});
    try tmp.dir.symLink(std.testing.io, "a", "rootfs/b", .{});
    // Each expansion remains within PATH_MAX, but their combined path does not.
    const long_target = ("component/" ** 230) ++ "tail";
    try tmp.dir.symLink(std.testing.io, long_target, "rootfs/long", .{});
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/rootfs", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(rootfs);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/a/missing", false, true));
    try std.testing.expect(diagnostics.diagnostic() != null);
    const overflow = "/long/" ++ ("suffix/" ** 300) ++ "file";
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, overflow, true, true));
    try std.testing.expect(diagnostics.diagnostic() != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/component", .{}));
    var too_long: [linux.PATH_MAX]u8 = @splat('x');
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, &too_long, false, true));
    try std.testing.expect(diagnostics.diagnostic() != null);
    // A dangling chain of exactly forty expansions is allowed.
    for (0..41) |i| {
        var link_buffer: [64]u8 = undefined;
        var target_buffer: [64]u8 = undefined;
        const chain_link = try std.fmt.bufPrint(&link_buffer, "rootfs/chain-{d}", .{i});
        const chain_target = if (i == 40) "missing" else try std.fmt.bufPrint(&target_buffer, "chain-{d}", .{i + 1});
        try tmp.dir.symLink(std.testing.io, chain_target, chain_link, .{});
    }
    try tmp.dir.symLink(std.testing.io, "absent/../chain-1", "rootfs/over-limit", .{});
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/over-limit", false, true));
    try std.testing.expect(diagnostics.diagnostic() != null);
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/chain-0", false, true));
    try std.testing.expect(diagnostics.diagnostic() != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "rootfs/missing", .{}));
    const fd = try mountDestination(root_fd, "/chain-1", false, true);
    closeFd(fd);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try tmp.dir.statFile(std.testing.io, "rootfs/missing", .{})).kind);
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
            if (err != error.ResolveRetryExhausted) linux.exit_group(5);
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
            if (err != error.ResolveRetryExhausted) linux.exit_group(9);
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

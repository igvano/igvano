const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../../backend.zig").Backend;
const queryDevicePrograms = @import("../devices.zig").queryDevicePrograms;
const OPEN_TREE_CLONE = @import("../mount.zig").OPEN_TREE_CLONE;
const OPEN_TREE_CLOEXEC = @import("../mount.zig").OPEN_TREE_CLOEXEC;
const MOUNT_ATTR_IDMAP = @import("../mount.zig").MOUNT_ATTR_IDMAP;
const MountAttr = @import("../mount.zig").MountAttr;
const PreparedMount = @import("../mount.zig").PreparedMount;
const mountDestination = @import("../mount.zig").mountDestination;
const remountFlags = @import("../mount.zig").remountFlags;
const applyMount = @import("../mount.zig").applyMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const writeCgroupFile = @import("../cgroup.zig").writeCgroupFile;
const V1Hierarchy = @import("../cgroup_v1.zig").V1Hierarchy;
const removeV1Cgroups = @import("../cgroup_v1.zig").removeV1Cgroups;
const removeV1Cgroup = @import("../cgroup_v1.zig").removeV1Cgroup;
const NamespaceJoin = @import("../namespaces.zig").NamespaceJoin;
const joinNamespaces = @import("../namespaces.zig").joinNamespaces;
const createMountUserNamespace = @import("../namespaces.zig").createMountUserNamespace;
const readMountinfo = @import("../mountinfo.zig").readMountinfo;
const MountInfo = @import("../mountinfo.zig").MountInfo;
const mountinfoPath = @import("../mountinfo.zig").mountinfoPath;
const mountId = @import("../rootfs.zig").mountId;
const statMount = @import("../rootfs.zig").statMount;
const RootfsStep = @import("../rootfs.zig").RootfsStep;
const startMountSourceHelper = @import("../mount_sources.zig").startMountSourceHelper;
const receiveMountSources = @import("../mount_sources.zig").receiveMountSources;
const LinuxBackend = @import("../../linux.zig").LinuxBackend;

pub fn cleanupV1TestHierarchies(hierarchies: []const V1Hierarchy, path: []const u8) void {
    removeV1Cgroups(hierarchies, path) catch {};
    for (hierarchies) |hierarchy| {
        if (std.fs.path.dirname(path)) |parent| {
            const fd = (walkCgroup(hierarchy.root.?, parent, false, &.{}) catch null) orelse continue;
            defer closeFd(fd);
            removeV1Cgroup(hierarchy.root.?, hierarchy.mount_root, parent, fd, null, null) catch {};
        }
    }
}

pub fn checkV2TestDevices(cgroup: posix.fd_t, namespace: posix.fd_t, root: posix.fd_t, allowed: bool) !void {
    const ids = try queryDevicePrograms(std.testing.allocator, cgroup, "device-test");
    defer std.testing.allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 1), ids.len);
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.fchdir(root)) catch linux.exit_group(2);
        checkResult(linux.chroot(".")) catch linux.exit_group(3);
        checkResult(linux.chdir("/")) catch linux.exit_group(4);
        // Seed a visible node from outside the container's device cgroup.
        const created = linux.errno(linux.mknod("/dev/denied", linux.S.IFCHR | 0o600, (10 << 8) | 237));
        if (created != .SUCCESS and created != .EXIST) linux.exit_group(5);
        _ = linux.unlink("/dev/denied-new");
        writeCgroupFile(cgroup, "cgroup.procs", "0", "device-test") catch linux.exit_group(6);
        const null_fd = openPath(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }) catch linux.exit_group(7);
        closeFd(null_fd);
        const zero_node = linux.errno(linux.mknod("/dev/zero", linux.S.IFCHR | 0o600, 0x105));
        if (zero_node != .SUCCESS and zero_node != .EXIST) linux.exit_group(11);
        const zero = openPath(linux.AT.FDCWD, "/dev/zero", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(12);
        closeFd(zero);
        const denied = linux.open("/dev/denied", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(denied) != (if (allowed) linux.E.SUCCESS else linux.E.PERM)) linux.exit_group(8);
        if (allowed) closeFd(@intCast(denied));
        const node = linux.errno(linux.mknod("/dev/zero-new", linux.S.IFCHR | 0o600, 0x105));
        if (node != .SUCCESS and node != .EXIST) linux.exit_group(13);
        const denied_node = linux.errno(linux.mknod("/dev/denied-new", linux.S.IFCHR | 0o600, (10 << 8) | 237));
        // Runc's defaults permit mknod even for devices denied read/write.
        if (denied_node != .SUCCESS) linux.exit_group(9);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

pub fn checkV2TestDefaultDevices(cgroup: posix.fd_t, namespace: posix.fd_t, root: posix.fd_t) !void {
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.fchdir(root)) catch linux.exit_group(2);
        checkResult(linux.chroot(".")) catch linux.exit_group(3);
        checkResult(linux.chdir("/")) catch linux.exit_group(4);
        writeCgroupFile(cgroup, "cgroup.procs", "0", "default-device-test") catch linux.exit_group(5);
        for ([_]struct { path: [:0]const u8, dev: u32 }{
            .{ .path = "/dev/null", .dev = 0x103 },
            .{ .path = "/dev/zero", .dev = 0x105 },
            .{ .path = "/dev/full", .dev = 0x107 },
            .{ .path = "/dev/random", .dev = 0x108 },
            .{ .path = "/dev/urandom", .dev = 0x109 },
        }) |device| {
            const err = linux.errno(linux.mknod(device.path, linux.S.IFCHR | 0o666, device.dev));
            if (err != .SUCCESS and err != .EXIST) linux.exit_group(6);
            const fd = openPath(linux.AT.FDCWD, device.path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }) catch linux.exit_group(7);
            closeFd(fd);
        }
        // Opening ptmx and its peer exercises both 5:2 and 136:*.
        const controller = openPath(linux.AT.FDCWD, "/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }) catch linux.exit_group(8);
        var unlock: i32 = 0;
        checkResult(linux.ioctl(controller, linux.T.IOCSPTLCK, @intFromPtr(&unlock))) catch linux.exit_group(9);
        var number: u32 = 0;
        checkResult(linux.ioctl(controller, linux.T.IOCGPTN, @intFromPtr(&number))) catch linux.exit_group(10);
        var buffer: [64]u8 = undefined;
        const path = std.fmt.bufPrintZ(&buffer, "/dev/pts/{d}", .{number}) catch linux.exit_group(11);
        const peer = openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }) catch linux.exit_group(12);
        checkResult(linux.setsid()) catch linux.exit_group(13);
        checkResult(linux.ioctl(peer, linux.T.IOCSCTTY, 0)) catch linux.exit_group(14);
        const tty_node = linux.errno(linux.mknod("/dev/tty", linux.S.IFCHR | 0o666, 0x500));
        if (tty_node != .SUCCESS and tty_node != .EXIST) linux.exit_group(15);
        const tty = openPath(linux.AT.FDCWD, "/dev/tty", .{ .ACCMODE = .RDWR, .CLOEXEC = true }) catch linux.exit_group(16);
        closeFd(tty);
        const console_node = linux.errno(linux.mknod("/dev/console", linux.S.IFCHR | 0o600, 0x501));
        if (console_node != .SUCCESS and console_node != .EXIST) linux.exit_group(17);
        // Console is not in runc's built-in defaults.
        const console_fd = linux.open("/dev/console", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0);
        if (linux.errno(console_fd) != .PERM) linux.exit_group(18);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

pub fn testIDMappedBindOwnership(base: []const u8, cgroup_path: []const u8) !void {
    const Mode = enum { new, joined, joined_without_mappings, plain };
    for ([_]Mode{ .new, .joined, .joined_without_mappings, .plain }) |mode| {
        const with_userns = mode != .plain;
        const joined = mode == .joined or mode == .joined_without_mappings;
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const suffix = @tagName(mode);
        const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}-rootfs", .{ base, suffix }, 0);
        const source = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}-source", .{ base, suffix }, 0);
        const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.fifo", .{ base, suffix }, 0);
        const created = try std.fmt.allocPrintSentinel(allocator, "{s}/created", .{source}, 0);
        try checkResult(linux.mkdir(rootfs, 0o755));
        try checkResult(linux.mkdir(source, 0o755));
        try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
        const source_uid: u32 = if (with_userns) 0 else 1000;
        const container_uid: u32 = if (with_userns) 100000 else 0;
        try checkResult(linux.chown(rootfs, container_uid, container_uid));
        try checkResult(linux.chown(source, source_uid, source_uid));
        const container_mapping: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 1 }};
        var options: Backend.CreateOptions = .{
            .allocator = allocator,
            .id = suffix,
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .namespaces = &.{.{ .kind = .mount }},
            .cgroup_path = cgroup_path,
        };
        if (with_userns) {
            options.namespaces = &.{ .{ .kind = .user }, .{ .kind = .mount } };
            options.uid_mappings = container_mapping;
            options.gid_mappings = container_mapping;
        }
        var joined_fd: ?posix.fd_t = null;
        defer if (joined_fd) |fd| closeFd(fd);
        if (joined) {
            const ranges: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 1 }};
            const fd = try createMountUserNamespace(allocator, .{ .uid = ranges, .gid = ranges });
            joined_fd = fd;
            const path = try std.fmt.allocPrintSentinel(allocator, "/proc/self/fd/{d}", .{fd}, 0);
            options.namespaces = &.{ .{ .kind = .user, .path = path }, .{ .kind = .mount } };
            if (mode == .joined_without_mappings) {
                options.uid_mappings = &.{};
                options.gid_mappings = &.{};
            }
        }
        // The mount map translates filesystem IDs to kernel IDs. Thus 0:100000
        // exposes a host-root-owned tree as root in a 0:100000 container.
        const mapping: []const Backend.IDMapping = &.{.{ .container_id = source_uid, .host_id = container_uid, .size = 1 }};
        const mappings: Backend.MountMappings = if (joined) .{
            .userns_path = options.namespaces[0].path,
        } else .{
            .uid = mapping,
            .gid = mapping,
        };
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        options.mounts = &.{.{
            .destination = "/data",
            .source = source,
            .type = null,
            .flags = linux.MS.BIND,
            .propagation = 0,
            .data = "",
            .mappings = mappings,
        }};
        const handle = try backend.create(options);
        defer {
            backend.kill(handle, 9) catch {};
            backend.delete(handle) catch {};
        }
        const proc_root = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/root", .{handle.pid}, 0);
        const root_fd = try openPath(linux.AT.FDCWD, proc_root, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        const joins = [_]NamespaceJoin{
            .{ .flag = linux.CLONE.NEWUSER, .path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/ns/user", .{handle.pid}, 0) },
            .{ .flag = linux.CLONE.NEWNS, .path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/ns/mnt", .{handle.pid}, 0) },
        };
        const inspector = try forkProcess();
        if (inspector == 0) {
            joinNamespaces(if (with_userns) &joins else joins[1..]) catch linux.exit_group(1);
            checkResult(linux.setgid(0)) catch linux.exit_group(2);
            checkResult(linux.setuid(0)) catch linux.exit_group(3);
            checkResult(linux.fchdir(root_fd)) catch linux.exit_group(4);
            checkResult(linux.chroot(".")) catch linux.exit_group(5);
            checkResult(linux.chdir("/")) catch linux.exit_group(6);
            var stat: linux.Statx = undefined;
            checkResult(linux.statx(linux.AT.FDCWD, "/data", 0, .BASIC_STATS, &stat)) catch linux.exit_group(7);
            if (stat.uid != 0 or stat.gid != 0) linux.exit_group(8);
            const file = linux.open("/data/created", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o644);
            checkResult(file) catch linux.exit_group(9);
            closeFd(@intCast(file));
            checkResult(linux.statx(linux.AT.FDCWD, "/data/created", 0, .BASIC_STATS, &stat)) catch linux.exit_group(10);
            if (stat.uid != 0 or stat.gid != 0) linux.exit_group(11);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(inspector));
        var stat: linux.Statx = undefined;
        try checkResult(linux.statx(linux.AT.FDCWD, created, 0, .BASIC_STATS, &stat));
        try std.testing.expectEqual(source_uid, stat.uid);
        try std.testing.expectEqual(source_uid, stat.gid);
        // The source itself was never chowned by the runtime.
        try checkResult(linux.statx(linux.AT.FDCWD, source, 0, .BASIC_STATS, &stat));
        try std.testing.expectEqual(source_uid, stat.uid);
        try std.testing.expectEqual(source_uid, stat.gid);
    }
}

/// Probe on tmpfs in an isolated mount namespace so unsupported kernels skip
/// without hiding failures on the actual bind source's filesystem.
pub fn requireTestIDMappedMounts(path: [:0]const u8) !void {
    const mapping: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 100000, .size = 1 }};
    const userns = createMountUserNamespace(std.testing.allocator, .{ .uid = mapping, .gid = mapping }) catch |err| switch (err) {
        error.PermissionDenied, error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    defer closeFd(userns);
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(2);
        checkResult(linux.mount("tmpfs", path, "tmpfs", 0, 0)) catch linux.exit_group(3);
        const tree = linux.syscall3(.open_tree, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(path.ptr), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        if (linux.errno(tree) == .NOSYS) linux.exit_group(77);
        checkResult(tree) catch linux.exit_group(4);
        const attr: MountAttr = .{ .attr_set = MOUNT_ATTR_IDMAP, .userns_fd = @intCast(userns) };
        const result = linux.syscall5(.mount_setattr, tree, @intFromPtr(""), linux.AT.EMPTY_PATH, @intFromPtr(&attr), @sizeOf(MountAttr));
        switch (linux.errno(result)) {
            .SUCCESS => linux.exit_group(0),
            .NOSYS, .INVAL => linux.exit_group(77),
            else => linux.exit_group(5),
        }
    }
    const status = try waitChild(pid);
    if (status == 77 << 8) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), status);
}

pub fn testPrivateUserNamespaceBindLocks(idmapped: bool) !void {
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
    const private_source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/private/data", .{source}, 0);
    defer std.testing.allocator.free(private_source);
    if (idmapped) try requireTestIDMappedMounts(source);
    const ms = linux.MS;
    const restrictions = ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC;
    for ([_]u32{ ms.RDONLY, ms.NOEXEC }) |requested| {
        const child = try forkProcess();
        if (child == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            checkResult(linux.chdir(source)) catch linux.exit_group(4);
            checkResult(linux.mkdir("private", 0o700)) catch linux.exit_group(5);
            checkResult(linux.mkdir("private/data", 0o700)) catch linux.exit_group(6);
            const owner: u32 = if (idmapped) 0 else 100000;
            checkResult(linux.chown("private/data", owner, owner)) catch linux.exit_group(21);
            checkResult(linux.mount(null, source, null, ms.BIND | ms.REMOUNT | restrictions, 0)) catch linux.exit_group(7);
            var mounts = [_]PreparedMount{.{
                .destination = "/bound",
                .source = private_source,
                .type = null,
                .flags = ms.BIND | requested,
                .propagation = 0,
                .data = "",
                .mappings = if (idmapped) mappings else null,
                .userns_fd = if (idmapped) userns else null,
            }};
            const helper = startMountSourceHelper(&mounts) catch linux.exit_group(8);
            checkResult(linux.setns(userns, linux.CLONE.NEWUSER)) catch linux.exit_group(10);
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(11);
            checkResult(linux.setgid(0)) catch linux.exit_group(12);
            checkResult(linux.setuid(0)) catch linux.exit_group(13);
            const inaccessible = linux.open(private_source, .{ .PATH = true, .CLOEXEC = true }, 0);
            if (linux.errno(inaccessible) != .ACCES) linux.exit_group(9);
            const namespace = openPath(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(22);
            receiveMountSources(&mounts, helper.socket, namespace) catch linux.exit_group(23);
            closeFd(namespace);
            closeFd(helper.socket);
            if ((waitChild(helper.pid) catch linux.exit_group(24)) != 0) linux.exit_group(25);
            const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(14);
            var step: RootfsStep = .{};
            applyMount(rootfs, root_fd, mounts[0], true, ms.PRIVATE | ms.REC, &step) catch |err| {
                step.report(err);
                linux.exit_group(15);
            };
            const target = mountDestination(root_fd, "/bound", false, false) catch linux.exit_group(16);
            const actual = remountFlags(target, 0) catch linux.exit_group(17);
            if (actual & restrictions != restrictions) linux.exit_group(18);
            checkResult(linux.fchdir(root_fd)) catch linux.exit_group(26);
            checkResult(linux.chroot(".")) catch linux.exit_group(27);
            checkResult(linux.chdir("/")) catch linux.exit_group(28);
            for ([_]u32{ ms.RDONLY, ms.NOSUID, ms.NODEV, ms.NOEXEC }) |flag| {
                const result = linux.mount(null, "/bound", null, ms.BIND | ms.REMOUNT | (actual & ~flag), 0);
                if (linux.errno(result) != .PERM) linux.exit_group(19);
            }
            const atime_mask = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
            const atime = if (actual & ms.NOATIME != 0) @as(u32, ms.RELATIME) else ms.NOATIME;
            const remount = linux.mount(null, "/bound", null, ms.BIND | ms.REMOUNT | (actual & ~@as(u32, atime_mask)) | atime, 0);
            if (linux.errno(remount) != .PERM) linux.exit_group(29);
            // The leaf is writable by mapped root; only the mount denies writes.
            const file = linux.open("/bound/created", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
            if (linux.errno(file) != .ROFS) linux.exit_group(20);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(child));
    }
}

pub fn expectNoRootfsMount(rootfs: []const u8) !void {
    const text = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(text);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (lines.next()) |line| {
        const entry = try MountInfo.parse(line);
        const path = try mountinfoPath(&buffer, entry.mountpoint);
        if (std.mem.eql(u8, path, rootfs) or
            (std.mem.startsWith(u8, path, rootfs) and path.len > rootfs.len and path[rootfs.len] == '/'))
        {
            std.debug.print("unexpected mount under rootfs: {s}\n", .{line});
            return error.TestUnexpectedResult;
        }
    }
}

pub fn expectOutsideRootfsUnchanged(before: []const u8, rootfs: []const u8) !void {
    const after = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(after);
    var outside: std.ArrayList(u8) = .empty;
    defer outside.deinit(std.testing.allocator);
    var lines = std.mem.tokenizeScalar(u8, after, '\n');
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (lines.next()) |line| {
        const path = try mountinfoPath(&buffer, (try MountInfo.parse(line)).mountpoint);
        if (std.mem.eql(u8, path, rootfs) or
            (std.mem.startsWith(u8, path, rootfs) and path.len > rootfs.len and path[rootfs.len] == '/'))
            continue;
        try outside.appendSlice(std.testing.allocator, line);
        try outside.append(std.testing.allocator, '\n');
    }
    try std.testing.expectEqualStrings(before, outside.items);
}

pub fn requireTestMountNamespace() !void {
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(pid) != 0) return error.SkipZigTest;
}

pub fn requireTestUniqueMountIds() !void {
    const fd = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(fd);
    const id = mountId(fd) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    _ = statMount(id) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
}

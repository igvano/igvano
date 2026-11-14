const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../../root.zig");
const hooks = @import("../../hooks.zig");
const PreparedMount = @import("../mount.zig").PreparedMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const makePipe = @import("../syscall.zig").makePipe;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const writeAll = @import("../syscall.zig").writeAll;
const openPath = @import("../syscall.zig").openPath;
const mountId = @import("../rootfs.zig").mountId;
const bootId = @import("../rootfs.zig").bootId;
const setupRootfs = @import("../rootfs.zig").setupRootfs;
const expectNoRootfsMount = @import("helpers.zig").expectNoRootfsMount;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const requireTestUniqueMountIds = @import("helpers.zig").requireTestUniqueMountIds;
const console = @import("../console.zig").console;
const PreparedDevice = @import("../device_nodes.zig").PreparedDevice;
const LinuxContainer = @import("../../linux.zig").Container;

test "linux rootfs console setup precedes restrictions and readonly without a dev tmpfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try testRootfsConsole(true, true);
}

test "linux rootfs cleanup preserves replacement self-binds and mounts from another boot" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    try requireTestUniqueMountIds();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "rootfs" });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.testing.allocator.dupeZ(u8, absolute);
    defer std.testing.allocator.free(rootfs);
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        testReplacementRootfsMount(rootfs) catch |err| {
            std.debug.print("replacement rootfs mount test: {s}\n", .{@errorName(err)});
            linux.exit_group(2);
        };
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

fn testReplacementRootfsMount(rootfs: [:0]const u8) !void {
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    const handle: libcontainer.State = .{
        .id = "replacement",
        .pid = 0,
        .starttime = "",
        .rootfs_mount = rootfs,
        .rootfs_mount_id = id: {
            const fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
            defer closeFd(fd);
            break :id try mountId(fd);
        },
        .rootfs_mount_boot_id = try bootId(),
    };
    // No descriptors or processes retain A's mount: its reusable ID is free.
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    const fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(fd);
    const replacement_id = try mountId(fd);
    try std.testing.expect(handle.rootfs_mount_id.? != replacement_id);
    try (delete: {
        var instance = LinuxContainer.load(handle);
        break :delete instance.container().delete();
    });
    const current_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(current_fd);
    try std.testing.expectEqual(replacement_id, try mountId(current_fd));
    var reboot_handle = handle;
    reboot_handle.rootfs_mount_id = replacement_id;
    reboot_handle.rootfs_mount_boot_id.?[0] ^= 1;
    try (delete: {
        var instance = LinuxContainer.load(reboot_handle);
        break :delete instance.container().delete();
    });
    var legacy_handle = handle;
    legacy_handle.rootfs_mount_id = replacement_id;
    legacy_handle.rootfs_mount_boot_id = null;
    try (delete: {
        var instance = LinuxContainer.load(legacy_handle);
        break :delete instance.container().delete();
    });
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID_UNIQUE = true }, &stat));
    try std.testing.expectEqual(replacement_id, stat.mnt_id);
    var replacement_handle = handle;
    replacement_handle.rootfs_mount_id = replacement_id;
    try (delete: {
        var instance = LinuxContainer.load(replacement_handle);
        break :delete instance.container().delete();
    });
    try expectNoRootfsMount(rootfs);
    try (delete: {
        var instance = LinuxContainer.load(replacement_handle);
        break :delete instance.container().delete();
    });
}

test "linux rootfs console setup uses move mount without procfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try testRootfsConsole(false, false);
}

fn testRootfsConsole(readonly: bool, mount_proc: bool) !void {
    try requireTestMountNamespace();
    if (!mount_proc) {
        // Invalid descriptors probe syscall availability without changing mounts.
        const invalid_fd = std.math.maxInt(usize);
        if (linux.errno(linux.syscall3(.open_tree, invalid_fd, @intFromPtr(""), linux.AT.EMPTY_PATH)) == .NOSYS or
            linux.errno(linux.move_mount(-1, "", -1, "", std.mem.zeroes(linux.MOVE_MOUNT))) == .NOSYS)
            return error.SkipZigTest;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = linux.MS.NOSUID | linux.MS.NOEXEC, .propagation = 0, .data = "newinstance,ptmxmode=666,mode=620" },
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
    };
    const symlinks = [_]libcontainer.Symlink{.{ .path = "/dev/ptmx", .target = "pts/ptmx" }};
    const sockets = try console.socketpair();
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(sockets[0]);
        closeFd(go[1]);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        // Exercise retained root descriptors when console replaces closed stdio.
        for (0..3) |fd| closeFd(@intCast(fd));
        setupRootfs(rootfs, mounts[0..if (mount_proc) 2 else 1], &.{}, &symlinks, readonly, .{
            .console_fd = sockets[1],
            .masked_paths = if (readonly) &.{"/dev/pts"} else &.{},
            .readonly_paths = if (readonly) &.{"/dev"} else &.{},
        }) catch linux.exit_group(2);
        if (linux.errno(linux.fcntl(sockets[1], linux.F.GETFD, 0)) != .BADF) linux.exit_group(3);
        if (!mount_proc and linux.errno(linux.access("/proc/self/fd", linux.F_OK)) != .NOENT) linux.exit_group(4);
        if (readonly) {
            for ([_][*:0]const u8{ "/new", "/dev/new" }) |path| {
                if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600)) != .ROFS)
                    linux.exit_group(5);
            }
            if (linux.errno(linux.access("/dev/pts/ptmx", linux.F_OK)) != .NOENT) linux.exit_group(6);
        }
        var root_stat: linux.Statx = undefined;
        var dev_stat: linux.Statx = undefined;
        var console_stat: linux.Statx = undefined;
        var replica_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/", 0, .BASIC_STATS, &root_stat)) catch linux.exit_group(7);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev", 0, .BASIC_STATS, &dev_stat)) catch linux.exit_group(7);
        if (root_stat.dev_major != dev_stat.dev_major or root_stat.dev_minor != dev_stat.dev_minor)
            linux.exit_group(8);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(9);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &replica_stat)) catch linux.exit_group(9);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != replica_stat.ino or
            console_stat.dev_major != replica_stat.dev_major or console_stat.dev_minor != replica_stat.dev_minor)
            linux.exit_group(10);
        if (!writeAll(1, "console\n")) linux.exit_group(11);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(12);
        linux.exit_group(0);
    }
    closeFd(sockets[1]);
    defer closeFd(sockets[0]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    const controller = try console.receiveFd(sockets[0]);
    defer closeFd(controller);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(controller, &output));
    try std.testing.expectEqualStrings("console\r\n", &output);
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
}

test "linux rootfs diagnostics preserve errors and name the failed mount and bind paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const cases = [_]struct { mount: PreparedMount, expected: []const u8 }{
        .{
            .mount = .{ .destination = "/proc", .source = "proc", .type = "igvano-missing-filesystem", .flags = 0, .propagation = 0, .data = "" },
            .expected = "igvano: cannot prepare rootfs: mount /proc (igvano-missing-filesystem): CreateFailed\n",
        },
        .{
            .mount = .{ .destination = "/target", .source = "/igvano-missing-source", .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" },
            .expected = "igvano: cannot prepare rootfs: open bind source /igvano-missing-source -> /target: CreateFailed\n",
        },
    };
    for (cases) |case| {
        const report = try makePipe();
        defer closeFd(report[0]);
        var writer: ?posix.fd_t = report[1];
        defer if (writer) |fd| closeFd(fd);
        const pid = try forkProcess();
        if (pid == 0) {
            closeFd(report[0]);
            checkResult(linux.dup2(report[1], 2)) catch linux.exit_group(1);
            closeFd(report[1]);
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(2);
            setupRootfs(rootfs, &.{case.mount}, &.{}, &.{}, false, .{}) catch |err| {
                // Diagnostics are reported, not printed; print as init's parent would.
                @import("../diagnostic.zig").printDiagnostic();
                linux.exit_group(if (err == error.CreateFailed) 0 else 3);
            };
            linux.exit_group(4);
        }
        closeFd(report[1]);
        writer = null;
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        var output: [512]u8 = undefined;
        const size = linux.read(report[0], &output, output.len);
        try checkResult(size);
        try std.testing.expectEqualStrings(case.expected, output[0..size]);
    }
}

test "linux rootfs setup applies ordered mounts detaches the host root and enforces readonly" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/item", .data = "bind contents" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source_dir = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source_dir);
    const source_file = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source/item", .{absolute}, 0);
    defer std.testing.allocator.free(source_file);
    const mounts = [_]PreparedMount{
        .{ .destination = "/work", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = linux.MS.PRIVATE, .data = "mode=755" },
        .{ .destination = "/work/from-bind", .source = source_dir, .type = null, .flags = linux.MS.BIND | linux.MS.REC, .propagation = 0, .data = "" },
        .{ .destination = "/etc/config", .source = source_file, .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY | linux.MS.NOSUID, .propagation = 0, .data = "" },
        .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = 0, .data = "mode=755" },
        .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = linux.MS.NOSUID | linux.MS.NOEXEC, .propagation = 0, .data = "newinstance,ptmxmode=666,mode=620" },
    };
    const devices = [_]PreparedDevice{
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 },
        .{ .path = "/run/pipe", .mode = linux.S.IFIFO | 0o640, .dev = 0 },
    };
    const symlinks: []const libcontainer.Symlink = &.{
        .{ .path = "/dev/fd", .target = "/proc/self/fd" },
        .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
        .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
        .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
        .{ .path = "/dev/ptmx", .target = "pts/ptmx" },
    };
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        _ = linux.syscall1(.umask, 0o777);
        setupRootfs(rootfs, &mounts, &devices, symlinks, true, .{}) catch linux.exit_group(2);
        // The source's old absolute host path is unreachable after detaching.
        if (linux.errno(linux.access(source_file, linux.F_OK)) != .NOENT) linux.exit_group(3);
        if (linux.errno(linux.open("/new", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644)) != .ROFS) linux.exit_group(4);
        if (linux.errno(linux.open("/etc/config", .{ .ACCMODE = .WRONLY }, 0)) != .ROFS) linux.exit_group(5);
        const fd = openPath(linux.AT.FDCWD, "/etc/config", .{}) catch linux.exit_group(6);
        var contents: ["bind contents".len]u8 = undefined;
        if (!readAll(fd, &contents) or !std.mem.eql(u8, &contents, "bind contents")) linux.exit_group(7);
        closeFd(fd);
        if (linux.errno(linux.access("/work/from-bind/item", linux.F_OK)) != .SUCCESS) linux.exit_group(8);
        const writable = linux.open("/work/new", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
        if (linux.errno(writable) != .SUCCESS) linux.exit_group(9);
        closeFd(@intCast(writable));
        var stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/null", 0, .BASIC_STATS, &stat)) catch linux.exit_group(10);
        if (stat.mode != linux.S.IFCHR | 0o666 or stat.rdev_major != 1 or stat.rdev_minor != 3 or stat.uid != 0 or stat.gid != 0)
            linux.exit_group(11);
        checkResult(linux.statx(linux.AT.FDCWD, "/run/pipe", 0, .BASIC_STATS, &stat)) catch linux.exit_group(12);
        if (stat.mode != linux.S.IFIFO | 0o640) linux.exit_group(13);
        for (symlinks) |link| {
            var link_buffer: [64]u8 = undefined;
            const result = linux.readlink(link.path, &link_buffer, link_buffer.len);
            checkResult(result) catch linux.exit_group(14);
            if (!std.mem.eql(u8, link_buffer[0..result], link.target)) linux.exit_group(15);
        }
        const null_fd = openPath(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch linux.exit_group(16);
        if (!writeAll(null_fd, "device works")) linux.exit_group(17);
        closeFd(null_fd);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));

    // A later /dev bind covers the tmpfs. Leave its host source untouched.
    var bind_mounts: [mounts.len + 1]PreparedMount = undefined;
    @memcpy(bind_mounts[0..mounts.len], &mounts);
    bind_mounts[mounts.len] = .{
        .destination = "/dev",
        .source = source_dir,
        .type = null,
        .flags = linux.MS.BIND,
        .propagation = 0,
        .data = "",
    };
    const bind_pid = try forkProcess();
    if (bind_pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        setupRootfs(rootfs, &bind_mounts, &devices, symlinks, true, .{}) catch linux.exit_group(2);
        if (linux.errno(linux.access("/dev/item", linux.F_OK)) != .SUCCESS) linux.exit_group(3);
        if (linux.errno(linux.access("/dev/null", linux.F_OK)) != .NOENT) linux.exit_group(4);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(bind_pid));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "source/null", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "source/fd", .{ .follow_symlinks = false }));
}

test "linux rootfs restrictions hide files and directories and preserve propagation modes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/masked-dir");
    try tmp.dir.createDirPath(std.testing.io, "rootfs/readonly-dir");
    for ([_][]const u8{ "masked-file", "masked-dir/secret", "readonly-file", "readonly-dir/item" }) |path| {
        const name = try std.fmt.allocPrint(std.testing.allocator, "rootfs/{s}", .{path});
        defer std.testing.allocator.free(name);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = "secret" });
    }
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
    };
    const devices = [_]PreparedDevice{.{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 }};
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const hook_env = try std.fmt.allocPrint(arena.allocator(), "ROOTFS={s}", .{rootfs});
    const create_hooks = try hooks.prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "test -f \"$ROOTFS/masked-dir/secret\" && IFS= read -r state && test \"$state\" = creating && printf hook > \"$ROOTFS/hook-observed\"" },
        .env = &.{hook_env},
        .timeout_seconds = 2,
    }});
    for ([_]u32{ linux.MS.PRIVATE, linux.MS.SLAVE, linux.MS.SHARED, linux.MS.UNBINDABLE }) |propagation| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            setupRootfs(rootfs, &mounts, &devices, &.{}, false, .{
                .propagation = propagation | linux.MS.REC,
                .create_hooks = create_hooks,
                .create_hook_state = "creating\n",
                .masked_paths = &.{ "/masked-file", "/masked-dir", "/missing-mask" },
                .readonly_paths = &.{ "/readonly-file", "/readonly-dir", "/missing-readonly" },
            }) catch |err| {
                std.debug.print("rootfs restriction setup: {s}\n", .{@errorName(err)});
                linux.exit_group(2);
            };
            if (linux.errno(linux.access("/hook-observed", linux.F_OK)) != .SUCCESS) linux.exit_group(3);
            const masked = openPath(linux.AT.FDCWD, "/masked-file", .{}) catch linux.exit_group(4);
            var byte: [1]u8 = undefined;
            if (linux.read(masked, &byte, 1) != 0) linux.exit_group(5);
            closeFd(masked);
            if (linux.errno(linux.access("/masked-dir/secret", linux.F_OK)) != .NOENT) linux.exit_group(6);
            for ([_][*:0]const u8{ "/masked-dir/new", "/readonly-file", "/readonly-dir/item", "/readonly-dir/new" }) |path| {
                if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600)) != .ROFS)
                    linux.exit_group(7);
            }
            if (linux.errno(linux.access("/missing-mask", linux.F_OK)) != .NOENT or
                linux.errno(linux.access("/missing-readonly", linux.F_OK)) != .NOENT) linux.exit_group(8);
            const mountinfo = openPath(linux.AT.FDCWD, "/proc/self/mountinfo", .{}) catch linux.exit_group(9);
            var buffer: [65536]u8 = undefined;
            const size = linux.read(mountinfo, &buffer, buffer.len);
            checkResult(size) catch linux.exit_group(10);
            var lines = std.mem.splitScalar(u8, buffer[0..size], '\n');
            var root_seen = false;
            while (lines.next()) |line| {
                var fields = std.mem.tokenizeScalar(u8, line, ' ');
                for (0..4) |_| _ = fields.next();
                const mountpoint = fields.next() orelse continue;
                if (std.mem.eql(u8, mountpoint, "/")) root_seen = true;
                const shared = std.mem.indexOf(u8, line, " shared:") != null;
                const unbindable = std.mem.indexOf(u8, line, " unbindable ") != null;
                if (shared != (propagation == linux.MS.SHARED) or
                    unbindable != (propagation == linux.MS.UNBINDABLE)) linux.exit_group(11);
            }
            if (!root_seen) linux.exit_group(12);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

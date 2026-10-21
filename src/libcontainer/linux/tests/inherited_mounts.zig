const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const libcontainer = @import("../../root.zig");
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const readMountinfo = @import("../mountinfo.zig").readMountinfo;
const mountId = @import("../rootfs.zig").mountId;
const expectNoRootfsMount = @import("helpers.zig").expectNoRootfsMount;
const expectOutsideRootfsUnchanged = @import("helpers.zig").expectOutsideRootfsUnchanged;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const requireTestUniqueMountIds = @import("helpers.zig").requireTestUniqueMountIds;
const LinuxContainer = @import("../../linux.zig").Container;
const expectCreateError = @import("helpers.zig").expectCreateError;

test "linux inherited mount namespace creates starts and detaches rootfs on delete and failure" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    try requireTestUniqueMountIds();
    if (linux.errno(linux.access("/bin/sh", linux.X_OK)) != .SUCCESS) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-inherited-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs space/masked-dir");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "rootfs space/marker", .data = "container root" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "rootfs space/masked-file", .data = "secret" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "rootfs space/masked-dir/secret", .data = "secret" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "rootfs space/readonly-file", .data = "read only" });
    // Stacked roots omit the host /bin bind and are killed before start.
    try tmp.dir.createDirPath(std.testing.io, "source/bin");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/bin/sh",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/masked-file", .data = "host secret" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/readonly-file", .data = "host writable" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs space", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const runtime = try forkProcess();
    if (runtime == 0) {
        // The runtime and container share this test-only namespace. No mount
        // operation in this test can reach the test runner's mount table.
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        testInheritedMountNamespace(rootfs, fifo, cgroup_path) catch |err| {
            std.debug.print("inherited mount namespace test: {s}\n", .{@errorName(err)});
            linux.exit_group(2);
        };
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(runtime));
}

fn testInheritedMountNamespace(rootfs: [:0]const u8, fifo: [:0]const u8, cgroup_path: []const u8) !void {
    // A shared test root detects accidental global propagation changes.
    // All peers from the real host were removed by the preceding PRIVATE|REC.
    try checkResult(linux.mount(null, "/", null, linux.MS.SHARED, 0));
    const before = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(before);
    var namespace_buffer: [128]u8 = undefined;
    const namespace_size = linux.readlink("/proc/self/ns/mnt", &namespace_buffer, namespace_buffer.len);
    try checkResult(namespace_size);
    const namespace = namespace_buffer[0..namespace_size];
    const process: libcontainer.Process = .{
        .args = &.{
            "/bin/sh", "-c",
            \\test "$(readlink /proc/self/ns/mnt)" = "$1" &&
            \\test "$(cat /marker)" = "container root" &&
            \\test -f /proc/self/stat && test -c /dev/null &&
            \\test ! -s /masked-file && test ! -e /masked-dir/secret &&
            \\test ! -s /bound/masked-file &&
            \\! ( : > /readonly-file ) 2>/dev/null &&
            \\! ( : > /bound/readonly-file ) 2>/dev/null &&
            \\! ( : > /new-root-file ) 2>/dev/null &&
            \\printf success > /dev/result
            ,
            "sh",      namespace,
        },
        .env = &.{"PATH=/bin:/usr/bin"},
        .cwd = "/",
        .uid = 0,
        .gid = 0,
    };
    var mounts: [7]libcontainer.Mount = undefined;
    mounts[0] = .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" };
    mounts[1] = .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = 0, .data = "mode=755" };
    var mount_count: usize = 2;
    // Supply the host shell and its loader without depending on a rootfs image.
    for ([_][:0]const u8{ "/bin", "/usr", "/lib", "/lib64" }) |path| {
        if (linux.errno(linux.access(path, linux.F_OK)) == .NOENT) continue;
        mounts[mount_count] = .{
            .destination = path,
            .source = path,
            .type = null,
            .flags = linux.MS.BIND | linux.MS.REC | linux.MS.RDONLY,
            .propagation = 0,
            .data = "",
        };
        mount_count += 1;
    }
    var source_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const source = try std.fmt.bufPrintZ(&source_buffer, "{s}/source", .{std.fs.path.dirname(rootfs).?});
    mounts[mount_count] = .{
        .destination = "/bound",
        .source = source,
        .type = null,
        .flags = linux.MS.BIND | linux.MS.REC,
        .propagation = 0,
        .data = "",
    };
    mount_count += 1;
    const Callback = struct {
        fn fail(_: *anyopaque, _: libcontainer.State) libcontainer.Error!void {
            return error.HookFailed;
        }
    };
    var callback_context: u8 = 0;
    var options: libcontainer.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "inherited",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .process = process,
        // Deliberately omit namespaces: every namespace is inherited.
        .readonly_rootfs = true,
        .cgroup_path = cgroup_path,
        .mounts = mounts[0..mount_count],
        .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
        .masked_paths = &.{ "/masked-file", "/masked-dir", "/bound/masked-file" },
        .readonly_paths = &.{ "/readonly-file", "/bound/readonly-file" },
        .on_create = .{ .ptr = &callback_context, .run = Callback.fail },
    };
    // Failure before init mounts anything must preserve an existing self-bind,
    // including its flags and submounts.
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    try checkResult(linux.mount(null, rootfs, null, linux.MS.PRIVATE | linux.MS.REC, 0));
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const existing_submount = try std.fmt.bufPrintZ(&path_buffer, "{s}/masked-dir", .{rootfs});
    try checkResult(linux.mount("tmpfs", existing_submount, "tmpfs", 0, 0));
    try checkResult(linux.mount(null, rootfs, null, linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID, 0));
    const existing_mounts = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(existing_mounts);
    options.resources = .{ .unified = &.{.{ .key = "igvano.invalid", .value = "1" }} };
    try expectCreateError(error.CgroupWriteFailed, options);
    options.resources = .{};
    options.namespaces = &.{.{ .kind = .network, .path = "/igvano-missing-namespace" }};
    try expectCreateError(error.CreateFailed, options);
    options.namespaces = &.{};
    const retained_mounts = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(retained_mounts);
    try std.testing.expectEqualStrings(existing_mounts, retained_mounts);
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));

    // A mount failure before the ready report must still detach our new bind.
    options.mounts = &.{.{
        .destination = "/invalid",
        .source = "none",
        .type = "igvano.invalid",
        .flags = 0,
        .propagation = 0,
        .data = "",
    }};
    try expectCreateError(error.CreateFailed, options);
    options.mounts = mounts[0..mount_count];
    try expectNoRootfsMount(rootfs);

    try expectCreateError(error.HookFailed, options);
    try expectNoRootfsMount(rootfs);
    options.on_create = null;
    // Also exercise a failure after chroot and path restrictions.
    options.process.?.cwd = "/missing-cwd";
    try expectCreateError(error.CreateFailed, options);
    try expectNoRootfsMount(rootfs);
    options.process.?.cwd = "/";
    var handle_instance = try LinuxContainer.create(options);
    defer handle_instance.deinit(options.allocator);
    const handle = handle_instance.state;
    const handle_container = handle_instance.container();
    defer {
        handle_container.kill(9) catch {};
        handle_container.delete() catch {};
    }
    try std.testing.expectEqualStrings(rootfs, handle.rootfs_mount.?);
    {
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        try std.testing.expectEqual(@as(?u64, try mountId(root_fd)), handle.rootfs_mount_id);
    }
    try expectOutsideRootfsUnchanged(before, rootfs);
    const child_namespace_path = try std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/mnt", .{handle.pid});
    var child_namespace_buffer: [128]u8 = undefined;
    const child_namespace_size = linux.readlink(child_namespace_path, &child_namespace_buffer, child_namespace_buffer.len);
    try checkResult(child_namespace_size);
    try std.testing.expectEqualStrings(namespace, child_namespace_buffer[0..child_namespace_size]);
    {
        const reader = try openPath(linux.AT.FDCWD, fifo, .{ .CLOEXEC = true });
        defer closeFd(reader);
        var acknowledgement: [1]u8 = undefined;
        try std.testing.expect(readAll(reader, &acknowledgement));
        try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
    }
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..200) |_| {
        if (!try handle_container.alive()) break;
        _ = linux.nanosleep(&delay, null);
    }
    try std.testing.expect(!try handle_container.alive());
    const result_path = try std.fmt.bufPrintZ(&path_buffer, "{s}/dev/result", .{rootfs});
    {
        const result_fd = try openPath(linux.AT.FDCWD, result_path, .{ .CLOEXEC = true });
        defer closeFd(result_fd);
        var result: ["success".len]u8 = undefined;
        try std.testing.expect(readAll(result_fd, &result));
        try std.testing.expectEqualStrings("success", &result);
    }
    try handle_container.delete();
    try expectNoRootfsMount(rootfs);
    try handle_container.delete();
    // Existing mount records, including /'s shared propagation, are unchanged.
    const after = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);

    // A configured root mount covers the self-bind whose identity cleanup owns.
    // Both prepared root destinations are "/".
    // The second pass checks repeated stacked-root create/fail/delete leaves no residue.
    for ([_][]const u8{ "/", "/" }) |destination| {
        const stacked_mounts = [_]libcontainer.Mount{
            .{
                .destination = destination,
                .source = source,
                .type = null,
                .flags = linux.MS.BIND | linux.MS.REC,
                .propagation = 0,
                .data = "",
            },
            mounts[0],
            mounts[1],
        };
        options.mounts = &.{
            stacked_mounts[0],
            .{ .destination = "/invalid", .source = "none", .type = "igvano.invalid", .flags = 0, .propagation = 0, .data = "" },
        };
        try expectCreateError(error.CreateFailed, options);
        try expectNoRootfsMount(rootfs);
        options.mounts = &stacked_mounts;
        options.on_create = .{ .ptr = &callback_context, .run = Callback.fail };
        try expectCreateError(error.HookFailed, options);
        try expectNoRootfsMount(rootfs);
        options.on_create = null;
        options.process.?.cwd = "/missing-cwd";
        try expectCreateError(error.CreateFailed, options);
        try expectNoRootfsMount(rootfs);
        options.process.?.cwd = "/";
        var stacked_handle_instance = try LinuxContainer.create(options);
        defer stacked_handle_instance.deinit(options.allocator);
        const stacked_handle = stacked_handle_instance.state;
        const stacked_handle_container = stacked_handle_instance.container();
        defer {
            stacked_handle_container.kill(9) catch {};
            stacked_handle_container.delete() catch {};
        }
        const top_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(top_fd);
        try std.testing.expect(stacked_handle.rootfs_mount_id.? != try mountId(top_fd));
        try expectOutsideRootfsUnchanged(before, rootfs);
        try stacked_handle_container.kill(9);
        try stacked_handle_container.delete();
        try expectNoRootfsMount(rootfs);
        try stacked_handle_container.delete();
    }
    options.mounts = mounts[0..mount_count];

    // Delete must preserve a replacement mount that is not our self-bind.
    try checkResult(linux.mount("tmpfs", rootfs, "tmpfs", 0, 0));
    var replacement: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &replacement));
    try handle_container.delete();
    var retained: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));

    // A replacement self-bind also belongs to someone else.
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &replacement));
    try handle_container.delete();
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    var legacy_handle = handle;
    legacy_handle.rootfs_mount_id = null;
    var legacy_handle_instance = LinuxContainer.load(legacy_handle);
    const legacy_handle_container = legacy_handle_instance.container();
    try legacy_handle_container.delete();
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));
}

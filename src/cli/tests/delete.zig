const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Config = @import("../args.zig").Config;
const deleteContainer = @import("../delete.zig").deleteContainer;

test "delete requires stopped containers unless forced and waits after SIGKILL" {
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        is_alive: bool,
        fail_freezer: bool,
        deleted: bool = false,
        signal: ?i32 = null,
        polls_after_kill: usize = 0,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete, .frozen = frozen };

        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque) libcontainer.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.signal != null) {
                self.polls_after_kill += 1;
                return self.polls_after_kill == 1;
            }
            return self.is_alive;
        }
        fn kill(ptr: *anyopaque, signal: i32) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.signal = signal;
        }
        fn frozen(ptr: *anyopaque) libcontainer.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.fail_freezer) return error.CgroupWriteFailed;
            return false;
        }
        fn delete(ptr: *anyopaque) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    for ([_]bool{ false, true }) |force| {
        const config: Config = .{ .root = root, .subcommand = .delete, .id = "example", .force = force };
        for ([_]oci.Status{ .creating, .created, .running, .paused, .stopped }) |status| {
            for ([_]bool{ true, false }) |is_alive| {
                try tmp.dir.createDir(std.testing.io, "example", .default_dir);
                try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
                try oci.saveState(std.testing.allocator, std.testing.io, root, .{
                    .id = "example",
                    .pid = 1234,
                    .status = status,
                    .bundle = "/bundle",
                });
                var implementation: TestContainer = .{ .is_alive = is_alive, .fail_freezer = force };
                const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
                if (!force and is_alive and status != .stopped) {
                    const before = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(4096));
                    defer std.testing.allocator.free(before);
                    try std.testing.expectError(error.InvalidStatus, deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config));
                    try std.testing.expect(!implementation.deleted);
                    try std.testing.expect(implementation.signal == null);
                    const after = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(4096));
                    defer std.testing.allocator.free(after);
                    try std.testing.expectEqualStrings(before, after);
                    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
                    defer std.testing.allocator.free(starttime);
                    try std.testing.expectEqualStrings("12345", starttime);
                    try tmp.dir.deleteTree(std.testing.io, "example");
                } else {
                    try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
                    try std.testing.expect(implementation.deleted);
                    if (force and is_alive and status != .stopped) {
                        try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
                        try std.testing.expectEqual(@as(usize, 2), implementation.polls_after_kill);
                    } else {
                        try std.testing.expect(implementation.signal == null);
                    }
                    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
                }
            }
        }
    }
}

test "delete uses persisted cgroup and rootfs mounts and preserves state on backend failure" {
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        fail_delete: bool = true,
        deleted: bool = false,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };

        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return error.NotImplemented;
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {
            return error.NotImplemented;
        }
        fn delete(ptr: *anyopaque) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const handle = self.state;
            if (!std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/persisted"))
                return error.InvalidPath;
            if (!std.mem.eql(u8, handle.rootfs_mount orelse return error.InvalidPath, "/bundle/rootfs"))
                return error.InvalidPath;
            if (handle.rootfs_mount_id != 12345) return error.InvalidPath;
            if (self.fail_delete) return error.CgroupDeleteFailed;
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .stopped,
        .bundle = "/no-longer-present",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "custom/persisted" });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id_unique\":12345,\"boot_id\":\"00000000-0000-0000-0000-000000000000\"}",
    });
    var implementation: TestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    const config: Config = .{ .root = root, .subcommand = .delete, .id = "example" };
    try std.testing.expectError(error.CgroupDeleteFailed, deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config));
    const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    state.deinit();
    implementation.fail_delete = false;
    try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
    try std.testing.expect(implementation.deleted);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "forced deletion recovers corrupt and unreadable cgroup drivers" {
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        stopped_scope: bool = false,
        cleaned: bool = false,
        systemd_cleanup: bool = false,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return false;
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {}
        fn delete(ptr: *anyopaque) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const handle = self.state;
            if (handle.systemd) {
                self.stopped_scope = true;
                return error.CgroupWriteFailed;
            }
            self.cleaned = true;
            self.systemd_cleanup = handle.systemd_cleanup;
        }
    };
    for ([_]oci.Status{ .stopped, .created }) |status| {
        for ([_]bool{ false, true }) |unreadable| {
            for ([_][]const u8{ "/user.slice/session-1.scope", "system.slice/test-other.scope", "igvano/example" }) |cgroup| {
                var tmp = std.testing.tmpDir(.{});
                defer tmp.cleanup();
                try tmp.dir.createDir(std.testing.io, "example", .default_dir);
                try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "123" });
                try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = cgroup });
                if (unreadable)
                    try tmp.dir.createDir(std.testing.io, "example/cgroup-driver", .default_dir)
                else
                    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup-driver", .data = "unknown" });
                const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
                defer std.testing.allocator.free(root);
                try oci.saveState(std.testing.allocator, std.testing.io, root, .{
                    .id = "example",
                    .pid = 42,
                    .status = status,
                    .bundle = "/bundle",
                });
                var implementation: TestContainer = .{};
                const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
                var config: Config = .{ .root = root, .id = "example", .subcommand = .delete };
                if (!unreadable) {
                    try std.testing.expectError(error.InvalidState, deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config));
                    try std.testing.expect(!implementation.cleaned);
                }
                config.force = true;
                try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
                try std.testing.expect(implementation.cleaned);
                try std.testing.expect(!implementation.stopped_scope);
                try std.testing.expect(!implementation.systemd_cleanup);
                try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
            }
        }
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "system.slice/test-example.scope" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup-driver", .data = "systemd" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .stopped,
        .bundle = "/bundle",
    });
    var implementation: TestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{
        .root = root,
        .id = "example",
        .subcommand = .delete,
        .force = true,
    });
    try std.testing.expect(implementation.stopped_scope);
    try std.testing.expect(implementation.cleaned);
    try std.testing.expect(implementation.systemd_cleanup);
}

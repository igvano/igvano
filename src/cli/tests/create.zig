const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const Config = @import("../args.zig").Config;
const loadDeviceNodes = @import("../state.zig").loadDeviceNodes;
const loadRootfsMount = @import("../state.zig").loadRootfsMount;
const createContainer = @import("../create.zig").createContainer;

test "create uses private state directories and preserves existing root permissions" {
    const TestBackend = struct {
        state_mode: ?std.posix.mode_t = null,
        configured: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .killAll = kill, .delete = delete };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const state_dir = std.fs.path.dirname(options.exec_fifo) orelse return error.InvalidPath;
            const stat = std.Io.Dir.cwd().statFile(std.testing.io, state_dir, .{}) catch return error.InvalidPath;
            // Inspect the real directory before setup failure rolls it back.
            self.state_mode = stat.permissions.toMode() & 0o7777;
            if (self.configured) {
                std.testing.expectEqualDeep(@as(?Backend.Process, .{
                    .args = &.{"/bin/sh"},
                    .env = &.{"PATH=/bin"},
                    .cwd = "/work",
                    .uid = 1000,
                    .gid = 1001,
                    .additional_gids = &.{42},
                    .no_new_privileges = true,
                }), options.process) catch return error.InvalidConfig;
                std.testing.expectEqualDeep(@as([]const Backend.Namespace, &.{
                    .{ .kind = .pid },    .{ .kind = .network, .path = "/proc/1234/ns/net" },
                    .{ .kind = .mount },  .{ .kind = .ipc },
                    .{ .kind = .uts },    .{ .kind = .user },
                    .{ .kind = .cgroup }, .{ .kind = .time },
                }), options.namespaces) catch return error.InvalidConfig;
                std.testing.expectEqualDeep(@as([]const Backend.IDMapping, &.{.{ .container_id = 0, .host_id = 100000, .size = 65536 }}), options.uid_mappings) catch return error.InvalidConfig;
                std.testing.expectEqualDeep(@as([]const Backend.IDMapping, &.{.{ .container_id = 0, .host_id = 200000, .size = 65536 }}), options.gid_mappings) catch return error.InvalidConfig;
                std.testing.expectEqualStrings("container", options.hostname orelse return error.InvalidConfig) catch return error.InvalidConfig;
                if (!options.readonly_rootfs) return error.InvalidConfig;
            } else {
                if (options.process != null or options.uid_mappings.len != 0 or options.gid_mappings.len != 0 or
                    options.hostname != null or options.readonly_rootfs)
                    return error.InvalidConfig;
                std.testing.expectEqualDeep(@as([]const Backend.Namespace, &.{.{ .kind = .mount }}), options.namespaces) catch return error.InvalidConfig;
            }
            const device_nodes = loadDeviceNodes(std.testing.allocator, std.testing.io, std.fs.path.dirname(state_dir).?, options.id) catch return error.InvalidConfig;
            defer oci.freeDevices(std.testing.allocator, device_nodes);
            std.testing.expectEqualDeep(options.devices, device_nodes) catch return error.InvalidConfig;
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return error.NotImplemented;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}],"devices":[{"path":"/dev/custom","type":"c","major":10,"minor":237}]}}
        ,
    });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    try tmp.dir.createDir(std.testing.io, "existing", .fromMode(0o755));
    const existing = try tmp.dir.statFile(std.testing.io, "existing", .{});
    for ([_][]const u8{ "new/containers", "existing" }) |root_name| {
        const root = try std.fs.path.join(std.testing.allocator, &.{ base, root_name });
        defer std.testing.allocator.free(root);
        var implementation: TestBackend = .{};
        try std.testing.expectError(error.NotImplemented, createContainer(std.testing.allocator, std.testing.io, .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        }, .{ .root = root, .subcommand = .create, .id = "example", .bundle = bundle }));
        if (comptime builtin.os.tag == .linux)
            try std.testing.expectEqual(@as(?std.posix.mode_t, 0o700), implementation.state_mode);
        const stat = try tmp.dir.statFile(std.testing.io, root_name, .{});
        const expected = if (std.mem.eql(u8, root_name, "existing")) existing.permissions.toMode() & 0o7777 else 0o700;
        try std.testing.expectEqual(expected, stat.permissions.toMode() & 0o7777);
    }
    const parent = try tmp.dir.statFile(std.testing.io, "new", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), parent.permissions.toMode() & 0o7777);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/","readonly":true},"hostname":"container","process":{"args":["/bin/sh"],"env":["PATH=/bin"],"cwd":"/work","user":{"uid":1000,"gid":1001,"additionalGids":[42]},"noNewPrivileges":true},"linux":{"namespaces":[{"type":"pid"},{"type":"network","path":"/proc/1234/ns/net"},{"type":"mount"},{"type":"ipc"},{"type":"uts"},{"type":"user"},{"type":"cgroup"},{"type":"time"}],"uidMappings":[{"containerID":0,"hostID":100000,"size":65536}],"gidMappings":[{"containerID":0,"hostID":200000,"size":65536}]}}
        ,
    });
    const configured_root = try std.fs.path.join(std.testing.allocator, &.{ base, "configured" });
    defer std.testing.allocator.free(configured_root);
    var configured_backend: TestBackend = .{ .configured = true };
    try std.testing.expectError(error.NotImplemented, createContainer(std.testing.allocator, std.testing.io, .{
        .ptr = &configured_backend,
        .vtable = &TestBackend.vtable,
    }, .{ .root = configured_root, .subcommand = .create, .id = "example", .bundle = bundle }));
    if (comptime builtin.os.tag == .linux)
        try std.testing.expectEqual(@as(?std.posix.mode_t, 0o700), configured_backend.state_mode);
}

test "create rejects a duplicate id without changing existing state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"}]}}
        ,
    });
    try tmp.dir.createDirPath(std.testing.io, "containers/example");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "containers/example/state.json", .data = "existing state" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "containers/example/lock", .data = "existing lock" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.fs.path.join(std.testing.allocator, &.{ base, "containers" });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.ContainerExists, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    const state = try tmp.dir.readFileAlloc(std.testing.io, "containers/example/state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(state);
    try std.testing.expectEqualStrings("existing state", state);
    const lock = try tmp.dir.readFileAlloc(std.testing.io, "containers/example/lock", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(lock);
    try std.testing.expectEqualStrings("existing lock", lock);
}

test "create rejects a missing bundle before creating the state directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "missing" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.FileNotFound, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = base,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create rejects propagation without mount isolation before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"rootfsPropagation":"private"},"mounts":[{"destination":"/proc","type":"proc"}]}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create rejects invalid process settings before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const cases = [_]struct { settings: []const u8, expected: anyerror }{
        .{ .settings = "\"capabilities\":{\"bounding\":[\"not-a-capability\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"bounding\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"effective\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"permitted\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"inheritable\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"ambient\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"ambient\":[\"CAP_CHOWN\"]}", .expected = error.AmbientCapabilitiesRequirePermittedAndInheritable },
        .{ .settings = "\"rlimits\":[{\"type\":\"RLIMIT_UNKNOWN\",\"hard\":1024,\"soft\":512}]", .expected = error.InvalidConfig },
        .{ .settings = "\"rlimits\":[{\"type\":\"RLIMIT_NOFILE\",\"hard\":512,\"soft\":1024}]", .expected = error.InvalidConfig },
    };
    for (cases) |case| {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"ociVersion\":\"1.0.2\",\"root\":{{\"path\":\"rootfs\"}},\"linux\":{{\"namespaces\":[{{\"type\":\"mount\"}}]}},\"process\":{{\"args\":[\"/bin/sh\"],\"cwd\":\"/\",\"user\":{{\"uid\":0,\"gid\":0}},{s}}}}}",
            .{case.settings},
        );
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        var implementation: backend_module.LinuxBackend = .{};
        try std.testing.expectError(case.expected, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        }));
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    }
}

test "create rejects invalid devices before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"}],"devices":[{"path":"/dev/null","type":"p"},{"path":"/dev/null","type":"c","major":1,"minor":3}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create removes its new state directory when setup fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"},{"type":"network"},{"type":"network","path":"/proc/1/ns/net"}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidConfig else error.NotImplemented,
        createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        }),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create with inherited mount isolation persists backend resources and rolls back a failed pid file" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        rootfs: [std.fs.max_path_bytes]u8 = undefined,
        rootfs_len: usize = 0,
        mounts_checked: bool = false,
        killed: bool = false,
        deleted: bool = false,

        const vtable: Backend.VTable = .{
            .create = create,
            .alive = alive,
            .kill = kill,
            .killAll = kill,
            .delete = delete,
        };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.rootfs_len = options.rootfs.len;
            @memcpy(self.rootfs[0..self.rootfs_len], options.rootfs);
            if (options.mounts.len != 2) return error.InvalidConfig;
            const bind = options.mounts[0];
            if (!std.mem.eql(u8, bind.destination, "/mnt") or
                !std.fs.path.isAbsolute(bind.source orelse return error.InvalidConfig) or
                !std.mem.endsWith(u8, bind.source.?, "/bundle/source") or
                bind.flags != (std.os.linux.MS.BIND | std.os.linux.MS.RDONLY) or
                bind.propagation != (std.os.linux.MS.PRIVATE | std.os.linux.MS.REC))
                return error.InvalidConfig;
            const mappings = bind.mappings orelse return error.InvalidConfig;
            if (mappings.uid.len != 1 or mappings.gid.len != 1 or mappings.recursive or
                !std.meta.eql(mappings.uid[0], Backend.IDMapping{ .container_id = 1000, .host_id = 0, .size = 1 }) or
                !std.meta.eql(mappings.gid[0], Backend.IDMapping{ .container_id = 2000, .host_id = 0, .size = 1 }))
                return error.InvalidConfig;
            const proc = options.mounts[1];
            if (!std.mem.eql(u8, proc.destination, "/proc") or
                !std.mem.eql(u8, proc.source orelse return error.InvalidConfig, "proc") or
                proc.flags != std.os.linux.MS.NOSUID or !std.mem.eql(u8, proc.data, "mode=755"))
                return error.InvalidConfig;
            self.mounts_checked = true;
            if (!std.mem.eql(u8, options.cgroup_path, "custom/test") or
                options.resources.memory == null or options.resources.memory.?.limit != 33554432 or
                options.resources.pids == null or options.resources.pids.?.limit != 5)
                return error.InvalidConfig;
            const caps = options.capabilities orelse return error.InvalidConfig;
            if (!std.meta.eql(caps, Backend.Capabilities{
                .bounding = 1 | (@as(u64, 1) << 39),
                .effective = 1,
                .permitted = 1,
                .inheritable = 1,
                .ambient = 1,
            })) return error.InvalidConfig;
            if (options.rlimits.len != 1 or !std.meta.eql(options.rlimits[0], Backend.Rlimit{
                .resource = .NOFILE,
                .hard = 1024,
                .soft = 512,
            })) return error.InvalidConfig;
            if (options.oom_score_adj != 100) return error.InvalidConfig;
            std.testing.expectEqualDeep(@as(?Backend.Process, .{
                .args = &.{"/bin/sh"},
                .cwd = "/",
                .uid = 1000,
                .gid = 1000,
            }), options.process) catch return error.InvalidConfig;
            if (options.hostname != null or options.readonly_rootfs or
                options.uid_mappings.len != 0 or options.gid_mappings.len != 0)
                return error.InvalidConfig;
            if (options.devices.len != 6 or
                !std.mem.eql(u8, options.devices[0].path, "/dev/null") or
                options.devices[0].kind != .character or options.devices[0].mode != 0o600 or
                options.devices[0].uid != 1000 or options.devices[0].gid != 1001 or
                options.device_symlinks.len != 4)
                return error.InvalidConfig;
            if (options.on_create) |callback| try callback.run(callback.ptr, .{
                .id = options.id,
                .pid = 1234,
                .starttime = "987654321",
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = options.rootfs,
                .rootfs_mount_id = 12345,
                .rootfs_mount_boot_id = "00000000-0000-0000-0000-000000000000".*,
            });
            return .{
                .id = options.id,
                .pid = 1234,
                .starttime = try options.allocator.dupe(u8, "987654321"),
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = options.rootfs,
                .rootfs_mount_id = 12345,
                .rootfs_mount_boot_id = "00000000-0000-0000-0000-000000000000".*,
            };
        }

        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/test"))
                return error.InvalidPath;
            if (!std.mem.eql(u8, handle.rootfs_mount orelse return error.InvalidPath, self.rootfs[0..self.rootfs_len]))
                return error.InvalidPath;
            if (handle.rootfs_mount_id != 12345) return error.InvalidPath;
            self.deleted = true;
        }

        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (handle.pid != 1234 or signal != 9) return error.CreateFailed;
            self.killed = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"9.9.9","root":{"path":"rootfs"},"linux":{"cgroupsPath":"/custom/test","devices":[{"path":"/dev/null","type":"c","major":1,"minor":3,"fileMode":384,"uid":1000,"gid":1001}],"resources":{"memory":{"limit":33554432},"pids":{"limit":5}}},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":1000,"gid":1000},"capabilities":{"bounding":["CAP_CHOWN","CAP_BPF"],"effective":["CAP_CHOWN"],"inheritable":["CAP_CHOWN"],"permitted":["CAP_CHOWN"],"ambient":["CAP_CHOWN"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":512}],"oomScoreAdj":100},"mounts":[{"destination":"/a/../mnt","type":"bind","source":"source","options":["ro","rprivate"],"uidMappings":[{"containerID":1000,"hostID":0,"size":1}],"gidMappings":[{"containerID":2000,"hostID":0,"size":1}]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","mode=755"]}],"annotations":{"org.example.description":"hello"}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const pid_file = try std.fs.path.join(std.testing.allocator, &.{ root, "init.pid" });
    defer std.testing.allocator.free(pid_file);
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    var config: Config = .{ .root = root, .subcommand = .create, .id = "example", .bundle = bundle, .pid_file = pid_file };
    try createContainer(std.testing.allocator, std.testing.io, backend, config);

    const json = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(json);
    const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, json, .{});
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.created, state.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), state.value.pid);
    try std.testing.expectEqualStrings("example", state.value.id);
    try std.testing.expectEqualStrings("1.0.2", state.value.ociVersion);
    try std.testing.expectEqualStrings("hello", state.value.annotations.?.map.get("org.example.description").?);
    const absolute_bundle = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, bundle, std.testing.allocator);
    defer std.testing.allocator.free(absolute_bundle);
    try std.testing.expectEqualStrings(absolute_bundle, state.value.bundle);
    const expected_rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_bundle, "rootfs" });
    defer std.testing.allocator.free(expected_rootfs);
    try std.testing.expectEqualStrings(expected_rootfs, implementation.rootfs[0..implementation.rootfs_len]);
    const pid = try tmp.dir.readFileAlloc(std.testing.io, "init.pid", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(pid);
    try std.testing.expectEqualStrings("1234", pid);
    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(starttime);
    try std.testing.expectEqualStrings("987654321", starttime);
    const cgroup = try tmp.dir.readFileAlloc(std.testing.io, "example/cgroup", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(cgroup);
    try std.testing.expectEqualStrings("custom/test", cgroup);
    const rootfs_mount = (try loadRootfsMount(std.testing.allocator, std.testing.io, root, "example")).?;
    defer std.testing.allocator.free(rootfs_mount.path);
    try std.testing.expectEqualStrings(expected_rootfs, rootfs_mount.path);
    try std.testing.expectEqual(@as(?u64, 12345), rootfs_mount.mount_id_unique);
    try std.testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &rootfs_mount.boot_id.?);
    const fifo = try tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{});
    try std.testing.expectEqual(std.Io.File.Kind.named_pipe, fifo.kind);
    try std.testing.expect(!implementation.killed);
    try std.testing.expect(!implementation.deleted);
    try std.testing.expect(implementation.mounts_checked);

    const bad_pid_file = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "init.pid" });
    defer std.testing.allocator.free(bad_pid_file);
    config.id = "other";
    try std.testing.expectError(error.InvalidConfig, createContainer(std.testing.allocator, std.testing.io, backend, config));
    try std.testing.expect(std.mem.indexOf(u8, oci.diagnostic().?, "already used by live container 'example'") != null);
    try std.testing.expect(!implementation.killed);
    try std.testing.expect(!implementation.deleted);
    // A private mount namespace can safely use the same rootfs.
    const private_config = parsedSpec: {
        const spec = try oci.loadSpec(std.testing.allocator, std.testing.io, absolute_bundle);
        defer spec.deinit();
        var value = spec.value;
        value.linux.?.namespaces = &.{.{ .type = .mount }};
        break :parsedSpec try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    };
    defer std.testing.allocator.free(private_config);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = private_config });
    config.pid_file = bad_pid_file;
    try std.testing.expectError(error.FileNotFound, createContainer(std.testing.allocator, std.testing.io, backend, config));
    try std.testing.expect(implementation.killed);
    try std.testing.expect(implementation.deleted);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "other", .{}));
}

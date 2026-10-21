const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("state.zig").ContainerInstance;
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const bindContainer = @import("state.zig").bindContainer;
const Config = @import("args.zig").Config;
const parseArgs = @import("args.zig").parseArgs;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const loadDeviceNodes = @import("state.zig").loadDeviceNodes;
const readLiveState = @import("state.zig").readLiveState;

pub fn updateContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    const parsed = if (config.resources_file) |path| try oci.loadResources(allocator, io, path) else null;
    defer if (parsed) |file| file.deinit();
    const resources = try oci.cgroupResources(allocator, if (parsed) |file| file.value else config.resource_flags);
    defer oci.freeCgroupResources(allocator, resources);
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const locked = if (lock) |file| try lockContainer(file, false) else true;
    if (locked) {
        if (lock) |file| try requireLinkedLock(io, file);
    } else {
        std.debug.print("igvano: warning: container '{s}' is busy; updating resources without the lock\n", .{config.id});
    }
    const state = try readLiveState(allocator, io, injected, config, locked);
    defer state.deinit();
    var instance: ContainerInstance = undefined;
    try oci.requireUpdate(state.parsed.value.status);
    var handle = state.container_state.?;
    if (resources.devices.len != 0)
        handle.device_nodes = try loadDeviceNodes(allocator, io, config.root, config.id);
    defer oci.freeDevices(allocator, handle.device_nodes);
    const container = bindContainer(&instance, injected, handle);
    try containerResult(container, container.update(resources));
}

test "update validates resource input before opening the container lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "resources.json" });
    defer allocator.free(path);
    try tmp.dir.writeFile(io, .{ .sub_path = "resources.json", .data = "{\"memory\":{\"limit\":-2}}" });
    const config: Config = .{ .root = root, .subcommand = .update, .id = "missing", .resources_file = path };
    try std.testing.expectError(error.InvalidConfig, updateContainer(allocator, io, null, config));
}

test "resource JSON ignores individual flags regardless of argument order" {
    const overrideContainer = @import("tests/helpers.zig").overrideContainer;
    const LockTestContainer = @import("tests/helpers.zig").LockTestContainer;
    defer oci.clearDiagnostic();
    const TestContainer = struct {
        var empty = false;
        var memory_only = false;

        fn update(ptr: *anyopaque, resources: libcontainer.Resources) libcontainer.Error!void {
            const self: *LockTestContainer = @ptrCast(@alignCast(ptr));
            const handle = self.state;
            if (handle.device_nodes.len != 0) return error.InvalidConfig;
            check(resources) catch return error.InvalidConfig;
        }

        fn check(resources: libcontainer.Resources) !void {
            if (memory_only) {
                try std.testing.expectEqual(@as(?i64, 64), resources.memory.?.limit);
                try std.testing.expect(resources.cpu == null and resources.devices.len == 0);
                return;
            }
            if (empty) {
                try std.testing.expect(resources.memory == null and resources.cpu == null and resources.block_io == null);
                return;
            }
            try std.testing.expectEqual(@as(?i64, 32), resources.memory.?.limit);
            try std.testing.expectEqual(@as(?i64, 134217728), resources.memory.?.swap);
            try std.testing.expectEqual(@as(?u64, 1024), resources.cpu.?.shares);
            try std.testing.expectEqual(@as(?u64, 100000), resources.cpu.?.period);
            try std.testing.expectEqualStrings("0", resources.cpu.?.cpus.?);
            try std.testing.expectEqual(@as(?i64, 50), resources.pids.?.limit);
            try std.testing.expectEqual(@as(?u16, 100), resources.block_io.?.weight);
            try std.testing.expectEqual(@as(?u16, 200), resources.block_io.?.leaf_weight);
            try std.testing.expectEqual(@as(u64, 4096), resources.hugepage_limits[0].limit);
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "r.json" });
    defer std.testing.allocator.free(path);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .running,
        .pid = 1234,
        .bundle = "/unused",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/devices.json",
        .data = "{corrupt",
    });
    var implementation: LockTestContainer = .{};
    var vtable = LockTestContainer.vtable;
    vtable.update = TestContainer.update;
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &vtable };
    const json =
        \\{"memory":{"limit":32,"swap":134217728},"cpu":{"shares":1024,"period":100000,"cpus":"0"},"pids":{"limit":50},"blockIO":{"weight":100,"leafWeight":200},"hugepageLimits":[{"pageSize":"2MB","limit":4096}]}
    ;
    for ([_][]const []const u8{
        &.{ "igvano", "update", "--resources=r.json", "--memory=64m", "--cpu-shares=512", "--blkio-weight=500", "example" },
        &.{ "igvano", "update", "--memory=64m", "--cpu-shares=512", "--blkio-weight=500", "--resources=r.json", "example" },
    }) |args| {
        var config = try parseArgs(args);
        config.root = root;
        config.resources_file = path;
        TestContainer.empty = false;
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = json });
        try updateContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
        TestContainer.empty = true;
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = "{}" });
        try updateContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
    }
    TestContainer.memory_only = true;
    try updateContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{
        .root = root,
        .subcommand = .update,
        .id = "example",
        .resource_flags = .{ .memory = .{ .limit = 64 } },
    });
    // Explicit device updates still require a readable device snapshot.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = "{\"devices\":[{\"allow\":true}]}" });
    try std.testing.expectError(error.InvalidState, updateContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{
        .root = root,
        .subcommand = .update,
        .id = "example",
        .resources_file = path,
    }));
}

test "update rejects stopped containers before applying resources" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .stopped,
        .bundle = "/unused",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "resources.json", .data = "{}" });
    const resources_file = try std.fs.path.join(std.testing.allocator, &.{ root, "resources.json" });
    defer std.testing.allocator.free(resources_file);
    const config = try parseArgs(&.{ "igvano", "--root", root, "update", "--resources", resources_file, "example" });
    try std.testing.expectError(error.InvalidStatus, updateContainer(std.testing.allocator, std.testing.io, null, config));
}

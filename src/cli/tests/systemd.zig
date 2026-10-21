const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("../state.zig").ContainerInstance;
const containerResult = @import("../diagnostic.zig").containerResult;
const parseArgs = @import("../args.zig").parseArgs;
const updateContainer = @import("../update.zig").updateContainer;
const containerState = @import("../state.zig").containerState;
const createContainer = @import("../create.zig").createContainer;
const startContainer = @import("../start.zig").startContainer;
const waitExec = @import("../exec.zig").waitExec;
const killContainer = @import("../kill.zig").killContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const pauseContainer = @import("../pause.zig").pauseContainer;
const runIsolatedSecurityTest = @import("helpers.zig").runIsolatedSecurityTest;
const readTestCgroup = @import("helpers.zig").readTestCgroup;
const execTestCommand = @import("helpers.zig").execTestCommand;

test "linux systemd cgroup scope lifecycle applies limits and removes the unit" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (std.os.linux.errno(std.os.linux.access("/run/systemd/private", std.os.linux.F_OK)) != .SUCCESS)
        return error.SkipZigTest;
    try runIsolatedSecurityTest(testSystemdLifecycle);
}

fn testSystemdLifecycle(base: []const u8) !void {
    try testSystemdLifecycleDeletion(base, true);
}

fn testSystemdLifecycleDeletion(base: []const u8, kill_before_delete: bool) !void {
    const linux = std.os.linux;
    var threaded: std.Io.Threaded = .init_single_threaded;
    threaded.allocator = std.heap.page_allocator;
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const bundle = try std.fs.path.join(allocator, &.{ base, "bundle" });
    const rootfs = try std.fs.path.join(allocator, &.{ bundle, "rootfs" });
    const root = try std.fs.path.join(allocator, &.{ base, "state" });
    try cwd.createDirPath(io, rootfs);
    const id = try std.fmt.allocPrint(allocator, "systemd-{d}", .{linux.getpid()});
    const cgroups_path = try std.fmt.allocPrint(allocator, "system.slice:igvano-test:{s}", .{id});
    const unit = try std.fmt.allocPrint(allocator, "igvano-test-{s}.scope", .{id});
    const path = try std.fmt.allocPrint(allocator, "system.slice/{s}", .{unit});
    var mounts: std.ArrayList(oci.Spec.Mount) = .empty;
    for ([_][]const u8{ "/bin", "/sbin", "/usr", "/lib", "/lib64" }) |source| {
        if (linux.errno(linux.access(try allocator.dupeZ(u8, source), linux.F_OK)) == .SUCCESS)
            try mounts.append(allocator, .{ .destination = source, .source = source, .type = "bind", .options = &.{ "rbind", "ro" } });
    }
    try mounts.append(allocator, .{ .destination = "/proc", .source = "proc", .type = "proc" });
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{ "sleep", "120" }, .env = &.{"PATH=/bin:/usr/bin"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        .linux = .{
            .cgroupsPath = cgroups_path,
            .namespaces = &.{ .{ .type = .mount }, .{ .type = .pid }, .{ .type = .cgroup } },
            .devices = &.{.{ .path = "/dev/custom", .type = "c", .major = 10, .minor = 238 }},
            .resources = .{
                .memory = .{ .limit = 67108864 },
                .cpu = .{ .shares = 1024, .quota = 50000, .period = 100000 },
                .pids = .{ .limit = 50 },
                .devices = &.{
                    .{ .allow = false },
                    .{ .allow = true, .type = "c", .major = 10, .minor = 237, .access = "rw" },
                },
            },
        },
        .mounts = mounts.items,
    };
    const config_path = try std.fs.path.join(allocator, &.{ bundle, "config.json" });
    try cwd.writeFile(io, .{ .sub_path = config_path, .data = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false }) });
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)) != .SUCCESS)
        return error.SubreaperFailed;

    const create = try parseArgs(&.{ "igvano", "--systemd-cgroup", "--root", root, "create", "--bundle", bundle, id });
    try createContainer(allocator, io, null, create);
    const remove = try parseArgs(&.{ "igvano", "--root", root, "delete", "--force", id });
    defer deleteContainer(allocator, io, null, remove) catch {};
    const saved = try oci.loadState(allocator, io, root, id);
    defer saved.deinit();
    const handle = try containerState(allocator, io, root, saved.value, false);
    try std.testing.expect(handle.systemd);
    try std.testing.expectEqualStrings(path, handle.cgroup_path.?);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(handle.pid, .KILL);
        (thaw: {
            var instance = ContainerInstance.load(handle);
            break :thaw instance.container().thaw();
        }) catch {};
        _ = waitExec(handle.pid) catch {};
    };
    const active = try std.process.run(allocator, io, .{ .argv = &.{ "systemctl", "show", unit, "-p", "ActiveState", "--value" } });
    try std.testing.expectEqualStrings("active", std.mem.trim(u8, active.stdout, " \t\n"));
    const membership = try readTestCgroup(allocator, io, try std.fmt.allocPrint(allocator, "/proc/{d}/cgroup", .{handle.pid}));
    try std.testing.expect(std.mem.indexOf(u8, membership, path) != null);
    const unified = linux.errno(linux.access("/sys/fs/cgroup/cgroup.controllers", linux.F_OK)) == .SUCCESS;
    if (!unified) try checkSystemdV1Devices(allocator, io, path, "c 10:237 rw\n", "c 10:238 rwm\n");
    const memory_path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{
        @as([]const u8, if (unified) "/sys/fs/cgroup" else "/sys/fs/cgroup/memory"), path,
        @as([]const u8, if (unified) "memory.max" else "memory.limit_in_bytes"),
    });
    try std.testing.expectEqualStrings("67108864", std.mem.trim(u8, try readTestCgroup(allocator, io, memory_path), " \t\n"));
    const start = try parseArgs(&.{ "igvano", "--root", root, "start", id });
    try startContainer(allocator, io, null, start);
    const update_path = try std.fs.path.join(allocator, &.{ base, "resources.json" });
    const update = try parseArgs(&.{ "igvano", "--root", root, "update", "--resources", update_path, id });
    try cwd.writeFile(io, .{ .sub_path = update_path, .data = "{\"memory\":{\"limit\":134217728}}" });
    try updateContainer(allocator, io, null, update);
    try std.testing.expectEqualStrings("134217728", std.mem.trim(u8, try readTestCgroup(allocator, io, memory_path), " \t\n"));
    if (!unified) {
        try checkSystemdV1Devices(allocator, io, path, "c 10:237 rw\n", "c 10:238 rwm\n");
        const reload = try std.process.run(allocator, io, .{ .argv = &.{ "systemctl", "daemon-reload" } });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, reload.term);
        try checkSystemdV1Devices(allocator, io, path, "c 10:237 rw\n", "c 10:238 rwm\n");
        // A new allowlist must clear cached DeviceAllow entries, so reload
        // cannot restore devices removed by an explicit resource update.
        try cwd.writeFile(io, .{ .sub_path = update_path, .data = "{\"devices\":[{\"allow\":false},{\"allow\":true,\"type\":\"c\",\"major\":10,\"minor\":239,\"access\":\"rw\"}]}" });
        try updateContainer(allocator, io, null, update);
        const reload_updated = try std.process.run(allocator, io, .{ .argv = &.{ "systemctl", "daemon-reload" } });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, reload_updated.term);
        // Create-time linux.devices allows survive explicit resource updates.
        try checkSystemdV1Devices(allocator, io, path, "c 10:239 rw\n", "c 10:238 rwm\n");
        const devices = try readTestCgroup(allocator, io, try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/devices/{s}/devices.list", .{path}));
        try std.testing.expect(std.mem.indexOf(u8, devices, "10:237") == null);
        // Privileged allow-all containers also need memory-only updates to work.
        try cwd.writeFile(io, .{ .sub_path = update_path, .data = "{\"devices\":[{\"allow\":true}]}" });
        try updateContainer(allocator, io, null, update);
        try cwd.writeFile(io, .{ .sub_path = update_path, .data = "{\"memory\":{\"limit\":134217728}}" });
        try updateContainer(allocator, io, null, update);
        const allow_all = try readTestCgroup(allocator, io, try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/devices/{s}/devices.list", .{path}));
        try std.testing.expect(std.mem.indexOf(u8, allow_all, "a *:* rwm") == null);
        try std.testing.expect(std.mem.indexOf(u8, allow_all, "c *:* rwm\n") != null);
        try std.testing.expect(std.mem.indexOf(u8, allow_all, "b *:* rwm\n") != null);
    }
    // Updating only quota preserves the period, including systemd's cached value.
    try cwd.writeFile(io, .{ .sub_path = update_path, .data = "{\"cpu\":{\"quota\":25000}}" });
    try updateContainer(allocator, io, null, update);
    const pause = try parseArgs(&.{ "igvano", "--root", root, "pause", id });
    try pauseContainer(allocator, io, null, pause);
    try std.testing.expect(try (frozen: {
        var instance = ContainerInstance.load(handle);
        break :frozen instance.container().frozen();
    }));
    const resume_config = try parseArgs(&.{ "igvano", "--root", root, "resume", id });
    try pauseContainer(allocator, io, null, resume_config);
    try std.testing.expect(!try (frozen: {
        var instance = ContainerInstance.load(handle);
        break :frozen instance.container().frozen();
    }));
    const command = try parseArgs(&.{ "igvano", "--root", root, "exec", id, "sh", "-c", "test \"$(cat /proc/self/cgroup)\" = \"$(cat /proc/1/cgroup)\"" });
    try std.testing.expectEqual(@as(u8, 0), try execTestCommand(command, null));
    const members = try (pids: {
        var instance = ContainerInstance.load(handle);
        break :pids instance.container().pids(allocator);
    });
    try std.testing.expect(std.mem.indexOfScalar(i32, members, handle.pid) != null);
    if (kill_before_delete) {
        const kill = try parseArgs(&.{ "igvano", "--root", root, "kill", id, "9" });
        try killContainer(allocator, io, null, kill);
        _ = try waitExec(handle.pid);
        reaped = true;
    }
    // Exercise StopUnit on an active scope as well as ordinary CLI deletion.
    if (!kill_before_delete) {
        var instance = ContainerInstance.load(handle);
        const loaded = instance.container();
        try containerResult(loaded, loaded.delete());
    }
    try deleteContainer(allocator, io, null, remove);
    if (!reaped) {
        _ = try waitExec(handle.pid);
        reaped = true;
    }
    const stopped = try std.process.run(allocator, io, .{ .argv = &.{ "systemctl", "show", unit, "-p", "ActiveState", "-p", "LoadState" } });
    try std.testing.expect(std.mem.indexOf(u8, stopped.stdout, "ActiveState=inactive") != null or
        std.mem.indexOf(u8, stopped.stdout, "LoadState=not-found") != null);
    var memberships = std.mem.tokenizeScalar(u8, membership, '\n');
    while (memberships.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next();
        const controllers = fields.next() orelse return error.InvalidState;
        const hierarchy = if (controllers.len == 0) "/sys/fs/cgroup" else try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/{s}", .{if (std.mem.eql(u8, controllers, "name=systemd")) "systemd" else controllers});
        const directory = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ hierarchy, path }, 0);
        try std.testing.expect(linux.errno(linux.access(directory, linux.F_OK)) == .NOENT);
    }
}

fn checkSystemdV1Devices(allocator: std.mem.Allocator, io: std.Io, path: []const u8, resource_rule: []const u8, configured_rule: ?[]const u8) !void {
    const devices = try readTestCgroup(allocator, io, try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/devices/{s}/devices.list", .{path}));
    try std.testing.expect(std.mem.indexOf(u8, devices, "a *:* rwm") == null);
    try std.testing.expect(std.mem.indexOf(u8, devices, "c 1:3 rwm\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, devices, resource_rule) != null);
    if (configured_rule) |rule| try std.testing.expect(std.mem.indexOf(u8, devices, rule) != null);
}

test "linux systemd cgroup scope lifecycle uses the system bus fallback" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    if (linux.errno(linux.access("/run/systemd/private", linux.F_OK)) != .SUCCESS or
        linux.errno(linux.access("/run/dbus/system_bus_socket", linux.F_OK)) != .SUCCESS)
        return error.SkipZigTest;
    try runIsolatedSecurityTest(testSystemdFallbackLifecycle);
}

fn testSystemdFallbackLifecycle(base: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const path = try std.fmt.allocPrintSentinel(std.heap.page_allocator, "{s}/private-placeholder", .{base}, 0);
    defer std.heap.page_allocator.free(path);
    const file = try std.Io.Dir.cwd().createFile(threaded.io(), path, .{});
    file.close(threaded.io());
    // This mount is confined to the test's private mount namespace. Connecting
    // to a regular file returns ECONNREFUSED and exercises the real fallback.
    const linux = std.os.linux;
    if (linux.errno(linux.mount(path, "/run/systemd/private", null, linux.MS.BIND, 0)) != .SUCCESS)
        return error.SystemResources;
    try testSystemdLifecycleDeletion(base, false);
}

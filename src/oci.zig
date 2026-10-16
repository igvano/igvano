const std = @import("std");

test "OCI resources parse every supported resource field" {
    const parsed = try std.json.parseFromSlice(Spec.Resources, std.testing.allocator,
        \\{"memory":{"limit":64,"reservation":32,"swap":128,"kernel":-1,"kernelTCP":16,"swappiness":50,"disableOOMKiller":false},
        \\"cpu":{"shares":1024,"quota":50000,"period":100000,"realtimeRuntime":-1,"realtimePeriod":1000000,"cpus":"0-2","mems":"0"},
        \\"pids":{"limit":32},
        \\"blockIO":{"weight":100,"leafWeight":200,"weightDevice":[{"major":8,"minor":0,"weight":300,"leafWeight":400}],
        \\"throttleReadBpsDevice":[{"major":8,"minor":0,"rate":1000}],"throttleWriteBpsDevice":[{"major":8,"minor":1,"rate":2000}],
        \\"throttleReadIOPSDevice":[{"major":8,"minor":2,"rate":30}],"throttleWriteIOPSDevice":[{"major":8,"minor":3,"rate":40}]},
        \\"hugepageLimits":[{"pageSize":"2MB","limit":4194304}],
        \\"network":{"classID":123,"priorities":[{"name":"eth0","priority":7}]},
        \\"devices":[{"allow":false},{"allow":true,"type":"c","major":1,"minor":3,"access":"rw"}],
        \\"unified":{"memory.high":"48","cpu.max":"max 200000"}}
    , .{});
    defer parsed.deinit();
    const resources = try cgroupResources(std.testing.allocator, parsed.value);
    defer freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqualDeep(Backend.Resources.Memory{
        .limit = 64,
        .reservation = 32,
        .swap = 128,
        .kernel = -1,
        .kernel_tcp = 16,
        .swappiness = 50,
        .disable_oom_killer = false,
    }, resources.memory.?);
    try std.testing.expectEqualDeep(Backend.Resources.Cpu{
        .shares = 1024,
        .quota = 50000,
        .period = 100000,
        .realtime_runtime = -1,
        .realtime_period = 1000000,
        .cpus = "0-2",
        .mems = "0",
    }, resources.cpu.?);
    try std.testing.expectEqual(@as(?i64, 32), resources.pids.?.limit);
    const block = resources.block_io.?;
    try std.testing.expectEqual(@as(?u16, 100), block.weight);
    try std.testing.expectEqual(@as(?u16, 200), block.leaf_weight);
    try std.testing.expectEqualDeep(Backend.Resources.WeightDevice{
        .major = 8,
        .minor = 0,
        .weight = 300,
        .leaf_weight = 400,
    }, block.weight_device[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 0, .rate = 1000 }, block.throttle_read_bps[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 1, .rate = 2000 }, block.throttle_write_bps[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 2, .rate = 30 }, block.throttle_read_iops[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 3, .rate = 40 }, block.throttle_write_iops[0]);
    try std.testing.expectEqualDeep(Backend.Resources.HugepageLimit{ .page_size = "2MB", .limit = 4194304 }, resources.hugepage_limits[0]);
    try std.testing.expectEqual(@as(?u32, 123), resources.network.?.class_id);
    try std.testing.expectEqualDeep(Backend.Resources.Priority{ .name = "eth0", .priority = 7 }, resources.network.?.priorities[0]);
    try std.testing.expectEqualDeep(Backend.Resources.DeviceRule{ .allow = false }, resources.devices[0]);
    try std.testing.expectEqualDeep(Backend.Resources.DeviceRule{
        .allow = true,
        .kind = .char,
        .major = 1,
        .minor = 3,
        .access = "rw",
    }, resources.devices[1]);
    try std.testing.expectEqualDeep(Backend.Resources.Unified{ .key = "memory.high", .value = "48" }, resources.unified[0]);
    try std.testing.expectEqualDeep(Backend.Resources.Unified{ .key = "cpu.max", .value = "max 200000" }, resources.unified[1]);
}

test "hooks parse all lifecycle stages and preserve their optional settings" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"hooks":{
        \\ "prestart":[{"path":"/compat"}],"createRuntime":[{"path":"/runtime","args":["custom","arg"],"env":["ONLY=hook"],"timeout":2}],
        \\ "createContainer":[{"path":"/create"}],"startContainer":[{"path":"/start"}],
        \\ "poststart":[{"path":"/started"}],"poststop":[{"path":"/stopped"}]}}
    , .{});
    defer parsed.deinit();
    try validateHooks(parsed.value.hooks);
    const hooks = parsed.value.hooks.?;
    try std.testing.expectEqualStrings("/compat", hooks.prestart.?[0].path);
    try std.testing.expectEqualStrings("custom", hooks.createRuntime.?[0].args.?[0]);
    try std.testing.expectEqualStrings("ONLY=hook", hooks.createRuntime.?[0].env.?[0]);
    try std.testing.expectEqual(@as(?u64, 2), hooks.createRuntime.?[0].timeout);
    try std.testing.expectEqualStrings("/create", hooks.createContainer.?[0].path);
    try std.testing.expectEqualStrings("/start", hooks.startContainer.?[0].path);
    try std.testing.expectEqualStrings("/started", hooks.poststart.?[0].path);
    try std.testing.expectEqualStrings("/stopped", hooks.poststop.?[0].path);
    try std.testing.expect(hooks.prestart.?[0].args == null);
    try std.testing.expect(hooks.prestart.?[0].env == null);
    try std.testing.expect(hooks.prestart.?[0].timeout == null);
}

test "hook validation rejects missing relative and NUL paths and zero timeout" {
    try std.testing.expectError(error.MissingField, std.json.parseFromSlice(Spec.Hook, std.testing.allocator, "{}", .{}));
    for ([_][]const u8{
        "{\"path\":\"relative\"}",
        "{\"path\":\"\"}",
        "{\"path\":\"/hook\\u0000\"}",
        "{\"path\":\"/hook\",\"timeout\":0}",
        "{\"path\":\"/hook\",\"args\":[\"bad\\u0000\"]}",
        "{\"path\":\"/hook\",\"env\":[\"bad\\u0000\"]}",
    }) |json| {
        const parsed = try std.json.parseFromSlice(Spec.Hook, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidConfig, validateHooks(.{ .poststop = &.{parsed.value} }));
    }
    try validateHooks(null);
    try validateHooks(.{ .prestart = &.{} });
    try validateHooks(.{ .startContainer = &.{.{ .path = "/hook", .timeout = 1 }} });
}

test "linux path restrictions parse ordered string lists and propagation modes" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"maskedPaths":["/proc/kcore","/secret"],"readonlyPaths":["/proc/sys"],"rootfsPropagation":"slave"}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.maskedPaths.?.len);
    try std.testing.expectEqualStrings("/proc/kcore", parsed.value.maskedPaths.?[0]);
    try std.testing.expectEqualStrings("/secret", parsed.value.maskedPaths.?[1]);
    try std.testing.expectEqualStrings("/proc/sys", parsed.value.readonlyPaths.?[0]);
    try std.testing.expectEqual(Spec.Propagation.slave, parsed.value.rootfsPropagation.?);
    const ms = std.os.linux.MS;
    const cases = [_]struct { mode: ?Spec.Propagation, expected: u32 }{
        .{ .mode = null, .expected = ms.PRIVATE | ms.REC },
        .{ .mode = .shared, .expected = ms.SHARED | ms.REC },
        .{ .mode = .slave, .expected = ms.SLAVE | ms.REC },
        .{ .mode = .private, .expected = ms.PRIVATE | ms.REC },
        .{ .mode = .unbindable, .expected = ms.UNBINDABLE | ms.REC },
    };
    for (cases) |case| try std.testing.expectEqual(case.expected, rootfsPropagation(case.mode));
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"rootfsPropagation":"rshared"}
    , .{}));
    try std.testing.expectError(error.UnexpectedToken, std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"maskedPaths":[1]}
    , .{}));
}

test "cgroup paths are relative to the mount root and reject escapes" {
    const cases = [_]struct { path: ?[]const u8, expected: []const u8 }{
        .{ .path = null, .expected = "igvano/example" },
        .{ .path = "/custom/example", .expected = "custom/example" },
        .{ .path = "custom/example", .expected = "custom/example" },
        .{ .path = "//custom/./nested/../example/", .expected = "custom/example" },
    };
    for (cases) |case| {
        const path = try resolveCgroupPath(std.testing.allocator, case.path, "example");
        defer std.testing.allocator.free(path);
        try std.testing.expectEqualStrings(case.expected, path);
    }
    for ([_][]const u8{ "", "/", ".", "..", "../outside", "/../outside", "a/../../outside", "a/..", "a\x00b" }) |path| {
        try std.testing.expectError(error.InvalidConfig, resolveCgroupPath(std.testing.allocator, path, "example"));
    }
    try std.testing.expectError(error.InvalidConfig, resolveCgroupPath(std.testing.allocator, null, "../outside"));
}

test "OCI resources retain typed limits without hierarchy mapping" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"cgroupsPath":"/custom/example","resources":{"memory":{"limit":67108864},"cpu":{"quota":50000,"period":100000,"shares":1024},"pids":{"limit":32},"devices":[]}}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/custom/example", parsed.value.cgroupsPath.?);
    const resources = try cgroupResources(std.testing.allocator, parsed.value.resources);
    defer freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqual(@as(?i64, 67108864), resources.memory.?.limit);
    try std.testing.expectEqualDeep(Backend.Resources.Cpu{ .quota = 50000, .period = 100000, .shares = 1024 }, resources.cpu.?);
    try std.testing.expectEqual(@as(?i64, 32), resources.pids.?.limit);
}

test "cgroup resources preserve zero unlimited and omitted settings" {
    for ([_]?Spec.Resources{
        null,
        .{},
        .{ .cpu = .{ .shares = 0 } },
        .{ .memory = .{} },
        .{ .memory = .{ .limit = 0 } },
        .{ .pids = .{ .limit = 0 } },
        .{ .memory = .{ .limit = 0 }, .pids = .{ .limit = 0 } },
    }) |resources| {
        const converted = try cgroupResources(std.testing.allocator, resources);
        defer freeCgroupResources(std.testing.allocator, converted);
        try std.testing.expectEqual(@as(usize, 0), converted.devices.len);
        try std.testing.expectEqual(@as(usize, 0), converted.unified.len);
        try std.testing.expectEqual(if (resources) |r| if (r.memory) |m| m.limit else null else null, if (converted.memory) |m| m.limit else null);
    }
    const resources = try cgroupResources(std.testing.allocator, .{
        .memory = .{ .limit = -1, .reservation = -1, .swap = -1, .kernel = -1, .kernelTCP = -1 },
        .cpu = .{ .quota = -1, .realtimeRuntime = -1 },
        .pids = .{ .limit = -1 },
    });
    defer freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqual(@as(?i64, -1), resources.memory.?.swap);
    try std.testing.expectEqual(@as(?i64, -1), resources.cpu.?.quota);
    try std.testing.expectEqual(@as(?i64, -1), resources.pids.?.limit);
}

test "cgroup resource validation rejects invalid signed limits and cpu shares" {
    for ([_]Spec.Resources{
        .{ .memory = .{ .limit = -2 } },
        .{ .pids = .{ .limit = -2 } },
        .{ .cpu = .{ .quota = -2 } },
        .{ .cpu = .{ .shares = 1 } },
        .{ .memory = .{ .limit = 64 }, .cpu = .{ .shares = 1 } },
        .{ .memory = .{ .reservation = -2 } },
        .{ .memory = .{ .swap = -2 } },
        .{ .memory = .{ .kernel = -2 } },
        .{ .memory = .{ .kernelTCP = -2 } },
        .{ .cpu = .{ .realtimeRuntime = -2 } },
        .{ .cpu = .{ .shares = 262145 } },
        .{ .cpu = .{ .shares = std.math.maxInt(u64) } },
    }) |resources| {
        try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, resources));
    }
}

test "cgroup resources validate device types access and wildcard numbers" {
    for ([_][]const u8{ "a", "b", "c" }, [_]@FieldType(Backend.Resources.DeviceRule, "kind"){ .all, .block, .char }) |kind, expected| {
        const resources = try cgroupResources(std.testing.allocator, .{ .devices = &.{
            .{ .allow = true, .type = kind, .major = -1, .minor = -1, .access = "mrw" },
        } });
        defer freeCgroupResources(std.testing.allocator, resources);
        try std.testing.expectEqual(expected, resources.devices[0].kind);
        try std.testing.expectEqual(@as(?i64, null), resources.devices[0].major);
        try std.testing.expectEqual(@as(?i64, null), resources.devices[0].minor);
    }
    for ([_]Spec.Resources.DeviceRule{
        .{ .allow = true, .type = "" },
        .{ .allow = true, .type = "char" },
        .{ .allow = true, .access = "rx" },
        .{ .allow = true, .access = "r\x00" },
        .{ .allow = true, .major = -2 },
        .{ .allow = true, .minor = -2 },
    }) |device| {
        try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, .{ .devices = &.{device} }));
    }
}

test "cgroup resources reject unsafe unified names and empty hugepage sizes" {
    for ([_][]const u8{ "", ".", "..", "/memory.max", "a/b", "a\x00b" }) |key| {
        var unified: std.json.ArrayHashMap([]const u8) = .{};
        defer unified.map.deinit(std.testing.allocator);
        try unified.map.put(std.testing.allocator, key, "1");
        try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, .{ .unified = unified }));
    }
    try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, .{
        .hugepageLimits = &.{.{ .pageSize = "", .limit = 1 }},
    }));
}

test "cgroup resources validate block device numbers and weight ranges" {
    for ([_]Spec.Resources{
        .{ .blockIO = .{ .weight = 9 } },
        .{ .blockIO = .{ .leafWeight = 1001 } },
        .{ .blockIO = .{ .weightDevice = &.{.{ .major = -1, .minor = 0 }} } },
        .{ .blockIO = .{ .weightDevice = &.{.{ .major = 8, .minor = -1 }} } },
        .{ .blockIO = .{ .weightDevice = &.{.{ .major = 8, .minor = 0, .weight = 1 }} } },
        .{ .blockIO = .{ .weightDevice = &.{.{ .major = 8, .minor = 0, .leafWeight = 1001 }} } },
        .{ .blockIO = .{ .throttleReadBpsDevice = &.{.{ .major = -1, .minor = 0, .rate = 1 }} } },
        .{ .blockIO = .{ .throttleWriteBpsDevice = &.{.{ .major = 8, .minor = -1, .rate = 1 }} } },
        .{ .blockIO = .{ .throttleReadIOPSDevice = &.{.{ .major = -1, .minor = 0, .rate = 1 }} } },
        .{ .blockIO = .{ .throttleWriteIOPSDevice = &.{.{ .major = 8, .minor = -1, .rate = 1 }} } },
    }) |resources| {
        try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, resources));
    }
}

test "bind mount recursive read-only options are explicit and ordered" {
    const cases = [_]struct { options: []const []const u8, recursive: ?bool }{
        .{ .options = &.{ "ro", "rbind" }, .recursive = null },
        .{ .options = &.{ "rbind", "rro" }, .recursive = true },
        .{ .options = &.{ "bind", "rrw" }, .recursive = false },
        .{ .options = &.{ "rbind", "rro", "rrw" }, .recursive = false },
        .{ .options = &.{ "rbind", "rrw", "rro" }, .recursive = true },
        .{ .options = &.{ "mode=755", "rbind", "rro" }, .recursive = true },
    };
    for (cases) |case| {
        const options = try parseMountOptions(std.testing.allocator, case.options, null);
        defer std.testing.allocator.free(options.data);
        try std.testing.expectEqual(case.recursive, options.recursive_readonly);
        try std.testing.expectEqualStrings("", options.data);
    }
}

test "cgroup resource conversion frees partially allocated arrays on allocation failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var unified: std.json.ArrayHashMap([]const u8) = .{};
            defer unified.map.deinit(allocator);
            try unified.map.put(allocator, "memory.high", "32");
            const resources = try cgroupResources(allocator, .{
                .blockIO = .{
                    .weightDevice = &.{.{ .major = 8, .minor = 0, .weight = 100 }},
                    .throttleReadBpsDevice = &.{.{ .major = 8, .minor = 0, .rate = 1 }},
                    .throttleWriteBpsDevice = &.{.{ .major = 8, .minor = 0, .rate = 2 }},
                    .throttleReadIOPSDevice = &.{.{ .major = 8, .minor = 0, .rate = 3 }},
                    .throttleWriteIOPSDevice = &.{.{ .major = 8, .minor = 0, .rate = 4 }},
                },
                .hugepageLimits = &.{.{ .pageSize = "2MB", .limit = 1 }},
                .network = .{ .priorities = &.{.{ .name = "eth0", .priority = 1 }} },
                .devices = &.{.{ .allow = false }},
                .unified = unified,
            });
            defer freeCgroupResources(allocator, resources);
            try std.testing.expectEqual(@as(usize, 1), resources.devices.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

pub const state_file_name = "state.json";
pub const lock_file_name = "lock";
pub const exec_fifo_name = "exec.fifo";
pub const starttime_file_name = "starttime";
pub const process_file_name = "process";
pub const cgroup_file_name = "cgroup";
pub const rootfs_mount_file_name = "rootfs_mount";
pub const hooks_file_name = "hooks.json";
pub const runtime_oci_version = "1.0.2";

/// Parsed config.json values needed by a namespace backend.
pub const Spec = struct {
    ociVersion: []const u8,
    root: Root,
    process: ?Process = null,
    hostname: ?[]const u8 = null,
    mounts: ?[]const Mount = null,
    hooks: ?Hooks = null,
    linux: ?Linux = null,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,

    pub const Root = struct {
        path: []const u8,
        readonly: bool = false,
    };

    pub const Process = struct {
        args: []const []const u8,
        env: ?[]const []const u8 = null,
        cwd: []const u8,
        terminal: ?bool = null,
        noNewPrivileges: bool = false,
        oomScoreAdj: ?i32 = null,
        user: User,
        capabilities: ?Capabilities = null,
        rlimits: ?[]const Rlimit = null,
    };

    pub const Capabilities = struct {
        bounding: ?[]const []const u8 = null,
        effective: ?[]const []const u8 = null,
        inheritable: ?[]const []const u8 = null,
        permitted: ?[]const []const u8 = null,
        ambient: ?[]const []const u8 = null,
    };

    pub const Rlimit = struct {
        type: []const u8,
        hard: u64,
        soft: u64,
    };

    pub const User = struct {
        uid: u32,
        gid: u32,
        additionalGids: ?[]const u32 = null,
    };

    pub const Mount = struct {
        destination: []const u8,
        type: ?[]const u8 = null,
        source: ?[]const u8 = null,
        options: ?[]const []const u8 = null,
    };

    pub const Linux = struct {
        namespaces: ?[]const Namespace = null,
        sysctl: ?std.json.ArrayHashMap([]const u8) = null,
        uidMappings: ?[]const IDMapping = null,
        gidMappings: ?[]const IDMapping = null,
        cgroupsPath: ?[]const u8 = null,
        resources: ?Resources = null,
        devices: ?[]const Device = null,
        maskedPaths: ?[]const []const u8 = null,
        readonlyPaths: ?[]const []const u8 = null,
        rootfsPropagation: ?Propagation = null,
    };

    pub const Propagation = enum { shared, slave, private, unbindable };

    pub const Hook = struct {
        path: []const u8,
        args: ?[]const []const u8 = null,
        env: ?[]const []const u8 = null,
        timeout: ?u64 = null,
    };

    pub const Hooks = struct {
        prestart: ?[]const Hook = null,
        createRuntime: ?[]const Hook = null,
        createContainer: ?[]const Hook = null,
        startContainer: ?[]const Hook = null,
        poststart: ?[]const Hook = null,
        poststop: ?[]const Hook = null,
    };

    pub const Device = struct {
        path: []const u8,
        type: []const u8,
        major: ?i64 = null,
        minor: ?i64 = null,
        fileMode: ?u32 = null,
        uid: ?u32 = null,
        gid: ?u32 = null,
    };

    pub const Resources = struct {
        memory: ?Memory = null,
        cpu: ?Cpu = null,
        pids: ?Pids = null,
        blockIO: ?BlockIO = null,
        hugepageLimits: ?[]const HugepageLimit = null,
        network: ?Network = null,
        devices: ?[]const DeviceRule = null,
        unified: ?std.json.ArrayHashMap([]const u8) = null,

        pub const Memory = struct {
            limit: ?i64 = null,
            reservation: ?i64 = null,
            swap: ?i64 = null,
            kernel: ?i64 = null,
            kernelTCP: ?i64 = null,
            swappiness: ?u64 = null,
            disableOOMKiller: ?bool = null,
        };
        pub const Cpu = struct {
            quota: ?i64 = null,
            period: ?u64 = null,
            shares: ?u64 = null,
            realtimeRuntime: ?i64 = null,
            realtimePeriod: ?u64 = null,
            cpus: ?[]const u8 = null,
            mems: ?[]const u8 = null,
        };
        pub const Pids = struct { limit: ?i64 = null };
        pub const BlockIO = struct {
            weight: ?u16 = null,
            leafWeight: ?u16 = null,
            weightDevice: ?[]const WeightDevice = null,
            throttleReadBpsDevice: ?[]const ThrottleDevice = null,
            throttleWriteBpsDevice: ?[]const ThrottleDevice = null,
            throttleReadIOPSDevice: ?[]const ThrottleDevice = null,
            throttleWriteIOPSDevice: ?[]const ThrottleDevice = null,
        };
        pub const WeightDevice = struct {
            major: i64,
            minor: i64,
            weight: ?u16 = null,
            leafWeight: ?u16 = null,
        };
        pub const ThrottleDevice = struct { major: i64, minor: i64, rate: u64 };
        pub const HugepageLimit = struct { pageSize: []const u8, limit: u64 };
        pub const Network = struct {
            classID: ?u32 = null,
            priorities: ?[]const Priority = null,
        };
        pub const Priority = struct { name: []const u8, priority: u32 };
        pub const DeviceRule = struct {
            allow: bool,
            type: []const u8 = "a",
            major: ?i64 = null,
            minor: ?i64 = null,
            access: []const u8 = "rwm",
        };
    };

    pub const Namespace = struct {
        type: enum { pid, network, mount, ipc, uts, user, cgroup, time },
        path: ?[]const u8 = null,
    };

    pub const IDMapping = struct {
        containerID: u32,
        hostID: u32,
        size: u32,
    };
};

/// Resolve absolute OCI paths relative to the cgroup mount, never the host root.
/// Root itself is forbidden, since delete must only remove a container cgroup.
pub fn resolveCgroupPath(allocator: std.mem.Allocator, configured: ?[]const u8, id: []const u8) ![]u8 {
    if (configured == null and (id.len == 0 or
        std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or
        std.mem.indexOfScalar(u8, id, 0) != null)) return error.InvalidConfig;
    const path = if (configured) |value|
        try std.fmt.allocPrint(allocator, "/{s}", .{value})
    else
        try std.fmt.allocPrint(allocator, "/igvano/{s}", .{id});
    defer allocator.free(path);
    const normalized = try resolveMountDestination(allocator, path);
    defer allocator.free(normalized);
    if (normalized.len == 1) return error.InvalidConfig;
    return allocator.dupe(u8, normalized[1..]);
}

const Backend = @import("backend.zig").Backend;

/// A joined IPC/network/UTS namespace must differ from the runtime's namespace.
fn sysctlNamespace(config: Spec.Linux, kind: @FieldType(Spec.Namespace, "type")) bool {
    for (config.namespaces orelse &.{}) |namespace| {
        if (namespace.type != kind) continue;
        const path = namespace.path orelse return true;
        if (comptime @import("builtin").os.tag == .linux) {
            const linux = std.os.linux;
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const target = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return false;
            var own: linux.Statx = undefined;
            var joined: linux.Statx = undefined;
            const own_path: [*:0]const u8 = switch (kind) {
                .ipc => "/proc/self/ns/ipc",
                .uts => "/proc/self/ns/uts",
                else => "/proc/self/ns/net",
            };
            if (linux.errno(linux.statx(linux.AT.FDCWD, own_path, 0, .{ .INO = true }, &own)) != .SUCCESS or
                linux.errno(linux.statx(linux.AT.FDCWD, target, 0, .{ .INO = true }, &joined)) != .SUCCESS or
                !own.mask.INO or !joined.mask.INO) return false;
            return own.dev_major != joined.dev_major or own.dev_minor != joined.dev_minor or own.ino != joined.ino;
        }
        return false;
    }
    return false;
}

pub fn validateSysctls(config: Spec.Linux) error{InvalidConfig}!void {
    const configured = config.sysctl orelse return;
    var entries = configured.map.iterator();
    while (entries.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        const allowed = allowed: {
            if (key.len == 0 or std.mem.indexOfAny(u8, key, "/\x00") != null or
                std.mem.indexOf(u8, key, "..") != null or
                std.mem.indexOfAny(u8, value, "\x00\n") != null) break :allowed false;
            if (std.mem.startsWith(u8, key, "net.")) break :allowed sysctlNamespace(config, .network);
            if (std.mem.eql(u8, key, "kernel.domainname") or std.mem.eql(u8, key, "kernel.hostname"))
                break :allowed sysctlNamespace(config, .uts);
            if (std.mem.startsWith(u8, key, "fs.mqueue.")) break :allowed sysctlNamespace(config, .ipc);
            for ([_][]const u8{
                "kernel.msgmax", "kernel.msgmnb", "kernel.msgmni", "kernel.sem",
                "kernel.shmall", "kernel.shmmax", "kernel.shmmni", "kernel.shm_rmid_forced",
            }) |ipc_key| {
                if (std.mem.eql(u8, key, ipc_key)) break :allowed sysctlNamespace(config, .ipc);
            }
            break :allowed false;
        };
        if (!allowed) {
            std.debug.print("igvano: sysctl '{s}' is not namespaced or the required namespace is not configured\n", .{key});
            return error.InvalidConfig;
        }
    }
}

/// The frontend validated namespace ownership; the backend receives only writes.
pub fn prepareSysctls(allocator: std.mem.Allocator, config: Spec.Linux) ![]Backend.Sysctl {
    const configured = config.sysctl orelse return allocator.alloc(Backend.Sysctl, 0);
    const entries = try allocator.alloc(Backend.Sysctl, configured.map.count());
    var iterator = configured.map.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1)
        entries[index] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
    return entries;
}

test "OCI sysctls parse and translate borrowed keys and values" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"namespaces":[{"type":"network"}],"sysctl":{"net.ipv4.ip_forward":"1"}}
    , .{});
    defer parsed.deinit();
    try validateSysctls(parsed.value);
    const settings = try prepareSysctls(std.testing.allocator, parsed.value);
    defer std.testing.allocator.free(settings);
    try std.testing.expectEqual(@as(usize, 1), settings.len);
    try std.testing.expectEqualStrings("net.ipv4.ip_forward", settings[0].key);
    try std.testing.expectEqualStrings("1", settings[0].value);
}

test "OCI sysctl validation requires the matching namespace" {
    const cases = [_]struct { key: []const u8, kind: @FieldType(Spec.Namespace, "type") }{
        .{ .key = "kernel.msgmax", .kind = .ipc },
        .{ .key = "kernel.msgmnb", .kind = .ipc },
        .{ .key = "kernel.msgmni", .kind = .ipc },
        .{ .key = "kernel.sem", .kind = .ipc },
        .{ .key = "kernel.shmall", .kind = .ipc },
        .{ .key = "kernel.shmmax", .kind = .ipc },
        .{ .key = "kernel.shmmni", .kind = .ipc },
        .{ .key = "kernel.shm_rmid_forced", .kind = .ipc },
        .{ .key = "fs.mqueue.msg_max", .kind = .ipc },
        .{ .key = "net.ipv4.ip_forward", .kind = .network },
        .{ .key = "kernel.hostname", .kind = .uts },
        .{ .key = "kernel.domainname", .kind = .uts },
    };
    for (cases) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, "1");
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{ .sysctl = sysctl }));
        for ([_]@FieldType(Spec.Namespace, "type"){ .ipc, .network, .uts, .mount }) |kind| {
            const config: Spec.Linux = .{ .sysctl = sysctl, .namespaces = &.{.{ .type = kind }} };
            if (kind == case.kind) {
                try validateSysctls(config);
            } else {
                try std.testing.expectError(error.InvalidConfig, validateSysctls(config));
            }
        }
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{
            .sysctl = sysctl,
            .namespaces = &.{.{ .type = case.kind, .path = "/proc/self/ns/missing" }},
        }));
    }
}

test "OCI sysctls reject host settings traversal and invalid values" {
    for ([_]struct { key: []const u8, value: []const u8 = "1" }{
        .{ .key = "vm.swappiness" },
        .{ .key = "kernel.core_pattern" },
        .{ .key = "fs.file-max" },
        .{ .key = "" },
        .{ .key = "net/ipv4/ip_forward" },
        .{ .key = "net..ipv4.ip_forward" },
        .{ .key = "net.ipv4.ip_forward\x00" },
        .{ .key = "net.ipv4.ip_forward", .value = "1\x00" },
        .{ .key = "net.ipv4.ip_forward", .value = "1\n" },
    }) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, case.value);
        const config: Spec.Linux = .{ .sysctl = sysctl, .namespaces = &.{ .{ .type = .ipc }, .{ .type = .network }, .{ .type = .uts } } };
        try std.testing.expectError(error.InvalidConfig, validateSysctls(config));
        try std.testing.expectError(error.InvalidConfig, requireCreate(.{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" }, .linux = config }));
    }
}

test "OCI IPC network and UTS sysctls reject joining the runtime namespace" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { key: []const u8, kind: @FieldType(Spec.Namespace, "type"), path: []const u8 }{
        .{ .key = "kernel.msgmax", .kind = .ipc, .path = "/proc/self/ns/ipc" },
        .{ .key = "net.ipv4.ip_forward", .kind = .network, .path = "/proc/self/ns/net" },
        .{ .key = "net.ipv4.ip_forward", .kind = .network, .path = "/proc/thread-self/ns/net" },
        .{ .key = "kernel.hostname", .kind = .uts, .path = "/proc/self/ns/uts" },
        .{ .key = "kernel.hostname", .kind = .uts, .path = "/proc/thread-self/ns/uts" },
        .{ .key = "kernel.domainname", .kind = .uts, .path = "/proc/self/ns/uts" },
        .{ .key = "kernel.domainname", .kind = .uts, .path = "/proc/thread-self/ns/uts" },
    }) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, "1");
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{
            .sysctl = sysctl,
            .namespaces = &.{.{ .type = case.kind, .path = case.path }},
        }));
    }
}

pub fn validateHooks(configured: ?Spec.Hooks) error{InvalidConfig}!void {
    const hooks = configured orelse return;
    inline for (std.meta.fields(Spec.Hooks)) |field| {
        for (@field(hooks, field.name) orelse &.{}) |hook| {
            if (!std.mem.startsWith(u8, hook.path, "/") or
                std.mem.indexOfScalar(u8, hook.path, 0) != null or
                hook.timeout == 0) return error.InvalidConfig;
            for (hook.args orelse &.{}) |arg|
                if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidConfig;
            for (hook.env orelse &.{}) |env|
                if (std.mem.indexOfScalar(u8, env, 0) != null) return error.InvalidConfig;
        }
    }
}

/// Translate OCI hook entries; all slices are borrowed from the parsed spec.
pub fn prepareHooks(allocator: std.mem.Allocator, configured: ?[]const Spec.Hook) ![]Backend.Hook {
    const entries = configured orelse &.{};
    const hooks = try allocator.alloc(Backend.Hook, entries.len);
    for (entries, hooks) |entry, *hook| hook.* = .{
        .path = entry.path,
        .args = entry.args orelse &.{},
        .env = entry.env orelse &.{},
        .timeout_seconds = entry.timeout,
    };
    return hooks;
}

pub fn rootfsPropagation(mode: ?Spec.Propagation) u32 {
    const ms = std.os.linux.MS;
    return ms.REC | @as(u32, switch (mode orelse .private) {
        .shared => ms.SHARED,
        .slave => ms.SLAVE,
        .private => ms.PRIVATE,
        .unbindable => ms.UNBINDABLE,
    });
}

const default_devices = [_]Backend.Device{
    .{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3, .required = false },
    .{ .path = "/dev/zero", .kind = .character, .major = 1, .minor = 5, .required = false },
    .{ .path = "/dev/full", .kind = .character, .major = 1, .minor = 7, .required = false },
    .{ .path = "/dev/random", .kind = .character, .major = 1, .minor = 8, .required = false },
    .{ .path = "/dev/urandom", .kind = .character, .major = 1, .minor = 9, .required = false },
    .{ .path = "/dev/tty", .kind = .character, .major = 5, .minor = 0, .required = false },
};

/// Configured devices take precedence over defaults. Paths are owned by the result.
pub fn prepareDevices(allocator: std.mem.Allocator, configured: ?[]const Spec.Device) ![]Backend.Device {
    var devices: std.ArrayList(Backend.Device) = .empty;
    errdefer {
        for (devices.items) |device| allocator.free(device.path);
        devices.deinit(allocator);
    }
    for (configured orelse &.{}) |device| {
        const kind: Backend.Device.Kind = if (std.mem.eql(u8, device.type, "c") or std.mem.eql(u8, device.type, "u"))
            .character
        else if (std.mem.eql(u8, device.type, "b"))
            .block
        else if (std.mem.eql(u8, device.type, "p"))
            .fifo
        else
            return error.InvalidConfig;
        const major = device.major orelse if (kind == .fifo) 0 else return error.InvalidConfig;
        const minor = device.minor orelse if (kind == .fifo) 0 else return error.InvalidConfig;
        // Linux mknod encodes 12 major bits and 20 minor bits.
        if (major < 0 or major > 0xfff or minor < 0 or minor > 0xfffff)
            return error.InvalidConfig;
        const mode = device.fileMode orelse 0o666;
        const uid = device.uid orelse 0;
        const gid = device.gid orelse 0;
        if (mode & ~@as(u32, 0o7777) != 0 or
            uid == std.math.maxInt(u32) or gid == std.math.maxInt(u32))
            return error.InvalidConfig;
        const path = try resolveMountDestination(allocator, device.path);
        errdefer allocator.free(path);
        if (path.len == 1) return error.InvalidConfig;
        for (devices.items) |previous| {
            if (std.mem.eql(u8, previous.path, path)) return error.InvalidConfig;
        }
        try devices.append(allocator, .{
            .path = path,
            .kind = kind,
            .major = @intCast(major),
            .minor = @intCast(minor),
            .mode = mode,
            .uid = uid,
            .gid = gid,
        });
    }
    for (default_devices) |device| {
        for (devices.items) |existing| {
            if (std.mem.eql(u8, existing.path, device.path)) break;
        } else {
            const path = try allocator.dupe(u8, device.path);
            errdefer allocator.free(path);
            var prepared = device;
            prepared.path = path;
            try devices.append(allocator, prepared);
        }
    }
    return devices.toOwnedSlice(allocator);
}

pub fn freeDevices(allocator: std.mem.Allocator, devices: []const Backend.Device) void {
    for (devices) |device| allocator.free(device.path);
    allocator.free(devices);
}

const default_device_symlinks = [_]Backend.Symlink{
    .{ .path = "/dev/fd", .target = "/proc/self/fd" },
    .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
    .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
    .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
    .{ .path = "/dev/ptmx", .target = "pts/ptmx" },
};

pub fn deviceSymlinks(mounts: []const Backend.Mount) []const Backend.Symlink {
    for (mounts) |mount| {
        if (std.mem.eql(u8, mount.destination, "/dev/pts") and
            mount.flags & std.os.linux.MS.BIND == 0 and
            std.mem.eql(u8, mount.type orelse "", "devpts"))
            return &default_device_symlinks;
    }
    return default_device_symlinks[0..4];
}

test "linux devices parse all types and default permissions and ownership" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"devices":[{"path":"/dev/custom","type":"c","major":1,"minor":3},{"path":"/disk","type":"b","major":8,"minor":0,"fileMode":416,"uid":1000,"gid":1001},{"path":"/dev/alias","type":"u","major":1,"minor":5,"fileMode":0},{"path":"/run/pipe","type":"p"}]}
    , .{});
    defer parsed.deinit();
    const devices = try prepareDevices(std.testing.allocator, parsed.value.devices);
    defer freeDevices(std.testing.allocator, devices);
    try std.testing.expectEqual(@as(usize, 10), devices.len);
    try std.testing.expectEqual(Backend.Device.Kind.character, devices[0].kind);
    try std.testing.expectEqual(@as(u32, 0o666), devices[0].mode);
    try std.testing.expectEqual(@as(u32, 0), devices[0].uid);
    try std.testing.expectEqual(@as(u32, 0), devices[0].gid);
    try std.testing.expectEqual(Backend.Device.Kind.block, devices[1].kind);
    try std.testing.expectEqualStrings("/disk", devices[1].path);
    try std.testing.expectEqual(@as(u32, 0o640), devices[1].mode);
    try std.testing.expectEqual(@as(u32, 1000), devices[1].uid);
    try std.testing.expectEqual(@as(u32, 1001), devices[1].gid);
    try std.testing.expectEqual(Backend.Device.Kind.character, devices[2].kind);
    try std.testing.expectEqual(@as(u32, 0), devices[2].mode);
    try std.testing.expectEqual(Backend.Device.Kind.fifo, devices[3].kind);
    try std.testing.expectEqual(@as(u32, 0), devices[3].major);
    try std.testing.expectEqual(@as(u32, 0), devices[3].minor);
}

test "linux devices reject invalid types paths numbers and duplicates" {
    const cases = [_][]const u8{
        \\[{"path":"/dev/custom","type":"a","major":1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"","major":1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"char","major":1,"minor":3}]
        ,
        \\[{"path":"dev/custom","type":"c","major":1,"minor":3}]
        ,
        \\[{"path":"","type":"p"}]
        ,
        \\[{"path":"/","type":"p"}]
        ,
        \\[{"path":"/../outside","type":"p"}]
        ,
        \\[{"path":"/dev/custom\u0000","type":"p"}]
        ,
        \\[{"path":"/dev/custom","type":"c","minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"b","major":8}]
        ,
        \\[{"path":"/dev/custom","type":"u","major":-1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":1,"minor":-1}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":4096,"minor":0}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":1,"minor":1048576}]
        ,
        \\[{"path":"/dev/custom","type":"p","fileMode":4096}]
        ,
        \\[{"path":"/dev/custom","type":"p","uid":4294967295}]
        ,
        \\[{"path":"/dev/custom","type":"p","gid":4294967295}]
        ,
        \\[{"path":"/dev/custom","type":"p"},{"path":"/dev/custom","type":"p"}]
        ,
        \\[{"path":"/dev/custom","type":"p"},{"path":"/dev/./custom","type":"p"}]
        ,
    };
    for (cases) |json| {
        const parsed = try std.json.parseFromSlice([]const Spec.Device, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidConfig, prepareDevices(std.testing.allocator, parsed.value));
    }
}

test "linux configured devices override default paths and preserve other defaults" {
    const devices = try prepareDevices(std.testing.allocator, &.{.{
        .path = "//dev/./null",
        .type = "u",
        .major = 1,
        .minor = 3,
        .fileMode = 0o600,
        .uid = 123,
        .gid = 456,
    }});
    defer freeDevices(std.testing.allocator, devices);
    try std.testing.expectEqual(@as(usize, 6), devices.len);
    try std.testing.expectEqualStrings("/dev/null", devices[0].path);
    try std.testing.expectEqual(@as(u32, 0o600), devices[0].mode);
    try std.testing.expectEqual(@as(u32, 123), devices[0].uid);
    try std.testing.expectEqual(@as(u32, 456), devices[0].gid);
    try std.testing.expect(devices[0].required);
    for (devices[1..]) |device| try std.testing.expect(!device.required);
    const defaults = try prepareDevices(std.testing.allocator, null);
    defer freeDevices(std.testing.allocator, defaults);
    const expected = [_]struct { path: []const u8, major: u32, minor: u32 }{
        .{ .path = "/dev/null", .major = 1, .minor = 3 },
        .{ .path = "/dev/zero", .major = 1, .minor = 5 },
        .{ .path = "/dev/full", .major = 1, .minor = 7 },
        .{ .path = "/dev/random", .major = 1, .minor = 8 },
        .{ .path = "/dev/urandom", .major = 1, .minor = 9 },
        .{ .path = "/dev/tty", .major = 5, .minor = 0 },
    };
    try std.testing.expectEqual(expected.len, defaults.len);
    for (expected, defaults) |want, actual| {
        try std.testing.expectEqualStrings(want.path, actual.path);
        try std.testing.expectEqual(want.major, actual.major);
        try std.testing.expectEqual(want.minor, actual.minor);
        try std.testing.expectEqual(Backend.Device.Kind.character, actual.kind);
        try std.testing.expectEqual(@as(u32, 0o666), actual.mode);
        try std.testing.expect(!actual.required);
        try std.testing.expectEqual(@as(u32, 0), actual.uid);
        try std.testing.expectEqual(@as(u32, 0), actual.gid);
    }
}

test "default device symlinks include ptmx only for a devpts mount" {
    const expected = [_]Backend.Symlink{
        .{ .path = "/dev/fd", .target = "/proc/self/fd" },
        .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
        .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
        .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
        .{ .path = "/dev/ptmx", .target = "pts/ptmx" },
    };
    for ([_][]const Backend.Mount{
        &.{},
        &.{.{ .destination = "/dev/pts", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" }},
        &.{.{ .destination = "/elsewhere", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }},
        &.{.{ .destination = "/dev/pts", .source = "/dev/pts", .type = "devpts", .flags = std.os.linux.MS.BIND, .propagation = 0, .data = "" }},
    }) |mounts| {
        const links = deviceSymlinks(mounts);
        try std.testing.expectEqual(@as(usize, 4), links.len);
        for (expected[0..4], links) |want, actual| {
            try std.testing.expectEqualStrings(want.path, actual.path);
            try std.testing.expectEqualStrings(want.target, actual.target);
        }
    }
    const links = deviceSymlinks(&.{.{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }});
    try std.testing.expectEqual(@as(usize, 5), links.len);
    for (expected, links) |want, actual| {
        try std.testing.expectEqualStrings(want.path, actual.path);
        try std.testing.expectEqualStrings(want.target, actual.target);
    }
}

test "device preparation frees paths on allocation failure including default overrides" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const devices = try prepareDevices(allocator, &.{
                .{ .path = "/dev/null", .type = "c", .major = 1, .minor = 3 },
                .{ .path = "/run/pipe", .type = "p" },
            });
            defer freeDevices(allocator, devices);
            try std.testing.expectEqual(@as(usize, 7), devices.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

/// Null means a well-formed CAP_* name unknown to our table, possibly a newer cap.
/// Linux constants are available on every build host; no syscalls are made.
pub fn capabilityNumber(name: []const u8) error{InvalidConfig}!?u6 {
    if (!std.mem.startsWith(u8, name, "CAP_") or name.len == 4) return error.InvalidConfig;
    for (name[4..]) |c| {
        if (!std.ascii.isUpper(c) and !std.ascii.isDigit(c) and c != '_') return error.InvalidConfig;
    }
    inline for (comptime std.meta.declarations(std.os.linux.CAP)) |decl| {
        if (comptime !std.mem.eql(u8, decl.name, "LAST_CAP") and
            @TypeOf(@field(std.os.linux.CAP, decl.name)) == comptime_int)
        {
            if (std.mem.eql(u8, name, "CAP_" ++ decl.name))
                return @intCast(@field(std.os.linux.CAP, decl.name));
        }
    }
    return null;
}

pub fn rlimitResource(name: []const u8) error{InvalidConfig}!std.os.linux.rlimit_resource {
    if (!std.mem.startsWith(u8, name, "RLIMIT_")) return error.InvalidConfig;
    return std.meta.stringToEnum(std.os.linux.rlimit_resource, name["RLIMIT_".len..]) orelse error.InvalidConfig;
}

pub fn processCapabilities(config: Spec.Capabilities) !Backend.Capabilities {
    var result: Backend.Capabilities = .{};
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
        for (@field(config, field.name) orelse &.{}) |name| {
            const number = try capabilityNumber(name) orelse {
                std.debug.print("igvano: unknown capability {s}\n", .{name});
                return error.InvalidConfig;
            };
            @field(result, field.name) |= @as(u64, 1) << number;
        }
    }
    if (result.ambient & ~(result.permitted & result.inheritable) != 0)
        return error.AmbientCapabilitiesRequirePermittedAndInheritable;
    return result;
}

pub fn processRlimits(allocator: std.mem.Allocator, config: ?[]const Spec.Rlimit) ![]Backend.Rlimit {
    const limits = config orelse &.{};
    const result = try allocator.alloc(Backend.Rlimit, limits.len);
    errdefer allocator.free(result);
    for (limits, result, 0..) |limit, *prepared, i| {
        if (limit.soft > limit.hard) return error.InvalidConfig;
        const resource = try rlimitResource(limit.type);
        for (result[0..i]) |previous| {
            if (previous.resource == resource) return error.InvalidConfig;
        }
        prepared.* = .{
            .resource = resource,
            .hard = limit.hard,
            .soft = limit.soft,
        };
    }
    return result;
}

test "capability names map the complete Linux set and reject malformed names" {
    const names = [_][]const u8{
        "CAP_CHOWN",           "CAP_DAC_OVERRIDE",       "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",          "CAP_FSETID",             "CAP_KILL",
        "CAP_SETGID",          "CAP_SETUID",             "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE",   "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",       "CAP_NET_RAW",            "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",       "CAP_SYS_MODULE",         "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",      "CAP_SYS_PTRACE",         "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",       "CAP_SYS_BOOT",           "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",    "CAP_SYS_TIME",           "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",           "CAP_LEASE",              "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",   "CAP_SETFCAP",            "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",       "CAP_SYSLOG",             "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",   "CAP_AUDIT_READ",         "CAP_PERFMON",
        "CAP_BPF",             "CAP_CHECKPOINT_RESTORE",
    };
    for (names, 0..) |name, number|
        try std.testing.expectEqual(@as(?u6, @intCast(number)), try capabilityNumber(name));
    const caps = try processCapabilities(.{
        .bounding = &names,
        .effective = &names,
        .permitted = &names,
        .inheritable = &names,
        .ambient = &names,
    });
    inline for (std.meta.fields(Backend.Capabilities)) |field|
        try std.testing.expectEqual(@as(u64, 0x1ffffffffff), @field(caps, field.name));
    for ([_][]const u8{ "", "CHOWN", "cap_chown", "CAP_", "CAP_chown", "CAP_CHOWN\x00", "CAP_CHOWN!" }) |name|
        try std.testing.expectError(error.InvalidConfig, capabilityNumber(name));
    try std.testing.expectEqual(@as(?u6, null), try capabilityNumber("CAP_FUTURE"));
}

test "rlimit names map every Linux resource and reject unknown names" {
    const cases = .{
        .{ "RLIMIT_CPU", .CPU },           .{ "RLIMIT_FSIZE", .FSIZE },
        .{ "RLIMIT_DATA", .DATA },         .{ "RLIMIT_STACK", .STACK },
        .{ "RLIMIT_CORE", .CORE },         .{ "RLIMIT_RSS", .RSS },
        .{ "RLIMIT_NPROC", .NPROC },       .{ "RLIMIT_NOFILE", .NOFILE },
        .{ "RLIMIT_MEMLOCK", .MEMLOCK },   .{ "RLIMIT_AS", .AS },
        .{ "RLIMIT_LOCKS", .LOCKS },       .{ "RLIMIT_SIGPENDING", .SIGPENDING },
        .{ "RLIMIT_MSGQUEUE", .MSGQUEUE }, .{ "RLIMIT_NICE", .NICE },
        .{ "RLIMIT_RTPRIO", .RTPRIO },     .{ "RLIMIT_RTTIME", .RTTIME },
    };
    inline for (cases) |case|
        try std.testing.expectEqual(@as(std.os.linux.rlimit_resource, case[1]), try rlimitResource(case[0]));
    for ([_][]const u8{ "", "NOFILE", "rlimit_nofile", "RLIMIT_UNKNOWN", "RLIMIT_", "RLIMIT_NOFILE\x00" }) |name|
        try std.testing.expectError(error.InvalidConfig, rlimitResource(name));
}

test "ambient capabilities require membership in both permitted and inheritable" {
    const cap: u64 = @as(u64, 1) << std.os.linux.CAP.NET_BIND_SERVICE;
    const valid = try processCapabilities(.{
        .bounding = &.{"CAP_NET_BIND_SERVICE"},
        .effective = &.{"CAP_NET_BIND_SERVICE"},
        .permitted = &.{"CAP_NET_BIND_SERVICE"},
        .inheritable = &.{"CAP_NET_BIND_SERVICE"},
        .ambient = &.{"CAP_NET_BIND_SERVICE"},
    });
    try std.testing.expectEqual(Backend.Capabilities{
        .bounding = cap,
        .effective = cap,
        .permitted = cap,
        .inheritable = cap,
        .ambient = cap,
    }, valid);
    try std.testing.expectEqual(Backend.Capabilities{}, try processCapabilities(.{}));
    for ([_]Spec.Capabilities{
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .permitted = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .inheritable = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .permitted = &.{"CAP_NET_BIND_SERVICE"}, .inheritable = &.{"CAP_CHOWN"} },
    }) |config| {
        try std.testing.expectError(error.AmbientCapabilitiesRequirePermittedAndInheritable, processCapabilities(config));
    }
    inline for (std.meta.fields(Spec.Capabilities)) |field| {
        var config: Spec.Capabilities = .{};
        @field(config, field.name) = &.{"not-a-capability"};
        try std.testing.expectError(error.InvalidConfig, processCapabilities(config));
    }
    const upper = try processCapabilities(.{ .bounding = &.{ "CAP_CHECKPOINT_RESTORE", "CAP_CHECKPOINT_RESTORE" } });
    try std.testing.expectEqual(@as(u64, 1) << 40, upper.bounding);
}

test "process capabilities reject unknown names in every set" {
    inline for (std.meta.fields(Spec.Capabilities)) |field| {
        var config: Spec.Capabilities = .{};
        @field(config, field.name) = &.{ "CAP_CHOWN", "CAP_FUTURE" };
        try std.testing.expectError(error.InvalidConfig, processCapabilities(config));
    }
}

test "process parses oomScoreAdj without range validation" {
    const cases = [_]struct { json_value: []const u8, expected: ?i32 }{
        .{ .json_value = "500", .expected = 500 },
        .{ .json_value = "100", .expected = 100 },
        .{ .json_value = "0", .expected = 0 },
        .{ .json_value = "-1000", .expected = -1000 },
        .{ .json_value = "1001", .expected = 1001 },
        .{ .json_value = "-1001", .expected = -1001 },
        .{ .json_value = "null", .expected = null },
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const json = try std.fmt.bufPrint(&buffer,
            \\{{"args":["/bin/sh"],"cwd":"/","user":{{"uid":0,"gid":0}},"oomScoreAdj":{s}}}
        , .{case.json_value});
        const parsed = try std.json.parseFromSlice(Spec.Process, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(case.expected, parsed.value.oomScoreAdj);
    }
}

test "process parses capabilities rlimits and supplementary groups" {
    const parsed = try std.json.parseFromSlice(Spec.Process, std.testing.allocator,
        \\{"args":["/bin/sh"],"cwd":"/","user":{"uid":1000,"gid":1001,"additionalGids":[1002,1003]},"capabilities":{"bounding":["CAP_CHOWN"],"effective":[],"permitted":["CAP_CHOWN"],"inheritable":[],"ambient":[]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":512},{"type":"RLIMIT_CORE","hard":18446744073709551615,"soft":0}]}
    , .{});
    defer parsed.deinit();
    const process = parsed.value;
    try std.testing.expectEqualSlices(u32, &.{ 1002, 1003 }, process.user.additionalGids.?);
    const caps = try processCapabilities(process.capabilities.?);
    try std.testing.expectEqual(@as(u64, 1), caps.bounding);
    try std.testing.expectEqual(@as(u64, 1), caps.permitted);
    try std.testing.expectEqual(@as(u64, 0), caps.effective);
    const limits = try processRlimits(std.testing.allocator, process.rlimits);
    defer std.testing.allocator.free(limits);
    try std.testing.expectEqual(@as(usize, 2), limits.len);
    try std.testing.expectEqual(Backend.Rlimit{ .resource = .NOFILE, .hard = 1024, .soft = 512 }, limits[0]);
    try std.testing.expectEqual(Backend.Rlimit{ .resource = .CORE, .hard = std.math.maxInt(u64), .soft = 0 }, limits[1]);
}

test "rlimit preparation rejects invalid names inverted limits and duplicates without leaking" {
    for ([_]Spec.Rlimit{
        .{ .type = "RLIMIT_UNKNOWN", .hard = 1024, .soft = 512 },
        .{ .type = "RLIMIT_NOFILE", .hard = 512, .soft = 1024 },
        .{ .type = "RLIMIT_NOFILE", .hard = 2048, .soft = 1024 },
    }) |invalid| {
        try std.testing.expectError(error.InvalidConfig, processRlimits(std.testing.allocator, &.{
            .{ .type = "RLIMIT_NOFILE", .hard = 1024, .soft = 512 },
            invalid,
        }));
    }
    const omitted = try processRlimits(std.testing.allocator, null);
    defer std.testing.allocator.free(omitted);
    try std.testing.expectEqual(@as(usize, 0), omitted.len);
}

/// Translate and validate OCI resources without selecting a cgroup hierarchy.
/// Arrays are caller-owned; strings are borrowed from the parsed spec.
pub fn cgroupResources(allocator: std.mem.Allocator, configured: ?Spec.Resources) !Backend.Resources {
    const settings = configured orelse return .{};
    var resources: Backend.Resources = .{};
    errdefer freeCgroupResources(allocator, resources);
    if (settings.memory) |memory| {
        inline for (.{ "limit", "reservation", "swap", "kernel", "kernelTCP" }) |field|
            try validateResourceLimit(@field(memory, field));
        resources.memory = .{
            .limit = memory.limit,
            .reservation = memory.reservation,
            .swap = memory.swap,
            .kernel = memory.kernel,
            .kernel_tcp = memory.kernelTCP,
            .swappiness = memory.swappiness,
            .disable_oom_killer = memory.disableOOMKiller,
        };
    }
    if (settings.cpu) |cpu| {
        try validateResourceLimit(cpu.quota);
        try validateResourceLimit(cpu.realtimeRuntime);
        if (cpu.shares) |shares|
            if (shares != 0 and (shares < 2 or shares > 262144)) return error.InvalidConfig;
        resources.cpu = .{
            .shares = cpu.shares,
            .quota = cpu.quota,
            .period = cpu.period,
            .realtime_runtime = cpu.realtimeRuntime,
            .realtime_period = cpu.realtimePeriod,
            .cpus = cpu.cpus,
            .mems = cpu.mems,
        };
    }
    if (settings.pids) |pids| {
        try validateResourceLimit(pids.limit);
        resources.pids = .{ .limit = pids.limit };
    }
    if (settings.blockIO) |block| {
        try validateResourceWeight(block.weight);
        try validateResourceWeight(block.leafWeight);
        resources.block_io = .{ .weight = block.weight, .leaf_weight = block.leafWeight };
        const weights = block.weightDevice orelse &.{};
        const translated = try allocator.alloc(Backend.Resources.WeightDevice, weights.len);
        resources.block_io.?.weight_device = translated;
        for (weights, translated) |entry, *device| {
            if (entry.major < 0 or entry.minor < 0) return error.InvalidConfig;
            try validateResourceWeight(entry.weight);
            try validateResourceWeight(entry.leafWeight);
            device.* = .{
                .major = entry.major,
                .minor = entry.minor,
                .weight = entry.weight,
                .leaf_weight = entry.leafWeight,
            };
        }
        resources.block_io.?.throttle_read_bps = try resourceThrottleDevices(allocator, block.throttleReadBpsDevice);
        resources.block_io.?.throttle_write_bps = try resourceThrottleDevices(allocator, block.throttleWriteBpsDevice);
        resources.block_io.?.throttle_read_iops = try resourceThrottleDevices(allocator, block.throttleReadIOPSDevice);
        resources.block_io.?.throttle_write_iops = try resourceThrottleDevices(allocator, block.throttleWriteIOPSDevice);
    }
    const hugepages = settings.hugepageLimits orelse &.{};
    const translated_pages = try allocator.alloc(Backend.Resources.HugepageLimit, hugepages.len);
    resources.hugepage_limits = translated_pages;
    for (hugepages, translated_pages) |entry, *page| {
        if (entry.pageSize.len == 0) return error.InvalidConfig;
        page.* = .{ .page_size = entry.pageSize, .limit = entry.limit };
    }
    if (settings.network) |network| {
        resources.network = .{ .class_id = network.classID };
        const priorities = network.priorities orelse &.{};
        const translated = try allocator.alloc(Backend.Resources.Priority, priorities.len);
        resources.network.?.priorities = translated;
        for (priorities, translated) |entry, *priority|
            priority.* = .{ .name = entry.name, .priority = entry.priority };
    }
    const devices = settings.devices orelse &.{};
    const translated_devices = try allocator.alloc(Backend.Resources.DeviceRule, devices.len);
    resources.devices = translated_devices;
    for (devices, translated_devices) |entry, *device| {
        const kind: @FieldType(Backend.Resources.DeviceRule, "kind") = if (std.mem.eql(u8, entry.type, "a"))
            .all
        else if (std.mem.eql(u8, entry.type, "b"))
            .block
        else if (std.mem.eql(u8, entry.type, "c"))
            .char
        else
            return error.InvalidConfig;
        for (entry.access) |access|
            if (access != 'r' and access != 'w' and access != 'm') return error.InvalidConfig;
        try validateResourceLimit(entry.major);
        try validateResourceLimit(entry.minor);
        device.* = .{
            .allow = entry.allow,
            .kind = kind,
            .major = if (entry.major == -1) null else entry.major,
            .minor = if (entry.minor == -1) null else entry.minor,
            .access = entry.access,
        };
    }
    if (settings.unified) |unified| {
        const translated = try allocator.alloc(Backend.Resources.Unified, unified.map.count());
        resources.unified = translated;
        for (unified.map.keys(), unified.map.values(), translated) |key, value, *entry| {
            if (key.len == 0 or std.mem.indexOfAny(u8, key, "/\x00") != null or
                std.mem.eql(u8, key, ".") or std.mem.eql(u8, key, "..")) return error.InvalidConfig;
            entry.* = .{ .key = key, .value = value };
        }
    }
    return resources;
}

fn validateResourceLimit(value: ?i64) error{InvalidConfig}!void {
    if (value) |limit|
        if (limit < -1) return error.InvalidConfig;
}

fn validateResourceWeight(value: ?u16) error{InvalidConfig}!void {
    if (value) |weight|
        if (weight != 0 and (weight < 10 or weight > 1000)) return error.InvalidConfig;
}

fn resourceThrottleDevices(allocator: std.mem.Allocator, configured: ?[]const Spec.Resources.ThrottleDevice) ![]Backend.Resources.ThrottleDevice {
    const entries = configured orelse &.{};
    const devices = try allocator.alloc(Backend.Resources.ThrottleDevice, entries.len);
    errdefer allocator.free(devices);
    for (entries, devices) |entry, *device| {
        if (entry.major < 0 or entry.minor < 0) return error.InvalidConfig;
        device.* = .{ .major = entry.major, .minor = entry.minor, .rate = entry.rate };
    }
    return devices;
}

pub fn freeCgroupResources(allocator: std.mem.Allocator, resources: Backend.Resources) void {
    if (resources.block_io) |block| {
        allocator.free(block.weight_device);
        allocator.free(block.throttle_read_bps);
        allocator.free(block.throttle_write_bps);
        allocator.free(block.throttle_read_iops);
        allocator.free(block.throttle_write_iops);
    }
    allocator.free(resources.hugepage_limits);
    if (resources.network) |network| allocator.free(network.priorities);
    allocator.free(resources.devices);
    allocator.free(resources.unified);
}

/// Linux mount constants are available on every build host; this performs no I/O.
/// The caller owns data, including when there are no filesystem-specific options.
pub const MountOptions = struct {
    flags: u32,
    propagation: u32,
    data: [:0]u8,
    recursive_readonly: ?bool = null,
};

pub fn parseMountOptions(allocator: std.mem.Allocator, options: []const []const u8, mount_type: ?[]const u8) !MountOptions {
    const ms = std.os.linux.MS;
    const atime = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
    const flag_options = [_]struct { name: []const u8, set: u32 = 0, clear: u32 = 0 }{
        .{ .name = "defaults" },
        .{ .name = "ro", .set = ms.RDONLY },
        .{ .name = "rw", .clear = ms.RDONLY },
        .{ .name = "nosuid", .set = ms.NOSUID },
        .{ .name = "suid", .clear = ms.NOSUID },
        .{ .name = "nodev", .set = ms.NODEV },
        .{ .name = "dev", .clear = ms.NODEV },
        .{ .name = "noexec", .set = ms.NOEXEC },
        .{ .name = "exec", .clear = ms.NOEXEC },
        .{ .name = "bind", .set = ms.BIND, .clear = ms.REC },
        .{ .name = "rbind", .set = ms.BIND | ms.REC },
        .{ .name = "relatime", .set = ms.RELATIME, .clear = atime },
        .{ .name = "noatime", .set = ms.NOATIME, .clear = atime },
        .{ .name = "strictatime", .set = ms.STRICTATIME, .clear = atime },
        .{ .name = "atime", .clear = ms.NOATIME },
        .{ .name = "nodiratime", .set = ms.NODIRATIME },
        .{ .name = "diratime", .clear = ms.NODIRATIME },
        .{ .name = "sync", .set = ms.SYNCHRONOUS },
        .{ .name = "async", .clear = ms.SYNCHRONOUS },
        .{ .name = "dirsync", .set = ms.DIRSYNC },
    };
    const propagation_options = [_]struct { name: []const u8, flags: u32 }{
        .{ .name = "private", .flags = ms.PRIVATE },
        .{ .name = "rprivate", .flags = ms.PRIVATE | ms.REC },
        .{ .name = "slave", .flags = ms.SLAVE },
        .{ .name = "rslave", .flags = ms.SLAVE | ms.REC },
        .{ .name = "shared", .flags = ms.SHARED },
        .{ .name = "rshared", .flags = ms.SHARED | ms.REC },
        .{ .name = "unbindable", .flags = ms.UNBINDABLE },
        .{ .name = "runbindable", .flags = ms.UNBINDABLE | ms.REC },
    };
    var flags: u32 = if (mount_type != null and std.mem.eql(u8, mount_type.?, "bind")) ms.BIND else 0;
    var propagation: u32 = 0;
    var recursive_readonly: ?bool = null;
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    option: for (options) |option| {
        if (std.mem.indexOfScalar(u8, option, 0) != null) return error.InvalidConfig;
        if (std.mem.eql(u8, option, "rro") or std.mem.eql(u8, option, "rrw")) {
            recursive_readonly = std.mem.eql(u8, option, "rro");
            continue;
        }
        for (flag_options) |entry| {
            if (std.mem.eql(u8, option, entry.name)) {
                flags = (flags & ~entry.clear) | entry.set;
                continue :option;
            }
        }
        // Propagation changes require their own mount syscall.
        for (propagation_options) |entry| {
            if (std.mem.eql(u8, option, entry.name)) {
                propagation = entry.flags;
                continue :option;
            }
        }
        if (data.items.len != 0) try data.append(allocator, ',');
        try data.appendSlice(allocator, option);
    }
    // Discard filesystem data for bind mounts because the kernel ignores it.
    if (flags & ms.BIND != 0) {
        if (data.items.len != 0)
            std.debug.print("igvano: warning: bind mount ignores options: {s}\n", .{data.items});
        data.clearRetainingCapacity();
    }
    return .{
        .flags = flags,
        .propagation = propagation,
        .data = try data.toOwnedSliceSentinel(allocator, 0),
        .recursive_readonly = recursive_readonly,
    };
}

pub fn validateMountDestination(destination: []const u8) !void {
    if (!std.mem.startsWith(u8, destination, "/") or
        std.mem.indexOfScalar(u8, destination, 0) != null) return error.InvalidConfig;
    var depth: usize = 0;
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (depth == 0) return error.InvalidConfig;
            depth -= 1;
        } else {
            depth += 1;
        }
    }
}

/// Returns an absolute, normalized container path, never a host path.
pub fn resolveMountDestination(allocator: std.mem.Allocator, destination: []const u8) ![]u8 {
    try validateMountDestination(destination);
    return std.fs.path.resolve(allocator, &.{destination});
}

/// Map ranges are half-open; widen before adding to avoid wrapping u32 IDs.
pub fn validateIDMappings(mappings: []const Spec.IDMapping) error{InvalidConfig}!void {
    if (mappings.len == 0 or mappings.len > 340) return error.InvalidConfig;
    var text_size: usize = 0;
    for (mappings, 0..) |mapping, i| {
        const end = @as(u64, mapping.containerID) + mapping.size;
        const host_end = @as(u64, mapping.hostID) + mapping.size;
        // Linux reserves (uid_t)-1 and (gid_t)-1 as unmapped IDs.
        if (mapping.size == 0 or end > std.math.maxInt(u32) or host_end > std.math.maxInt(u32))
            return error.InvalidConfig;
        text_size += std.fmt.count("{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
        if (text_size >= 4096) return error.InvalidConfig; // Linux requires a write smaller than one page.
        for (mappings[0..i]) |previous| {
            const previous_end = @as(u64, previous.containerID) + previous.size;
            const previous_host_end = @as(u64, previous.hostID) + previous.size;
            if ((mapping.containerID < previous_end and previous.containerID < end) or
                (mapping.hostID < previous_host_end and previous.hostID < host_end))
                return error.InvalidConfig;
        }
    }
}

/// Omitted namespace types are inherited from the runtime.
pub fn requireCreate(spec: Spec) !void {
    _ = std.SemanticVersion.parse(spec.ociVersion) catch return error.InvalidConfig;
    try validateHooks(spec.hooks);
    const settings: Spec.Linux = spec.linux orelse .{};
    try validateSysctls(settings);
    const uid_mappings: []const Spec.IDMapping = settings.uidMappings orelse &.{};
    const gid_mappings: []const Spec.IDMapping = settings.gidMappings orelse &.{};
    const namespaces = settings.namespaces orelse &.{};
    var has_mount = false;
    var has_user = false;
    for (namespaces) |namespace| {
        if (namespace.type == .mount) has_mount = true;
        if (namespace.type == .user and namespace.path == null) has_user = true;
    }
    if (has_user) {
        for ([_][]const Spec.IDMapping{ uid_mappings, gid_mappings }) |mappings| {
            try validateIDMappings(mappings);
            // OCI does not require a root mapping; our init, like runc, needs one.
            for (mappings) |mapping| {
                if (mapping.containerID == 0) break;
            } else return error.InvalidConfig;
        }
    } else if (uid_mappings.len > 0 or gid_mappings.len > 0) {
        return error.InvalidConfig;
    }
    if (!has_mount and settings.rootfsPropagation != null) {
        std.debug.print("igvano: cannot change propagation without a private mount namespace\n", .{});
        return error.InvalidConfig;
    }
    if (spec.root.path.len == 0) return error.InvalidConfig;
    if (spec.process) |process| try validateProcess(process);
    for (spec.mounts orelse &.{}) |mount| try validateMountDestination(mount.destination);
    for (settings.maskedPaths orelse &.{}) |path| try validateMountDestination(path);
    for (settings.readonlyPaths orelse &.{}) |path| try validateMountDestination(path);
}

pub fn validateEnv(entry: []const u8) !void {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return error.InvalidProcess;
    if (equals == 0 or std.mem.indexOfScalar(u8, entry, 0) != null) return error.InvalidProcess;
}

pub fn validateProcess(process: Spec.Process) !void {
    if (!std.mem.startsWith(u8, process.cwd, "/") or
        std.mem.indexOfScalar(u8, process.cwd, 0) != null or
        process.args.len == 0 or process.args[0].len == 0) return error.InvalidProcess;
    for (process.args) |arg| {
        if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidProcess;
    }
    for (process.env orelse &.{}) |entry| try validateEnv(entry);
    if (process.oomScoreAdj) |value| {
        if (value < -1000 or value > 1000) return error.InvalidConfig;
    }
}

test "mount options translate flags propagation and filesystem data" {
    const ms = std.os.linux.MS;
    const cases = [_]struct {
        options: []const []const u8,
        flags: u32 = 0,
        propagation: u32 = 0,
        data: []const u8 = "",
    }{
        .{ .options = &.{} },
        .{ .options = &.{"ro"}, .flags = ms.RDONLY },
        .{ .options = &.{ "ro", "rw" } },
        .{ .options = &.{ "rw", "ro" }, .flags = ms.RDONLY },
        .{ .options = &.{ "nosuid", "nodev", "noexec" }, .flags = ms.NOSUID | ms.NODEV | ms.NOEXEC },
        .{ .options = &.{ "nosuid", "suid", "nodev", "dev", "noexec", "exec", "defaults" } },
        .{ .options = &.{"bind"}, .flags = ms.BIND },
        .{ .options = &.{ "ro", "rbind" }, .flags = ms.RDONLY | ms.BIND | ms.REC },
        .{ .options = &.{ "rbind", "bind" }, .flags = ms.BIND },
        .{ .options = &.{"private"}, .propagation = ms.PRIVATE },
        .{ .options = &.{"rprivate"}, .propagation = ms.PRIVATE | ms.REC },
        .{ .options = &.{"slave"}, .propagation = ms.SLAVE },
        .{ .options = &.{"rslave"}, .propagation = ms.SLAVE | ms.REC },
        .{ .options = &.{"shared"}, .propagation = ms.SHARED },
        .{ .options = &.{"rshared"}, .propagation = ms.SHARED | ms.REC },
        .{ .options = &.{"unbindable"}, .propagation = ms.UNBINDABLE },
        .{ .options = &.{"runbindable"}, .propagation = ms.UNBINDABLE | ms.REC },
        .{ .options = &.{ "rshared", "private" }, .propagation = ms.PRIVATE },
        .{ .options = &.{ "runbindable", "shared" }, .propagation = ms.SHARED },
        .{ .options = &.{ "rbind", "private" }, .flags = ms.BIND | ms.REC, .propagation = ms.PRIVATE },
        .{ .options = &.{ "nosuid", "strictatime", "mode=755", "size=1k", "bind", "shared" }, .flags = ms.NOSUID | ms.STRICTATIME | ms.BIND, .propagation = ms.SHARED },
        .{ .options = &.{"relatime"}, .flags = ms.RELATIME },
        .{ .options = &.{"noatime"}, .flags = ms.NOATIME },
        .{ .options = &.{"strictatime"}, .flags = ms.STRICTATIME },
        .{ .options = &.{ "noatime", "relatime", "strictatime" }, .flags = ms.STRICTATIME },
        .{ .options = &.{ "ro", "size=65536k", "nosuid", "mode=755", "custom" }, .flags = ms.RDONLY | ms.NOSUID, .data = "size=65536k,mode=755,custom" },
    };
    for (cases) |case| {
        const result = try parseMountOptions(std.testing.allocator, case.options, null);
        defer std.testing.allocator.free(result.data);
        try std.testing.expectEqual(case.flags, result.flags);
        try std.testing.expectEqual(case.propagation, result.propagation);
        try std.testing.expectEqualStrings(case.data, result.data);
    }
    try std.testing.expectError(error.InvalidConfig, parseMountOptions(std.testing.allocator, &.{"mode=7\x0055"}, null));
}

test "mount destinations normalize within the root and reject escapes" {
    const cases = [_]struct { destination: []const u8, expected: []const u8 }{
        .{ .destination = "/", .expected = "/" },
        .{ .destination = "/proc", .expected = "/proc" },
        .{ .destination = "//dev/./pts/", .expected = "/dev/pts" },
        .{ .destination = "/a/../mnt", .expected = "/mnt" },
        .{ .destination = "/a/b/../../", .expected = "/" },
    };
    for (cases) |case| {
        const destination = try resolveMountDestination(std.testing.allocator, case.destination);
        defer std.testing.allocator.free(destination);
        try std.testing.expectEqualStrings(case.expected, destination);
    }
    for ([_][]const u8{ "", "proc", "../proc", "/..", "/../proc", "/a/../../outside", "/a/../..", "/proc\x00/../outside" }) |destination| {
        try std.testing.expectError(error.InvalidConfig, resolveMountDestination(std.testing.allocator, destination));
    }
}

test "bind mounts discard filesystem data regardless of option order" {
    const cases = [_][]const []const u8{
        &.{ "bind", "custom" },
        &.{ "custom", "bind" },
        &.{ "rbind", "size=65536k", "ro" },
        &.{ "mode=755", "rbind", "rprivate" },
        &.{ "bind", "" },
        &.{ "bind", "nosuid", "nosiud", "mode=755", "size=1k" },
    };
    for (cases) |options| {
        const bind = try parseMountOptions(std.testing.allocator, options, null);
        defer std.testing.allocator.free(bind.data);
        try std.testing.expectEqualStrings("", bind.data);
    }
    const custom = try parseMountOptions(std.testing.allocator, &.{"custom"}, "bind");
    defer std.testing.allocator.free(custom.data);
    try std.testing.expectEqualStrings("", custom.data);
    const bind = try parseMountOptions(std.testing.allocator, &.{ "ro", "rprivate" }, "bind");
    defer std.testing.allocator.free(bind.data);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.BIND | std.os.linux.MS.RDONLY), bind.flags);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.PRIVATE | std.os.linux.MS.REC), bind.propagation);
}

test "create validation accepts inherited mount namespaces with or without mounts" {
    var spec: Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" } };
    try requireCreate(spec);
    spec.linux = .{};
    try requireCreate(spec);
    spec.linux = .{ .namespaces = &.{.{ .type = .pid }} };
    spec.mounts = &.{.{ .destination = "/proc", .type = "proc" }};
    try requireCreate(spec);
    spec.linux = .{ .namespaces = &.{.{ .type = .mount }} };
    try requireCreate(spec);
    spec.mounts = null;
    spec.root.readonly = true;
    try requireCreate(spec);
    spec.mounts = &.{.{ .destination = "/../outside" }};
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.mounts = null;
    spec.process = .{ .args = &.{"/bin/sh"}, .cwd = "relative", .user = .{ .uid = 0, .gid = 0 } };
    try std.testing.expectError(error.InvalidProcess, requireCreate(spec));
}

test "create rejects explicit rootfs propagation without a mount namespace" {
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .rootfsPropagation = .private },
    };
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux.?.namespaces = &.{.{ .type = .mount, .path = "/proc/123/ns/mnt" }};
    try requireCreate(spec);
}

test "create rejects malformed OCI version strings" {
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
    };
    for ([_][]const u8{ "", "invalid", "1.0", "1.0.0.0" }) |version| {
        spec.ociVersion = version;
        try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    }
}

test "create accepts new user namespaces with maps and joins without maps" {
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } },
            .uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 65536 }},
            .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 65536 }},
        },
    };
    try requireCreate(spec);
    spec.linux.?.namespaces = &.{ .{ .type = .mount }, .{ .type = .user, .path = "/proc/1/ns/user" } };
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux.?.uidMappings = null;
    spec.linux.?.gidMappings = null;
    try requireCreate(spec);
}

test "create rejects mappings without a user namespace and missing user namespace maps" {
    const mappings: []const Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 100000, .size = 1 }};
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
    };
    for ([_]Spec.Linux{
        .{ .namespaces = &.{.{ .type = .mount }}, .uidMappings = mappings },
        .{ .namespaces = &.{.{ .type = .mount }}, .gidMappings = mappings },
        .{ .uidMappings = mappings },
        .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } } },
        .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } }, .uidMappings = mappings },
        .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } }, .gidMappings = mappings },
    }) |settings| {
        spec.linux = settings;
        try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    }
}

test "create tolerates empty mapping arrays without a user namespace" {
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
    };
    for ([_]Spec.Linux{
        .{ .namespaces = &.{.{ .type = .mount }}, .uidMappings = &.{} },
        .{ .namespaces = &.{.{ .type = .mount }}, .gidMappings = &.{} },
        .{ .namespaces = &.{.{ .type = .mount }}, .uidMappings = &.{}, .gidMappings = &.{} },
    }) |settings| {
        spec.linux = settings;
        try requireCreate(spec);
    }
}

test "mapping validation rejects empty zero sized overlapping and oversized maps" {
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&.{}));
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&.{.{ .containerID = 0, .hostID = 1000, .size = 0 }}));
    for ([_][]const Spec.IDMapping{
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 9, .hostID = 2000, .size = 2 } },
        &.{ .{ .containerID = 9, .hostID = 2000, .size = 2 }, .{ .containerID = 0, .hostID = 1000, .size = 10 } },
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 2, .hostID = 2000, .size = 1 } },
        &.{.{ .containerID = std.math.maxInt(u32) - 1, .hostID = 0, .size = 3 }},
        &.{.{ .containerID = 0, .hostID = std.math.maxInt(u32) - 1, .size = 3 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, validateIDMappings(mappings));
    }
    var mappings: [341]Spec.IDMapping = undefined;
    for (&mappings, 0..) |*mapping, i| {
        mapping.* = .{ .containerID = @intCast(i), .hostID = @intCast(1000 + i), .size = 1 };
    }
    try validateIDMappings(mappings[0..340]);
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
    try validateIDMappings(&.{
        .{ .containerID = 10, .hostID = 2000, .size = 2 },
        .{ .containerID = 0, .hostID = 1000, .size = 10 },
    });
}

test "mapping validation rejects overlapping host ranges in either order" {
    for ([_][]const Spec.IDMapping{
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 10, .hostID = 1009, .size = 2 } },
        &.{ .{ .containerID = 10, .hostID = 1009, .size = 2 }, .{ .containerID = 0, .hostID = 1000, .size = 10 } },
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 20, .hostID = 1002, .size = 1 } },
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, validateIDMappings(mappings));
    }
    try validateIDMappings(&.{
        .{ .containerID = 10, .hostID = 1010, .size = 2 },
        .{ .containerID = 0, .hostID = 1000, .size = 10 },
    });
}

test "mapping validation requires formatted text smaller than 4096 bytes" {
    var mappings: [171]Spec.IDMapping = undefined;
    for (&mappings, 0..) |*mapping, i| {
        // Each line is 24 bytes; 170 lines fit, but 171 exceed the limit.
        mapping.* = .{ .containerID = @intCast(1000000000 + i), .hostID = @intCast(2000000000 + i), .size = 1 };
    }
    try validateIDMappings(mappings[0..170]);
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
    // The final line brings the total to 4095 bytes, then exactly 4096.
    mappings[170] = .{ .containerID = 0, .hostID = 1000000000, .size = 1 };
    try validateIDMappings(&mappings);
    mappings[170].containerID = 10;
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
}

test "create validates both user namespace mapping arrays" {
    const valid: []const Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 100000, .size = 1 }};
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } },
            .uidMappings = valid,
            .gidMappings = valid,
        },
    };
    spec.linux.?.uidMappings = &.{};
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux.?.uidMappings = valid;
    spec.linux.?.gidMappings = &.{};
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
}

test "create requires container root in both user namespace maps" {
    const root_mapping: []const Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 100000, .size = 10 }};
    const nonroot_mapping: []const Spec.IDMapping = &.{.{ .containerID = 1, .hostID = 200000, .size = 10 }};
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .mount }, .{ .type = .user } },
            .uidMappings = nonroot_mapping,
            .gidMappings = root_mapping,
        },
    };
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux.?.uidMappings = root_mapping;
    spec.linux.?.gidMappings = nonroot_mapping;
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux.?.gidMappings = root_mapping;
    spec.process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 1, .gid = 1 } };
    try requireCreate(spec);
}

/// Loads <bundle>/config.json. The caller owns the result and must call deinit().
pub fn loadSpec(allocator: std.mem.Allocator, io: std.Io, bundle_dir: []const u8) !std.json.Parsed(Spec) {
    const path = try std.fs.path.join(allocator, &.{ bundle_dir, "config.json" });
    defer allocator.free(path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(Spec, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    try validateHooks(parsed.value.hooks);
    return parsed;
}

/// Resolves root.path against an absolute bundle directory. The caller owns the path.
pub fn resolveRootfs(allocator: std.mem.Allocator, bundle_dir: []const u8, root_path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(bundle_dir)) return error.RelativeBundle;
    if (std.fs.path.isAbsolute(root_path)) return allocator.dupe(u8, root_path);
    return std.fs.path.join(allocator, &.{ bundle_dir, root_path });
}

pub const Status = enum {
    creating,
    created,
    running,
    stopped,
};

pub fn requireStart(status: Status, has_process: bool) !void {
    if (status != .created) return error.InvalidStatus;
    if (!has_process) return error.MissingProcess;
}

pub fn requireKill(status: Status) !void {
    if (status != .created and status != .running) return error.InvalidStatus;
}

pub fn requireDelete(status: Status) !void {
    if (status != .stopped) return error.InvalidStatus;
}

pub const State = struct {
    ociVersion: []const u8 = runtime_oci_version,
    id: []const u8,
    status: Status,
    pid: ?i32 = null,
    bundle: []const u8,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,
};

/// Used by state stdout and every hook, with identical optional-field handling.
pub fn stateJson(allocator: std.mem.Allocator, state: State) ![]u8 {
    const json = try std.json.Stringify.valueAlloc(allocator, state, .{ .emit_null_optional_fields = false });
    defer allocator.free(json);
    return std.fmt.allocPrint(allocator, "{s}\n", .{json});
}

/// A named temporary file in the destination directory is renamed after writing.
pub fn atomicWrite(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .replace = true });
    defer file.deinit(io);
    try file.file.writeStreamingAll(io, bytes);
    try file.file.sync(io);
    try file.replace(io);
}

pub fn saveState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, state: State) !void {
    const path = try std.fs.path.join(allocator, &.{ root, state.id, state_file_name });
    defer allocator.free(path);
    const json = try stateJson(allocator, state);
    defer allocator.free(json);
    try atomicWrite(io, path, json);
}

/// The caller owns the returned state and must call deinit().
pub fn loadState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !std.json.Parsed(State) {
    const path = try std.fs.path.join(allocator, &.{ root, id, state_file_name });
    defer allocator.free(path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(json);
    return std.json.parseFromSlice(State, allocator, json, .{ .allocate = .alloc_always });
}

test "state JSON round-trips a running container with annotations" {
    const json =
        \\{"ociVersion":"1.0.2","id":"example","status":"running","pid":1234,"bundle":"/tmp/bundle","annotations":{"org.example.description":"hello"}}
    ;
    const parsed = try std.json.parseFromSlice(State, std.testing.allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("1.0.2", parsed.value.ociVersion);
    try std.testing.expectEqualStrings("example", parsed.value.id);
    try std.testing.expectEqual(Status.running, parsed.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), parsed.value.pid);
    try std.testing.expectEqualStrings("/tmp/bundle", parsed.value.bundle);
    try std.testing.expectEqualStrings("hello", parsed.value.annotations.?.map.get("org.example.description").?);

    const output = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(json, output);
}

test "state JSON accepts lifecycle statuses and omits absent optional fields" {
    for ([_]Status{ .creating, .created, .stopped }) |status| {
        const pid: ?i32 = if (status == .created) 1234 else null;
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"ociVersion\":\"1.0.2\",\"id\":\"example\",\"status\":\"{s}\"{s},\"bundle\":\"/tmp/bundle\"}}",
            .{ @tagName(status), if (pid != null) ",\"pid\":1234" else "" },
        );
        defer std.testing.allocator.free(json);
        const parsed = try std.json.parseFromSlice(State, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(status, parsed.value.status);
        try std.testing.expectEqual(pid, parsed.value.pid);
        try std.testing.expect(parsed.value.annotations == null);

        const output = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{
            .emit_null_optional_fields = false,
        });
        defer std.testing.allocator.free(output);
        try std.testing.expectEqualStrings(json, output);
    }
}

test "state JSON rejects an unknown lifecycle status" {
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSlice(State, std.testing.allocator,
        \\{"ociVersion":"1.0.2","id":"example","status":"paused","bundle":"/tmp/bundle"}
    , .{}));
}

test "state reads a fixture from the selected root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/state.json",
        .data =
        \\{
        \\  "bundle": "/tmp/bundle",
        \\  "status": "created",
        \\  "pid": 1234,
        \\  "id": "example",
        \\  "ociVersion": "1.0.2",
        \\  "annotations": {"org.example.description": "hello"}
        \\}
        ,
    });

    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const parsed = try loadState(std.testing.allocator, std.testing.io, root, "example");
    defer parsed.deinit();
    try std.testing.expectEqualStrings("example", parsed.value.id);
    try std.testing.expectEqual(Status.created, parsed.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), parsed.value.pid);
    try std.testing.expectEqualStrings("hello", parsed.value.annotations.?.map.get("org.example.description").?);
}

test "state reports a missing container" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.FileNotFound, loadState(std.testing.allocator, std.testing.io, root, "missing"));
}

test "state rejects files larger than one MiB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const data = try std.testing.allocator.alloc(u8, (1 << 20) + 1);
    defer std.testing.allocator.free(data);
    @memset(data, ' ');
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/state.json",
        .data = data,
    });

    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.StreamTooLong, loadState(std.testing.allocator, std.testing.io, root, "example"));
}

test "loadSpec parses a runc-style config and tolerates unknown fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "config.json",
        .data =
        \\{
        \\  "ociVersion": "1.0.2",
        \\  "root": {"path": "rootfs", "readonly": true},
        \\  "process": {
        \\    "terminal": true,
        \\    "user": {"uid": 1000, "gid": 1001, "additionalGids": [1002]},
        \\    "args": ["/bin/sh", "-c", "echo hello"],
        \\    "env": ["PATH=/usr/bin:/bin", "TERM=xterm"],
        \\    "cwd": "/",
        \\    "capabilities": {"bounding": ["CAP_CHOWN"]},
        \\    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        \\    "noNewPrivileges": true
        \\  },
        \\  "hostname": "example",
        \\  "mounts": [{
        \\    "destination": "/proc",
        \\    "type": "proc",
        \\    "source": "proc",
        \\    "options": ["nosuid", "noexec", "nodev"]
        \\  }],
        \\  "linux": {
        \\    "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "uts"}],
        \\    "resources": {"devices": [{"allow": false, "access": "rwm"}]},
        \\    "maskedPaths": ["/proc/kcore"]
        \\  },
        \\  "annotations": {"org.example.description": "hello"}
        \\}
        ,
    });

    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    const parsed = try loadSpec(std.testing.allocator, std.testing.io, bundle);
    defer parsed.deinit();
    const spec = parsed.value;
    try std.testing.expectEqualStrings("1.0.2", spec.ociVersion);
    try std.testing.expectEqualStrings("rootfs", spec.root.path);
    try std.testing.expect(spec.root.readonly);
    const process = spec.process.?;
    try std.testing.expectEqual(@as(usize, 3), process.args.len);
    try std.testing.expectEqualStrings("/bin/sh", process.args[0]);
    try std.testing.expectEqualStrings("-c", process.args[1]);
    try std.testing.expectEqualStrings("echo hello", process.args[2]);
    try std.testing.expectEqual(@as(usize, 2), process.env.?.len);
    try std.testing.expectEqualStrings("PATH=/usr/bin:/bin", process.env.?[0]);
    try std.testing.expectEqualStrings("TERM=xterm", process.env.?[1]);
    try std.testing.expectEqualStrings("/", process.cwd);
    try std.testing.expectEqual(@as(?bool, true), process.terminal);
    try std.testing.expect(process.noNewPrivileges);
    try std.testing.expectEqual(@as(u32, 1000), process.user.uid);
    try std.testing.expectEqual(@as(u32, 1001), process.user.gid);
    try std.testing.expectEqualStrings("example", spec.hostname.?);
    try std.testing.expectEqual(@as(usize, 1), spec.mounts.?.len);
    const mount = spec.mounts.?[0];
    try std.testing.expectEqualStrings("/proc", mount.destination);
    try std.testing.expectEqualStrings("proc", mount.type.?);
    try std.testing.expectEqualStrings("proc", mount.source.?);
    try std.testing.expectEqual(@as(usize, 3), mount.options.?.len);
    try std.testing.expectEqualStrings("nosuid", mount.options.?[0]);
    try std.testing.expectEqualStrings("noexec", mount.options.?[1]);
    try std.testing.expectEqualStrings("nodev", mount.options.?[2]);
    const namespaces = spec.linux.?.namespaces.?;
    try std.testing.expectEqual(@as(usize, 3), namespaces.len);
    try std.testing.expectEqual(.pid, namespaces[0].type);
    try std.testing.expectEqual(.mount, namespaces[1].type);
    try std.testing.expectEqual(.uts, namespaces[2].type);
    try std.testing.expect(namespaces[0].path == null);
    try std.testing.expectEqualStrings("hello", spec.annotations.?.map.get("org.example.description").?);
}

test "spec defaults omitted optional fields" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try std.testing.expect(!parsed.value.root.readonly);
    try std.testing.expect(parsed.value.process.?.env == null);
    try std.testing.expect(parsed.value.process.?.terminal == null);
    try std.testing.expect(!parsed.value.process.?.noNewPrivileges);
    try std.testing.expect(parsed.value.process.?.oomScoreAdj == null);
    try std.testing.expect(parsed.value.process.?.capabilities == null);
    try std.testing.expect(parsed.value.process.?.rlimits == null);
    try std.testing.expect(parsed.value.process.?.user.additionalGids == null);
    try std.testing.expect(parsed.value.hostname == null);
    try std.testing.expect(parsed.value.mounts == null);
    try std.testing.expect(parsed.value.linux == null);
    try std.testing.expect(parsed.value.annotations == null);
}

test "process user retains supplementary groups from JSON" {
    const json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[1001,1002]}";
    const parsed = try std.json.parseFromSlice(Spec.User, std.testing.allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const output = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(json, output);
}

test "spec parses namespace paths and user id mappings" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{
        \\  "ociVersion": "1.0.2",
        \\  "root": {"path": "rootfs"},
        \\  "process": {"args": ["/bin/sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
        \\  "mounts": [{"destination": "/mnt"}],
        \\  "linux": {
        \\    "namespaces": [
        \\      {"type": "network", "path": "/proc/1234/ns/net"},
        \\      {"type": "ipc"}, {"type": "user"}, {"type": "cgroup"}
        \\    ],
        \\    "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
        \\    "gidMappings": [{"containerID": 0, "hostID": 1001, "size": 1}]
        \\  }
        \\}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const namespaces = parsed.value.linux.?.namespaces.?;
    try std.testing.expectEqual(.network, namespaces[0].type);
    try std.testing.expectEqualStrings("/proc/1234/ns/net", namespaces[0].path.?);
    try std.testing.expectEqual(.ipc, namespaces[1].type);
    try std.testing.expectEqual(.user, namespaces[2].type);
    try std.testing.expectEqual(.cgroup, namespaces[3].type);
    const uid_mapping = parsed.value.linux.?.uidMappings.?[0];
    try std.testing.expectEqual(@as(u32, 0), uid_mapping.containerID);
    try std.testing.expectEqual(@as(u32, 1000), uid_mapping.hostID);
    try std.testing.expectEqual(@as(u32, 1), uid_mapping.size);
    const gid_mapping = parsed.value.linux.?.gidMappings.?[0];
    try std.testing.expectEqual(@as(u32, 0), gid_mapping.containerID);
    try std.testing.expectEqual(@as(u32, 1001), gid_mapping.hostID);
    try std.testing.expectEqual(@as(u32, 1), gid_mapping.size);
    const mount = parsed.value.mounts.?[0];
    try std.testing.expect(mount.type == null);
    try std.testing.expect(mount.source == null);
    try std.testing.expect(mount.options == null);
}

test "loadSpec reports a missing config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    try std.testing.expectError(error.FileNotFound, loadSpec(std.testing.allocator, std.testing.io, bundle));
}

test "loadSpec rejects files larger than one MiB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try std.testing.allocator.alloc(u8, (1 << 20) + 1);
    defer std.testing.allocator.free(data);
    @memset(data, ' ');
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "config.json", .data = data });
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    try std.testing.expectError(error.StreamTooLong, loadSpec(std.testing.allocator, std.testing.io, bundle));
}

test "rootfs resolution uses the bundle only for relative paths" {
    const cases = [_]struct { bundle: []const u8, root_path: []const u8, expected: []const u8 }{
        .{ .bundle = "/b", .root_path = "rootfs", .expected = "/b/rootfs" },
        .{ .bundle = "/b", .root_path = "/var/lib/rootfs", .expected = "/var/lib/rootfs" },
    };
    for (cases) |case| {
        const rootfs = try resolveRootfs(std.testing.allocator, case.bundle, case.root_path);
        defer std.testing.allocator.free(rootfs);
        try std.testing.expectEqualStrings(case.expected, rootfs);
    }
}

test "spec accepts an omitted process and a time namespace" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"time"}]}}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.process == null);
    try std.testing.expectEqual(.time, parsed.value.linux.?.namespaces.?[0].type);
}

test "rootfs resolution rejects a relative bundle even for an absolute rootfs" {
    try std.testing.expectError(error.RelativeBundle, resolveRootfs(std.testing.allocator, "bundle", "rootfs"));
    try std.testing.expectError(error.RelativeBundle, resolveRootfs(std.testing.allocator, "bundle", "/rootfs"));
}

test "lifecycle operations enforce their legal statuses" {
    for ([_]Status{ .creating, .created, .running, .stopped }) |status| {
        if (status == .created) {
            try requireStart(status, true);
            try std.testing.expectError(error.MissingProcess, requireStart(status, false));
        } else {
            try std.testing.expectError(error.InvalidStatus, requireStart(status, true));
        }
        if (status == .created or status == .running) {
            try requireKill(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireKill(status));
        }
        if (status == .stopped) {
            try requireDelete(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireDelete(status));
        }
    }
}

test "atomic write replaces complete contents and cleans up after a failed rename" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "state.json" });
    defer std.testing.allocator.free(path);
    const original = "first, longer contents";
    try atomicWrite(std.testing.io, path, original);
    const old_file = try tmp.dir.openFile(std.testing.io, "state.json", .{});
    defer old_file.close(std.testing.io);
    try atomicWrite(std.testing.io, path, "second");
    // Readers that already opened the old state keep seeing its complete contents.
    var old_contents: [original.len]u8 = undefined;
    try std.testing.expectEqual(original.len, try old_file.readPositionalAll(std.testing.io, &old_contents, 0));
    try std.testing.expectEqualStrings(original, &old_contents);
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("second", contents);

    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    const directory = try std.fs.path.join(std.testing.allocator, &.{ root, "directory" });
    defer std.testing.allocator.free(directory);
    if (atomicWrite(std.testing.io, directory, "cannot replace a directory")) {
        return error.TestUnexpectedResult;
    } else |_| {}
    var entries = tmp.dir.iterate();
    var count: usize = 0;
    while (try entries.next(std.testing.io)) |entry| {
        try std.testing.expect(std.mem.eql(u8, entry.name, "state.json") or std.mem.eql(u8, entry.name, "directory"));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

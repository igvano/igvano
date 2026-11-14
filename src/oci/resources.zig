const std = @import("std");
const libcontainer = @import("libcontainer");
const recordDiagnostic = @import("diagnostic.zig").recordDiagnostic;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const diagnosticContext = @import("diagnostic.zig").diagnosticContext;
const Spec = @import("spec.zig").Spec;
const json_size_limit = @import("spec.zig").json_size_limit;
const resolveMountDestination = @import("mounts.zig").resolveMountDestination;

/// Resolve absolute OCI paths relative to the cgroup mount, never the host root.
/// Root itself is forbidden, since delete must only remove a container cgroup.
pub fn resolveCgroupPath(allocator: std.mem.Allocator, configured: ?[]const u8, id: []const u8) ![]u8 {
    if (configured == null and (id.len == 0 or
        std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or
        std.mem.indexOfScalar(u8, id, 0) != null)) return invalidConfig("linux.cgroupsPath: invalid container id", .{});
    const path = if (configured) |value|
        try std.fmt.allocPrint(allocator, "/{s}", .{value})
    else
        try std.fmt.allocPrint(allocator, "/igvano/{s}", .{id});
    defer allocator.free(path);
    const normalized = resolveMountDestination(allocator, path) catch |err| {
        diagnosticContext("linux.cgroupsPath", .{});
        return err;
    };
    defer allocator.free(normalized);
    if (normalized.len == 1) return invalidConfig("linux.cgroupsPath: must not resolve to the cgroup root", .{});
    return allocator.dupe(u8, normalized[1..]);
}

/// Translate and validate OCI resources without selecting a cgroup hierarchy.
/// Arrays are caller-owned; strings are borrowed from the parsed spec.
pub fn cgroupResources(allocator: std.mem.Allocator, configured: ?Spec.Resources) !libcontainer.Resources {
    const settings = configured orelse return .{};
    var resources: libcontainer.Resources = .{};
    errdefer freeCgroupResources(allocator, resources);
    if (settings.memory) |value| resources.memory = try resourceMemory(value);
    if (settings.cpu) |value| resources.cpu = try resourceCpu(value);
    if (settings.pids) |pids| {
        try validateResourceLimit(pids.limit, "linux.resources.pids.limit");
        resources.pids = .{ .limit = pids.limit };
    }
    if (settings.blockIO) |value| try prepareBlockResources(allocator, &resources, value);
    try prepareHugepageResources(allocator, &resources, settings.hugepageLimits);
    if (settings.network) |network| {
        resources.network = .{ .class_id = network.classID };
        const priorities = network.priorities orelse &.{};
        const translated = try allocator.alloc(libcontainer.Resources.Priority, priorities.len);
        resources.network.?.priorities = translated;
        for (priorities, translated) |entry, *priority|
            priority.* = .{ .name = entry.name, .priority = entry.priority };
    }
    resources.devices = try resourceDeviceRules(allocator, settings.devices);
    if (settings.unified) |value| try prepareUnifiedResources(allocator, &resources, value);
    return resources;
}

fn resourceMemory(memory: Spec.Resources.Memory) !libcontainer.Resources.Memory {
    inline for (.{ "limit", "reservation", "swap", "kernel", "kernelTCP" }) |field|
        try validateResourceLimit(@field(memory, field), "linux.resources.memory." ++ field);
    return .{
        .limit = memory.limit,
        .reservation = memory.reservation,
        .swap = memory.swap,
        .kernel = memory.kernel,
        .kernel_tcp = memory.kernelTCP,
        .swappiness = memory.swappiness,
        .disable_oom_killer = memory.disableOOMKiller,
        .check_before_update = memory.checkBeforeUpdate orelse false,
    };
}

fn resourceCpu(cpu: Spec.Resources.Cpu) !libcontainer.Resources.Cpu {
    try validateResourceLimit(cpu.quota, "linux.resources.cpu.quota");
    try validateResourceLimit(cpu.realtimeRuntime, "linux.resources.cpu.realtimeRuntime");
    return .{
        .shares = cpu.shares,
        .quota = cpu.quota,
        .period = cpu.period,
        .realtime_runtime = cpu.realtimeRuntime,
        .realtime_period = cpu.realtimePeriod,
        .idle = cpu.idle,
        .burst = cpu.burst,
        .cpus = cpu.cpus,
        .mems = cpu.mems,
    };
}

fn prepareBlockResources(allocator: std.mem.Allocator, resources: *libcontainer.Resources, block: Spec.Resources.BlockIO) !void {
    try validateResourceWeight(block.weight, "linux.resources.blockIO.weight");
    try validateResourceWeight(block.leafWeight, "linux.resources.blockIO.leafWeight");
    resources.block_io = .{ .weight = block.weight, .leaf_weight = block.leafWeight };
    const weights = block.weightDevice orelse &.{};
    const translated = try allocator.alloc(libcontainer.Resources.WeightDevice, weights.len);
    resources.block_io.?.weight_device = translated;
    for (weights, translated, 0..) |entry, *device, i| {
        if (entry.major < 0 or entry.minor < 0) return invalidConfig("linux.resources.blockIO.weightDevice[{d}]: major/minor must be nonnegative", .{i});
        try validateResourceWeight(entry.weight, "linux.resources.blockIO.weightDevice.weight");
        try validateResourceWeight(entry.leafWeight, "linux.resources.blockIO.weightDevice.leafWeight");
        device.* = .{
            .major = entry.major,
            .minor = entry.minor,
            .weight = entry.weight,
            .leaf_weight = entry.leafWeight,
        };
    }
    resources.block_io.?.throttle_read_bps = try resourceThrottleDevices(allocator, block.throttleReadBpsDevice, "throttleReadBpsDevice");
    resources.block_io.?.throttle_write_bps = try resourceThrottleDevices(allocator, block.throttleWriteBpsDevice, "throttleWriteBpsDevice");
    resources.block_io.?.throttle_read_iops = try resourceThrottleDevices(allocator, block.throttleReadIOPSDevice, "throttleReadIOPSDevice");
    resources.block_io.?.throttle_write_iops = try resourceThrottleDevices(allocator, block.throttleWriteIOPSDevice, "throttleWriteIOPSDevice");
}

fn prepareUnifiedResources(allocator: std.mem.Allocator, resources: *libcontainer.Resources, unified: std.json.ArrayHashMap([]const u8)) !void {
    const translated = try allocator.alloc(libcontainer.Resources.Unified, unified.map.count());
    resources.unified = translated;
    for (unified.map.keys(), unified.map.values(), translated) |key, value, *entry| {
        if (key.len == 0 or std.mem.indexOfAny(u8, key, "/\x00") != null or
            std.mem.eql(u8, key, ".") or std.mem.eql(u8, key, "..")) return invalidConfig("linux.resources.unified: invalid key '{s}'", .{key});
        entry.* = .{ .key = key, .value = value };
    }
}

fn prepareHugepageResources(allocator: std.mem.Allocator, resources: *libcontainer.Resources, configured: ?[]const Spec.Resources.HugepageLimit) !void {
    const hugepages = configured orelse &.{};
    const translated_pages = try allocator.alloc(libcontainer.Resources.HugepageLimit, hugepages.len);
    resources.hugepage_limits = translated_pages;
    for (hugepages, translated_pages, 0..) |entry, *page, i| {
        if (entry.pageSize != null and entry.pagesize != null) return invalidConfig("linux.resources.hugepageLimits[{d}]: pageSize given twice", .{i});
        if (entry.size().len == 0) return invalidConfig("linux.resources.hugepageLimits[{d}].pageSize: must not be empty", .{i});
        page.* = .{ .page_size = entry.size(), .limit = entry.limit };
    }
}

fn resourceDeviceRules(allocator: std.mem.Allocator, configured: ?[]const Spec.Resources.DeviceRule) ![]libcontainer.Resources.DeviceRule {
    const devices = configured orelse &.{};
    const translated = try allocator.alloc(libcontainer.Resources.DeviceRule, devices.len);
    errdefer allocator.free(translated);
    for (devices, translated, 0..) |entry, *device, i| {
        const kind: @FieldType(libcontainer.Resources.DeviceRule, "kind") = if (std.mem.eql(u8, entry.type, "a"))
            .all
        else if (std.mem.eql(u8, entry.type, "b"))
            .block
        else if (std.mem.eql(u8, entry.type, "c"))
            .char
        else
            return invalidConfig("linux.resources.devices[{d}].type: expected a, b or c", .{i});
        if (deviceAccess(entry.access).len == 0) return invalidConfig("linux.resources.devices[{d}].access: needs r, w or m", .{i});
        try validateResourceLimit(entry.major, "linux.resources.devices.major");
        try validateResourceLimit(entry.minor, "linux.resources.devices.minor");
        device.* = .{
            .allow = entry.allow,
            .kind = kind,
            .major = if (entry.major == -1) null else entry.major,
            .minor = if (entry.minor == -1) null else entry.minor,
            .access = deviceAccess(entry.access),
        };
    }
    return translated;
}

/// Like runc's Permissions.toSet: keep r, w and m, and ignore anything else.
fn deviceAccess(access: []const u8) []const u8 {
    const names = [_][]const u8{ "", "r", "w", "rw", "m", "rm", "wm", "rwm" };
    var set: usize = 0;
    for (access) |char| switch (char) {
        'r' => set |= 1,
        'w' => set |= 2,
        'm' => set |= 4,
        else => {},
    };
    return names[set];
}

test "device access keeps only r, w and m, like runc" {
    try std.testing.expectEqualStrings("rw", deviceAccess("rwa"));
    try std.testing.expectEqualStrings("rwm", deviceAccess("mwr"));
    try std.testing.expectEqualStrings("", deviceAccess("x"));
}

fn validateResourceLimit(value: ?i64, comptime field: []const u8) error{InvalidConfig}!void {
    if (value) |limit|
        if (limit < -1) return invalidConfig(field ++ ": must be -1 or nonnegative", .{});
}

fn validateResourceWeight(value: ?u16, comptime field: []const u8) error{InvalidConfig}!void {
    if (value) |weight|
        if (weight != 0 and (weight < 10 or weight > 1000)) return invalidConfig(field ++ ": expected 0 or 10..1000", .{});
}

fn resourceThrottleDevices(allocator: std.mem.Allocator, configured: ?[]const Spec.Resources.ThrottleDevice, comptime field: []const u8) ![]libcontainer.Resources.ThrottleDevice {
    const entries = configured orelse &.{};
    const devices = try allocator.alloc(libcontainer.Resources.ThrottleDevice, entries.len);
    errdefer allocator.free(devices);
    for (entries, devices, 0..) |entry, *device, i| {
        if (entry.major < 0 or entry.minor < 0) return invalidConfig("linux.resources.blockIO." ++ field ++ "[{d}]: major/minor must be nonnegative", .{i});
        device.* = .{ .major = entry.major, .minor = entry.minor, .rate = entry.rate };
    }
    return devices;
}

pub fn freeCgroupResources(allocator: std.mem.Allocator, resources: libcontainer.Resources) void {
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

/// Loads resource JSON from a file or stdin. The caller must call deinit().
pub fn loadResources(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Spec.Resources) {
    const json = if (std.mem.eql(u8, path, "-")) input: {
        var reader = std.Io.File.stdin().readerStreaming(io, &.{});
        break :input reader.interface.allocRemaining(allocator, json_size_limit) catch |err| {
            if (err == error.StreamTooLong) recordDiagnostic(err, "resources: JSON exceeds 1 MiB", .{});
            return err;
        };
    } else std.Io.Dir.cwd().readFileAlloc(io, path, allocator, json_size_limit) catch |err| {
        if (err == error.StreamTooLong) recordDiagnostic(err, "resources: JSON exceeds 1 MiB", .{});
        return err;
    };
    defer allocator.free(json);
    return std.json.parseFromSlice(Spec.Resources, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        if (err != error.OutOfMemory) recordDiagnostic(err, "resources: invalid JSON or schema ({s})", .{@errorName(err)});
        return err;
    };
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
    try std.testing.expectEqualDeep(libcontainer.Resources.Cpu{ .quota = 50000, .period = 100000, .shares = 1024 }, resources.cpu.?);
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
        .{ .memory = .{ .reservation = -2 } },
        .{ .memory = .{ .swap = -2 } },
        .{ .memory = .{ .kernel = -2 } },
        .{ .memory = .{ .kernelTCP = -2 } },
        .{ .cpu = .{ .realtimeRuntime = -2 } },
    }) |resources| {
        try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, resources));
    }
}

test "cgroup resources validate device types access and wildcard numbers" {
    for ([_][]const u8{ "a", "b", "c" }, [_]@FieldType(libcontainer.Resources.DeviceRule, "kind"){ .all, .block, .char }) |kind, expected| {
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
        .{ .allow = true, .access = "x" },
        .{ .allow = true, .access = "" },
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

test "resource files preserve omitted fields and validate device rules through create's translation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "resources.json" });
    defer std.testing.allocator.free(path);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "resources.json",
        .data = "{\"cpu\":{\"shares\":512},\"devices\":[{\"allow\":true,\"type\":\"c\",\"major\":1,\"minor\":3,\"access\":\"rw\"}]}",
    });
    const parsed = try loadResources(std.testing.allocator, std.testing.io, path);
    defer parsed.deinit();
    const resources = try cgroupResources(std.testing.allocator, parsed.value);
    defer freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expect(resources.memory == null and resources.pids == null);
    try std.testing.expectEqual(@as(?u64, 512), resources.cpu.?.shares);
    try std.testing.expect(resources.cpu.?.quota == null and resources.cpu.?.period == null);
    try std.testing.expectEqualDeep(libcontainer.Resources.DeviceRule{
        .allow = true,
        .kind = .char,
        .major = 1,
        .minor = 3,
        .access = "rw",
    }, resources.devices[0]);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "resources.json", .data = "{\"devices\":[{\"allow\":true,\"type\":\"invalid\"}]}" });
    const invalid = try loadResources(std.testing.allocator, std.testing.io, path);
    defer invalid.deinit();
    try std.testing.expectError(error.InvalidConfig, cgroupResources(std.testing.allocator, invalid.value));
}

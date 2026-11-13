const std = @import("std");
const libcontainer = @import("../root.zig");
const Resources = libcontainer.Resources;
const dbus = @import("../dbus.zig");
const diagnostics = @import("diagnostic.zig");
const v2DeviceRules = @import("devices.zig").v2DeviceRules;
const deviceEmulator = @import("devices.zig").deviceEmulator;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const v2Writes = @import("cgroup_v2.zig").v2Writes;
const Write = @import("cgroup_v2.zig").Write;
const cpuWeight = @import("cgroup_v2.zig").cpuWeight;
const freeWrites = @import("cgroup_v2.zig").freeWrites;
const CgroupMode = @import("cgroup.zig").CgroupMode;

test "systemd memory-only updates leave device properties untouched" {
    const allocator = std.testing.allocator;
    for ([_]CgroupMode{ .legacy, .unified }) |mode| {
        const properties = try systemdProperties(allocator, .{ .memory = .{ .limit = 4096 } }, mode, &.{});
        defer freeSystemdProperties(allocator, properties);
        try std.testing.expectEqual(@as(usize, 1), properties.len);
        try std.testing.expectEqualStrings(if (mode == .legacy) "MemoryLimit" else "MemoryMax", properties[0].name);
        try std.testing.expectEqual(@as(u64, 4096), properties[0].value.uint64);
    }
}

test "systemd legacy device properties preserve defaults and configured rules with wildcard majors" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const rules = try v2DeviceRules(allocator, &.{
                .{ .allow = false },
                .{ .allow = true, .kind = .char, .minor = 5 },
                .{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" },
                .{ .allow = false, .kind = .block, .major = 8, .minor = 0, .access = "w" },
            });
            defer allocator.free(rules);
            const properties = try systemdProperties(allocator, .{}, .legacy, rules);
            defer freeSystemdProperties(allocator, properties);
            try std.testing.expectEqual(@as(usize, 3), properties.len);
            try std.testing.expectEqualStrings("DeviceAllow", properties[0].name);
            try std.testing.expectEqual(@as(usize, 0), properties[0].value.string_pairs.len);
            try std.testing.expectEqualStrings("DevicePolicy", properties[1].name);
            try std.testing.expectEqualStrings("strict", properties[1].value.string);
            const expected: []const [2][]const u8 = &.{
                .{ "block-*", "m" },
                .{ "char-*", "m" },
                .{ "/dev/char/1:3", "rwm" },
                .{ "/dev/char/1:5", "rwm" },
                .{ "/dev/char/1:7", "rwm" },
                .{ "/dev/char/1:8", "rwm" },
                .{ "/dev/char/1:9", "rwm" },
                .{ "/dev/char/5:0", "rwm" },
                .{ "/dev/char/5:2", "rwm" },
                .{ "/dev/block/8:0", "r" },
                .{ "/dev/char/10:200", "rwm" },
                .{ "char-136", "rwm" },
            };
            try std.testing.expectEqualStrings("DeviceAllow", properties[2].name);
            try std.testing.expectEqualDeep(expected, properties[2].value.string_pairs);
        }
    };
    try AllocationTest.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

test "systemd device normalization merges permissions and delegates deny-lists" {
    const allocator = std.testing.allocator;
    defer diagnostics.last_diagnostic_len = 0;
    const allows = try systemdDeviceAllows(allocator, &.{
        .{ .allow = true, .kind = .char, .major = 10, .minor = 237, .access = "r" },
        .{ .allow = true, .kind = .char, .major = 10, .minor = 237, .access = "w" },
        .{ .allow = true, .kind = .block, .major = -1, .minor = -1, .access = "m" },
    });
    defer freeSystemdValue(allocator, .{ .string_pairs = allows });
    try std.testing.expectEqualDeep(@as([]const [2][]const u8, &.{
        .{ "block-*", "m" }, .{ "/dev/char/10:237", "rw" },
    }), @as([]const [2][]const u8, allows));
    const denylist_rules: []const Resources.DeviceRule = &.{
        .{ .allow = true },
        .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
    };
    try std.testing.expectError(error.Unsupported, systemdDeviceAllows(allocator, denylist_rules));
    const properties = try systemdProperties(allocator, .{}, .legacy, denylist_rules);
    defer freeSystemdProperties(allocator, properties);
    try std.testing.expectEqual(@as(usize, 2), properties.len);
    try std.testing.expectEqualStrings("DeviceAllow", properties[0].name);
    try std.testing.expectEqual(@as(usize, 0), properties[0].value.string_pairs.len);
    try std.testing.expectEqualStrings("strict", properties[1].value.string);
    const wildcard = try systemdDeviceAllows(allocator, &.{
        .{ .allow = true, .kind = .char, .minor = 5 },
    });
    defer freeSystemdValue(allocator, .{ .string_pairs = wildcard });
    try std.testing.expectEqual(@as(usize, 0), wildcard.len);
    const all = try systemdDeviceAllows(allocator, &.{.{ .allow = true }});
    defer freeSystemdValue(allocator, .{ .string_pairs = all });
    try std.testing.expectEqualDeep(@as([]const [2][]const u8, &.{
        .{ "char-*", "rwm" }, .{ "block-*", "rwm" },
    }), @as([]const [2][]const u8, all));
    const rules: []const Resources.DeviceRule = &.{
        .{ .allow = true, .kind = .char, .major = 10 },
        .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
    };
    try std.testing.expectError(error.InvalidConfig, systemdDeviceAllows(allocator, rules));
    try std.testing.expectError(error.InvalidConfig, systemdProperties(allocator, .{}, .legacy, rules));
}

test "systemd wildcard subtraction changes only exact exceptions" {
    const allocator = std.testing.allocator;
    const allows = try systemdDeviceAllows(allocator, &.{
        .{ .allow = true, .kind = .char, .access = "rm" },
        .{ .allow = false, .kind = .char, .access = "m" },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 3, .access = "rw" },
        .{ .allow = false, .kind = .char, .major = 1, .access = "w" },
        .{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" },
    });
    defer freeSystemdValue(allocator, .{ .string_pairs = allows });
    try std.testing.expectEqualDeep(@as([]const [2][]const u8, &.{
        .{ "char-*", "r" }, .{ "/dev/char/1:3", "rw" }, .{ "/dev/block/8:0", "rw" },
    }), @as([]const [2][]const u8, allows));
}

test "systemd properties use hierarchy-specific limits and round CPU quotas up" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const resources: Resources = .{
        .memory = .{ .limit = 4096, .reservation = 1024, .swap = 8192 },
        .cpu = .{ .shares = 1024, .quota = 1234, .period = 100000, .cpus = "0-2,8", .mems = "0" },
        .pids = .{ .limit = -1 },
    };
    const unified = try systemdProperties(arena.allocator(), resources, .unified, &.{});
    const expected = [_]dbus.Property{
        .{ .name = "MemoryMax", .value = .{ .uint64 = 4096 } },
        .{ .name = "MemoryLow", .value = .{ .uint64 = 1024 } },
        .{ .name = "MemorySwapMax", .value = .{ .uint64 = 4096 } },
        .{ .name = "CPUQuotaPeriodUSec", .value = .{ .uint64 = 100000 } },
        .{ .name = "CPUQuotaPerSecUSec", .value = .{ .uint64 = 20000 } },
        .{ .name = "CPUWeight", .value = .{ .uint64 = 100 } },
        .{ .name = "AllowedCPUs", .value = .{ .bytes = &.{ 7, 1 } } },
        .{ .name = "AllowedMemoryNodes", .value = .{ .bytes = &.{1} } },
        .{ .name = "TasksMax", .value = .{ .uint64 = std.math.maxInt(u64) } },
    };
    try std.testing.expectEqualDeep(@as([]const dbus.Property, &expected), @as([]const dbus.Property, unified));
    const legacy = try systemdProperties(arena.allocator(), resources, .legacy, &.{});
    try std.testing.expectEqualStrings("MemoryLimit", legacy[0].name);
    try std.testing.expectEqualStrings("CPUShares", legacy[1].name);
    try std.testing.expectEqual(@as(u64, 1024), legacy[1].value.uint64);
    for ([_][]const u8{ "a", "1-0", "1-2-3", "1,,2", "65536" }) |invalid|
        try std.testing.expectError(error.InvalidConfig, systemdCpuSet(arena.allocator(), invalid));
}

pub fn systemdFailure(client: *const dbus.Client, operation: []const u8, err: dbus.Error) libcontainer.Error {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    const detail = client.diagnostic();
    reportDiagnostic("{s}: {s}", .{ operation, if (detail.len != 0) detail else @errorName(err) });
    return error.CgroupWriteFailed;
}

/// Properties, CPU-set arrays and DeviceAllow paths are owned by the caller.
pub fn freeSystemdProperties(allocator: std.mem.Allocator, properties: []const dbus.Property) void {
    for (properties) |property| freeSystemdValue(allocator, property.value);
    allocator.free(properties);
}

fn freeSystemdValue(allocator: std.mem.Allocator, value: dbus.Value) void {
    switch (value) {
        .bytes => |bytes| allocator.free(bytes),
        .string_pairs => |pairs| {
            for (pairs) |pair| allocator.free(pair[0]);
            allocator.free(pairs);
        },
        else => {},
    }
}

fn setSystemdProperty(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), property: dbus.Property) libcontainer.Error!void {
    errdefer freeSystemdValue(allocator, property.value);
    for (properties.items) |*existing| {
        if (!std.mem.eql(u8, existing.name, property.name)) continue;
        freeSystemdValue(allocator, existing.value);
        existing.* = property;
        return;
    }
    try properties.append(allocator, property);
}

fn systemdCpuSet(allocator: std.mem.Allocator, cpus: []const u8) libcontainer.Error![]u8 {
    var bits: std.ArrayList(u8) = .empty;
    errdefer bits.deinit(allocator);
    if (cpus.len == 0) return bits.toOwnedSlice(allocator);
    var parts = std.mem.splitScalar(u8, cpus, ',');
    while (parts.next()) |part| {
        var range = std.mem.splitScalar(u8, part, '-');
        const first = std.fmt.parseInt(u32, range.next().?, 10) catch return error.InvalidConfig;
        const last = if (range.next()) |end| std.fmt.parseInt(u32, end, 10) catch return error.InvalidConfig else first;
        if (range.next() != null or last < first or last > 65535) return error.InvalidConfig;
        const length = last / 8 + 1;
        if (length > bits.items.len) try bits.appendNTimes(allocator, 0, length - bits.items.len);
        for (first..last + 1) |cpu| bits.items[cpu / 8] |= @as(u8, 1) << @intCast(cpu % 8);
    }
    return bits.toOwnedSlice(allocator);
}

fn systemdQuota(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), quota: i64, configured_period: u64) libcontainer.Error!void {
    if (quota < -1) return error.InvalidConfig;
    const period = if (configured_period == 0) 100000 else configured_period;
    if (configured_period != 0)
        try setSystemdProperty(allocator, properties, .{ .name = "CPUQuotaPeriodUSec", .value = .{ .uint64 = configured_period } });
    var per_sec: u64 = std.math.maxInt(u64);
    if (quota > 0) {
        // runc rounds up to a whole percent; cgroupfs later applies the exact value.
        const raw = (@as(u128, @intCast(quota)) * 1_000_000) / period;
        const rounded = ((raw + 9999) / 10000) * 10000;
        per_sec = std.math.cast(u64, rounded) orelse return error.InvalidConfig;
    }
    try setSystemdProperty(allocator, properties, .{ .name = "CPUQuotaPerSecUSec", .value = .{ .uint64 = per_sec } });
}

fn systemdNumber(value: []const u8) libcontainer.Error!u64 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "max")) return std.math.maxInt(u64);
    return std.fmt.parseInt(u64, trimmed, 10) catch error.InvalidConfig;
}

/// systemd cannot express deny-lists or wildcard-major/concrete-minor rules.
/// Deny-lists use a temporary strict policy; wildcard-major rules are skipped.
/// The caller then applies exact cgroupfs rules.
fn systemdDeviceAllows(allocator: std.mem.Allocator, rules: []const Resources.DeviceRule) libcontainer.Error![][2][]const u8 {
    var policy = try deviceEmulator(allocator, rules);
    defer policy.deinit(allocator);
    if (policy.default_allow and !policy.isAllowAll()) return error.Unsupported;
    const normalized = try policy.rules(allocator);
    defer allocator.free(normalized);
    const all: []const Resources.DeviceRule = &.{
        .{ .allow = true, .kind = .char },
        .{ .allow = true, .kind = .block },
    };
    var allows: std.ArrayList([2][]const u8) = .empty;
    errdefer {
        for (allows.items) |pair| allocator.free(pair[0]);
        allows.deinit(allocator);
    }
    for (if (policy.default_allow) all else normalized) |rule| {
        const kind: []const u8 = if (rule.kind == .char) "char" else "block";
        if (rule.major == null and rule.minor != null) {
            std.debug.print("igvano: warning: systemd cannot represent a wildcard-major device rule; leaving it to cgroupfs\n", .{});
            continue;
        }
        const path = if (rule.major) |major|
            if (rule.minor) |minor|
                try std.fmt.allocPrint(allocator, "/dev/{s}/{d}:{d}", .{ kind, major, minor })
            else
                try std.fmt.allocPrint(allocator, "{s}-{d}", .{ kind, major })
        else
            try std.fmt.allocPrint(allocator, "{s}-*", .{kind});
        errdefer allocator.free(path);
        try allows.append(allocator, .{ path, rule.access });
    }
    return allows.toOwnedSlice(allocator);
}

/// Convert the same values used by cgroupfs, so swap conversion and unified
/// overrides cannot diverge from the kernel writes. Unknown files stay on fs.
pub fn systemdProperties(allocator: std.mem.Allocator, resources: Resources, mode: CgroupMode, device_rules: []const Resources.DeviceRule) libcontainer.Error![]dbus.Property {
    var properties: std.ArrayList(dbus.Property) = .empty;
    errdefer {
        for (properties.items) |property| freeSystemdValue(allocator, property.value);
        properties.deinit(allocator);
    }
    if (mode == .unified) {
        try setSystemdUnifiedProperties(allocator, &properties, resources);
    } else {
        if (resources.memory) |memory| try setSystemdMemoryProperties(allocator, &properties, memory);
        if (resources.cpu) |cpu| try setSystemdCpuProperties(allocator, &properties, cpu);
        if (resources.pids) |pids| try setSystemdPidsProperties(allocator, &properties, pids);
        if (resources.block_io) |block| try setSystemdBlockIOProperties(allocator, &properties, block);
    }
    if (mode == .legacy and device_rules.len != 0)
        try appendSystemdDeviceProperties(allocator, &properties, device_rules);
    return properties.toOwnedSlice(allocator);
}

fn setSystemdUnifiedProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), resources: Resources) libcontainer.Error!void {
    const writes = try v2Writes(allocator, resources);
    defer freeWrites(allocator, writes);
    for (writes) |write| try setSystemdUnifiedProperty(allocator, properties, write);
}

fn setSystemdUnifiedProperty(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), write: Write) libcontainer.Error!void {
    if (std.mem.eql(u8, write.name, "cpu.max")) {
        try setSystemdCpuMax(allocator, properties, write.value);
        return;
    }
    if (std.mem.eql(u8, write.name, "cpuset.cpus") or std.mem.eql(u8, write.name, "cpuset.mems")) {
        try setSystemdProperty(allocator, properties, .{
            .name = if (std.mem.eql(u8, write.name, "cpuset.cpus")) "AllowedCPUs" else "AllowedMemoryNodes",
            .value = .{ .bytes = try systemdCpuSet(allocator, std.mem.trim(u8, write.value, " \t\r\n")) },
        });
        return;
    }
    const mappings = [_][2][]const u8{
        .{ "memory.max", "MemoryMax" },          .{ "memory.low", "MemoryLow" },
        .{ "memory.high", "MemoryHigh" },        .{ "memory.min", "MemoryMin" },
        .{ "memory.swap.max", "MemorySwapMax" }, .{ "cpu.weight", "CPUWeight" },
        .{ "pids.max", "TasksMax" },
    };
    for (mappings) |mapping| {
        if (std.mem.eql(u8, write.name, mapping[0])) {
            try setSystemdProperty(allocator, properties, .{ .name = mapping[1], .value = .{ .uint64 = try systemdNumber(write.value) } });
            break;
        }
    }
}

fn setSystemdCpuMax(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), value: []const u8) libcontainer.Error!void {
    var fields = std.mem.tokenizeAny(u8, value, " \t\r\n");
    const quota_text = fields.next() orelse return error.InvalidConfig;
    const quota: i64 = if (std.mem.eql(u8, quota_text, "max")) -1 else std.fmt.parseInt(i64, quota_text, 10) catch return error.InvalidConfig;
    const period = if (fields.next()) |text| std.fmt.parseInt(u64, text, 10) catch return error.InvalidConfig else 100000;
    if (fields.next() != null) return error.InvalidConfig;
    try systemdQuota(allocator, properties, quota, period);
}

fn setSystemdMemoryProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), memory: Resources.Memory) libcontainer.Error!void {
    if (memory.limit) |limit| {
        if (limit != 0) try setSystemdProperty(allocator, properties, .{ .name = "MemoryLimit", .value = .{ .uint64 = @bitCast(limit) } });
    }
}

fn setSystemdCpuProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), cpu: Resources.Cpu) libcontainer.Error!void {
    if (cpu.shares) |shares| if (shares != 0) {
        try setSystemdProperty(allocator, properties, .{ .name = "CPUShares", .value = .{ .uint64 = shares } });
    };
    if (cpu.quota != null or cpu.period != null) try systemdQuota(allocator, properties, cpu.quota orelse -1, cpu.period orelse 0);
    inline for (.{ .{ "cpus", "AllowedCPUs" }, .{ "mems", "AllowedMemoryNodes" } }) |field| {
        if (@field(cpu, field[0])) |value|
            try setSystemdProperty(allocator, properties, .{ .name = field[1], .value = .{ .bytes = try systemdCpuSet(allocator, value) } });
    }
}

fn setSystemdPidsProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), pids: Resources.Pids) libcontainer.Error!void {
    if (pids.limit) |limit| {
        if (limit != 0) try setSystemdProperty(allocator, properties, .{ .name = "TasksMax", .value = .{ .uint64 = @bitCast(limit) } });
    }
}

fn setSystemdBlockIOProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), block: Resources.BlockIO) libcontainer.Error!void {
    if (block.weight) |weight| {
        if (weight != 0) try setSystemdProperty(allocator, properties, .{ .name = "BlockIOWeight", .value = .{ .uint64 = weight } });
    }
}

fn appendSystemdDeviceProperties(allocator: std.mem.Allocator, properties: *std.ArrayList(dbus.Property), device_rules: []const Resources.DeviceRule) libcontainer.Error!void {
    // As in runc, deny-lists temporarily use a strict deny-all policy.
    // The v1 manager then applies the exact policy.
    const allows = systemdDeviceAllows(allocator, device_rules) catch |err| switch (err) {
        error.Unsupported => {
            try properties.appendSlice(allocator, &.{
                .{ .name = "DeviceAllow", .value = .{ .string_pairs = &.{} } },
                .{ .name = "DevicePolicy", .value = .{ .string = "strict" } },
            });
            return;
        },
        else => return err,
    };
    errdefer freeSystemdValue(allocator, .{ .string_pairs = allows });
    try properties.appendSlice(allocator, &.{
        .{ .name = "DeviceAllow", .value = .{ .string_pairs = &.{} } },
        .{ .name = "DevicePolicy", .value = .{ .string = "strict" } },
    });
    try properties.append(allocator, .{ .name = "DeviceAllow", .value = .{ .string_pairs = allows } });
}

pub fn setSystemdResources(allocator: std.mem.Allocator, handle: libcontainer.State, resources: Resources, mode: CgroupMode, omit_inferred_memory_limit: bool, device_rules: []const Resources.DeviceRule) libcontainer.Error!void {
    if (!handle.systemd) return;
    const path = handle.cgroup_path orelse return error.InvalidPath;
    const properties = try systemdProperties(allocator, resources, mode, device_rules);
    defer freeSystemdProperties(allocator, properties);
    var selected: std.ArrayList(dbus.Property) = .empty;
    defer selected.deinit(allocator);
    if (omit_inferred_memory_limit) {
        for (properties) |property| {
            if (!std.mem.eql(u8, property.name, "MemoryMax")) try selected.append(allocator, property);
        }
    }
    const requested_properties = if (omit_inferred_memory_limit) selected.items else properties;
    if (requested_properties.len == 0) return;
    var client = dbus.Client.init(allocator);
    defer client.deinit();
    client.connect() catch |err| return systemdFailure(&client, "update systemd scope", err);
    client.setProperties(std.fs.path.basename(path), requested_properties) catch |err| return systemdFailure(&client, "update systemd scope", err);
}

pub fn stopSystemdScope(allocator: std.mem.Allocator, unit: []const u8) libcontainer.Error!void {
    var client = dbus.Client.init(allocator);
    defer client.deinit();
    client.connect() catch |err| return systemdFailure(&client, "stop systemd scope", err);
    client.stop(unit) catch |err| return systemdFailure(&client, "stop systemd scope", err);
}

pub fn systemdCgroupMatches(allocator: std.mem.Allocator, unit: []const u8, path: []const u8) dbus.Error!bool {
    var client = dbus.Client.init(allocator);
    defer client.deinit();
    try client.connect();
    return client.controlGroupMatches(unit, path);
}

test "systemd unified overrides replace properties and free replaced CPU sets" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const properties = try systemdProperties(allocator, .{
                .memory = .{ .limit = 4096, .swap = 8192 },
                .cpu = .{ .cpus = "0-2" },
                .unified = &.{
                    .{ .key = "memory.max", .value = "8192" },
                    .{ .key = "cpuset.cpus", .value = "8" },
                },
            }, .unified, &.{});
            defer freeSystemdProperties(allocator, properties);
            const expected: []const dbus.Property = &.{
                .{ .name = "MemoryMax", .value = .{ .uint64 = 8192 } },
                .{ .name = "MemorySwapMax", .value = .{ .uint64 = 4096 } },
                .{ .name = "AllowedCPUs", .value = .{ .bytes = &.{ 0, 1 } } },
            };
            try std.testing.expectEqualDeep(expected, @as([]const dbus.Property, properties));
        }
    };
    try AllocationTest.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

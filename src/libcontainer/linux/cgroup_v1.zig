const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const Resources = libcontainer.Resources;
const DeviceEmulator = @import("../devices.zig").Emulator;
const diagnostics = @import("diagnostic.zig");
const v2DeviceRules = @import("devices.zig").v2DeviceRules;
const runningInUserNamespace = @import("devices.zig").runningInUserNamespace;
const deviceEmulator = @import("devices.zig").deviceEmulator;
const deviceEmulatorFromList = @import("devices.zig").deviceEmulatorFromList;
const statfsType = @import("syscall.zig").statfsType;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const cgroupLimit = @import("cgroup_v2.zig").cgroupLimit;
const cpuWeight = @import("cgroup_v2.zig").cpuWeight;
const ioWeight = @import("cgroup_v2.zig").ioWeight;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const createCgroupDirectory = @import("cgroup.zig").createCgroupDirectory;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const readCgroupFile = @import("cgroup.zig").readCgroupFile;
const collectCgroupPids = @import("cgroup.zig").collectCgroupPids;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const cgroupPopulated = @import("cgroup.zig").cgroupPopulated;
const removeCgroupChildren = @import("cgroup.zig").removeCgroupChildren;
const procCgroupMatches = @import("cgroup.zig").procCgroupMatches;
const readMountinfo = @import("mountinfo.zig").readMountinfo;
const MountInfo = @import("mountinfo.zig").MountInfo;
const mountinfoPath = @import("mountinfo.zig").mountinfoPath;
const cgroupFrozen = @import("freezer.zig").cgroupFrozen;
const waitFrozen = @import("freezer.zig").waitFrozen;
const readProcFileAt = @import("proc.zig").readProcFileAt;
const openPidfd = @import("proc.zig").openPidfd;
const signalPid = @import("proc.zig").signalPid;

pub const V1Write = struct {
    controller: []const u8,
    name: []const u8,
    value: []const u8,
    fallback: ?[]const u8 = null,
    optional: bool = false,
};

/// Controller and fallback names are static; the caller owns name and value.
fn appendV1Write(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), controller: []const u8, name: []const u8, value: []u8, fallback: ?[]const u8, optional: bool) libcontainer.Error!void {
    errdefer allocator.free(value);
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    try writes.append(allocator, .{ .controller = controller, .name = owned_name, .value = value, .fallback = fallback, .optional = optional });
}

pub fn freeV1Writes(allocator: std.mem.Allocator, writes: []const V1Write) void {
    for (writes) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    }
    allocator.free(writes);
}

fn v1Limit(allocator: std.mem.Allocator, limit: i64) libcontainer.Error![]u8 {
    if (limit < -1) return error.InvalidConfig;
    return std.fmt.allocPrint(allocator, "{d}", .{limit});
}

/// Pure legacy resource mapping; devices use the emulator's transition separately.
/// Memory/memsw order is finalized by the writer after reading the current limit.
pub fn v1Writes(allocator: std.mem.Allocator, resources: Resources) libcontainer.Error![]V1Write {
    if (resources.unified.len != 0) return error.InvalidConfig;
    var policy = try deviceEmulator(allocator, resources.devices);
    defer policy.deinit(allocator);
    var writes: std.ArrayList(V1Write) = .empty;
    defer writes.deinit(allocator);
    errdefer for (writes.items) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    };
    if (resources.memory) |memory| try appendV1MemoryWrites(allocator, &writes, memory);
    if (resources.cpu) |cpu| try appendV1CpuWrites(allocator, &writes, cpu);
    if (resources.pids) |pids| try appendV1PidsWrites(allocator, &writes, pids);
    if (resources.block_io) |block| try appendV1BlockIOWrites(allocator, &writes, block);
    try appendV1HugepageWrites(allocator, &writes, resources.hugepage_limits);
    if (resources.network) |network| try appendV1NetworkWrites(allocator, &writes, network);
    return writes.toOwnedSlice(allocator);
}

fn appendV1MemoryWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), memory: Resources.Memory) libcontainer.Error!void {
    inline for (.{
        .{ "limit", "memory.limit_in_bytes" },
        .{ "reservation", "memory.soft_limit_in_bytes" },
        .{ "swap", "memory.memsw.limit_in_bytes" },
        .{ "kernel", "memory.kmem.limit_in_bytes" },
        .{ "kernel_tcp", "memory.kmem.tcp.limit_in_bytes" },
    }) |field| {
        if (@field(memory, field[0])) |value| {
            if (value != 0)
                try appendV1Write(allocator, writes, "memory", field[1], try v1Limit(allocator, value), null, false);
        }
    }
    if (memory.swappiness) |value| {
        if (value > 100) return error.InvalidConfig;
        try appendV1Write(allocator, writes, "memory", "memory.swappiness", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
    }
    if (memory.disable_oom_killer orelse false)
        try appendV1Write(allocator, writes, "memory", "memory.oom_control", try allocator.dupe(u8, "1"), null, false);
    if (memory.limit != null and memory.swap != null and memory.swap.? > 0 and
        (memory.limit.? == -1 or memory.swap.? < memory.limit.?)) return error.InvalidConfig;
}

fn appendV1CpuWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), cpu: Resources.Cpu) libcontainer.Error!void {
    if (cpu.shares) |value| {
        _ = try cpuWeight(value);
        if (value != 0)
            try appendV1Write(allocator, writes, "cpu", "cpu.shares", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
    }
    inline for (.{
        .{ "period", "cpu.cfs_period_us" },
        .{ "quota", "cpu.cfs_quota_us" },
        .{ "realtime_period", "cpu.rt_period_us" },
        .{ "realtime_runtime", "cpu.rt_runtime_us" },
    }) |field| {
        if (@field(cpu, field[0])) |value| {
            if (value < 0 and value != -1) return error.InvalidConfig;
            if (value != 0)
                try appendV1Write(allocator, writes, "cpu", field[1], try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
        }
    }
    if (cpu.cpus) |value|
        try appendV1Write(allocator, writes, "cpuset", "cpuset.cpus", try allocator.dupe(u8, value), null, false);
    if (cpu.mems) |value|
        try appendV1Write(allocator, writes, "cpuset", "cpuset.mems", try allocator.dupe(u8, value), null, false);
}

fn appendV1PidsWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), pids: Resources.Pids) libcontainer.Error!void {
    if (pids.limit) |value| {
        if (value != 0)
            try appendV1Write(allocator, writes, "pids", "pids.max", try cgroupLimit(allocator, value), null, false);
    }
}

fn appendV1BlockIOWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), block: Resources.BlockIO) libcontainer.Error!void {
    inline for (.{ .{ "weight", "blkio.weight", @as(?[]const u8, "blkio.bfq.weight"), false }, .{ "leaf_weight", "blkio.leaf_weight", @as(?[]const u8, null), true } }) |field| {
        if (@field(block, field[0])) |value| {
            _ = try ioWeight(value);
            if (value != 0)
                try appendV1Write(allocator, writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}", .{value}), field[2], field[3]);
        }
    }
    for (block.weight_device) |device| try appendV1DeviceWeightWrites(allocator, writes, device);
    inline for (.{
        .{ "throttle_read_bps", "blkio.throttle.read_bps_device" },
        .{ "throttle_write_bps", "blkio.throttle.write_bps_device" },
        .{ "throttle_read_iops", "blkio.throttle.read_iops_device" },
        .{ "throttle_write_iops", "blkio.throttle.write_iops_device" },
    }) |field| {
        for (@field(block, field[0])) |device| {
            if (device.major < 0 or device.minor < 0) return error.InvalidConfig;
            try appendV1Write(allocator, writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, device.rate }), null, false);
        }
    }
}

fn appendV1DeviceWeightWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), device: Resources.WeightDevice) libcontainer.Error!void {
    if (device.major < 0 or device.minor < 0) return error.InvalidConfig;
    inline for (.{ .{ "weight", "blkio.weight_device", @as(?[]const u8, "blkio.bfq.weight_device"), false }, .{ "leaf_weight", "blkio.leaf_weight_device", @as(?[]const u8, null), true } }) |field| {
        if (@field(device, field[0])) |value| {
            _ = try ioWeight(value);
            if (value != 0)
                try appendV1Write(allocator, writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, value }), field[2], field[3]);
        }
    }
}

fn appendV1HugepageWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), pages: []const Resources.HugepageLimit) libcontainer.Error!void {
    for (pages) |page| {
        if (page.page_size.len == 0 or std.mem.indexOfAny(u8, page.page_size, "/\x00") != null) return error.InvalidConfig;
        const name = try std.fmt.allocPrint(allocator, "hugetlb.{s}.limit_in_bytes", .{page.page_size});
        defer allocator.free(name);
        try appendV1Write(allocator, writes, "hugetlb", name, try std.fmt.allocPrint(allocator, "{d}", .{page.limit}), null, false);
    }
}

fn appendV1NetworkWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), network: Resources.Network) libcontainer.Error!void {
    if (network.class_id) |value|
        try appendV1Write(allocator, writes, "net_cls", "net_cls.classid", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
    for (network.priorities) |priority| {
        if (priority.name.len == 0 or std.mem.indexOfAny(u8, priority.name, " \t\n\x00") != null) return error.InvalidConfig;
        try appendV1Write(allocator, writes, "net_prio", "net_prio.ifpriomap", try std.fmt.allocPrint(allocator, "{s} {d}", .{ priority.name, priority.priority }), null, false);
    }
}

fn appendV1DeviceRule(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), rule: Resources.DeviceRule) libcontainer.Error!void {
    if (rule.access.len == 0) return error.InvalidConfig;
    for (rule.access) |access| {
        if (std.mem.indexOfScalar(u8, "rwm", access) == null) return error.InvalidConfig;
    }
    var major_buffer: [24]u8 = undefined;
    var minor_buffer: [24]u8 = undefined;
    const major = if (rule.major) |value| try v1DeviceNumber(&major_buffer, value) else "*";
    const minor = if (rule.minor) |value| try v1DeviceNumber(&minor_buffer, value) else "*";
    const kind: u8 = switch (rule.kind) {
        .all => 'a',
        .block => 'b',
        .char => 'c',
    };
    try appendV1Write(allocator, writes, "devices", if (rule.allow) "devices.allow" else "devices.deny", try std.fmt.allocPrint(allocator, "{c} {s}:{s} {s}", .{ kind, major, minor, rule.access }), null, false);
}

pub fn v1DeviceNumber(buffer: []u8, value: i64) libcontainer.Error![]const u8 {
    if (value == -1) return "*";
    if (value < 0) return error.InvalidConfig;
    return std.fmt.bufPrint(buffer, "{d}", .{value}) catch return error.InvalidConfig;
}

test "v1 creation preserves configured device order and round-trips wildcard defaults" {
    const allocator = std.testing.allocator;
    const configured = try v2DeviceRules(allocator, &.{
        .{ .allow = false },
        .{ .allow = true, .kind = .char, .major = 10, .minor = 229 },
        .{ .allow = true, .kind = .block, .major = 8, .minor = -1, .access = "rw" },
    }, &.{});
    defer allocator.free(configured);
    var target = try deviceEmulator(allocator, configured);
    defer target.deinit(allocator);
    const rules = try target.creationRules(allocator);
    defer allocator.free(rules);
    var writes: std.ArrayList(V1Write) = .empty;
    defer {
        for (writes.items) |write| {
            allocator.free(write.name);
            allocator.free(write.value);
        }
        writes.deinit(allocator);
    }
    for (rules) |rule| try appendV1DeviceRule(allocator, &writes, rule);
    const expected = [_][]const u8{
        "a *:* rwm", "c 10:229 rwm", "b 8:* rw",  "c *:* m",      "b *:* m",
        "c 1:3 rwm", "c 1:8 rwm",    "c 1:7 rwm", "c 5:0 rwm",    "c 1:5 rwm",
        "c 1:9 rwm", "c 136:* rwm",  "c 5:2 rwm", "c 10:200 rwm",
    };
    try std.testing.expectEqual(expected.len, writes.items.len);
    var list: std.Io.Writer.Allocating = .init(allocator);
    defer list.deinit();
    for (writes.items, expected, 0..) |write, value, index| {
        try std.testing.expectEqualStrings(value, write.value);
        try std.testing.expectEqualStrings(if (index == 0) "devices.deny" else "devices.allow", write.name);
        if (index != 0) try list.writer.print("{s}\n", .{write.value});
    }
    var reloaded = try deviceEmulatorFromList(allocator, list.written());
    defer reloaded.deinit(allocator);
    try std.testing.expectEqualDeep(target.entries.items, reloaded.entries.items);
    const round_trip = try reloaded.creationRules(allocator);
    defer allocator.free(round_trip);
    try std.testing.expectEqualDeep(rules, round_trip);
}

fn v1MemorySwapFirst(limit: i64, current_memsw: u64) bool {
    return (if (limit == -1) std.math.maxInt(u64) else @as(u64, @intCast(limit))) > current_memsw;
}

pub const V1Hierarchy = struct {
    mountpoint: []const u8,
    mount_root: []const u8,
    controllers: []const []const u8,
    root: ?posix.fd_t = null,
    leaf: ?posix.fd_t = null,

    pub fn has(self: V1Hierarchy, controller: []const u8) bool {
        for (self.controllers) |name| {
            if (std.mem.eql(u8, name, controller)) return true;
        }
        return false;
    }
};

pub fn freeV1Hierarchies(allocator: std.mem.Allocator, hierarchies: []const V1Hierarchy) void {
    for (hierarchies) |hierarchy| freeV1Hierarchy(allocator, hierarchy);
    allocator.free(hierarchies);
}

fn freeV1Hierarchy(allocator: std.mem.Allocator, hierarchy: V1Hierarchy) void {
    if (comptime builtin.os.tag == .linux) {
        if (hierarchy.leaf) |fd| closeFd(fd);
        if (hierarchy.root) |fd| closeFd(fd);
    }
    for (hierarchy.controllers) |name| allocator.free(name);
    allocator.free(hierarchy.controllers);
    allocator.free(hierarchy.mountpoint);
    allocator.free(hierarchy.mount_root);
}

/// The fs driver ignores named hierarchies; systemd also owns name=systemd.
pub fn v1Hierarchies(allocator: std.mem.Allocator, text: []const u8) libcontainer.Error![]V1Hierarchy {
    return v1HierarchiesForDriver(allocator, text, false);
}

fn v1HierarchiesForDriver(allocator: std.mem.Allocator, text: []const u8, systemd: bool) libcontainer.Error![]V1Hierarchy {
    var result: std.ArrayList(V1Hierarchy) = .empty;
    defer result.deinit(allocator);
    errdefer for (result.items) |hierarchy| freeV1Hierarchy(allocator, hierarchy);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const hierarchy = (try parseV1Hierarchy(allocator, line, systemd)) orelse continue;
        errdefer freeV1Hierarchy(allocator, hierarchy);
        // Bind mounts can expose the same hierarchy more than once.
        if (hasV1Controller(result.items, hierarchy.controllers[0])) {
            freeV1Hierarchy(allocator, hierarchy);
            continue;
        }
        try result.append(allocator, hierarchy);
    }
    return result.toOwnedSlice(allocator);
}

fn parseV1Hierarchy(allocator: std.mem.Allocator, line: []const u8, systemd: bool) libcontainer.Error!?V1Hierarchy {
    const separator = std.mem.indexOf(u8, line, " - ") orelse return error.CreateFailed;
    var fields = std.mem.tokenizeScalar(u8, line[separator + 3 ..], ' ');
    if (!std.mem.eql(u8, fields.next() orelse return error.CreateFailed, "cgroup")) return null;
    _ = fields.next() orelse return error.CreateFailed;
    const options = fields.next() orelse return error.CreateFailed;
    if (!includeV1Hierarchy(options, systemd)) return null;
    var controllers: std.ArrayList([]const u8) = .empty;
    defer controllers.deinit(allocator);
    errdefer for (controllers.items) |name| allocator.free(name);
    var names = std.mem.tokenizeScalar(u8, options, ',');
    while (names.next()) |name| {
        if (!isV1Controller(name)) continue;
        const owned = try allocator.dupe(u8, name);
        errdefer allocator.free(owned);
        try controllers.append(allocator, owned);
    }
    if (controllers.items.len == 0) return null;
    const mount = try MountInfo.parse(line);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const mountpoint = try allocator.dupe(u8, try mountinfoPath(&buffer, mount.mountpoint));
    errdefer allocator.free(mountpoint);
    const mount_root = try allocator.dupe(u8, try mountinfoPath(&buffer, mount.root));
    errdefer allocator.free(mount_root);
    const owned_controllers = try controllers.toOwnedSlice(allocator);
    errdefer {
        for (owned_controllers) |name| allocator.free(name);
        allocator.free(owned_controllers);
    }
    return .{ .mountpoint = mountpoint, .mount_root = mount_root, .controllers = owned_controllers };
}

fn includeV1Hierarchy(options: []const u8, systemd: bool) bool {
    var mount_options = std.mem.tokenizeScalar(u8, options, ',');
    var named = false;
    var systemd_named = false;
    while (mount_options.next()) |option| {
        if (std.mem.startsWith(u8, option, "name=")) named = true;
        if (std.mem.eql(u8, option, "name=systemd")) systemd_named = true;
    }
    return !named or (systemd and systemd_named);
}

fn isV1Controller(name: []const u8) bool {
    // Only kernel controllers; rw, relatime, xattr, release_agent etc.
    // are mount options rather than subsystem names.
    for ([_][]const u8{ "cpu", "cpuacct", "cpuset", "memory", "devices", "pids", "blkio", "hugetlb", "net_cls", "net_prio", "freezer", "perf_event", "rdma", "misc", "debug", "name=systemd" }) |controller| {
        if (std.mem.eql(u8, name, controller)) return true;
    }
    return false;
}

fn hasV1Controller(hierarchies: []const V1Hierarchy, controller: []const u8) bool {
    for (hierarchies) |hierarchy| {
        if (hierarchy.has(controller)) return true;
    }
    return false;
}

test "v1 writes preserve native memory limits and CPU ordering" {
    const writes = try v1Writes(std.testing.allocator, .{
        .memory = .{ .limit = -1, .reservation = 32, .swap = -1, .kernel = 64, .kernel_tcp = 128, .swappiness = 50, .disable_oom_killer = true },
        .cpu = .{ .shares = 1024, .period = 100000, .quota = 50000, .realtime_period = 1000000, .realtime_runtime = 950000, .cpus = "0-2,4", .mems = "0,2" },
        .pids = .{ .limit = -1 },
    });
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]V1Write{
        .{ .controller = "memory", .name = "memory.limit_in_bytes", .value = "-1" },
        .{ .controller = "memory", .name = "memory.soft_limit_in_bytes", .value = "32" },
        .{ .controller = "memory", .name = "memory.memsw.limit_in_bytes", .value = "-1" },
        .{ .controller = "memory", .name = "memory.kmem.limit_in_bytes", .value = "64" },
        .{ .controller = "memory", .name = "memory.kmem.tcp.limit_in_bytes", .value = "128" },
        .{ .controller = "memory", .name = "memory.swappiness", .value = "50" },
        .{ .controller = "memory", .name = "memory.oom_control", .value = "1" },
        .{ .controller = "cpu", .name = "cpu.shares", .value = "1024" },
        .{ .controller = "cpu", .name = "cpu.cfs_period_us", .value = "100000" },
        .{ .controller = "cpu", .name = "cpu.cfs_quota_us", .value = "50000" },
        .{ .controller = "cpu", .name = "cpu.rt_period_us", .value = "1000000" },
        .{ .controller = "cpu", .name = "cpu.rt_runtime_us", .value = "950000" },
        .{ .controller = "cpuset", .name = "cpuset.cpus", .value = "0-2,4" },
        .{ .controller = "cpuset", .name = "cpuset.mems", .value = "0,2" },
        .{ .controller = "pids", .name = "pids.max", .value = "max" },
    }, writes);
}

test "v1 writes retain block IO weights with BFQ alternatives and separate throttle devices" {
    const writes = try v1Writes(std.testing.allocator, .{ .block_io = .{
        .weight = 100,
        .leaf_weight = 200,
        .weight_device = &.{.{ .major = 8, .minor = 0, .weight = 300, .leaf_weight = 400 }},
        .throttle_read_bps = &.{ .{ .major = 8, .minor = 0, .rate = 1000 }, .{ .major = 8, .minor = 1, .rate = 2000 } },
        .throttle_write_bps = &.{.{ .major = 8, .minor = 0, .rate = 3000 }},
        .throttle_read_iops = &.{.{ .major = 8, .minor = 0, .rate = 40 }},
        .throttle_write_iops = &.{.{ .major = 8, .minor = 1, .rate = 50 }},
    } });
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]V1Write{
        .{ .controller = "blkio", .name = "blkio.weight", .value = "100", .fallback = "blkio.bfq.weight" },
        .{ .controller = "blkio", .name = "blkio.leaf_weight", .value = "200", .optional = true },
        .{ .controller = "blkio", .name = "blkio.weight_device", .value = "8:0 300", .fallback = "blkio.bfq.weight_device" },
        .{ .controller = "blkio", .name = "blkio.leaf_weight_device", .value = "8:0 400", .optional = true },
        .{ .controller = "blkio", .name = "blkio.throttle.read_bps_device", .value = "8:0 1000" },
        .{ .controller = "blkio", .name = "blkio.throttle.read_bps_device", .value = "8:1 2000" },
        .{ .controller = "blkio", .name = "blkio.throttle.write_bps_device", .value = "8:0 3000" },
        .{ .controller = "blkio", .name = "blkio.throttle.read_iops_device", .value = "8:0 40" },
        .{ .controller = "blkio", .name = "blkio.throttle.write_iops_device", .value = "8:1 50" },
    }, writes);
}

test "v1 writes map hugepages and network while devices use the transition writer" {
    const writes = try v1Writes(std.testing.allocator, .{
        .hugepage_limits = &.{ .{ .page_size = "2MB", .limit = 4194304 }, .{ .page_size = "1GB", .limit = 0 } },
        .network = .{ .class_id = 1048577, .priorities = &.{ .{ .name = "eth0", .priority = 2 }, .{ .name = "lo", .priority = 3 } } },
        .devices = &.{
            .{ .allow = false },
            .{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" },
            .{ .allow = false, .kind = .char, .major = 10, .access = "m" },
        },
    });
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]V1Write{
        .{ .controller = "hugetlb", .name = "hugetlb.2MB.limit_in_bytes", .value = "4194304" },
        .{ .controller = "hugetlb", .name = "hugetlb.1GB.limit_in_bytes", .value = "0" },
        .{ .controller = "net_cls", .name = "net_cls.classid", .value = "1048577" },
        .{ .controller = "net_prio", .name = "net_prio.ifpriomap", .value = "eth0 2" },
        .{ .controller = "net_prio", .name = "net_prio.ifpriomap", .value = "lo 3" },
    }, writes);
}

test "v1 resource validation rejects holes in wildcard device allows" {
    const allocator = std.testing.allocator;
    defer diagnostics.last_diagnostic_len = 0;
    for ([_]Resources.DeviceRule{
        .{ .allow = true, .kind = .char, .major = 10 },
        .{ .allow = true, .kind = .char, .major = 10, .minor = -1 },
        .{ .allow = true, .kind = .char, .minor = 237 },
    }) |allow| {
        try std.testing.expectError(error.InvalidConfig, v1Writes(allocator, .{ .devices = &.{
            allow,
            .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
        } }));
        try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "cannot punch hole in existing wildcard rule") != null);
    }
}

test "v1 wildcard device rules permit exact subtraction and nonoverlapping denies" {
    for ([_][]const Resources.DeviceRule{
        &.{
            .{ .allow = true, .kind = .char, .major = 10, .access = "rw" },
            .{ .allow = false, .kind = .char, .major = 10, .access = "w" },
        },
        &.{
            .{ .allow = true, .kind = .char, .major = 10, .access = "r" },
            .{ .allow = false, .kind = .char, .major = 10, .minor = 237, .access = "w" },
        },
        &.{
            .{ .allow = true, .kind = .char, .major = 10 },
            .{ .allow = false, .kind = .block, .major = 10, .minor = 237 },
        },
        &.{
            .{ .allow = true, .kind = .char, .major = 10 },
            .{ .allow = false, .kind = .char, .major = 10 },
            .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
        },
        &.{
            .{ .allow = true },
            .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
        },
    }) |rules| {
        const writes = try v1Writes(std.testing.allocator, .{ .devices = rules });
        defer freeV1Writes(std.testing.allocator, writes);
        // Device writes are emitted only by the transition writer.
        try std.testing.expectEqual(@as(usize, 0), writes.len);
    }
}

test "v1 memory ordering raises memsw first only when the new limit exceeds current memsw" {
    try std.testing.expect(v1MemorySwapFirst(64, 32));
    try std.testing.expect(!v1MemorySwapFirst(64, 64));
    try std.testing.expect(!v1MemorySwapFirst(32, 64));
    try std.testing.expect(v1MemorySwapFirst(-1, 64));
}

test "v1 hierarchy discovery retains unescaped roots and excludes duplicate named and unified mounts" {
    const text =
        \\1 0 0:1 / /sys/fs/cgroup rw - tmpfs tmpfs rw
        \\2 1 0:2 /docker/cid /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
        \\3 1 0:3 /docker/a\040b /sys/fs/cgroup/net\040class rw shared:1 - cgroup cgroup rw,net_cls,net_prio
        \\4 1 0:4 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,xattr,name=systemd
        \\5 1 0:5 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw
        \\6 1 0:6 / /sys/fs/cgroup/memory rw - cgroup memory rw,memory
        \\7 1 0:2 /docker/duplicate /copy rw - cgroup cgroup rw,cpu,cpuacct
    ;
    const hierarchies = try v1HierarchiesForDriver(std.testing.allocator, text, false);
    defer freeV1Hierarchies(std.testing.allocator, hierarchies);
    try std.testing.expectEqual(@as(usize, 3), hierarchies.len);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/cpu,cpuacct", hierarchies[0].mountpoint);
    try std.testing.expectEqualStrings("/docker/cid", hierarchies[0].mount_root);
    try std.testing.expectEqualDeep(&[_][]const u8{ "cpu", "cpuacct" }, hierarchies[0].controllers);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/net class", hierarchies[1].mountpoint);
    try std.testing.expectEqualStrings("/docker/a b", hierarchies[1].mount_root);
    try std.testing.expectEqualDeep(&[_][]const u8{ "net_cls", "net_prio" }, hierarchies[1].controllers);
    try std.testing.expectEqualStrings("/", hierarchies[2].mount_root);
    try std.testing.expectEqualDeep(&[_][]const u8{"memory"}, hierarchies[2].controllers);
    try std.testing.expectError(error.CreateFailed, v1HierarchiesForDriver(std.testing.allocator, text ++ "\ninvalid", false));
}

test "v1 mapping rejects unified and malformed resources and preserves wildcard numbers" {
    for ([_]Resources{
        .{ .unified = &.{.{ .key = "memory.max", .value = "32" }} },
        .{ .memory = .{ .limit = -2 } },
        .{ .memory = .{ .limit = 128, .swap = 64 } },
        .{ .memory = .{ .swappiness = 101 } },
        .{ .cpu = .{ .shares = 1 } },
        .{ .cpu = .{ .quota = -2 } },
        .{ .block_io = .{ .weight = 9 } },
        .{ .hugepage_limits = &.{.{ .page_size = "../2MB", .limit = 1 }} },
        .{ .network = .{ .priorities = &.{.{ .name = "eth0\n1", .priority = 1 }} } },
        .{ .devices = &.{.{ .allow = true, .major = -2 }} },
        .{ .devices = &.{.{ .allow = true, .access = "x" }} },
    }) |resources|
        try std.testing.expectError(error.InvalidConfig, v1Writes(std.testing.allocator, resources));
    const writes = try v1Writes(std.testing.allocator, .{ .devices = &.{.{ .allow = true, .kind = .char, .major = -1, .minor = -1 }} });
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqual(@as(usize, 0), writes.len);
    const unset = try v1Writes(std.testing.allocator, .{ .memory = .{ .limit = 0, .swap = 0, .disable_oom_killer = false }, .cpu = .{ .shares = 0, .period = 0, .quota = 0 }, .pids = .{ .limit = 0 } });
    defer freeV1Writes(std.testing.allocator, unset);
    try std.testing.expectEqual(@as(usize, 0), unset.len);
}

test "v1 mapping and hierarchy discovery release partial allocations" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const writes = try v1Writes(allocator, .{
                .memory = .{ .limit = 64, .reservation = 32, .swap = 128, .kernel = 1, .kernel_tcp = 2, .swappiness = 0, .disable_oom_killer = true },
                .cpu = .{ .shares = 1024, .period = 100000, .quota = -1, .realtime_period = 1000000, .realtime_runtime = -1, .cpus = "0", .mems = "0" },
                .pids = .{ .limit = 32 },
                .block_io = .{ .weight = 100, .leaf_weight = 200, .weight_device = &.{.{ .major = 8, .minor = 0, .weight = 100, .leaf_weight = 200 }}, .throttle_read_bps = &.{.{ .major = 8, .minor = 0, .rate = 100 }} },
                .hugepage_limits = &.{.{ .page_size = "2MB", .limit = 1 }},
                .network = .{ .class_id = 1, .priorities = &.{.{ .name = "lo", .priority = 0 }} },
                .devices = &.{.{ .allow = false }},
            });
            defer freeV1Writes(allocator, writes);
            const hierarchies = try v1Hierarchies(allocator,
                \\1 0 0:1 /docker/cid /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct
                \\2 0 0:1 /docker/a\040b /copy rw - cgroup cgroup rw,cpu,cpuacct
                \\3 0 0:2 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
            );
            defer freeV1Hierarchies(allocator, hierarchies);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

pub fn openV1Hierarchies(allocator: std.mem.Allocator, systemd: bool) libcontainer.Error![]V1Hierarchy {
    const text = try readMountinfo(allocator);
    defer allocator.free(text);
    const hierarchies = try v1HierarchiesForDriver(allocator, text, systemd);
    errdefer freeV1Hierarchies(allocator, hierarchies);
    const host_root = try openPath(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(host_root);
    for (hierarchies) |*hierarchy| {
        if (!std.mem.startsWith(u8, hierarchy.mountpoint, "/")) return error.InvalidPath;
        // Pin every component of the mount path too, rather than trusting a
        // final NOFOLLOW on a path containing unpinned parent directories.
        hierarchy.root = (try walkCgroup(host_root, hierarchy.mountpoint[1..], false, &.{})) orelse return error.CreateFailed;
        var fs: [32]usize = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(hierarchy.root.?), @intFromPtr(&fs)));
        if (statfsType(&fs) != 0x27e0eb) return error.Unsupported; // CGROUP_SUPER_MAGIC
    }
    return hierarchies;
}

fn seedV1Cpuset(allocator: std.mem.Allocator, parent: posix.fd_t, child: posix.fd_t, path: []const u8) libcontainer.Error!void {
    for ([_][:0]const u8{ "cpuset.cpus", "cpuset.mems" }) |name| {
        const existing = try readCgroupFile(allocator, child, name);
        defer allocator.free(existing);
        if (std.mem.trim(u8, existing, " \t\n").len != 0) continue;
        const inherited = try readCgroupFile(allocator, parent, name);
        defer allocator.free(inherited);
        try writeCgroupFile(child, name, std.mem.trim(u8, inherited, " \t\n"), path);
    }
}

/// Seed each newly created cpuset directory before descending into its child.
pub fn walkV1Cgroup(allocator: std.mem.Allocator, root: posix.fd_t, mount_root: []const u8, path: []const u8, create: bool, cpuset: bool) libcontainer.Error!?posix.fd_t {
    try validateCgroupPath(path);
    var current = try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        const created = if (create) try createCgroupDirectory(current, name, path, components.peek() == null) else false;
        const opened = linux.openat(current, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .SUCCESS => {},
            .NOENT => {
                if (create) return error.CreateFailed;
                closeFd(current);
                return null;
            },
            else => try checkResult(opened),
        }
        const child: posix.fd_t = @intCast(opened);
        errdefer closeFd(child);
        errdefer if (created and components.peek() == null) removeV1Cgroup(root, mount_root, path, child, null, null) catch {};
        if (created and cpuset) try seedV1Cpuset(allocator, current, child, path);
        closeFd(current);
        current = child;
    }
    return current;
}

/// Keep errno available for BFQ fallbacks and deprecated kmem handling.
fn tryV1Write(dir: posix.fd_t, filename: []const u8, value: []const u8) linux.E {
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{filename}) catch return .INVAL;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => |err| return err,
        }
    };
    defer closeFd(fd);
    while (true) {
        const result = linux.write(fd, value.ptr, value.len);
        const err = linux.errno(result);
        if (err == .INTR) continue;
        if (err == .SUCCESS and result != value.len) return .IO;
        return err;
    }
}

pub fn writeV1Resource(dir: posix.fd_t, write: V1Write, path: []const u8, kmem_warned: *bool) libcontainer.Error!void {
    var name = write.name;
    var err = tryV1Write(dir, name, write.value);
    if (err == .NOENT) {
        if (write.fallback) |fallback| {
            name = fallback;
            err = tryV1Write(dir, name, write.value);
        }
    }
    if (err == .SUCCESS) return;
    if (err == .NOENT and write.optional) {
        std.debug.print("igvano: warning: cgroup v1 {s} is unavailable; ignoring\n", .{name});
        return;
    }
    if (std.mem.startsWith(u8, name, "memory.kmem.") and (err == .NOENT or err == .OPNOTSUPP or err == .INVAL)) {
        if (!kmem_warned.*) std.debug.print("igvano: warning: kernel rejects deprecated cgroup v1 kmem limits; ignoring\n", .{});
        kmem_warned.* = true;
        return;
    }
    reportDiagnostic("cgroup '{s}' cannot write {s} = '{s}': {s}", .{ path, name, write.value, @tagName(err) });
    return error.CgroupWriteFailed;
}

fn requiredV1Controller(controller: []const u8, resources: Resources, devices: []const libcontainer.Device) bool {
    if (std.mem.eql(u8, controller, "memory") or std.mem.eql(u8, controller, "pids")) return true;
    if (std.mem.eql(u8, controller, "devices")) {
        if (resources.devices.len != 0) return true;
        for (devices) |device| {
            if (device.required and device.kind != .fifo) return true;
        }
    }
    return false;
}

// Null devices selects update: leave an omitted ruleset alone.
pub fn applyV1Writes(allocator: std.mem.Allocator, hierarchies: []const V1Hierarchy, writes: []const V1Write, resources: Resources, devices: ?[]const libcontainer.Device, path: []const u8, create: bool) libcontainer.Error!void {
    const has_devices = devices != null or resources.devices.len != 0;
    const nodes = devices orelse &.{};
    const configured = if (has_devices) try v2DeviceRules(allocator, resources.devices, nodes) else &.{};
    defer allocator.free(configured);
    var target = try deviceEmulator(allocator, configured);
    defer target.deinit(allocator);
    if (has_devices) try checkV1DeviceController(hierarchies, resources, nodes);
    try checkV1WriteControllers(hierarchies, writes, resources, nodes);
    var kmem_warned = false;
    for (hierarchies) |hierarchy| {
        try applyV1HierarchyWrites(allocator, hierarchy, writes, resources, path, &kmem_warned);
        if (has_devices and hierarchy.has("devices") and !runningInUserNamespace())
            try applyV1DeviceWrites(allocator, hierarchy.leaf.?, target, path, create, &kmem_warned);
    }
}

fn checkV1DeviceController(hierarchies: []const V1Hierarchy, resources: Resources, nodes: []const libcontainer.Device) libcontainer.Error!void {
    if (hasV1Controller(hierarchies, "devices")) return;
    if (requiredV1Controller("devices", resources, nodes)) {
        reportDiagnostic("cgroup v1 controller devices is required but not mounted", .{});
        return error.CgroupWriteFailed;
    }
    std.debug.print("igvano: warning: cgroup v1 controller devices is not mounted; ignoring\n", .{});
}

fn checkV1WriteControllers(hierarchies: []const V1Hierarchy, writes: []const V1Write, resources: Resources, nodes: []const libcontainer.Device) libcontainer.Error!void {
    // Warn once per missing controller, including controllers with many writes.
    for (writes, 0..) |write, index| {
        if (hasV1Controller(hierarchies, write.controller)) continue;
        if (requiredV1Controller(write.controller, resources, nodes)) {
            reportDiagnostic("cgroup v1 controller {s} is required but not mounted", .{write.controller});
            return error.CgroupWriteFailed;
        }
        const warned = hasV1WriteController(writes[0..index], write.controller);
        if (!warned) std.debug.print("igvano: warning: cgroup v1 controller {s} is not mounted; ignoring\n", .{write.controller});
    }
}

fn hasV1WriteController(writes: []const V1Write, controller: []const u8) bool {
    for (writes) |write| {
        if (std.mem.eql(u8, write.controller, controller)) return true;
    }
    return false;
}

const V1MemoryWriteOrder = struct {
    limit: ?usize = null,
    swap_first: ?usize = null,
};

fn v1MemoryWriteOrder(allocator: std.mem.Allocator, hierarchy: V1Hierarchy, writes: []const V1Write, resources: Resources) libcontainer.Error!V1MemoryWriteOrder {
    if (!hierarchy.has("memory")) return .{};
    var swap_first: ?usize = null;
    var limit_write: ?usize = null;
    var swap_write: ?usize = null;
    for (writes, 0..) |write, index| {
        if (std.mem.eql(u8, write.name, "memory.limit_in_bytes")) limit_write = index;
        if (std.mem.eql(u8, write.name, "memory.memsw.limit_in_bytes")) swap_write = index;
    }
    if (limit_write != null and swap_write != null) {
        const current = try readCgroupFile(allocator, hierarchy.leaf.?, "memory.memsw.limit_in_bytes");
        defer allocator.free(current);
        const memsw = std.fmt.parseInt(u64, std.mem.trim(u8, current, " \t\n"), 10) catch return error.CgroupWriteFailed;
        if (v1MemorySwapFirst(resources.memory.?.limit.?, memsw)) swap_first = swap_write;
    }
    return .{ .limit = limit_write, .swap_first = swap_first };
}

fn applyV1HierarchyWrites(allocator: std.mem.Allocator, hierarchy: V1Hierarchy, writes: []const V1Write, resources: Resources, path: []const u8, kmem_warned: *bool) libcontainer.Error!void {
    const order = try v1MemoryWriteOrder(allocator, hierarchy, writes, resources);
    for (writes, 0..) |write, index| {
        if (!hierarchy.has(write.controller)) continue;
        if (order.swap_first) |swap| {
            if (index == swap) continue;
            if (index == order.limit.?) try writeV1Resource(hierarchy.leaf.?, writes[swap], path, kmem_warned);
        }
        try writeV1Resource(hierarchy.leaf.?, write, path, kmem_warned);
    }
}

fn applyV1DeviceWrites(allocator: std.mem.Allocator, dir: posix.fd_t, target: DeviceEmulator, path: []const u8, create: bool, kmem_warned: *bool) libcontainer.Error!void {
    const list = try readCgroupFile(allocator, dir, "devices.list");
    defer allocator.free(list);
    var current = try deviceEmulatorFromList(allocator, list);
    defer current.deinit(allocator);
    // ponytail: a deny-list source briefly clears deny exceptions on
    // reset; devices.list cannot reveal them, matching runc's v1 Set.
    const transition = if (create) try target.creationRules(allocator) else try current.transition(allocator, target);
    defer allocator.free(transition);
    var device_writes: std.ArrayList(V1Write) = .empty;
    defer {
        for (device_writes.items) |write| {
            allocator.free(write.name);
            allocator.free(write.value);
        }
        device_writes.deinit(allocator);
    }
    for (transition) |rule| try appendV1DeviceRule(allocator, &device_writes, rule);
    for (device_writes.items) |write|
        try writeV1Resource(dir, write, path, kmem_warned);
    const updated_list = try readCgroupFile(allocator, dir, "devices.list");
    defer allocator.free(updated_list);
    var updated = try deviceEmulatorFromList(allocator, updated_list);
    defer updated.deinit(allocator);
    const matches = if (target.default_allow)
        updated.default_allow
    else matches: {
        const remaining = try updated.transition(allocator, target);
        defer allocator.free(remaining);
        break :matches remaining.len == 0;
    };
    if (!matches) {
        reportDiagnostic("cgroup '{s}' devices.list does not match the requested device policy after update", .{path});
        return error.CgroupWriteFailed;
    }
}

pub fn killV1Members(dir: posix.fd_t, freezer: ?posix.fd_t, signal: i32, mount_root: []const u8, path: []const u8, controller: ?[]const u8) libcontainer.Error!void {
    const allocator = std.heap.page_allocator;
    if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
    const was_frozen = if (freezer) |fd| try cgroupFrozen(fd, .legacy) else false;
    const owned_freezer = if (!was_frozen) freezer else null;
    defer if (owned_freezer) |fd| thawV1Quietly(fd, path);
    if (owned_freezer) |fd| try freezeV1Members(fd, path);
    var members: std.ArrayList(i32) = .empty;
    defer members.deinit(allocator);
    try collectCgroupPids(allocator, dir, &members);
    var matched = false;
    for (members.items) |pid| {
        if (try signalV1Member(pid, signal, mount_root, path, controller)) matched = true;
    }
    if (!matched) try verifyV1MembersEmpty(allocator, dir, &members, mount_root, path, controller);
    // SIGKILL on v1 needs a thaw after signaling, even for a user pause.
    if (was_frozen and signal == @intFromEnum(linux.SIG.KILL))
        try writeCgroupFile(freezer.?, "freezer.state", "THAWED", path);
}

fn thawV1Quietly(fd: posix.fd_t, path: []const u8) void {
    const saved_diagnostic = diagnostics.last_diagnostic;
    const saved_len = diagnostics.last_diagnostic_len;
    writeCgroupFile(fd, "freezer.state", "THAWED", path) catch {};
    diagnostics.last_diagnostic = saved_diagnostic;
    diagnostics.last_diagnostic_len = saved_len;
}

fn freezeV1Members(fd: posix.fd_t, path: []const u8) libcontainer.Error!void {
    try writeCgroupFile(fd, "freezer.state", "FROZEN", path);
    if (!try waitFrozen(fd, .legacy, true, 50)) thawV1Quietly(fd, path);
}

fn signalV1Member(pid: i32, signal: i32, mount_root: []const u8, path: []const u8, controller: ?[]const u8) libcontainer.Error!bool {
    const pidfd = openPidfd(pid) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        else => return err,
    };
    defer if (pidfd) |fd| closeFd(fd);
    var buffer: [64 * 1024]u8 = undefined;
    const cgroups = readProcFileAt(linux.AT.FDCWD, pid, "cgroup", &buffer) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        else => return err,
    };
    if (!procCgroupMatches(cgroups, mount_root, path, controller)) return false;
    signalPid(pid, pidfd, signal) catch |err| switch (err) {
        error.ProcessNotFound => {},
        else => return err,
    };
    return true;
}

fn verifyV1MembersEmpty(allocator: std.mem.Allocator, dir: posix.fd_t, members: *std.ArrayList(i32), mount_root: []const u8, path: []const u8, controller: ?[]const u8) libcontainer.Error!void {
    // Members may have exited or moved after enumeration. Verify that the
    // subtree is still populated before reporting an unverifiable policy.
    // V1 cannot detect members hidden by our PID namespace; only v2's
    // cgroup.events reports population independently of PID visibility.
    members.clearRetainingCapacity();
    try collectCgroupPids(allocator, dir, members);
    const populated = members.items.len != 0 or if (controller) |name|
        name.len == 0 and try cgroupPopulated(dir)
    else
        false;
    if (populated) {
        reportDiagnostic("cgroup '{s}' is populated but no member could be verified in /proc; cgroup namespace paths may not expose mount root '{s}'", .{ path, mount_root });
        return error.KillFailed;
    }
}

pub fn removeV1Cgroups(hierarchies: []const V1Hierarchy, path: []const u8) libcontainer.Error!void {
    var freezer: ?posix.fd_t = null;
    var failure: ?libcontainer.Error = null;
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("freezer")) freezer = hierarchy.leaf;
    }
    // Retain the freezer leaf until every other hierarchy has been drained.
    for ([_]bool{ false, true }) |freezer_pass| {
        for (hierarchies) |hierarchy| {
            if (hierarchy.has("freezer") != freezer_pass) continue;
            removeV1Hierarchy(hierarchy, path, freezer) catch |err| {
                if (failure == null) failure = err;
            };
        }
    }
    if (failure) |err| return err;
}

fn removeV1Hierarchy(hierarchy: V1Hierarchy, path: []const u8, freezer: ?posix.fd_t) libcontainer.Error!void {
    const fd = hierarchy.leaf orelse return;
    try removeV1Cgroup(hierarchy.root.?, hierarchy.mount_root, path, fd, freezer, hierarchy.controllers[0]);
}

/// Only remove our leaf, checking identity against the pinned fd on every retry.
pub fn removeV1Cgroup(root: posix.fd_t, mount_root: []const u8, path: []const u8, owned_fd: posix.fd_t, freezer: ?posix.fd_t, controller: ?[]const u8) libcontainer.Error!void {
    try validateCgroupPath(path);
    const parent = if (std.fs.path.dirname(path)) |parent_path|
        (try walkCgroup(root, parent_path, false, &.{})) orelse return
    else
        try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(parent);
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(path)}) catch return error.InvalidPath;
    var owned: linux.Statx = undefined;
    try checkResult(linux.statx(owned_fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &owned));
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..50) |_| {
        const opened = linux.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .SUCCESS => {},
            .NOENT => return,
            .INTR => continue,
            else => return error.CgroupDeleteFailed,
        }
        const leaf: posix.fd_t = @intCast(opened);
        defer closeFd(leaf);
        if (!try v1CgroupIdentityMatches(owned, leaf)) return;
        killV1Members(leaf, freezer, @intFromEnum(linux.SIG.KILL), mount_root, path, controller) catch |err| return switch (err) {
            error.PermissionDenied, error.KillFailed => error.CgroupDeleteFailed,
            else => err,
        };
        try removeCgroupChildren(leaf, path);
        const result = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => return,
            .INTR => continue,
            .BUSY, .NOTEMPTY => _ = linux.nanosleep(&delay, null),
            else => return error.CgroupDeleteFailed,
        }
    }
    reportDiagnostic("cgroup '{s}' is still busy after waiting for members to exit", .{path});
    return error.CgroupDeleteFailed;
}

fn v1CgroupIdentityMatches(owned: linux.Statx, leaf: posix.fd_t) libcontainer.Error!bool {
    var current: linux.Statx = undefined;
    try checkResult(linux.statx(leaf, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &current));
    if (!owned.mask.INO or !current.mask.INO) return error.CgroupDeleteFailed;
    return owned.dev_major == current.dev_major and owned.dev_minor == current.dev_minor and owned.ino == current.ino;
}

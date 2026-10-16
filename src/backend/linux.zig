const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../backend.zig").Backend;
const Resources = Backend.Resources;
const oci = @import("../oci.zig");
const hooks = @import("hooks.zig");
const seccomp = @import("seccomp.zig");

const ST_NOATIME: usize = 1024;
const ST_RELATIME: usize = 4096; // Unlike MS_RELATIME.
const OPEN_TREE_CLONE: u32 = 1;
const OPEN_TREE_CLOEXEC: u32 = 1 << @bitOffsetOf(linux.O, "CLOEXEC");

// Borrowed diagnostic detail for this process; no allocation after fork.
// ponytail: One backend per process; move this buffer into LinuxBackend if the library ever hosts several.
var last_diagnostic: [512]u8 = @splat(0);
var last_diagnostic_len: usize = 0;

fn diagnosticWrite(bytes: []const u8) void {
    const len = @min(bytes.len, last_diagnostic.len - last_diagnostic_len);
    @memcpy(last_diagnostic[last_diagnostic_len..][0..len], bytes[0..len]);
    last_diagnostic_len += len;
    _ = writeAll(2, bytes);
}

fn diagnosticDrain(_: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    for (data[0 .. data.len - 1]) |bytes| diagnosticWrite(bytes);
    for (0..splat) |_| diagnosticWrite(data[data.len - 1]);
    return std.Io.Writer.countSplat(data, splat);
}

/// Formatting and raw writes need neither allocator nor inherited debug locks.
pub fn reportDiagnostic(comptime fmt: []const u8, args: anytype) void {
    last_diagnostic_len = 0;
    _ = writeAll(2, "igvano: ");
    var writer: std.Io.Writer = .{ .vtable = &.{ .drain = diagnosticDrain }, .buffer = &.{} };
    writer.print(fmt, args) catch {};
    _ = writeAll(2, "\n");
    if (last_diagnostic_len == last_diagnostic.len) {
        // Avoid ending a truncated JSON diagnostic halfway through a codepoint.
        var start = last_diagnostic_len - 1;
        while (start > 0 and last_diagnostic[start] & 0xc0 == 0x80) start -= 1;
        const len = std.unicode.utf8ByteSequenceLength(last_diagnostic[start]) catch 1;
        if (len > last_diagnostic_len - start) last_diagnostic_len = start;
    }
}

test "backend diagnostic records formatted detail and truncates safely" {
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    defer last_diagnostic_len = 0;
    last_diagnostic_len = 0;
    try std.testing.expect(backend.diagnostic() == null);
    reportDiagnostic("failed at {s}: {d}", .{ "/proc", 42 });
    try std.testing.expectEqualStrings("failed at /proc: 42", backend.diagnostic().?);
    reportDiagnostic("{s}", .{"x" ** 600});
    try std.testing.expectEqualStrings("x" ** 512, backend.diagnostic().?);
    reportDiagnostic("{s}{s}", .{ "x" ** 511, "é" });
    try std.testing.expectEqualStrings("x" ** 511, backend.diagnostic().?);
    reportDiagnostic("short", .{});
    try std.testing.expectEqualStrings("short", backend.diagnostic().?);
    childError(": ", error.CreateFailed);
    try std.testing.expectEqualStrings(": CreateFailed", backend.diagnostic().?);
}

const Write = struct { name: []const u8, value: []const u8 };
const CgroupMode = enum { unified, legacy };
const V1Write = struct {
    controller: []const u8,
    name: []const u8,
    value: []const u8,
    fallback: ?[]const u8 = null,
    optional: bool = false,
};

/// Controller and fallback names are static; the caller owns name and value.
fn appendV1Write(allocator: std.mem.Allocator, writes: *std.ArrayList(V1Write), controller: []const u8, name: []const u8, value: []u8, fallback: ?[]const u8, optional: bool) Backend.Error!void {
    errdefer allocator.free(value);
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    try writes.append(allocator, .{ .controller = controller, .name = owned_name, .value = value, .fallback = fallback, .optional = optional });
}

fn freeV1Writes(allocator: std.mem.Allocator, writes: []const V1Write) void {
    for (writes) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    }
    allocator.free(writes);
}

fn v1Limit(allocator: std.mem.Allocator, limit: i64) Backend.Error![]u8 {
    if (limit < -1) return error.InvalidConfig;
    return std.fmt.allocPrint(allocator, "{d}", .{limit});
}

/// Pure legacy mapping, including the devices that rootfs setup will create.
/// Memory/memsw order is finalized by the writer after reading the current limit.
// Null devices selects update: replace an explicit ruleset, leave an omitted one alone.
fn v1Writes(allocator: std.mem.Allocator, resources: Resources, devices: ?[]const Backend.Device) Backend.Error![]V1Write {
    if (resources.unified.len != 0) return error.InvalidConfig;
    var writes: std.ArrayList(V1Write) = .empty;
    defer writes.deinit(allocator);
    errdefer for (writes.items) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    };
    if (resources.memory) |memory| {
        inline for (.{
            .{ "limit", "memory.limit_in_bytes" },
            .{ "reservation", "memory.soft_limit_in_bytes" },
            .{ "swap", "memory.memsw.limit_in_bytes" },
            .{ "kernel", "memory.kmem.limit_in_bytes" },
            .{ "kernel_tcp", "memory.kmem.tcp.limit_in_bytes" },
        }) |field| {
            if (@field(memory, field[0])) |value| {
                if (value != 0)
                    try appendV1Write(allocator, &writes, "memory", field[1], try v1Limit(allocator, value), null, false);
            }
        }
        if (memory.swappiness) |value| {
            if (value > 100) return error.InvalidConfig;
            try appendV1Write(allocator, &writes, "memory", "memory.swappiness", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
        }
        if (memory.disable_oom_killer orelse false)
            try appendV1Write(allocator, &writes, "memory", "memory.oom_control", try allocator.dupe(u8, "1"), null, false);
        if (memory.limit != null and memory.swap != null and memory.swap.? > 0 and
            (memory.limit.? == -1 or memory.swap.? < memory.limit.?)) return error.InvalidConfig;
    }
    if (resources.cpu) |cpu| {
        if (cpu.shares) |value| {
            _ = try cpuWeight(value);
            if (value != 0)
                try appendV1Write(allocator, &writes, "cpu", "cpu.shares", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
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
                    try appendV1Write(allocator, &writes, "cpu", field[1], try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
            }
        }
        if (cpu.cpus) |value|
            try appendV1Write(allocator, &writes, "cpuset", "cpuset.cpus", try allocator.dupe(u8, value), null, false);
        if (cpu.mems) |value|
            try appendV1Write(allocator, &writes, "cpuset", "cpuset.mems", try allocator.dupe(u8, value), null, false);
    }
    if (resources.pids) |pids| {
        if (pids.limit) |value| {
            if (value != 0)
                try appendV1Write(allocator, &writes, "pids", "pids.max", try cgroupLimit(allocator, value), null, false);
        }
    }
    if (resources.block_io) |block| {
        inline for (.{ .{ "weight", "blkio.weight", @as(?[]const u8, "blkio.bfq.weight"), false }, .{ "leaf_weight", "blkio.leaf_weight", @as(?[]const u8, null), true } }) |field| {
            if (@field(block, field[0])) |value| {
                _ = try ioWeight(value);
                if (value != 0)
                    try appendV1Write(allocator, &writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}", .{value}), field[2], field[3]);
            }
        }
        for (block.weight_device) |device| {
            if (device.major < 0 or device.minor < 0) return error.InvalidConfig;
            inline for (.{ .{ "weight", "blkio.weight_device", @as(?[]const u8, "blkio.bfq.weight_device"), false }, .{ "leaf_weight", "blkio.leaf_weight_device", @as(?[]const u8, null), true } }) |field| {
                if (@field(device, field[0])) |value| {
                    _ = try ioWeight(value);
                    if (value != 0)
                        try appendV1Write(allocator, &writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, value }), field[2], field[3]);
                }
            }
        }
        inline for (.{
            .{ "throttle_read_bps", "blkio.throttle.read_bps_device" },
            .{ "throttle_write_bps", "blkio.throttle.write_bps_device" },
            .{ "throttle_read_iops", "blkio.throttle.read_iops_device" },
            .{ "throttle_write_iops", "blkio.throttle.write_iops_device" },
        }) |field| {
            for (@field(block, field[0])) |device| {
                if (device.major < 0 or device.minor < 0) return error.InvalidConfig;
                try appendV1Write(allocator, &writes, "blkio", field[1], try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, device.rate }), null, false);
            }
        }
    }
    for (resources.hugepage_limits) |page| {
        if (page.page_size.len == 0 or std.mem.indexOfAny(u8, page.page_size, "/\x00") != null) return error.InvalidConfig;
        const name = try std.fmt.allocPrint(allocator, "hugetlb.{s}.limit_in_bytes", .{page.page_size});
        defer allocator.free(name);
        try appendV1Write(allocator, &writes, "hugetlb", name, try std.fmt.allocPrint(allocator, "{d}", .{page.limit}), null, false);
    }
    if (resources.network) |network| {
        if (network.class_id) |value|
            try appendV1Write(allocator, &writes, "net_cls", "net_cls.classid", try std.fmt.allocPrint(allocator, "{d}", .{value}), null, false);
        for (network.priorities) |priority| {
            if (priority.name.len == 0 or std.mem.indexOfAny(u8, priority.name, " \t\n\x00") != null) return error.InvalidConfig;
            try appendV1Write(allocator, &writes, "net_prio", "net_prio.ifpriomap", try std.fmt.allocPrint(allocator, "{s} {d}", .{ priority.name, priority.priority }), null, false);
        }
    }
    if (devices == null and resources.devices.len != 0)
        try appendV1Write(allocator, &writes, "devices", "devices.deny", try allocator.dupe(u8, "a *:* rwm"), null, false);
    for (resources.devices) |rule| {
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
        try appendV1Write(allocator, &writes, "devices", if (rule.allow) "devices.allow" else "devices.deny", try std.fmt.allocPrint(allocator, "{c} {s}:{s} {s}", .{ kind, major, minor, rule.access }), null, false);
    }
    if (devices != null or resources.devices.len != 0) {
        for ([_][]const u8{ "c 1:3 rwm", "c 1:5 rwm", "c 1:7 rwm", "c 1:8 rwm", "c 1:9 rwm", "c 5:0 rwm", "c 5:2 rwm", "c 136:* rwm" }) |value|
            try appendV1Write(allocator, &writes, "devices", "devices.allow", try allocator.dupe(u8, value), null, false);
    }
    for (devices orelse &.{}) |device| {
        if (device.kind == .fifo) continue;
        try appendV1Write(allocator, &writes, "devices", "devices.allow", try std.fmt.allocPrint(allocator, "{c} {d}:{d} rwm", .{ @as(u8, if (device.kind == .character) 'c' else 'b'), device.major, device.minor }), null, false);
    }
    return writes.toOwnedSlice(allocator);
}

fn v1DeviceNumber(buffer: []u8, value: i64) Backend.Error![]const u8 {
    if (value == -1) return "*";
    if (value < 0) return error.InvalidConfig;
    return std.fmt.bufPrint(buffer, "{d}", .{value}) catch return error.InvalidConfig;
}

fn v1MemorySwapFirst(limit: i64, current_memsw: u64) bool {
    return (if (limit == -1) std.math.maxInt(u64) else @as(u64, @intCast(limit))) > current_memsw;
}

const V1Hierarchy = struct {
    mountpoint: []const u8,
    controllers: []const []const u8,
    root: ?posix.fd_t = null,
    leaf: ?posix.fd_t = null,

    fn has(self: V1Hierarchy, controller: []const u8) bool {
        for (self.controllers) |name| {
            if (std.mem.eql(u8, name, controller)) return true;
        }
        return false;
    }
};

fn freeV1Hierarchies(allocator: std.mem.Allocator, hierarchies: []const V1Hierarchy) void {
    for (hierarchies) |hierarchy| {
        if (comptime builtin.os.tag == .linux) {
            if (hierarchy.leaf) |fd| closeFd(fd);
            if (hierarchy.root) |fd| closeFd(fd);
        }
        for (hierarchy.controllers) |name| allocator.free(name);
        allocator.free(hierarchy.controllers);
        allocator.free(hierarchy.mountpoint);
    }
    allocator.free(hierarchies);
}

/// Ignore named hierarchies and the hybrid unified mount. Comounts are one entry.
fn v1Hierarchies(allocator: std.mem.Allocator, text: []const u8) Backend.Error![]V1Hierarchy {
    var result: std.ArrayList(V1Hierarchy) = .empty;
    defer result.deinit(allocator);
    errdefer {
        for (result.items) |hierarchy| {
            for (hierarchy.controllers) |name| allocator.free(name);
            allocator.free(hierarchy.controllers);
            allocator.free(hierarchy.mountpoint);
        }
    }
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const separator = std.mem.indexOf(u8, line, " - ") orelse return error.CreateFailed;
        var fields = std.mem.tokenizeScalar(u8, line[separator + 3 ..], ' ');
        if (!std.mem.eql(u8, fields.next() orelse return error.CreateFailed, "cgroup")) continue;
        _ = fields.next() orelse return error.CreateFailed;
        const options = fields.next() orelse return error.CreateFailed;
        var mount_options = std.mem.tokenizeScalar(u8, options, ',');
        var named = false;
        while (mount_options.next()) |option| {
            if (std.mem.startsWith(u8, option, "name=")) named = true;
        }
        if (named) continue;
        var controllers: std.ArrayList([]const u8) = .empty;
        defer controllers.deinit(allocator);
        errdefer for (controllers.items) |name| allocator.free(name);
        var names = std.mem.tokenizeScalar(u8, options, ',');
        while (names.next()) |name| {
            // Only kernel controllers; rw, relatime, xattr, release_agent etc.
            // are mount options rather than subsystem names.
            for ([_][]const u8{ "cpu", "cpuacct", "cpuset", "memory", "devices", "pids", "blkio", "hugetlb", "net_cls", "net_prio", "freezer", "perf_event", "rdma", "misc", "debug" }) |controller| {
                if (std.mem.eql(u8, name, controller)) {
                    const owned = try allocator.dupe(u8, name);
                    errdefer allocator.free(owned);
                    try controllers.append(allocator, owned);
                    break;
                }
            }
        }
        if (controllers.items.len == 0) continue;
        const mount = try MountInfo.parse(line);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const mountpoint = try allocator.dupe(u8, try mountinfoPath(&buffer, mount.mountpoint));
        errdefer allocator.free(mountpoint);
        const owned_controllers = try controllers.toOwnedSlice(allocator);
        errdefer {
            for (owned_controllers) |name| allocator.free(name);
            allocator.free(owned_controllers);
        }
        // Bind mounts can expose the same hierarchy more than once.
        var duplicate = false;
        for (result.items) |existing| {
            if (existing.has(owned_controllers[0])) duplicate = true;
        }
        if (duplicate) {
            for (owned_controllers) |name| allocator.free(name);
            allocator.free(owned_controllers);
            allocator.free(mountpoint);
            continue;
        }
        try result.append(allocator, .{ .mountpoint = mountpoint, .controllers = owned_controllers });
    }
    return result.toOwnedSlice(allocator);
}

test "v1 writes preserve native memory limits and CPU ordering" {
    const writes = try v1Writes(std.testing.allocator, .{
        .memory = .{ .limit = -1, .reservation = 32, .swap = -1, .kernel = 64, .kernel_tcp = 128, .swappiness = 50, .disable_oom_killer = true },
        .cpu = .{ .shares = 1024, .period = 100000, .quota = 50000, .realtime_period = 1000000, .realtime_runtime = 950000, .cpus = "0-2,4", .mems = "0,2" },
        .pids = .{ .limit = -1 },
    }, &.{});
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
    }, writes[0 .. writes.len - 8]);
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
    } }, &.{});
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
    }, writes[0 .. writes.len - 8]);
}

test "v1 writes map hugepages network and ordered device rules before allowed devices" {
    const writes = try v1Writes(std.testing.allocator, .{
        .hugepage_limits = &.{ .{ .page_size = "2MB", .limit = 4194304 }, .{ .page_size = "1GB", .limit = 0 } },
        .network = .{ .class_id = 1048577, .priorities = &.{ .{ .name = "eth0", .priority = 2 }, .{ .name = "lo", .priority = 3 } } },
        .devices = &.{
            .{ .allow = false },
            .{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" },
            .{ .allow = false, .kind = .char, .major = 10, .access = "m" },
        },
    }, &.{
        .{ .path = "/disk", .kind = .block, .major = 8, .minor = 1 },
        .{ .path = "/dev/custom", .kind = .character, .major = 10, .minor = 200 },
        .{ .path = "/pipe", .kind = .fifo },
    });
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]V1Write{
        .{ .controller = "hugetlb", .name = "hugetlb.2MB.limit_in_bytes", .value = "4194304" },
        .{ .controller = "hugetlb", .name = "hugetlb.1GB.limit_in_bytes", .value = "0" },
        .{ .controller = "net_cls", .name = "net_cls.classid", .value = "1048577" },
        .{ .controller = "net_prio", .name = "net_prio.ifpriomap", .value = "eth0 2" },
        .{ .controller = "net_prio", .name = "net_prio.ifpriomap", .value = "lo 3" },
        .{ .controller = "devices", .name = "devices.deny", .value = "a *:* rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "b 8:0 rw" },
        .{ .controller = "devices", .name = "devices.deny", .value = "c 10:* m" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 1:3 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 1:5 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 1:7 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 1:8 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 1:9 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 5:0 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 5:2 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 136:* rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "b 8:1 rwm" },
        .{ .controller = "devices", .name = "devices.allow", .value = "c 10:200 rwm" },
    }, writes);
}

test "v1 memory ordering raises memsw first only when the new limit exceeds current memsw" {
    try std.testing.expect(v1MemorySwapFirst(64, 32));
    try std.testing.expect(!v1MemorySwapFirst(64, 64));
    try std.testing.expect(!v1MemorySwapFirst(32, 64));
    try std.testing.expect(v1MemorySwapFirst(-1, 64));
}

test "v1 hierarchy discovery excludes named and unified mounts and combines controllers" {
    const text =
        \\1 0 0:1 / /sys/fs/cgroup rw - tmpfs tmpfs rw
        \\2 1 0:2 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
        \\3 1 0:3 / /sys/fs/cgroup/net\040class rw shared:1 - cgroup cgroup rw,net_cls,net_prio
        \\4 1 0:4 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,xattr,name=systemd
        \\5 1 0:5 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw
        \\6 1 0:6 / /sys/fs/cgroup/memory rw - cgroup memory rw,memory
    ;
    const hierarchies = try v1Hierarchies(std.testing.allocator, text);
    defer freeV1Hierarchies(std.testing.allocator, hierarchies);
    try std.testing.expectEqual(@as(usize, 3), hierarchies.len);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/cpu,cpuacct", hierarchies[0].mountpoint);
    try std.testing.expectEqualDeep(&[_][]const u8{ "cpu", "cpuacct" }, hierarchies[0].controllers);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/net class", hierarchies[1].mountpoint);
    try std.testing.expectEqualDeep(&[_][]const u8{ "net_cls", "net_prio" }, hierarchies[1].controllers);
    try std.testing.expectEqualDeep(&[_][]const u8{"memory"}, hierarchies[2].controllers);
}

test "cgroup mode detects unified and legacy roots" {
    try std.testing.expectEqual(CgroupMode.unified, try cgroupMode(0x63677270));
    try std.testing.expectEqual(CgroupMode.legacy, try cgroupMode(0x01021994));
    try std.testing.expectError(error.Unsupported, cgroupMode(0x27e0eb));
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
        try std.testing.expectError(error.InvalidConfig, v1Writes(std.testing.allocator, resources, &.{}));
    const writes = try v1Writes(std.testing.allocator, .{ .devices = &.{.{ .allow = true, .kind = .char, .major = -1, .minor = -1 }} }, &.{});
    defer freeV1Writes(std.testing.allocator, writes);
    try std.testing.expectEqualStrings("c *:* rwm", writes[0].value);
    const unset = try v1Writes(std.testing.allocator, .{ .memory = .{ .limit = 0, .swap = 0, .disable_oom_killer = false }, .cpu = .{ .shares = 0, .period = 0, .quota = 0 }, .pids = .{ .limit = 0 } }, &.{});
    defer freeV1Writes(std.testing.allocator, unset);
    try std.testing.expectEqual(@as(usize, 8), unset.len);
}

test "linux update requires a persisted cgroup path" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    try std.testing.expectError(error.Unsupported, backend.update(.{
        .id = "example",
        .pid = 1,
        .starttime = "1",
    }, .{ .memory = .{ .limit = 67108864 } }));
    try std.testing.expect(std.mem.indexOf(u8, backend.diagnostic().?, "no cgroup") != null);
}

test "resource updates write only requested limits and replace explicit v1 device rules" {
    const resources: Resources = .{ .cpu = .{ .shares = 512 } };
    const v1 = try v1Writes(std.testing.allocator, resources, null);
    defer freeV1Writes(std.testing.allocator, v1);
    try std.testing.expectEqual(@as(usize, 1), v1.len);
    try std.testing.expectEqualStrings("cpu.shares", v1[0].name);
    try std.testing.expectEqualStrings("512", v1[0].value);
    const v2 = try v2Writes(std.testing.allocator, resources);
    defer freeWrites(std.testing.allocator, v2);
    try std.testing.expectEqual(@as(usize, 1), v2.len);
    try std.testing.expectEqualStrings("cpu.weight", v2[0].name);
    try std.testing.expectEqualStrings("20", v2[0].value);
    const devices = try v1Writes(std.testing.allocator, .{
        .devices = &.{.{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" }},
    }, null);
    defer freeV1Writes(std.testing.allocator, devices);
    try std.testing.expectEqualStrings("devices.deny", devices[0].name);
    try std.testing.expectEqualStrings("a *:* rwm", devices[0].value);
    try std.testing.expectEqualStrings("devices.allow", devices[1].name);
    try std.testing.expectEqualStrings("b 8:0 rw", devices[1].value);
    try std.testing.expectEqualStrings("c 1:3 rwm", devices[2].value);
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
            }, &.{.{ .path = "/disk", .kind = .block, .major = 8, .minor = 0 }});
            defer freeV1Writes(allocator, writes);
            const hierarchies = try v1Hierarchies(allocator,
                \\1 0 0:1 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct
                \\2 0 0:1 / /copy rw - cgroup cgroup rw,cpu,cpuacct
                \\3 0 0:2 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
            );
            defer freeV1Hierarchies(allocator, hierarchies);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

/// Pure cgroup v2 mapping. The caller owns the slice and both strings.
fn v2Writes(allocator: std.mem.Allocator, resources: Resources) Backend.Error![]Write {
    var writes: std.ArrayList(Write) = .empty;
    defer writes.deinit(allocator);
    errdefer for (writes.items) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    };
    if (resources.memory) |memory| {
        if (memory.limit) |limit| {
            if (limit != 0)
                try appendWrite(allocator, &writes, "memory.max", try cgroupLimit(allocator, limit));
        }
        if (memory.reservation) |reservation|
            try appendWrite(allocator, &writes, "memory.low", try cgroupLimit(allocator, reservation));
        if (memory.swap) |swap| {
            const limit = memory.limit orelse 0;
            if (swap < -1) return error.InvalidConfig;
            if (swap == -1) {
                try appendWrite(allocator, &writes, "memory.swap.max", try allocator.dupe(u8, "max"));
            } else if (swap > 0) {
                if (limit <= 0) {
                    reportDiagnostic("swap limit requires a memory limit", .{});
                    return error.InvalidConfig;
                }
                if (swap < limit) return error.InvalidConfig;
                try appendWrite(allocator, &writes, "memory.swap.max", try cgroupLimit(allocator, swap - limit));
            }
        }
    }
    if (resources.cpu) |cpu| {
        const quota = cpu.quota orelse -1;
        if (quota < -1) return error.InvalidConfig;
        const period = if ((cpu.period orelse 0) == 0) 100000 else cpu.period.?;
        if (cpu.quota != null or cpu.period != null) {
            const value = if (quota <= 0)
                try std.fmt.allocPrint(allocator, "max {d}", .{period})
            else
                try std.fmt.allocPrint(allocator, "{d} {d}", .{ quota, period });
            try appendWrite(allocator, &writes, "cpu.max", value);
        }
        if (cpu.shares) |shares| {
            const weight = try cpuWeight(shares);
            if (weight != 0)
                try appendWrite(allocator, &writes, "cpu.weight", try std.fmt.allocPrint(allocator, "{d}", .{weight}));
        }
        if (cpu.cpus) |cpus|
            try appendWrite(allocator, &writes, "cpuset.cpus", try allocator.dupe(u8, cpus));
        if (cpu.mems) |mems|
            try appendWrite(allocator, &writes, "cpuset.mems", try allocator.dupe(u8, mems));
    }
    if (resources.pids) |pids| {
        if (pids.limit) |limit| {
            if (limit != 0)
                try appendWrite(allocator, &writes, "pids.max", try cgroupLimit(allocator, limit));
        }
    }
    if (resources.block_io) |block| {
        if (block.weight) |weight| {
            const converted = try ioWeight(weight);
            if (converted != 0)
                try appendWrite(allocator, &writes, "io.weight", try std.fmt.allocPrint(allocator, "{d}", .{converted}));
        }
        for (block.weight_device) |device| {
            if (device.weight) |weight| {
                const converted = try ioWeight(weight);
                if (converted != 0)
                    try appendWrite(allocator, &writes, "io.weight", try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, converted }));
            }
        }
        inline for (.{
            .{ "throttle_read_bps", "rbps" },
            .{ "throttle_write_bps", "wbps" },
            .{ "throttle_read_iops", "riops" },
            .{ "throttle_write_iops", "wiops" },
        }) |throttle| {
            for (@field(block, throttle[0])) |device|
                try appendWrite(allocator, &writes, "io.max", try std.fmt.allocPrint(allocator, "{d}:{d} {s}={d}", .{ device.major, device.minor, throttle[1], device.rate }));
        }
    }
    for (resources.hugepage_limits) |page| {
        if (page.page_size.len == 0 or std.mem.indexOfAny(u8, page.page_size, "/\x00") != null)
            return error.InvalidConfig;
        const name = try std.fmt.allocPrint(allocator, "hugetlb.{s}.max", .{page.page_size});
        defer allocator.free(name);
        try appendWrite(allocator, &writes, name, try std.fmt.allocPrint(allocator, "{d}", .{page.limit}));
    }
    // ponytail: device rules remain unenforced on v2; add an eBPF
    // BPF_CGROUP_DEVICE filter when device access enforcement is required.
    // Raw settings are last so they override any typed resource mapping.
    for (resources.unified) |entry|
        try appendWrite(allocator, &writes, entry.key, try allocator.dupe(u8, entry.value));
    return writes.toOwnedSlice(allocator);
}

fn cgroupLimit(allocator: std.mem.Allocator, limit: i64) Backend.Error![]u8 {
    if (limit < -1) return error.InvalidConfig;
    if (limit == -1) return allocator.dupe(u8, "max");
    return std.fmt.allocPrint(allocator, "{d}", .{limit});
}

/// Zero shares means unset; the remaining range maps to [1, 10000].
fn cpuWeight(shares: u64) Backend.Error!u64 {
    if (shares == 0) return 0;
    if (shares < 2 or shares > 262144) return error.InvalidConfig;
    return 1 + ((shares - 2) * 9999) / 262142;
}

fn ioWeight(weight: u16) Backend.Error!u64 {
    if (weight == 0) return 0;
    if (weight < 10 or weight > 1000) return error.InvalidConfig;
    return 1 + (@as(u64, weight - 10) * 9999) / 990;
}

fn appendWrite(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), name: []const u8, value: []u8) Backend.Error!void {
    errdefer allocator.free(value);
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    try writes.append(allocator, .{ .name = owned_name, .value = value });
}

fn freeWrites(allocator: std.mem.Allocator, writes: []const Write) void {
    for (writes) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    }
    allocator.free(writes);
}

fn v2IgnoredFields(allocator: std.mem.Allocator, resources: Resources) ![]u8 {
    var fields: std.ArrayList(u8) = .empty;
    defer fields.deinit(allocator);
    if (resources.memory) |memory| {
        inline for (.{ "kernel", "kernel_tcp", "swappiness", "disable_oom_killer" }) |field|
            if (@field(memory, field) != null) try appendIgnoredField(allocator, &fields, "memory." ++ field);
    }
    if (resources.cpu) |cpu| {
        inline for (.{ "realtime_runtime", "realtime_period" }) |field|
            if (@field(cpu, field) != null) try appendIgnoredField(allocator, &fields, "cpu." ++ field);
    }
    if (resources.block_io) |block| {
        if (block.leaf_weight != null) try appendIgnoredField(allocator, &fields, "block_io.leaf_weight");
        for (block.weight_device) |device| {
            if (device.leaf_weight != null) {
                try appendIgnoredField(allocator, &fields, "block_io.weight_device.leaf_weight");
                break;
            }
        }
    }
    if (resources.network) |network| {
        if (network.class_id != null) try appendIgnoredField(allocator, &fields, "network.class_id");
        if (network.priorities.len != 0) try appendIgnoredField(allocator, &fields, "network.priorities");
    }
    return fields.toOwnedSlice(allocator);
}

fn appendIgnoredField(allocator: std.mem.Allocator, fields: *std.ArrayList(u8), name: []const u8) !void {
    if (fields.items.len != 0) try fields.appendSlice(allocator, ", ");
    try fields.appendSlice(allocator, name);
}

fn enabledControllers(buffer: *[64]u8, writes: []const Write) []const u8 {
    var len: usize = 0;
    const controllers = [_]struct { prefix: []const u8, enable: []const u8 }{
        .{ .prefix = "memory.", .enable = "+memory " },
        .{ .prefix = "cpu.", .enable = "+cpu " },
        .{ .prefix = "pids.", .enable = "+pids " },
        .{ .prefix = "cpuset.", .enable = "+cpuset " },
        .{ .prefix = "io.", .enable = "+io " },
        .{ .prefix = "hugetlb.", .enable = "+hugetlb " },
    };
    for (controllers) |controller| {
        for (writes) |write| {
            if (std.mem.startsWith(u8, write.name, controller.prefix)) {
                @memcpy(buffer[len..][0..controller.enable.len], controller.enable);
                len += controller.enable.len;
                break;
            }
        }
    }
    return buffer[0..len];
}

test "cpu shares map to cgroup2 weights without underflow or overflow" {
    const cases = [_]struct { shares: u64, weight: u64 }{
        .{ .shares = 0, .weight = 0 },
        .{ .shares = 2, .weight = 1 },
        .{ .shares = 1024, .weight = 39 },
        .{ .shares = 262144, .weight = 10000 },
    };
    for (cases) |case| try std.testing.expectEqual(case.weight, try cpuWeight(case.shares));
    for ([_]u64{ 1, 262145, std.math.maxInt(u64) }) |shares|
        try std.testing.expectError(error.InvalidConfig, cpuWeight(shares));
}

test "v2 writes preserve existing memory cpu and pids mappings" {
    const writes = try v2Writes(std.testing.allocator, .{
        .memory = .{ .limit = 67108864 },
        .cpu = .{ .quota = 50000, .period = 100000, .shares = 1024 },
        .pids = .{ .limit = 32 },
    });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "memory.max", .value = "67108864" },
        .{ .name = "cpu.max", .value = "50000 100000" },
        .{ .name = "cpu.weight", .value = "39" },
        .{ .name = "pids.max", .value = "32" },
    }, writes);
}

test "v2 writes preserve unlimited values and CPU defaults" {
    const cases = [_]struct { resources: Resources, name: []const u8, value: []const u8 }{
        .{ .resources = .{ .memory = .{ .limit = -1 } }, .name = "memory.max", .value = "max" },
        .{ .resources = .{ .pids = .{ .limit = -1 } }, .name = "pids.max", .value = "max" },
        .{ .resources = .{ .cpu = .{ .quota = -1, .period = 200000 } }, .name = "cpu.max", .value = "max 200000" },
        .{ .resources = .{ .cpu = .{ .period = 200000 } }, .name = "cpu.max", .value = "max 200000" },
        .{ .resources = .{ .cpu = .{ .quota = 50000 } }, .name = "cpu.max", .value = "50000 100000" },
        .{ .resources = .{ .cpu = .{ .quota = 0, .period = 0 } }, .name = "cpu.max", .value = "max 100000" },
    };
    for (cases) |case| {
        const writes = try v2Writes(std.testing.allocator, case.resources);
        defer freeWrites(std.testing.allocator, writes);
        try std.testing.expectEqualDeep(&[_]Write{.{ .name = case.name, .value = case.value }}, writes);
    }
    for ([_]Resources{
        .{},
        .{ .cpu = .{ .shares = 0 } },
        .{ .memory = .{} },
        .{ .memory = .{ .limit = 0 } },
        .{ .pids = .{ .limit = 0 } },
        .{ .memory = .{ .limit = 0 }, .pids = .{ .limit = 0 } },
    }) |resources| {
        const writes = try v2Writes(std.testing.allocator, resources);
        defer freeWrites(std.testing.allocator, writes);
        try std.testing.expectEqual(@as(usize, 0), writes.len);
    }
    const writes = try v2Writes(std.testing.allocator, .{
        .memory = .{ .limit = 0 },
        .pids = .{ .limit = 0 },
        .cpu = .{ .shares = 1024 },
    });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{.{ .name = "cpu.weight", .value = "39" }}, writes);
}

test "v2 resource mapping frees partially allocated writes on allocation failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const writes = try v2Writes(allocator, .{
                .memory = .{ .limit = 67108864, .reservation = 32, .swap = -1 },
                .cpu = .{ .quota = 50000, .period = 100000, .shares = 1024, .cpus = "0", .mems = "0" },
                .pids = .{ .limit = 32 },
                .block_io = .{
                    .weight = 100,
                    .weight_device = &.{.{ .major = 8, .minor = 0, .weight = 100 }},
                    .throttle_read_bps = &.{.{ .major = 8, .minor = 0, .rate = 1000 }},
                    .throttle_write_bps = &.{.{ .major = 8, .minor = 0, .rate = 2000 }},
                    .throttle_read_iops = &.{.{ .major = 8, .minor = 0, .rate = 30 }},
                    .throttle_write_iops = &.{.{ .major = 8, .minor = 0, .rate = 40 }},
                },
                .hugepage_limits = &.{.{ .page_size = "2MB", .limit = 4194304 }},
                .unified = &.{.{ .key = "memory.high", .value = "32" }},
            });
            defer freeWrites(allocator, writes);
            try std.testing.expectEqual(@as(usize, 16), writes.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

test "v2 writes map memory reservation and total swap to swap-only limits" {
    const cases = [_]struct { memory: Resources.Memory, expected: []const Write }{
        .{ .memory = .{ .reservation = 32 }, .expected = &.{.{ .name = "memory.low", .value = "32" }} },
        .{ .memory = .{ .reservation = 0 }, .expected = &.{.{ .name = "memory.low", .value = "0" }} },
        .{ .memory = .{ .reservation = -1 }, .expected = &.{.{ .name = "memory.low", .value = "max" }} },
        .{ .memory = .{ .limit = 64, .swap = 128 }, .expected = &.{
            .{ .name = "memory.max", .value = "64" }, .{ .name = "memory.swap.max", .value = "64" },
        } },
        .{ .memory = .{ .limit = 64, .swap = 64 }, .expected = &.{
            .{ .name = "memory.max", .value = "64" }, .{ .name = "memory.swap.max", .value = "0" },
        } },
        .{ .memory = .{ .limit = 64, .swap = -1 }, .expected = &.{
            .{ .name = "memory.max", .value = "64" }, .{ .name = "memory.swap.max", .value = "max" },
        } },
        .{ .memory = .{ .limit = -1, .swap = -1 }, .expected = &.{
            .{ .name = "memory.max", .value = "max" }, .{ .name = "memory.swap.max", .value = "max" },
        } },
        .{ .memory = .{ .swap = -1 }, .expected = &.{.{ .name = "memory.swap.max", .value = "max" }} },
        .{ .memory = .{ .limit = 0, .swap = -1 }, .expected = &.{.{ .name = "memory.swap.max", .value = "max" }} },
        .{ .memory = .{ .swap = 0 }, .expected = &.{} },
        .{ .memory = .{ .limit = 0, .swap = 0 }, .expected = &.{} },
    };
    for (cases) |case| {
        const writes = try v2Writes(std.testing.allocator, .{ .memory = case.memory });
        defer freeWrites(std.testing.allocator, writes);
        try std.testing.expectEqualDeep(case.expected, writes);
    }
    for ([_]Resources.Memory{
        .{ .swap = 128 },
        .{ .limit = 128, .swap = 64 },
        .{ .limit = 0, .swap = 64 },
        .{ .limit = -1, .swap = 64 },
        .{ .limit = 64, .swap = -2 },
    }) |memory|
        try std.testing.expectError(error.InvalidConfig, v2Writes(std.testing.allocator, .{ .memory = memory }));
}

test "v2 writes preserve cpuset strings" {
    const writes = try v2Writes(std.testing.allocator, .{ .cpu = .{ .cpus = "0-2,4", .mems = "0,2" } });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "cpuset.cpus", .value = "0-2,4" }, .{ .name = "cpuset.mems", .value = "0,2" },
    }, writes);
}

test "v2 swap without a finite memory limit reports why it is invalid" {
    defer last_diagnostic_len = 0;
    for ([_]?i64{ null, 0, -1 }) |limit| {
        last_diagnostic_len = 0;
        try std.testing.expectError(error.InvalidConfig, v2Writes(std.testing.allocator, .{ .memory = .{ .limit = limit, .swap = 128 } }));
        try std.testing.expectEqualStrings("swap limit requires a memory limit", last_diagnostic[0..last_diagnostic_len]);
    }
}

test "v2 writes convert global and per-device block IO weights" {
    const cases = [_]struct { weight: u16, expected: []const u8 }{
        .{ .weight = 10, .expected = "1" },
        .{ .weight = 100, .expected = "910" },
        .{ .weight = 500, .expected = "4950" },
        .{ .weight = 1000, .expected = "10000" },
    };
    for (cases) |case| {
        const writes = try v2Writes(std.testing.allocator, .{ .block_io = .{ .weight = case.weight } });
        defer freeWrites(std.testing.allocator, writes);
        try std.testing.expectEqualDeep(&[_]Write{.{ .name = "io.weight", .value = case.expected }}, writes);
    }
    const writes = try v2Writes(std.testing.allocator, .{ .block_io = .{
        .weight = 0,
        .weight_device = &.{
            .{ .major = 8, .minor = 0, .weight = 10 },
            .{ .major = 8, .minor = 1, .weight = 1000 },
            .{ .major = 8, .minor = 2, .weight = 0 },
            .{ .major = 8, .minor = 3, .leaf_weight = 100 },
        },
    } });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "io.weight", .value = "8:0 1" },
        .{ .name = "io.weight", .value = "8:1 10000" },
    }, writes);
    for ([_]u16{ 1, 9, 1001, std.math.maxInt(u16) }) |weight|
        try std.testing.expectError(error.InvalidConfig, v2Writes(std.testing.allocator, .{ .block_io = .{ .weight = weight } }));
}

test "v2 writes map each block IO throttle device and kind separately" {
    const writes = try v2Writes(std.testing.allocator, .{ .block_io = .{
        .throttle_read_bps = &.{
            .{ .major = 8, .minor = 0, .rate = 1000 }, .{ .major = 8, .minor = 1, .rate = 2000 },
        },
        .throttle_write_bps = &.{.{ .major = 8, .minor = 0, .rate = 3000 }},
        .throttle_read_iops = &.{.{ .major = 8, .minor = 0, .rate = 40 }},
        .throttle_write_iops = &.{.{ .major = 8, .minor = 1, .rate = 50 }},
    } });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "io.max", .value = "8:0 rbps=1000" },
        .{ .name = "io.max", .value = "8:1 rbps=2000" },
        .{ .name = "io.max", .value = "8:0 wbps=3000" },
        .{ .name = "io.max", .value = "8:0 riops=40" },
        .{ .name = "io.max", .value = "8:1 wiops=50" },
    }, writes);
}

test "v2 writes generate hugepage filenames and apply unified entries last" {
    const writes = try v2Writes(std.testing.allocator, .{
        .memory = .{ .limit = 64 },
        .hugepage_limits = &.{ .{ .page_size = "2MB", .limit = 4194304 }, .{ .page_size = "1GB", .limit = 0 } },
        .unified = &.{
            .{ .key = "memory.max", .value = "128" },
            .{ .key = "hugetlb.2MB.max", .value = "8388608" },
            .{ .key = "custom.file", .value = "verbatim\n" },
        },
    });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "memory.max", .value = "64" },
        .{ .name = "hugetlb.2MB.max", .value = "4194304" },
        .{ .name = "hugetlb.1GB.max", .value = "0" },
        .{ .name = "memory.max", .value = "128" },
        .{ .name = "hugetlb.2MB.max", .value = "8388608" },
        .{ .name = "custom.file", .value = "verbatim\n" },
    }, writes);
}

test "v2 ignored fields form one warning list without device rules" {
    const resources: Resources = .{
        .memory = .{ .kernel = 0, .kernel_tcp = -1, .swappiness = 0, .disable_oom_killer = false },
        .cpu = .{ .realtime_runtime = 0, .realtime_period = 0 },
        .block_io = .{
            .leaf_weight = 0,
            .weight_device = &.{
                .{ .major = 8, .minor = 0, .leaf_weight = 100 },
                .{ .major = 8, .minor = 1, .leaf_weight = 200 },
            },
        },
        .network = .{ .class_id = 0, .priorities = &.{.{ .name = "eth0", .priority = 0 }} },
        .devices = &.{.{ .allow = false }},
    };
    const ignored = try v2IgnoredFields(std.testing.allocator, resources);
    defer std.testing.allocator.free(ignored);
    try std.testing.expectEqualStrings(
        "memory.kernel, memory.kernel_tcp, memory.swappiness, memory.disable_oom_killer, " ++
            "cpu.realtime_runtime, cpu.realtime_period, block_io.leaf_weight, block_io.weight_device.leaf_weight, " ++
            "network.class_id, network.priorities",
        ignored,
    );
    const writes = try v2Writes(std.testing.allocator, resources);
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqual(@as(usize, 0), writes.len);

    for ([_]Resources{
        .{},
        .{ .devices = &.{.{ .allow = false }} },
        .{ .memory = .{ .limit = 64, .reservation = 32, .swap = 128 } },
        .{ .cpu = .{ .shares = 1024, .cpus = "0", .mems = "0" } },
        .{ .block_io = .{ .weight = 100, .weight_device = &.{.{ .major = 8, .minor = 0, .weight = 100 }} } },
        .{ .network = .{} },
    }) |supported| {
        const fields = try v2IgnoredFields(std.testing.allocator, supported);
        defer std.testing.allocator.free(fields);
        try std.testing.expectEqualStrings("", fields);
    }
    const cases = [_]struct { resources: Resources, field: []const u8 }{
        .{ .resources = .{ .memory = .{ .kernel = 64 } }, .field = "memory.kernel" },
        .{ .resources = .{ .memory = .{ .kernel_tcp = 64 } }, .field = "memory.kernel_tcp" },
        .{ .resources = .{ .memory = .{ .swappiness = 50 } }, .field = "memory.swappiness" },
        .{ .resources = .{ .memory = .{ .disable_oom_killer = true } }, .field = "memory.disable_oom_killer" },
        .{ .resources = .{ .cpu = .{ .realtime_runtime = 1 } }, .field = "cpu.realtime_runtime" },
        .{ .resources = .{ .cpu = .{ .realtime_period = 1 } }, .field = "cpu.realtime_period" },
        .{ .resources = .{ .block_io = .{ .leaf_weight = 100 } }, .field = "block_io.leaf_weight" },
        .{ .resources = .{ .block_io = .{ .weight_device = &.{.{ .major = 8, .minor = 0, .leaf_weight = 100 }} } }, .field = "block_io.weight_device.leaf_weight" },
        .{ .resources = .{ .network = .{ .class_id = 1 } }, .field = "network.class_id" },
        .{ .resources = .{ .network = .{ .priorities = &.{.{ .name = "eth0", .priority = 1 }} } }, .field = "network.priorities" },
    };
    for (cases) |case| {
        const fields = try v2IgnoredFields(std.testing.allocator, case.resources);
        defer std.testing.allocator.free(fields);
        try std.testing.expectEqualStrings(case.field, fields);
    }
}

test "v2 ignored field collection cleans up on allocation failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const fields = try v2IgnoredFields(allocator, .{
                .memory = .{ .kernel = 64, .kernel_tcp = 64, .swappiness = 50, .disable_oom_killer = true },
                .cpu = .{ .realtime_runtime = 1, .realtime_period = 1 },
                .block_io = .{ .leaf_weight = 100 },
                .network = .{ .class_id = 1 },
            });
            defer allocator.free(fields);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

test "v2 controller selection uses write prefixes and enables each controller once" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("+memory +cpu +pids +cpuset +io +hugetlb ", enabledControllers(&buffer, &.{
        .{ .name = "hugetlb.2MB.max", .value = "0" },
        .{ .name = "cpuset.mems", .value = "0" },
        .{ .name = "io.max", .value = "8:0 rbps=1" },
        .{ .name = "memory.max", .value = "64" },
        .{ .name = "memory.low", .value = "32" },
        .{ .name = "cpu.max", .value = "max 100000" },
        .{ .name = "pids.max", .value = "32" },
        .{ .name = "cpuset.cpus", .value = "0-1" },
        .{ .name = "io.weight", .value = "1" },
        .{ .name = "cgroup.freeze", .value = "0" },
    }));
    try std.testing.expectEqualStrings("", enabledControllers(&buffer, &.{}));
    const writes = try v2Writes(std.testing.allocator, .{ .unified = &.{.{ .key = "io.max", .value = "8:0 rbps=1" }} });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualStrings("+io ", enabledControllers(&buffer, writes));
}

/// EPERM fallback preserves flags even in an inherited user namespace.
/// Strict atime is implicit in statfs; never combine incompatible atime modes.
pub fn lockedMountFlags(requested: u32, fs_flags: usize) Backend.Error!u32 {
    const ms = linux.MS;
    const common = ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC | ms.NODIRATIME;
    const atime_mask = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
    const atime: u32 = (if (fs_flags & ST_NOATIME != 0) @as(u32, ms.NOATIME) else 0) |
        (if (fs_flags & ST_RELATIME != 0) @as(u32, ms.RELATIME) else 0) |
        (if (fs_flags & (ST_NOATIME | ST_RELATIME) == 0) @as(u32, ms.STRICTATIME) else 0);
    const requested_atime = requested & atime_mask;
    if (requested_atime != 0 and requested_atime != atime) return error.InvalidConfig;
    return requested | @as(u32, @intCast(fs_flags & common)) |
        (if (requested_atime == 0) atime else 0);
}

test "user namespace remount flags retain only locked statfs flags" {
    const ms = linux.MS;
    const requested: u32 = ms.BIND | ms.REMOUNT | ms.RDONLY;
    const cases = [_]struct { statfs: usize, expected: u32 }{
        .{ .statfs = 0, .expected = requested | ms.STRICTATIME },
        .{ .statfs = 2, .expected = requested | ms.NOSUID | ms.STRICTATIME },
        .{ .statfs = 4, .expected = requested | ms.NODEV | ms.STRICTATIME },
        .{ .statfs = 8, .expected = requested | ms.NOEXEC | ms.STRICTATIME },
        .{ .statfs = 1024, .expected = requested | ms.NOATIME },
        .{ .statfs = 2048, .expected = requested | ms.NODIRATIME | ms.STRICTATIME },
        .{ .statfs = 4096, .expected = requested | ms.RELATIME },
        .{ .statfs = 2 | 4 | 8 | 1024 | 2048 | 4096, .expected = requested | ms.NOSUID | ms.NODEV | ms.NOEXEC | ms.NOATIME | ms.NODIRATIME | ms.RELATIME },
        .{ .statfs = 1 | 16 | 32 | 64 | 128 | 256 | 512 | 8192, .expected = requested | ms.STRICTATIME },
    };
    for (cases) |case|
        try std.testing.expectEqual(case.expected, try lockedMountFlags(requested, case.statfs));
    try std.testing.expectEqual(ms.NOEXEC | ms.NOSUID | ms.STRICTATIME, try lockedMountFlags(ms.NOEXEC, 2));
    try std.testing.expectEqual(ms.RDONLY | ms.RELATIME, try lockedMountFlags(0, 1 | 4096));
}

test "locked atime modes are inherited only when absent and conflicts are rejected" {
    const ms = linux.MS;
    try std.testing.expectEqual(@as(u32, ms.RELATIME), try lockedMountFlags(ms.RELATIME, 4096));
    try std.testing.expectEqual(@as(u32, ms.NOATIME), try lockedMountFlags(ms.NOATIME, 1024));
    try std.testing.expectEqual(@as(u32, ms.STRICTATIME), try lockedMountFlags(ms.STRICTATIME, 0));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.STRICTATIME, 4096));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.RELATIME, 1024));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.NOATIME, 0));
}

/// Legacy cgroup mounts are expanded during parent-side mount preparation.
pub fn cgroupMountType(mount_type: []const u8, host_fs_type: usize) Backend.Error![]const u8 {
    if (!std.mem.eql(u8, mount_type, "cgroup") and !std.mem.eql(u8, mount_type, "cgroup2")) return mount_type;
    if (host_fs_type != 0x63677270) {
        if (std.mem.eql(u8, mount_type, "cgroup2")) {
            reportDiagnostic("cannot mount cgroup2 on a cgroup v1 host", .{});
            return error.Unsupported;
        }
        return "cgroup";
    }
    return "cgroup2";
}

/// Strings and symlinks are owned by the caller's preparation arena.
fn prepareMounts(allocator: std.mem.Allocator, mounts: []const Backend.Mount, host_fs_type: usize, hierarchies: []const V1Hierarchy, cgroup_path: []const u8) Backend.Error![]PreparedMount {
    var prepared: std.ArrayList(PreparedMount) = .empty;
    defer prepared.deinit(allocator);
    for (mounts) |mount| {
        if (!std.mem.startsWith(u8, mount.destination, "/")) return error.InvalidPath;
        var mount_type = mount.type;
        if (mount_type != null and mount.flags & linux.MS.BIND == 0)
            mount_type = try cgroupMountType(mount_type.?, host_fs_type);
        if (mount_type != null and std.mem.eql(u8, mount_type.?, "cgroup") and mount.flags & linux.MS.BIND == 0) {
            const destination = try pathString(allocator, mount.destination);
            try prepared.append(allocator, .{
                .destination = destination,
                .source = "tmpfs",
                .type = "tmpfs",
                .flags = mount.flags & ~@as(u32, linux.MS.RDONLY),
                .propagation = mount.propagation,
                .data = "mode=755",
            });
            var symlinks: std.ArrayList(Backend.Symlink) = .empty;
            defer symlinks.deinit(allocator);
            // ponytail: named hierarchies (name=systemd) are not exposed;
            // discover and join them too if applications need that membership.
            // ponytail: bind the leaf even with a cgroup namespace; runc mounts
            // cgroupfs with subsystem options there. Use that if needed.
            for (hierarchies) |hierarchy| {
                const basename = std.fs.path.basename(hierarchy.mountpoint);
                try prepared.append(allocator, .{
                    .destination = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ destination, basename }, 0),
                    .source = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ hierarchy.mountpoint, cgroup_path }, 0),
                    .type = null,
                    .flags = mount.flags | linux.MS.BIND,
                    .propagation = 0,
                    .data = "",
                    .recursive_readonly = mount.recursive_readonly,
                });
                if (std.mem.indexOfScalar(u8, basename, ',') != null) {
                    var names = std.mem.tokenizeScalar(u8, basename, ',');
                    while (names.next()) |name| try symlinks.append(allocator, .{
                        .path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ destination, name }, 0),
                        .target = try allocator.dupeZ(u8, basename),
                    });
                }
            }
            // Finish links after all bind targets exist, preserving any names
            // already present, then make only the covering tmpfs readonly.
            prepared.items[prepared.items.len - 1].symlinks = try symlinks.toOwnedSlice(allocator);
            if (mount.flags & linux.MS.RDONLY != 0) try prepared.append(allocator, .{
                .destination = destination,
                .source = null,
                .type = null,
                .flags = mount.flags | linux.MS.REMOUNT,
                .propagation = 0,
                .data = "",
            });
            continue;
        }
        try prepared.append(allocator, .{
            .destination = try pathString(allocator, mount.destination),
            .source = if (mount.source) |source| try pathString(allocator, source) else null,
            .type = if (mount_type) |value| try pathString(allocator, value) else null,
            .flags = mount.flags,
            .propagation = mount.propagation,
            .data = try pathString(allocator, mount.data),
            .recursive_readonly = mount.recursive_readonly,
        });
    }
    return prepared.toOwnedSlice(allocator);
}

test "cgroup mounts map to cgroup2 only on unified hosts" {
    defer last_diagnostic_len = 0;
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup", 0x63677270));
    for ([_]usize{ 0x01021994, 0x27e0eb, 0 }) |host_fs_type| {
        try std.testing.expectEqualStrings("cgroup", try cgroupMountType("cgroup", host_fs_type));
    }
    try std.testing.expectEqualStrings("tmpfs", try cgroupMountType("tmpfs", 0x01021994));
    try std.testing.expectError(error.Unsupported, cgroupMountType("cgroup2", 0x01021994));
    try std.testing.expect(std.mem.indexOf(u8, last_diagnostic[0..last_diagnostic_len], "cgroup2") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_diagnostic[0..last_diagnostic_len], "v1") != null);
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup2", 0x63677270));
}

test "v1 cgroup mount expansion binds leaves and links comounted controllers before readonly remount" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const hierarchies = try v1Hierarchies(allocator,
        \\1 0 0:1 / /sys/fs/cgroup rw - tmpfs tmpfs rw
        \\2 1 0:2 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
        \\3 1 0:3 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
        \\4 1 0:4 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd
        \\5 1 0:5 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw
    );
    const restrictions = linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV;
    for ([_]bool{ false, true }) |readonly| {
        const flags = restrictions | @as(u32, if (readonly) linux.MS.RDONLY else 0);
        const mounts = try prepareMounts(allocator, &.{.{
            .destination = "/custom/cgroups",
            .source = "cgroup",
            .type = "cgroup",
            .flags = flags,
            .propagation = linux.MS.PRIVATE,
            .data = "",
        }}, 0x01021994, hierarchies, "igvano/example");
        try std.testing.expectEqual(@as(usize, if (readonly) 4 else 3), mounts.len);
        try std.testing.expectEqualStrings("/custom/cgroups", mounts[0].destination);
        try std.testing.expectEqualStrings("tmpfs", mounts[0].type.?);
        try std.testing.expectEqualStrings("mode=755", mounts[0].data);
        try std.testing.expectEqual(restrictions, mounts[0].flags);
        try std.testing.expectEqual(@as(u32, linux.MS.PRIVATE), mounts[0].propagation);
        for ([_]struct { source: []const u8, destination: []const u8 }{
            .{ .source = "/sys/fs/cgroup/cpu,cpuacct/igvano/example", .destination = "/custom/cgroups/cpu,cpuacct" },
            .{ .source = "/sys/fs/cgroup/memory/igvano/example", .destination = "/custom/cgroups/memory" },
        }, mounts[1..3]) |expected, mount| {
            try std.testing.expectEqualStrings(expected.source, mount.source.?);
            try std.testing.expectEqualStrings(expected.destination, mount.destination);
            try std.testing.expectEqual(flags | linux.MS.BIND, mount.flags);
            try std.testing.expect(mount.type == null);
        }
        const links = mounts[2].symlinks;
        try std.testing.expectEqual(@as(usize, 2), links.len);
        try std.testing.expectEqualStrings("/custom/cgroups/cpu", links[0].path);
        try std.testing.expectEqualStrings("/custom/cgroups/cpuacct", links[1].path);
        for (links) |link| try std.testing.expectEqualStrings("cpu,cpuacct", link.target);
        if (readonly) {
            try std.testing.expectEqualStrings("/custom/cgroups", mounts[3].destination);
            try std.testing.expectEqual(flags | linux.MS.REMOUNT, mounts[3].flags);
            try std.testing.expect(mounts[3].source == null and mounts[3].type == null);
        }
    }
}

fn needsSetupDev(mounts: anytype) bool {
    var setup = true;
    for (mounts) |mount| {
        if (std.mem.eql(u8, mount.destination, "/dev"))
            setup = mount.flags & linux.MS.BIND == 0;
    }
    return setup;
}

fn validateDeviceMounts(mounts: []const Backend.Mount, devices: []const Backend.Device) Backend.Error!void {
    if (needsSetupDev(mounts)) return;
    for (devices) |device| {
        if (device.required) return error.Unsupported;
    }
}

test "bind-mounted dev skips defaults and rejects explicit devices" {
    const bind: Backend.Mount = .{ .destination = "/dev", .source = "/dev", .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" };
    const tmpfs: Backend.Mount = .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" };
    const cases = [_]struct { mounts: []const Backend.Mount, setup: bool }{
        .{ .mounts = &.{}, .setup = true },
        .{ .mounts = &.{bind}, .setup = false },
        .{ .mounts = &.{ tmpfs, bind }, .setup = false },
        .{ .mounts = &.{ bind, tmpfs }, .setup = true },
    };
    const defaults = [_]Backend.Device{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3, .required = false }};
    for (cases) |case| {
        try std.testing.expectEqual(case.setup, needsSetupDev(case.mounts));
        try validateDeviceMounts(case.mounts, &defaults);
        const explicit = [_]Backend.Device{.{ .path = "/dev/custom", .kind = .fifo }};
        if (case.setup)
            try validateDeviceMounts(case.mounts, &explicit)
        else
            try std.testing.expectError(error.Unsupported, validateDeviceMounts(case.mounts, &explicit));
    }
}

fn namespaceFlag(kind: @FieldType(oci.Spec.Namespace, "type")) usize {
    return switch (kind) {
        .pid => linux.CLONE.NEWPID,
        .network => linux.CLONE.NEWNET,
        .mount => linux.CLONE.NEWNS,
        .ipc => linux.CLONE.NEWIPC,
        .uts => linux.CLONE.NEWUTS,
        .user => linux.CLONE.NEWUSER,
        .cgroup => linux.CLONE.NEWCGROUP,
        .time => linux.CLONE.NEWTIME,
    };
}

/// Only namespaces without paths are unshared. Constants work on macOS too.
pub fn namespaceFlags(config: ?oci.Spec.Linux) Backend.Error!usize {
    const settings = config orelse return 0;
    const namespaces = settings.namespaces orelse return 0;
    var flags: usize = 0;
    var seen: usize = 0;
    for (namespaces) |namespace| {
        const flag = namespaceFlag(namespace.type);
        if (seen & flag != 0) return error.InvalidConfig;
        seen |= flag;
        if (namespace.path) |path| {
            if (!std.mem.startsWith(u8, path, "/") or std.mem.indexOfScalar(u8, path, 0) != null)
                return error.InvalidPath;
        } else flags |= flag;
    }
    return flags;
}

const NamespaceJoin = struct {
    flag: usize,
    path: [:0]const u8,
};

fn validateNamespaceFd(fd: posix.fd_t, flag: usize) Backend.Error!void {
    const result = linux.ioctl(fd, linux.IOCTL.IO(0xb7, 3), 0); // NS_GET_NSTYPE
    switch (linux.errno(result)) {
        .SUCCESS => if (result != flag) return error.InvalidConfig,
        // Old kernels lack NS_GET_NSTYPE; trust the configured type. setns
        // still validates that the descriptor refers to a namespace.
        .NOTTY => {},
        else => try checkResult(result),
    }
}

/// Open every host path before entering a user or mount namespace.
fn joinNamespaces(joins: []const NamespaceJoin) Backend.Error!void {
    var fds: [8]posix.fd_t = @splat(-1);
    if (joins.len > fds.len) return error.InvalidConfig;
    defer for (fds) |fd| {
        if (fd >= 0) closeFd(fd);
    };
    for (joins, 0..) |join, i| {
        fds[i] = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        try validateNamespaceFd(fds[i], join.flag);
    }
    try joinNamespaceFds(joins, fds[0..joins.len]);
}

fn joinNamespaceFds(joins: []const NamespaceJoin, fds: []const posix.fd_t) Backend.Error!void {
    // User first grants capabilities in the target owner; mount last keeps
    // host paths reachable until all other namespace operations have finished.
    for ([_]usize{
        linux.CLONE.NEWUSER, linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC,
        linux.CLONE.NEWUTS,  linux.CLONE.NEWNET,    linux.CLONE.NEWPID,
        linux.CLONE.NEWTIME, linux.CLONE.NEWNS,
    }) |flag| {
        for (joins, 0..) |join, i| {
            if (join.flag == flag and fds[i] >= 0) {
                checkResult(linux.setns(fds[i], @intCast(flag))) catch |err| {
                    reportDiagnostic("cannot join namespace {s}: {s}", .{ join.path, @errorName(err) });
                    return err;
                };
            }
        }
    }
}

pub const LinuxBackend = struct {
    pub fn backend(self: *LinuxBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .create = create,
        .exec = exec,
        .alive = alive,
        .kill = kill,
        .killAll = killAll,
        .update = update,
        .pids = pids,
        .freeze = freeze,
        .thaw = thaw,
        .frozen = frozen,
        .delete = delete,
        .diagnostic = diagnostic,
    };

    fn diagnostic(_: *anyopaque) ?[]const u8 {
        return if (last_diagnostic_len == 0) null else last_diagnostic[0..last_diagnostic_len];
    }

    fn exec(ptr: *anyopaque, handle: Backend.Handle, options: Backend.ExecOptions) Backend.Error!i32 {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        if (!try alive(ptr, handle)) return error.ProcessNotFound;
        if (options.argv.len == 0 or options.argv[0].len == 0 or !std.fs.path.isAbsolute(options.cwd))
            return error.InvalidProcess;
        try validateCgroupPath(options.cgroup_path);
        var arena: std.heap.ArenaAllocator = .init(options.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const seccomp_program = if (options.seccomp) |config|
            seccomp.compile(allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
                return error.InvalidConfig;
            }
        else
            null;
        const cwd = try pathString(allocator, options.cwd);
        const argv = try allocator.allocSentinel(?[*:0]const u8, options.argv.len, null);
        for (options.argv, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
        const envp = try allocator.allocSentinel(?[*:0]const u8, options.envp.len, null);
        for (options.envp, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;
        const process: ProcessSettings = .{
            .uid = options.uid,
            .gid = options.gid,
            .additional_gids = options.additional_gids,
            .no_new_privileges = options.no_new_privileges,
            .capabilities = if (options.capabilities) |caps| try kernelCapabilities(caps) else null,
            .rlimits = options.rlimits,
        };
        if (process.capabilities) |caps| {
            if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
                return error.AmbientCapabilitiesRequirePermittedAndInheritable;
        }
        for (options.rlimits) |limit| if (limit.soft > limit.hard) return error.InvalidConfig;

        const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(proc_dir);
        const root_path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/root", .{handle.pid}, 0);
        const root = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root);
        const cgroup_root = try openCgroupRoot();
        defer closeFd(cgroup_root.fd);
        const cgroup: ?posix.fd_t = if (cgroup_root.mode == .unified)
            (try walkCgroup(cgroup_root.fd, options.cgroup_path, false, &.{})) orelse return error.ProcessNotFound
        else
            null;
        defer if (cgroup) |fd| closeFd(fd);
        const hierarchies: []V1Hierarchy = if (cgroup_root.mode == .legacy) try openV1Hierarchies(allocator) else &.{};
        defer if (cgroup_root.mode == .legacy) freeV1Hierarchies(allocator, hierarchies);
        for (hierarchies) |*hierarchy|
            hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, options.cgroup_path, false, false)) orelse return error.ProcessNotFound;

        var joins: [8]NamespaceJoin = undefined;
        var ns_fds: [8]posix.fd_t = @splat(-1);
        defer for (ns_fds) |fd| if (fd >= 0) closeFd(fd);
        const names = [_][]const u8{ "user", "cgroup", "ipc", "uts", "net", "pid", "mnt", "time" };
        const flags = [_]usize{
            linux.CLONE.NEWUSER, linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC, linux.CLONE.NEWUTS,
            linux.CLONE.NEWNET,  linux.CLONE.NEWPID,    linux.CLONE.NEWNS,  linux.CLONE.NEWTIME,
        };
        for (names, flags, 0..) |name, flag, i| {
            const path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/ns/{s}", .{ handle.pid, name }, 0);
            joins[i] = .{ .flag = flag, .path = path };
            const opened = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            if (std.mem.eql(u8, name, "time") and linux.errno(opened) == .NOENT) continue;
            try checkResult(opened);
            ns_fds[i] = @intCast(opened);
            try validateNamespaceFd(ns_fds[i], flag);
        }
        // Recheck after pinning root and namespaces, before entering any of them.
        if (!try alive(ptr, handle)) return error.ProcessNotFound;
        const report = try makePipe();
        defer closeFd(report[0]);
        var report_writer: ?posix.fd_t = report[1];
        defer if (report_writer) |fd| closeFd(fd);
        const ready = try makePipe();
        var owns_ready = true;
        defer if (owns_ready) for (ready) |fd| closeFd(fd);
        const helper = try forkProcess();
        if (helper == 0) {
            // Hide the host runtime and its descriptors from container ptrace/procfs.
            checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(report[1], err);
            closeFd(report[0]);
            if (options.console_fds) |fds| closeFd(fds[0]);
            // Membership must be established while still in the host cgroup
            // namespace; the grandchild inherits it across the second fork.
            if (cgroup) |fd| {
                writeCgroupFile(fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
            }
            for (hierarchies) |hierarchy|
                writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
            for (names, 0..) |name, i| {
                if (ns_fds[i] < 0) continue;
                var buffer: [64]u8 = undefined;
                const own_path = std.fmt.bufPrintZ(&buffer, "self/ns/{s}", .{name}) catch unreachable;
                const own = openPath(proc_dir, own_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch |err| failCreate(report[1], err);
                var own_stat: linux.Statx = undefined;
                var target_stat: linux.Statx = undefined;
                checkResult(linux.statx(own, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &own_stat)) catch |err| failCreate(report[1], err);
                checkResult(linux.statx(ns_fds[i], "", linux.AT.EMPTY_PATH, .{ .INO = true }, &target_stat)) catch |err| failCreate(report[1], err);
                closeFd(own);
                if (!own_stat.mask.INO or !target_stat.mask.INO) failCreate(report[1], error.CreateFailed);
                // In particular, setns into the current user namespace is EINVAL.
                if (own_stat.dev_major == target_stat.dev_major and own_stat.dev_minor == target_stat.dev_minor and own_stat.ino == target_stat.ino) {
                    closeFd(ns_fds[i]);
                    ns_fds[i] = -1;
                }
            }
            var stat_buffer: [4096]u8 = undefined;
            const stat = readProcStatAt(proc_dir, handle.pid, &stat_buffer) catch |err| failCreate(report[1], err);
            if (!stat.matches(handle.starttime)) failCreate(report[1], error.ProcessNotFound);
            // Negative adjustments require CAP_SYS_RESOURCE in the initial user
            // namespace. Set it here; the grandchild inherits it across fork.
            applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
            joinNamespaceFds(&joins, &ns_fds) catch |err| failCreate(report[1], err);
            const child = forkProcess() catch |err| failCreate(report[1], err);
            if (child == 0) {
                closeFd(report[1]);
                closeFd(ready[0]);
                // setns(mnt) changes mount visibility, not our inherited root
                // and cwd. Use init's pinned root from the joined mount tree;
                // fchdir + chroot(".") avoids resolving a host PID in container /proc.
                checkResult(linux.fchdir(root)) catch |err| failCreate(ready[1], err);
                checkResult(linux.chroot(".")) catch |err| failCreate(ready[1], err);
                // Actually close host directories before cwd can follow /proc/self/fd.
                // Keep only stdio, the CLOEXEC sync pipe and optional console socket.
                const console_fd = if (options.console_fds) |fds| fds[1] else ready[1];
                var next_fd: u32 = 3;
                for ([_]posix.fd_t{ @min(ready[1], console_fd), @max(ready[1], console_fd) }) |fd| {
                    const keep_fd: u32 = @intCast(fd);
                    if (keep_fd < next_fd) continue;
                    if (next_fd < keep_fd)
                        checkResult(linux.syscall3(.close_range, next_fd, keep_fd - 1, 0)) catch |err| failCreate(ready[1], err);
                    next_fd = keep_fd + 1;
                }
                checkResult(linux.syscall3(.close_range, next_fd, std.math.maxInt(u32), 0)) catch |err| failCreate(ready[1], err);
                checkResult(linux.chdir(cwd)) catch |err| {
                    childError("cannot change exec cwd: ", err);
                    failCreate(ready[1], err);
                };
                var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const cwd_len = linux.getcwd(&cwd_buffer, cwd_buffer.len);
                checkResult(cwd_len) catch |err| {
                    childError("cannot verify exec cwd: ", err);
                    failCreate(ready[1], err);
                };
                if (std.mem.startsWith(u8, cwd_buffer[0..cwd_len], "(unreachable)")) {
                    childError("exec cwd is outside the container root: ", error.InvalidPath);
                    failCreate(ready[1], error.InvalidPath);
                }
                // Exec shares init's mount namespace; preserve its /dev/console.
                if (options.console_fds) |fds| setupConsole(fds[1], false) catch |err| {
                    childError("cannot set up exec console: ", err);
                    failCreate(ready[1], err);
                };
                // Retain CAP_SYS_ADMIN for installation when NNP is false,
                // matching init's ordering before dropping process privileges.
                if (!process.no_new_privileges) {
                    if (seccomp_program) |program|
                        installSeccomp(program) catch |err| failCreate(ready[1], err);
                }
                applyProcessSettings(process) catch |err| {
                    childError("cannot apply exec process settings: ", err);
                    failCreate(ready[1], err);
                };
                var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const executable = resolveExecutable(argv.ptr, envp.ptr, &executable_buffer) catch
                    failCreate(ready[1], error.CreateFailed);
                checkResult(linux.syscall3(.close_range, 3, std.math.maxInt(u32), 1 << 2)) catch |err| failCreate(ready[1], err);
                if (process.no_new_privileges) {
                    if (seccomp_program) |program|
                        installSeccomp(program) catch |err| failCreate(ready[1], err);
                }
                execResolved(executable, argv.ptr, envp.ptr) catch {
                    failCreate(ready[1], error.CreateFailed);
                };
            }
            closeFd(ready[1]);
            // EOF closes the grandchild's CLOEXEC writer, on exec or death.
            waitExecReady(ready[0]) catch |err| {
                _ = linux.kill(child, .KILL);
                _ = waitChild(child) catch {};
                failCreate(report[1], err);
            };
            // Leave even an already-exited child for the frontend or shim to reap.
            var response: CreateResponse = .{ .pid = child };
            if (!writeAll(report[1], std.mem.asBytes(&response))) {
                _ = linux.kill(child, .KILL);
                _ = waitChild(child) catch {};
                linux.exit_group(1);
            }
            // Adoption is by the nearest subreaper: the shim for detached exec,
            // or the frontend (which enables subreaping) for an attached exec.
            linux.exit_group(0);
        }
        for (ready) |fd| closeFd(fd);
        owns_ready = false;
        closeFd(report_writer.?);
        report_writer = null;
        var response: CreateResponse = .{};
        const reported = readAll(report[0], std.mem.asBytes(&response));
        const status = try waitChild(helper);
        if (!reported) return error.CreateFailed;
        if (response.failureError()) |err| return err;
        if (status != 0 or response.pid <= 0) return error.CreateFailed;
        return response.pid;
    }

    fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag == .linux) {
            const flags = try namespaceFlags(options.spec.linux);
            var isolation_flags = flags;
            for (if (options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace|
                isolation_flags |= namespaceFlag(namespace.type);
            const private_mount_namespace = isolation_flags & linux.CLONE.NEWNS != 0;
            if (!private_mount_namespace and options.rootfs_propagation != null) {
                reportDiagnostic("cannot change propagation without a private mount namespace", .{});
                return error.InvalidConfig;
            }
            if (options.spec.hostname != null and isolation_flags & linux.CLONE.NEWUTS == 0)
                return error.InvalidConfig;
            if (options.spec.process) |process| {
                if (process.args.len == 0) return error.InvalidProcess;
            }
            const terminal = if (options.spec.process) |process| process.terminal orelse false else false;
            if (terminal != (options.console_fds != null)) return error.InvalidConfig;
            if (options.capabilities) |caps| {
                if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
                    return error.AmbientCapabilitiesRequirePermittedAndInheritable;
            }
            const capabilities = if (options.capabilities) |caps| try kernelCapabilities(caps) else null;
            for (options.rlimits) |limit| {
                if (limit.soft > limit.hard) return error.InvalidConfig;
            }
            try validateDeviceMounts(options.mounts, options.devices);
            if (!std.fs.path.isAbsolute(options.exec_fifo) or
                std.mem.indexOfScalar(u8, options.exec_fifo, 0) != null)
                return error.InvalidPath;

            // Prepare the init's strings before either fork.
            var arena: std.heap.ArenaAllocator = .init(options.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            const seccomp_program = if (options.seccomp) |config|
                seccomp.compile(allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
                    return error.InvalidConfig;
                }
            else
                null;
            var joins: std.ArrayList(NamespaceJoin) = .empty;
            for (if (options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace| {
                if (namespace.path) |path| try joins.append(allocator, .{
                    .flag = namespaceFlag(namespace.type),
                    .path = try pathString(allocator, path),
                });
            }
            // Safety guard: rootfs setup in our mount namespace would mutate host mounts.
            for (joins.items) |join| {
                if (join.flag != linux.CLONE.NEWNS) continue;
                const own_fd = try openPath(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
                defer closeFd(own_fd);
                const target_fd = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
                defer closeFd(target_fd);
                try validateNamespaceFd(target_fd, join.flag);
                var own_stat: linux.Statx = undefined;
                var target_stat: linux.Statx = undefined;
                try checkResult(linux.statx(own_fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &own_stat));
                try checkResult(linux.statx(target_fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &target_stat));
                if (!own_stat.mask.INO or !target_stat.mask.INO) return error.CreateFailed;
                if (own_stat.dev_major == target_stat.dev_major and
                    own_stat.dev_minor == target_stat.dev_minor and own_stat.ino == target_stat.ino)
                {
                    reportDiagnostic("cannot join the runtime's own mount namespace", .{});
                    return error.InvalidConfig;
                }
            }
            const user_namespace = flags & linux.CLONE.NEWUSER != 0;
            const joined_user_namespace = !user_namespace and isolation_flags & linux.CLONE.NEWUSER != 0;
            // Library callers bypass frontend validation, so mapping-presence checks are intentional.
            const uid_mappings = if (user_namespace) options.spec.linux.?.uidMappings orelse return error.InvalidConfig else &.{};
            const gid_mappings = if (user_namespace) options.spec.linux.?.gidMappings orelse return error.InvalidConfig else &.{};
            if (user_namespace and (uid_mappings.len == 0 or gid_mappings.len == 0)) return error.InvalidConfig;
            const fifo_uid = if (user_namespace) try mappedRootID(uid_mappings) else 0;
            const fifo_gid = if (user_namespace) try mappedRootID(gid_mappings) else 0;
            const uid_map = try formatIDMappings(allocator, uid_mappings);
            const gid_map = try formatIDMappings(allocator, gid_mappings);
            const fifo = try allocator.dupeZ(u8, options.exec_fifo);
            const rootfs = try processString(allocator, options.rootfs);
            const cwd = try processString(allocator, if (options.spec.process) |process| process.cwd else "/");
            if (!std.fs.path.isAbsolute(cwd)) return error.InvalidProcess;
            if (!std.fs.path.isAbsolute(rootfs)) return error.InvalidPath;
            var rootfs_mount_before: ?u64 = null;
            var rootfs_mount_boot_id: ?[36]u8 = null;
            if (!private_mount_namespace) {
                const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
                defer closeFd(root_fd);
                var fd_buffer: [64]u8 = undefined;
                var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const size = linux.readlink(fdPath(&fd_buffer, root_fd), &resolved_buffer, resolved_buffer.len);
                try checkResult(size);
                if (size == 1 and resolved_buffer[0] == '/') {
                    reportDiagnostic("cannot use / as rootfs without a private mount namespace", .{});
                    return error.InvalidConfig;
                }
                rootfs_mount_before = mountId(root_fd) catch |err| {
                    if (err == error.Unsupported)
                        reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
                    return err;
                };
                // Probe both APIs before creating any mounts.
                _ = (statMount(rootfs_mount_before.?) catch |err| {
                    if (err == error.Unsupported)
                        reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
                    return err;
                }) orelse return error.CreateFailed;
                rootfs_mount_boot_id = try bootId();
            }
            try validateCgroupPath(options.cgroup_path);
            // Joined user namespaces may map root to a different host UID.
            // Only the outside parent can chmod this host-owned FIFO. Readers
            // remain root-only, as when init drops to a nonzero process UID.
            if (joined_user_namespace) try checkResult(linux.fchmodat(linux.AT.FDCWD, fifo, 0o622));
            const cgroup_root = try openCgroupRoot();
            defer closeFd(cgroup_root.fd);
            const hierarchies: []V1Hierarchy = if (cgroup_root.mode == .legacy) try openV1Hierarchies(allocator) else &.{};
            defer if (cgroup_root.mode == .legacy) freeV1Hierarchies(allocator, hierarchies);
            const mounts = try prepareMounts(allocator, options.mounts, cgroup_root.fs_type, hierarchies, options.cgroup_path);
            const devices = try allocator.alloc(PreparedDevice, options.devices.len);
            for (options.devices, devices) |device, *prepared| {
                if (!std.mem.startsWith(u8, device.path, "/") or
                    device.major > 0xfff or device.minor > 0xfffff or
                    device.mode & ~@as(u32, 0o7777) != 0)
                    return error.InvalidConfig;
                prepared.* = .{
                    .path = try pathString(allocator, device.path),
                    .mode = device.mode | @as(u32, switch (device.kind) {
                        .character => linux.S.IFCHR,
                        .block => linux.S.IFBLK,
                        .fifo => linux.S.IFIFO,
                    }),
                    .dev = (device.major << 8) | (device.minor & 0xff) | ((device.minor & 0xfff00) << 12),
                    .uid = device.uid,
                    .gid = device.gid,
                };
            }
            const args: []const []const u8 = if (options.spec.process) |process| process.args else &.{};
            const env: []const []const u8 = if (options.spec.process) |process| process.env orelse &.{} else &.{};
            const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);
            for (args, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
            const envp = try allocator.allocSentinel(?[*:0]const u8, env.len, null);
            for (env, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;
            const create_hooks = try hooks.prepare(allocator, options.create_hooks);
            const start_hooks = try hooks.prepare(allocator, options.start_hooks);
            const create_state = try allocator.alloc(u8, options.create_hook_state.prefix.len + 20 + options.create_hook_state.suffix.len);
            const start_state = try allocator.alloc(u8, options.start_hook_state.prefix.len + 20 + options.start_hook_state.suffix.len);
            const masked_paths = try preparePaths(allocator, options.masked_paths);
            const readonly_paths = try preparePaths(allocator, options.readonly_paths);
            const cgroup_writes: []const Write = if (cgroup_root.mode == .unified) try v2Writes(allocator, options.resources) else &.{};
            defer if (cgroup_root.mode == .unified) freeWrites(allocator, cgroup_writes);
            if (cgroup_root.mode == .legacy and options.resources.unified.len != 0) {
                reportDiagnostic("unified resources require cgroup v2", .{});
                return error.InvalidConfig;
            }
            const v1_writes: []const V1Write = if (cgroup_root.mode == .legacy) try v1Writes(allocator, options.resources, options.devices) else &.{};
            defer if (cgroup_root.mode == .legacy) freeV1Writes(allocator, v1_writes);
            const ignored_fields = if (cgroup_root.mode == .unified) try v2IgnoredFields(allocator, options.resources) else try allocator.dupe(u8, "");
            defer allocator.free(ignored_fields);
            if (ignored_fields.len != 0)
                std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ignored_fields});

            // pivot_root also changes child1's root while it waits in the same
            // mount namespace. Pin host /proc so it can still capture identity.
            const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
            defer closeFd(proc_dir);
            // Init must retain the host FIFO across namespace changes without
            // traversing the private state directory as a mapped user.
            const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
            defer closeFd(fifo_fd);
            const cgroup: ?posix.fd_t = if (cgroup_root.mode == .unified) (try walkCgroup(cgroup_root.fd, options.cgroup_path, true, cgroup_writes)).? else null;
            defer if (cgroup) |fd| closeFd(fd);
            var rootfs_mount_id: ?u64 = null;
            errdefer {
                const saved_diagnostic = last_diagnostic;
                const saved_len = last_diagnostic_len;
                defer {
                    last_diagnostic = saved_diagnostic;
                    last_diagnostic_len = saved_len;
                }
                // Child1 can die before reporting child2's PID. Kill the entire
                // cgroup before removing it, including any blocked init.
                if (cgroup) |fd| {
                    writeCgroupFile(fd, "cgroup.kill", "1", options.cgroup_path) catch {};
                    removeCreatedCgroup(cgroup_root.fd, options.cgroup_path, fd) catch {};
                } else {
                    removeV1Cgroups(hierarchies, options.cgroup_path) catch {};
                }
                if (rootfs_mount_before) |before| detachRootfs(rootfs, if (rootfs_mount_id) |id|
                    .{ .created = id }
                else
                    .{ .before_create = before }) catch {};
            }
            // Create every bind source before either fork; child1 joins these
            // leaves before NEWCGROUP, and child2 mounts them during rootfs setup.
            for (hierarchies) |*hierarchy|
                hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, options.cgroup_path, true, hierarchy.has("cpuset"))).?;
            for (cgroup_writes) |write|
                try writeCgroupFile(cgroup.?, write.name, write.value, options.cgroup_path);
            if (cgroup_root.mode == .legacy)
                try applyV1Writes(allocator, hierarchies, v1_writes, options.resources, options.devices, options.cgroup_path);
            // getpid() in child2 may be 1. Child1 supplies its host PID for
            // opaque hook input; buffers and JSON fragments were prepared above.
            const pid_pipe = try makePipe();
            var owns_pid_pipe = true;
            defer if (owns_pid_pipe) {
                for (pid_pipe) |fd| closeFd(fd);
            };
            const report = try makePipe();
            const ready = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                return err;
            };
            const create_go = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                return err;
            };
            var owns_create_go = true;
            defer if (owns_create_go) {
                for (create_go) |fd| closeFd(fd);
            };
            const map_pipe = if (user_namespace) makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                return err;
            } else null;
            const child1 = forkProcess() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                if (map_pipe) |fds| for (fds) |fd| closeFd(fd);
                return err;
            };
            if (child1 == 0) {
                checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(report[1], err);
                if (options.console_fds) |fds| closeFd(fds[0]);
                closeFd(create_go[1]);
                if (map_pipe) |fds| closeFd(fds[1]);
                closeFd(cgroup_root.fd);
                closeFd(report[0]);
                // Join before NEWCGROUP snapshots the namespace root. Child2
                // inherits this membership; the runtime parent stays outside.
                if (cgroup) |fd| {
                    writeCgroupFile(fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                    closeFd(fd);
                } else for (hierarchies) |hierarchy| {
                    writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                    closeFd(hierarchy.leaf.?);
                    closeFd(hierarchy.root.?);
                }
                // Set with host privileges before entering user namespaces.
                // Child2 inherits the adjustment across fork and exec.
                applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
                joinNamespaces(joins.items) catch |err| failCreate(report[1], err);
                // NEWUSER is unshared together with the others so it owns them.
                if (flags != 0) checkResult(linux.unshare(flags)) catch |err| failCreate(report[1], err);
                // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
                const child2 = forkProcess() catch |err| failCreate(report[1], err);
                if (child2 == 0) {
                    closeFd(pid_pipe[1]);
                    var host_pid: i32 = undefined;
                    if (!readAll(pid_pipe[0], std.mem.asBytes(&host_pid))) linux.exit_group(1);
                    closeFd(pid_pipe[0]);
                    // Let the parent see report EOF if child1 dies during the map wait.
                    closeFd(report[1]);
                    closeFd(ready[0]);
                    // Host procfs resolves "self" to child2's host PID, even
                    // when a joined mount namespace supplies a different /proc.
                    const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
                    closeFd(proc_dir);
                    // The outside parent must install our ID maps
                    // before any rootfs, mount, hostname, or process work.
                    if (map_pipe) |fds| {
                        var byte: [1]u8 = undefined;
                        if (!readAll(fds[0], &byte)) linux.exit_group(1);
                        closeFd(fds[0]);
                    }
                    if (isolation_flags & linux.CLONE.NEWUSER != 0) {
                        // Like runc nsexec stage-2, become root in the user ns.
                        // Unmapped host-root fsuid/fsgid make may_create() fail
                        // with EOVERFLOW on filesystems mounted in this ns.
                        checkResult(linux.setgid(0)) catch linux.exit_group(1);
                        checkResult(linux.setuid(0)) catch linux.exit_group(1);
                    }
                    const create_input = std.fmt.bufPrint(create_state, "{s}{d}{s}", .{
                        options.create_hook_state.prefix, host_pid, options.create_hook_state.suffix,
                    }) catch linux.exit_group(1);
                    const start_input = std.fmt.bufPrint(start_state, "{s}{d}{s}", .{
                        options.start_hook_state.prefix, host_pid, options.start_hook_state.suffix,
                    }) catch linux.exit_group(1);
                    runInit(options.spec, capabilities, options.rlimits, isolation_flags, rootfs, mounts, devices, options.device_symlinks, cwd, fifo_fd, fd_dir, argv.ptr, envp.ptr, ready[1], .{
                        .private_mount_namespace = private_mount_namespace,
                        .propagation = options.rootfs_propagation orelse (linux.MS.PRIVATE | linux.MS.REC),
                        .create_hooks = create_hooks,
                        .create_hook_state = create_input,
                        .masked_paths = masked_paths,
                        .readonly_paths = readonly_paths,
                        .sysctls = options.sysctls,
                        .runtime_sync = .{ .ready_fd = ready[1], .go_fd = create_go[0] },
                        .console_fd = if (options.console_fds) |fds| fds[1] else null,
                        .fifo_writable = joined_user_namespace,
                    }, start_hooks, start_input, seccomp_program);
                }
                closeFd(fifo_fd);
                if (options.console_fds) |fds| closeFd(fds[1]);
                closeFd(create_go[0]);
                closeFd(pid_pipe[0]);
                var host_pid = child2;
                if (!writeAll(pid_pipe[1], std.mem.asBytes(&host_pid))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], error.CreateFailed);
                }
                closeFd(pid_pipe[1]);
                if (map_pipe) |fds| {
                    closeFd(fds[0]);
                    var mapping_response: CreateResponse = .{ .pid = child2 };
                    if (!writeAll(report[1], std.mem.asBytes(&mapping_response))) {
                        _ = linux.kill(child2, .KILL);
                        _ = waitChild(child2) catch {};
                        linux.exit_group(1);
                    }
                }
                closeFd(ready[1]);
                if (!private_mount_namespace) {
                    var mount_response: CreateResponse = .{};
                    if (!readAll(ready[0], std.mem.asBytes(&mount_response)) or mount_response.failure != 0) {
                        _ = waitChild(child2) catch {};
                        failCreate(report[1], mount_response.failureError() orelse error.CreateFailed);
                    }
                    if (!writeAll(report[1], std.mem.asBytes(&mount_response))) {
                        _ = linux.kill(child2, .KILL);
                        _ = waitChild(child2) catch {};
                        linux.exit_group(1);
                    }
                }
                var init_response: CreateResponse = .{};
                // Child2 has applied mounts and waits before child hooks/pivot.
                if (!readAll(ready[0], std.mem.asBytes(&init_response)) or init_response.failure != 0) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], init_response.failureError() orelse error.CreateFailed);
                }
                // Capture identity while child2 is still our child, so its PID
                // cannot be recycled even if it has already exited.
                var stat_buffer: [4096]u8 = undefined;
                const stat = readProcStatAt(proc_dir, child2, &stat_buffer) catch |err| {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], err);
                };
                var response: CreateResponse = .{
                    .pid = child2,
                    .starttime = std.fmt.parseInt(u64, stat.starttime, 10) catch unreachable,
                };
                if (!writeAll(report[1], std.mem.asBytes(&response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
                init_response = .{};
                const initialized = readAll(ready[0], std.mem.asBytes(&init_response));
                closeFd(ready[0]);
                if (!initialized or init_response.failure != 0) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], init_response.failureError() orelse error.CreateFailed);
                }
                if (!writeAll(report[1], std.mem.asBytes(&response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
                // No shim: exiting child1 reparents the blocked init to host init.
                linux.exit_group(0);
            }

            // Only child1 writes the PID. Keeping a writer in this parent
            // would strand child2 if child1 died before sending it, preventing
            // report EOF and hanging create.
            for (pid_pipe) |fd| closeFd(fd);
            owns_pid_pipe = false;
            closeFd(report[1]);
            for (ready) |fd| closeFd(fd);
            defer closeFd(report[0]);
            // Keep a reader to prevent SIGPIPE if init exits before release.
            defer closeFd(create_go[0]);
            var create_writer: ?posix.fd_t = create_go[1];
            defer if (create_writer) |fd| closeFd(fd);
            owns_create_go = false;
            // Retain a reader so a dying init cannot SIGPIPE the runtime on go.
            defer if (map_pipe) |fds| closeFd(fds[0]);
            var map_writer: ?posix.fd_t = if (map_pipe) |fds| fds[1] else null;
            // On failure, close before waiting to unblock init; null prevents double close.
            defer if (map_writer) |fd| closeFd(fd);
            var child1_reaped = false;
            errdefer if (!child1_reaped) {
                if (map_writer) |fd| {
                    closeFd(fd);
                    map_writer = null;
                }
                if (create_writer) |fd| {
                    closeFd(fd);
                    create_writer = null;
                }
                _ = waitChild(child1) catch {};
            };
            if (map_writer) |fd| {
                var mapping_response: CreateResponse = .{};
                if (!readAll(report[0], std.mem.asBytes(&mapping_response))) return error.CreateFailed;
                if (mapping_response.failureError()) |err| return err;
                if (mapping_response.pid <= 0) return error.CreateFailed;
                try writeUserMappings(mapping_response.pid, gid_map, uid_map);
                // Init needs ownership as namespace root, even for a non-root process.
                try checkResult(linux.chown(fifo, fifo_uid, fifo_gid));
                if (!writeAll(fd, &.{1})) return error.CreateFailed;
                closeFd(fd);
                map_writer = null;
            }
            if (rootfs_mount_before) |before| {
                var mount_response: CreateResponse = .{};
                if (!readAll(report[0], std.mem.asBytes(&mount_response))) return error.CreateFailed;
                if (mount_response.failureError()) |err| return err;
                if (mount_response.rootfs_mount_id == 0 or mount_response.rootfs_mount_id == before)
                    return error.CreateFailed;
                rootfs_mount_id = mount_response.rootfs_mount_id;
            }
            var response: CreateResponse = .{};
            const reported = readAll(report[0], std.mem.asBytes(&response));
            var starttime_buffer: [20]u8 = undefined;
            const starttime = std.fmt.bufPrint(&starttime_buffer, "{d}", .{response.starttime}) catch unreachable;
            const handle: Backend.Handle = .{
                .id = options.id,
                .pid = response.pid,
                .starttime = starttime,
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = if (private_mount_namespace) null else options.rootfs,
                .rootfs_mount_id = rootfs_mount_id,
                .rootfs_mount_boot_id = rootfs_mount_boot_id,
            };
            errdefer if (reported and handle.pid > 0) {
                const saved_diagnostic = last_diagnostic;
                const saved_len = last_diagnostic_len;
                kill(ptr, handle, 9) catch {};
                last_diagnostic = saved_diagnostic;
                last_diagnostic_len = saved_len;
            };
            if (!reported) return error.CreateFailed;
            if (response.failureError()) |err| return err;
            if (response.pid <= 0) return error.CreateFailed;
            if (options.on_create) |callback| try callback.run(callback.ptr, handle);
            if (!writeAll(create_writer.?, &.{1})) return error.CreateFailed;
            closeFd(create_writer.?);
            create_writer = null;
            response = .{};
            const initialized = readAll(report[0], std.mem.asBytes(&response));
            child1_reaped = true;
            const status = try waitChild(child1);
            if (!initialized) return error.CreateFailed;
            if (response.failureError()) |err| return err;
            if (status != 0 or response.pid <= 0) {
                return error.CreateFailed;
            }
            const owned_starttime = try options.allocator.dupe(u8, starttime);
            errdefer options.allocator.free(owned_starttime);
            return .{
                .id = options.id,
                .pid = response.pid,
                .starttime = owned_starttime,
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = if (private_mount_namespace) null else options.rootfs,
                .rootfs_mount_id = rootfs_mount_id,
                .rootfs_mount_boot_id = rootfs_mount_boot_id,
            };
        } else {
            return error.NotImplemented;
        }
    }

    fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            switch (linux.errno(linux.kill(handle.pid, @enumFromInt(0)))) {
                .SUCCESS, .PERM => {},
                .SRCH => return false,
                else => return error.LivenessFailed,
            }
            var buffer: [4096]u8 = undefined;
            // ponytail: /proc mounted with hidepid can conceal a live process.
            // Require a readable host /proc; kill(0) alone cannot verify identity.
            const stat = readProcStat(handle.pid, &buffer) catch |err| switch (err) {
                error.ProcessNotFound => return false,
                else => return err,
            };
            return stat.matches(handle.starttime);
        } else {
            return error.NotImplemented;
        }
    }

    fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
            // ponytail: PID reuse between alive() and kill() can signal the wrong
            // process. Fix with pidfd_open before checking identity, then use
            // pidfd_send_signal on that same descriptor.
            if (!try alive(ptr, handle)) return error.ProcessNotFound;
            switch (linux.errno(linux.kill(handle.pid, @enumFromInt(@as(u32, @intCast(signal)))))) {
                .SUCCESS => {},
                .SRCH => return error.ProcessNotFound,
                .PERM => return error.PermissionDenied,
                else => return error.KillFailed,
            }
            // A v1 freezer holds SIGKILL until the paused cgroup is thawed.
            if (signal == @intFromEnum(linux.SIG.KILL)) {
                const root = openCgroupRoot() catch return;
                defer closeFd(root.fd);
                if (root.mode == .unified) return;
                if (openFreezerCgroup(handle) catch null) |cgroup| {
                    defer closeFd(cgroup.fd);
                    if (cgroupFrozen(cgroup.fd, .legacy) catch false)
                        writeCgroupFile(cgroup.fd, "freezer.state", "THAWED", handle.cgroup_path.?) catch {};
                }
            }
        } else {
            return error.NotImplemented;
        }
    }

    fn killAll(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag == .linux) {
            if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
            const path = handle.cgroup_path orelse {
                kill(ptr, handle, signal) catch |err| switch (err) {
                    error.ProcessNotFound => {},
                    else => return err,
                };
                return;
            };
            try validateCgroupPath(path);
            const allocator = std.heap.page_allocator;
            const root = try openCgroupRoot();
            defer closeFd(root.fd);
            // ponytail: cgroup.procs enumeration signals only the leaf's own
            // members. runc walks descendants; upgrade this path by recursing.
            if (root.mode == .legacy) {
                const hierarchies = try openV1Hierarchies(allocator);
                defer freeV1Hierarchies(allocator, hierarchies);
                var members: ?posix.fd_t = null;
                var freezer: ?posix.fd_t = null;
                for (hierarchies) |*hierarchy| {
                    hierarchy.leaf = try walkV1Cgroup(allocator, hierarchy.root.?, path, false, false);
                    if (hierarchy.leaf) |fd| {
                        if (members == null) members = fd;
                        if (hierarchy.has("freezer")) {
                            freezer = fd;
                            members = fd;
                        }
                    }
                }
                if (members) |fd| try killV1Members(fd, freezer, signal, path);
                return;
            }
            const cgroup = (try walkCgroup(root.fd, path, false, &.{})) orelse return;
            defer closeFd(cgroup);
            if (signal == @intFromEnum(linux.SIG.KILL)) {
                while (true) {
                    const opened = linux.openat(cgroup, "cgroup.kill", .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
                    switch (linux.errno(opened)) {
                        .SUCCESS => {
                            closeFd(@intCast(opened));
                            try writeCgroupFile(cgroup, "cgroup.kill", "1", path);
                            return;
                        },
                        .NOENT => break,
                        .INTR => continue,
                        else => try checkResult(opened),
                    }
                }
            }
            try killV2Members(cgroup, signal, path);
        } else {
            return error.NotImplemented;
        }
    }

    fn update(_: *anyopaque, handle: Backend.Handle, resources: Resources) Backend.Error!void {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        const path = handle.cgroup_path orelse {
            reportDiagnostic("container '{s}' has no cgroup to update", .{handle.id});
            return error.Unsupported;
        };
        try validateCgroupPath(path);
        const allocator = std.heap.page_allocator;
        const root = try openCgroupRoot();
        defer closeFd(root.fd);
        if (root.mode == .legacy) {
            if (resources.unified.len != 0) {
                reportDiagnostic("unified resources require cgroup v2", .{});
                return error.InvalidConfig;
            }
            const writes = try v1Writes(allocator, resources, null);
            defer freeV1Writes(allocator, writes);
            // ponytail: Deny-all then allows briefly blocks device opens, and
            // partial lists drop create-time allows. Upgrade to runc's devices emulator.
            const hierarchies = try openV1Hierarchies(allocator);
            defer freeV1Hierarchies(allocator, hierarchies);
            for (hierarchies) |*hierarchy|
                hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, path, false, false)) orelse return error.ProcessNotFound;
            try applyV1Writes(allocator, hierarchies, writes, resources, &.{}, path);
        } else {
            var requested = resources;
            var inferred_memory_limit = false;
            if (requested.memory) |memory| {
                if (memory.limit == null and (memory.swap orelse 0) > 0) {
                    const existing = (try walkCgroup(root.fd, path, false, &.{.{ .name = "memory.max", .value = "" }})) orelse return error.ProcessNotFound;
                    defer closeFd(existing);
                    const current = try readCgroupFile(allocator, existing, "memory.max");
                    defer allocator.free(current);
                    const value = std.mem.trim(u8, current, " \t\n");
                    requested.memory.?.limit = if (std.mem.eql(u8, value, "max"))
                        -1
                    else
                        std.fmt.parseInt(i64, value, 10) catch return error.CgroupWriteFailed;
                    inferred_memory_limit = true;
                }
            }
            var writes = try v2Writes(allocator, requested);
            defer freeWrites(allocator, writes);
            const ignored_fields = try v2IgnoredFields(allocator, resources);
            defer allocator.free(ignored_fields);
            if (ignored_fields.len != 0)
                std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ignored_fields});
            const cgroup = (try walkCgroup(root.fd, path, false, writes)) orelse return error.ProcessNotFound;
            defer closeFd(cgroup);
            if (requested.cpu) |cpu| {
                if ((cpu.quota != null or cpu.period != null) and (cpu.quota == null or cpu.period == null)) {
                    // cpu.max combines two fields; preserve the omitted half.
                    const current = try readCgroupFile(allocator, cgroup, "cpu.max");
                    defer allocator.free(current);
                    var fields = std.mem.tokenizeAny(u8, current, " \t\n");
                    const quota = fields.next() orelse return error.CgroupWriteFailed;
                    const period = fields.next() orelse return error.CgroupWriteFailed;
                    if (cpu.quota == null) requested.cpu.?.quota = if (std.mem.eql(u8, quota, "max"))
                        -1
                    else
                        std.fmt.parseInt(i64, quota, 10) catch return error.CgroupWriteFailed;
                    if (cpu.period == null)
                        requested.cpu.?.period = std.fmt.parseInt(u64, period, 10) catch return error.CgroupWriteFailed;
                    const completed = try v2Writes(allocator, requested);
                    freeWrites(allocator, writes);
                    writes = completed;
                }
            }
            for (writes) |write| {
                // The current limit was needed only to convert total swap.
                if (inferred_memory_limit and std.mem.eql(u8, write.name, "memory.max")) {
                    inferred_memory_limit = false;
                    continue;
                }
                try writeCgroupFile(cgroup, write.name, write.value, path);
            }
        }
    }

    fn pids(ptr: *anyopaque, handle: Backend.Handle, allocator: std.mem.Allocator) Backend.Error![]i32 {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        const path = handle.cgroup_path orelse {
            return allocator.dupe(i32, if (try alive(ptr, handle)) &.{handle.pid} else &.{});
        };
        try validateCgroupPath(path);
        var result: std.ArrayList(i32) = .empty;
        errdefer result.deinit(allocator);
        const root = try openCgroupRoot();
        defer closeFd(root.fd);
        const members = if (root.mode == .legacy) members: {
            const hierarchies = try openV1Hierarchies(allocator);
            defer freeV1Hierarchies(allocator, hierarchies);
            for ([_]?[]const u8{ "freezer", "pids", null }) |controller| {
                for (hierarchies) |hierarchy| {
                    if (controller) |name| {
                        if (!hierarchy.has(name)) continue;
                    }
                    if (try walkV1Cgroup(allocator, hierarchy.root.?, path, false, false)) |fd|
                        break :members fd;
                }
            }
            break :members null;
        } else try walkCgroup(root.fd, path, false, &.{});
        if (members) |fd| {
            defer closeFd(fd);
            try collectCgroupPids(allocator, fd, &result);
        }
        return result.toOwnedSlice(allocator);
    }

    fn freeze(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        return setFrozen(handle, true);
    }

    fn thaw(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        return setFrozen(handle, false);
    }

    fn frozen(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        const cgroup = (try openFreezerCgroup(handle)) orelse return false;
        defer closeFd(cgroup.fd);
        return cgroupFrozen(cgroup.fd, cgroup.mode);
    }

    fn delete(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        last_diagnostic_len = 0;
        if (comptime builtin.os.tag == .linux) {
            if (handle.cgroup_path) |path| cgroup_cleanup: {
                try validateCgroupPath(path);
                const root = try openCgroupRoot();
                defer closeFd(root.fd);
                if (root.mode == .legacy) {
                    const allocator = std.heap.page_allocator;
                    const hierarchies = try openV1Hierarchies(allocator);
                    defer freeV1Hierarchies(allocator, hierarchies);
                    for (hierarchies) |*hierarchy| {
                        hierarchy.leaf = try walkV1Cgroup(allocator, hierarchy.root.?, path, false, false);
                    }
                    try removeV1Cgroups(hierarchies, path);
                    break :cgroup_cleanup;
                }
                const cgroup = (try walkCgroup(root.fd, path, false, &.{})) orelse break :cgroup_cleanup;
                defer closeFd(cgroup);
                // kill targets init only. delete terminates any remaining descendants.
                if (try cgroupPopulated(cgroup))
                    try writeCgroupFile(cgroup, "cgroup.kill", "1", path);
                try removeCgroup(root.fd, path);
            }
            // Cgroup removal waits for all members to exit before mounts detach.
            if (handle.rootfs_mount) |path| {
                // Old state has no ownership identity, so preserve its mounts.
                if (handle.rootfs_mount_id) |id| {
                    const created_boot = handle.rootfs_mount_boot_id orelse return;
                    const current_boot = try bootId();
                    if (std.mem.eql(u8, &created_boot, &current_boot))
                        try detachRootfs(path, .{ .created = id });
                }
            }
        } else {
            return error.NotImplemented;
        }
    }
};

fn readMountinfo(allocator: std.mem.Allocator) Backend.Error![]u8 {
    const fd = try openPath(linux.AT.FDCWD, "/proc/self/mountinfo", .{ .CLOEXEC = true });
    defer closeFd(fd);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.read(fd, &buffer, buffer.len);
        if (linux.errno(result) == .INTR) continue;
        try checkResult(result);
        if (result == 0) return text.toOwnedSlice(allocator);
        try text.appendSlice(allocator, buffer[0..result]);
    }
}

const MountInfo = struct {
    id: u64,
    parent: u64,
    device: []const u8,
    root: []const u8,
    mountpoint: []const u8,

    fn parse(line: []const u8) Backend.Error!MountInfo {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        return .{
            .id = std.fmt.parseInt(u64, fields.next() orelse return error.CreateFailed, 10) catch return error.CreateFailed,
            .parent = std.fmt.parseInt(u64, fields.next() orelse return error.CreateFailed, 10) catch return error.CreateFailed,
            .device = fields.next() orelse return error.CreateFailed,
            .root = fields.next() orelse return error.CreateFailed,
            .mountpoint = fields.next() orelse return error.CreateFailed,
        };
    }
};

fn mountinfoPath(buffer: []u8, escaped: []const u8) Backend.Error![]const u8 {
    var used: usize = 0;
    var i: usize = 0;
    while (i < escaped.len) : (i += 1) {
        if (used == buffer.len) return error.InvalidPath;
        if (escaped[i] == '\\') {
            if (escaped.len - i < 4) return error.InvalidPath;
            buffer[used] = std.fmt.parseInt(u8, escaped[i + 1 .. i + 4], 8) catch return error.InvalidPath;
            i += 3;
        } else {
            buffer[used] = escaped[i];
        }
        used += 1;
    }
    return buffer[0..used];
}

/// A self-bind has the same filesystem root as its directory in the parent
/// mount. This checks its shape, not ownership; mountinfo IDs are reusable.
fn isRootfsSelfBind(text: []const u8, mount_id: u64, path: []const u8) Backend.Error!bool {
    var mount: ?MountInfo = null;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const entry = try MountInfo.parse(line);
        if (entry.id == mount_id) {
            mount = entry;
            break;
        }
    }
    const entry = mount orelse return false;
    var point_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (!std.mem.eql(u8, try mountinfoPath(&point_buffer, entry.mountpoint), path) or
        std.mem.eql(u8, path, "/")) return false;
    lines.reset();
    while (lines.next()) |line| {
        const parent = try MountInfo.parse(line);
        if (parent.id != entry.parent) continue;
        if (!std.mem.eql(u8, entry.device, parent.device)) return false;
        const parent_point = try mountinfoPath(&point_buffer, parent.mountpoint);
        const relative = if (std.mem.eql(u8, parent_point, "/"))
            path[1..]
        else if (std.mem.eql(u8, parent_point, path))
            ""
        else if (std.mem.startsWith(u8, path, parent_point) and path.len > parent_point.len and path[parent_point.len] == '/')
            path[parent_point.len + 1 ..]
        else
            return false;
        var parent_root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const parent_root = try mountinfoPath(&parent_root_buffer, parent.root);
        var expected_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const expected = std.fmt.bufPrint(&expected_buffer, "{s}{s}{s}", .{
            parent_root,
            if (relative.len == 0 or std.mem.eql(u8, parent_root, "/")) "" else "/",
            relative,
        }) catch return error.InvalidPath;
        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        return std.mem.eql(u8, try mountinfoPath(&root_buffer, entry.root), expected);
    }
    return false;
}

fn mountId(fd: posix.fd_t) Backend.Error!u64 {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .MNT_ID_UNIQUE = true }, &stat));
    if (!stat.mask.MNT_ID_UNIQUE) return error.Unsupported;
    return stat.mnt_id;
}

fn bootId() Backend.Error![36]u8 {
    const fd = try openPath(linux.AT.FDCWD, "/proc/sys/kernel/random/boot_id", .{ .CLOEXEC = true });
    defer closeFd(fd);
    var id: [36]u8 = undefined;
    if (!readAll(fd, &id)) return error.CreateFailed;
    return id;
}

// Linux 6.8 UAPI: STATMOUNT_MNT_BASIC supplies both unique and mountinfo IDs.
const StatMount = extern struct {
    size: u32,
    spare1: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    spare2: [50]u64,
};

fn statMount(id: u64) Backend.Error!?StatMount {
    const Request = extern struct {
        size: u32 = @sizeOf(@This()),
        spare: u32 = 0,
        mnt_id: u64,
        param: u64 = 2, // STATMOUNT_MNT_BASIC
    };
    const request: Request = .{ .mnt_id = id };
    var result: StatMount = undefined;
    switch (linux.errno(linux.syscall4(.statmount, @intFromPtr(&request), @intFromPtr(&result), @sizeOf(StatMount), 0))) {
        .SUCCESS => {},
        .NOENT => return null,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
    if (result.mask & 2 == 0 or result.mnt_id != id) return error.Unsupported;
    return result;
}

const RootfsMountIdentity = union(enum) {
    /// Used when init failed before reporting its newly created mount.
    before_create: u64,
    created: u64,
};

/// Configured mounts at "/" cover the self-bind, but remain its descendants.
fn rootfsSelfBindId(text: []const u8, current_id: u64, path: []const u8, identity: RootfsMountIdentity) Backend.Error!?u64 {
    var id = current_id;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (true) {
        const stat = (try statMount(id)) orelse return null;
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        const entry = find: {
            while (lines.next()) |line| {
                const mount = try MountInfo.parse(line);
                if (mount.id == stat.mnt_id_old) break :find mount;
            }
            return null;
        };
        if (!std.mem.eql(u8, try mountinfoPath(&buffer, entry.mountpoint), path)) return null;
        const owned = switch (identity) {
            .created => |created| id == created,
            .before_create => |before| id != before and stat.mnt_parent_id == before,
        };
        if (owned) return if (try isRootfsSelfBind(text, stat.mnt_id_old, path)) id else null;
        if (stat.mnt_parent_id == id) return null;
        id = stat.mnt_parent_id;
    }
}

fn detachRootfs(path: []const u8, identity: RootfsMountIdentity) Backend.Error!void {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.InvalidPath;
    while (true) {
        const opened = linux.openat(linux.AT.FDCWD, path_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .NOENT => return,
            else => try checkResult(opened),
        }
        const fd: posix.fd_t = @intCast(opened);
        defer closeFd(fd);
        const current_id = try mountId(fd);
        var fd_buffer: [64]u8 = undefined;
        var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const size = linux.readlink(fdPath(&fd_buffer, fd), &resolved_buffer, resolved_buffer.len);
        try checkResult(size);
        if (size == resolved_buffer.len) return error.InvalidPath;
        const text = try readMountinfo(std.heap.page_allocator);
        defer std.heap.page_allocator.free(text);
        const owned_id = (try rootfsSelfBindId(text, current_id, resolved_buffer[0..size], identity)) orelse return;
        // Recursive binds can retain host peers. As in the pivot_root path, cut
        // propagation on the owned tree before detach can unmount those peers.
        try checkResult(linux.mount(null, fdPath(&fd_buffer, fd), null, linux.MS.SLAVE | linux.MS.REC, 0));
        // Address the pinned mount, rather than a replacement at the original path.
        switch (linux.errno(linux.umount2(fdPath(&fd_buffer, fd), linux.MNT.DETACH))) {
            .SUCCESS => if (current_id == owned_id) return,
            .INVAL, .NOENT => return,
            else => return error.CreateFailed,
        }
    }
}

test "rootfs cleanup recognizes self-binds including escaped paths and bind-mounted parents" {
    const text =
        \\1 0 8:1 / / rw - ext4 /dev/root rw
        \\2 1 8:1 /containers /runtime rw - ext4 /dev/root rw
        \\3 2 8:1 /containers/rootfs\040space /runtime/rootfs\040space rw - ext4 /dev/root rw
        \\4 2 0:42 / /runtime/tmpfs rw - tmpfs tmpfs rw
        \\5 2 8:1 /elsewhere /runtime/other-bind rw - ext4 /dev/root rw
        \\6 1 8:1 /rootfs /rootfs rw - ext4 /dev/root rw
    ;
    try std.testing.expect(try isRootfsSelfBind(text, 3, "/runtime/rootfs space"));
    try std.testing.expect(try isRootfsSelfBind(text, 6, "/rootfs"));
    try std.testing.expect(!try isRootfsSelfBind(text, 4, "/runtime/tmpfs"));
    try std.testing.expect(!try isRootfsSelfBind(text, 5, "/runtime/other-bind"));
    try std.testing.expect(!try isRootfsSelfBind(text, 2, "/runtime"));
    try std.testing.expect(!try isRootfsSelfBind(text, 1, "/"));
    try std.testing.expect(!try isRootfsSelfBind(text, 3, "/runtime"));
    try std.testing.expect(!try isRootfsSelfBind(text, 99, "/missing"));
}

fn validateCgroupPath(path: []const u8) Backend.Error!void {
    if (path.len == 0 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or component.len > 255)
            return error.InvalidPath;
    }
}

fn cgroupMode(fs_type: usize) Backend.Error!CgroupMode {
    return switch (fs_type) {
        0x63677270 => .unified, // CGROUP2_SUPER_MAGIC
        0x01021994 => .legacy, // TMPFS_MAGIC
        else => error.Unsupported,
    };
}

fn openCgroupRoot() Backend.Error!struct { fd: posix.fd_t, fs_type: usize, mode: CgroupMode } {
    const opened = linux.openat(linux.AT.FDCWD, "/sys/fs/cgroup", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return error.Unsupported,
        else => try checkResult(opened),
    }
    const root: posix.fd_t = @intCast(opened);
    errdefer closeFd(root);
    // Zig has no statfs wrapper. f_type is the first native word of Linux statfs.
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(root), @intFromPtr(&fs)));
    const mode = cgroupMode(fs[0]) catch {
        reportDiagnostic("unsupported cgroup filesystem at /sys/fs/cgroup", .{});
        return error.Unsupported;
    };
    // ponytail: hybrid hosts use v1 only, without systemd-unified membership,
    // like runc's fs driver without systemd.
    return .{ .fd = root, .fs_type = fs[0], .mode = mode };
}

fn openV1Hierarchies(allocator: std.mem.Allocator) Backend.Error![]V1Hierarchy {
    const text = try readMountinfo(allocator);
    defer allocator.free(text);
    const hierarchies = try v1Hierarchies(allocator, text);
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
        if (fs[0] != 0x27e0eb) return error.Unsupported; // CGROUP_SUPER_MAGIC
    }
    return hierarchies;
}

fn readCgroupFile(allocator: std.mem.Allocator, dir: posix.fd_t, filename: [:0]const u8) Backend.Error![]u8 {
    const fd = try openPath(dir, filename, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.CgroupWriteFailed,
        }
        if (result == 0) return text.toOwnedSlice(allocator);
        try text.appendSlice(allocator, buffer[0..result]);
    }
}

fn collectCgroupPids(allocator: std.mem.Allocator, dir: posix.fd_t, result: *std.ArrayList(i32)) Backend.Error!void {
    const text = try readCgroupFile(allocator, dir, "cgroup.procs");
    defer allocator.free(text);
    var fields = std.mem.tokenizeAny(u8, text, " \t\n");
    while (fields.next()) |field| {
        const pid = std.fmt.parseInt(i32, field, 10) catch return error.InvalidProcess;
        if (pid <= 0) return error.InvalidProcess;
        if (std.mem.indexOfScalar(i32, result.items, pid) == null) try result.append(allocator, pid);
    }
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) return;
        var offset: usize = 0;
        while (offset < count) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            offset += entry.reclen;
            if (entry.type != linux.DT.DIR) continue;
            const name_ptr: [*]const u8 = &entry.name;
            const padded = name_ptr[0 .. entry.reclen - @offsetOf(linux.dirent64, "name")];
            const name = name_ptr[0..std.mem.indexOfScalar(u8, padded, 0).? :0];
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            const opened = linux.openat(dir, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
            if (linux.errno(opened) == .NOENT) continue; // A child can disappear during ps.
            try checkResult(opened);
            const child: posix.fd_t = @intCast(opened);
            defer closeFd(child);
            try collectCgroupPids(allocator, child, result);
        }
    }
}

fn openFreezerCgroup(handle: Backend.Handle) Backend.Error!?struct { fd: posix.fd_t, mode: CgroupMode } {
    const path = handle.cgroup_path orelse return null;
    try validateCgroupPath(path);
    const root = openCgroupRoot() catch |err| switch (err) {
        error.Unsupported => return null,
        else => return err,
    };
    defer closeFd(root.fd);
    const fd = if (root.mode == .legacy) freezer: {
        const allocator = std.heap.page_allocator;
        const hierarchies = try openV1Hierarchies(allocator);
        defer freeV1Hierarchies(allocator, hierarchies);
        for (hierarchies) |hierarchy| {
            if (hierarchy.has("freezer"))
                break :freezer (try walkV1Cgroup(allocator, hierarchy.root.?, path, false, false)) orelse return null;
        }
        return null;
    } else (try walkCgroup(root.fd, path, false, &.{})) orelse return null;
    errdefer closeFd(fd);
    const name: [:0]const u8 = if (root.mode == .unified) "cgroup.freeze" else "freezer.state";
    const probe = linux.openat(fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(probe) == .NOENT) {
        closeFd(fd);
        return null;
    }
    try checkResult(probe);
    closeFd(@intCast(probe));
    return .{ .fd = fd, .mode = root.mode };
}

fn cgroupFrozen(dir: posix.fd_t, mode: CgroupMode) Backend.Error!bool {
    const fd = try openPath(dir, if (mode == .unified) "cgroup.freeze" else "freezer.state", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var buffer: [4096]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const count = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) break;
        used += count;
    }
    const state = std.mem.trim(u8, buffer[0..used], " \t\n");
    if (mode == .unified) return std.mem.eql(u8, state, "1");
    return std.mem.eql(u8, state, "FROZEN") or std.mem.eql(u8, state, "FREEZING");
}

/// Both freezer implementations are asynchronous; poll every ten milliseconds.
fn waitFrozen(dir: posix.fd_t, mode: CgroupMode, wanted: bool, attempts: usize) Backend.Error!bool {
    const allocator = std.heap.page_allocator;
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..attempts) |_| {
        if (mode == .legacy) {
            const state = try readCgroupFile(allocator, dir, "freezer.state");
            defer allocator.free(state);
            if (std.mem.eql(u8, std.mem.trim(u8, state, " \t\n"), if (wanted) "FROZEN" else "THAWED"))
                return true;
        } else {
            const events = try readCgroupFile(allocator, dir, "cgroup.events");
            defer allocator.free(events);
            var lines = std.mem.tokenizeScalar(u8, events, '\n');
            const frozen = while (lines.next()) |line| {
                if (std.mem.eql(u8, line, "frozen 1")) break true;
                if (std.mem.eql(u8, line, "frozen 0")) break false;
            } else {
                reportDiagnostic("cgroup.events has no freezer state", .{});
                return error.Unsupported;
            };
            if (frozen == wanted) return true;
        }
        _ = linux.nanosleep(&delay, null);
    }
    return false;
}

fn setFrozen(handle: Backend.Handle, wanted: bool) Backend.Error!void {
    last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const cgroup = (try openFreezerCgroup(handle)) orelse {
        reportDiagnostic("container '{s}' has no cgroup freezer; pause/resume is unsupported", .{handle.id});
        return error.Unsupported;
    };
    defer closeFd(cgroup.fd);
    // Explicit pause allows ten seconds for busy containers to freeze.
    try setCgroupFrozen(cgroup.fd, cgroup.mode, wanted, handle.cgroup_path.?, if (wanted) 1000 else 50);
}

fn setCgroupFrozen(dir: posix.fd_t, mode: CgroupMode, wanted: bool, path: []const u8, attempts: usize) Backend.Error!void {
    const name: []const u8 = if (mode == .unified) "cgroup.freeze" else "freezer.state";
    const value: []const u8 = if (mode == .unified)
        (if (wanted) "1" else "0")
    else
        (if (wanted) "FROZEN" else "THAWED");
    try writeCgroupFile(dir, name, value, path);
    errdefer if (wanted) {
        const saved_diagnostic = last_diagnostic;
        const saved_len = last_diagnostic_len;
        writeCgroupFile(dir, name, if (mode == .unified) "0" else "THAWED", path) catch {};
        last_diagnostic = saved_diagnostic;
        last_diagnostic_len = saved_len;
    };
    if (!try waitFrozen(dir, mode, wanted, attempts)) {
        reportDiagnostic("cgroup '{s}' did not reach freezer state {s}", .{ path, value });
        return error.CgroupWriteFailed;
    }
}

test "linux explicit freeze timeout cancels the request and retains its diagnostic" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer last_diagnostic_len = 0;
    for ([_]CgroupMode{ .unified, .legacy }) |mode| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const name: [:0]const u8 = if (mode == .unified) "cgroup.freeze" else "freezer.state";
        const thawed: []const u8 = if (mode == .unified) "0" else "THAWED";
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = thawed });
        // Exhaust the polling budget immediately to exercise timeout cleanup
        // without needing an unfreezable process or a real cgroup hierarchy.
        try std.testing.expectError(error.CgroupWriteFailed, setCgroupFrozen(tmp.dir.handle, mode, true, "igvano/pause-test", 0));
        const state = try readCgroupFile(std.testing.allocator, tmp.dir.handle, name);
        defer std.testing.allocator.free(state);
        try std.testing.expectEqualStrings(thawed, state);
        const diagnostic = last_diagnostic[0..last_diagnostic_len];
        try std.testing.expect(std.mem.indexOf(u8, diagnostic, "igvano/pause-test") != null);
        try std.testing.expect(std.mem.indexOf(u8, diagnostic, "did not reach freezer state") != null);
    }
}

test "linux v2 freezer status follows the local request while completion follows events" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { request: []const u8, events: []const u8, frozen: bool, completed: bool }{
        .{ .request = "1\n", .events = "populated 1\nfrozen 0\n", .frozen = true, .completed = false },
        .{ .request = "0\n", .events = "populated 1\nfrozen 1\n", .frozen = false, .completed = true },
    }) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.freeze", .data = case.request });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = case.events });
        try std.testing.expectEqual(case.frozen, try cgroupFrozen(tmp.dir.handle, .unified));
        try std.testing.expect(try waitFrozen(tmp.dir.handle, .unified, case.completed, 1));
        try std.testing.expect(!try waitFrozen(tmp.dir.handle, .unified, case.frozen, 1));
    }
}

test "linux v2 kill all retains a pending user freeze request" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.freeze", .data = "1" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = "populated 0\nfrozen 0\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = "" });
    for ([_]i32{ 0, 9, 15 }) |signal| {
        try killV2Members(tmp.dir.handle, signal, "igvano/pending-pause-test");
        const state = try readCgroupFile(std.testing.allocator, tmp.dir.handle, "cgroup.freeze");
        defer std.testing.allocator.free(state);
        try std.testing.expectEqualStrings("1", state);
    }
}

fn seedV1Cpuset(allocator: std.mem.Allocator, parent: posix.fd_t, child: posix.fd_t, path: []const u8) Backend.Error!void {
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
fn walkV1Cgroup(allocator: std.mem.Allocator, root: posix.fd_t, path: []const u8, create: bool, cpuset: bool) Backend.Error!?posix.fd_t {
    try validateCgroupPath(path);
    var current = try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        var created = false;
        if (create) {
            const result = linux.mkdirat(current, name, 0o755);
            switch (linux.errno(result)) {
                .SUCCESS => created = true,
                .EXIST => if (components.peek() == null) {
                    reportDiagnostic("cgroup '{s}' already exists", .{path});
                    return error.CreateFailed;
                },
                else => try checkResult(result),
            }
        }
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
        errdefer if (created and components.peek() == null) removeV1Cgroup(root, path, child, null) catch {};
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

fn writeV1Resource(dir: posix.fd_t, write: V1Write, path: []const u8, kmem_warned: *bool) Backend.Error!void {
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

test "linux v1 ignores missing deprecated kmem files but requires other memory files" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    var kmem_warned = false;
    for ([_][]const u8{ "memory.kmem.limit_in_bytes", "memory.kmem.tcp.limit_in_bytes" }) |name| {
        try writeV1Resource(root, .{ .controller = "memory", .name = name, .value = "64" }, "test", &kmem_warned);
        try std.testing.expect(kmem_warned);
    }
    try std.testing.expectError(error.CgroupWriteFailed, writeV1Resource(root, .{
        .controller = "memory",
        .name = "memory.limit_in_bytes",
        .value = "64",
    }, "test", &kmem_warned));
}

fn requiredV1Controller(controller: []const u8, resources: Resources, devices: []const Backend.Device) bool {
    if (std.mem.eql(u8, controller, "memory") or std.mem.eql(u8, controller, "pids")) return true;
    if (std.mem.eql(u8, controller, "devices")) {
        if (resources.devices.len != 0) return true;
        for (devices) |device| {
            if (device.required and device.kind != .fifo) return true;
        }
    }
    return false;
}

fn applyV1Writes(allocator: std.mem.Allocator, hierarchies: []const V1Hierarchy, writes: []const V1Write, resources: Resources, devices: []const Backend.Device, path: []const u8) Backend.Error!void {
    // Warn once per missing controller, including controllers with many writes.
    for (writes, 0..) |write, index| {
        var mounted = false;
        for (hierarchies) |hierarchy| {
            if (hierarchy.has(write.controller)) mounted = true;
        }
        if (mounted) continue;
        if (requiredV1Controller(write.controller, resources, devices)) {
            reportDiagnostic("cgroup v1 controller {s} is required but not mounted", .{write.controller});
            return error.CgroupWriteFailed;
        }
        var warned = false;
        for (writes[0..index]) |previous| {
            if (std.mem.eql(u8, previous.controller, write.controller)) warned = true;
        }
        if (!warned) std.debug.print("igvano: warning: cgroup v1 controller {s} is not mounted; ignoring\n", .{write.controller});
    }
    var kmem_warned = false;
    for (hierarchies) |hierarchy| {
        var swap_first: ?usize = null;
        var limit_write: ?usize = null;
        var swap_write: ?usize = null;
        if (hierarchy.has("memory")) {
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
        }
        for (writes, 0..) |write, index| {
            if (!hierarchy.has(write.controller)) continue;
            if (swap_first) |swap| {
                if (index == swap) continue;
                if (index == limit_write.?) try writeV1Resource(hierarchy.leaf.?, writes[swap], path, &kmem_warned);
            }
            try writeV1Resource(hierarchy.leaf.?, write, path, &kmem_warned);
        }
    }
}

fn killV2Members(dir: posix.fd_t, signal: i32, path: []const u8) Backend.Error!void {
    const was_frozen = try cgroupFrozen(dir, .unified);
    // Only undo a freeze owned by this operation.
    defer if (!was_frozen) {
        const saved_diagnostic = last_diagnostic;
        const saved_len = last_diagnostic_len;
        writeCgroupFile(dir, "cgroup.freeze", "0", path) catch {};
        last_diagnostic = saved_diagnostic;
        last_diagnostic_len = saved_len;
    };
    if (!was_frozen) {
        try writeCgroupFile(dir, "cgroup.freeze", "1", path);
        _ = try waitFrozen(dir, .unified, true, 50);
    }
    // The v1 helper also enumerates cgroup.procs without a freezer.
    try killV1Members(dir, null, signal, path);
}

fn killV1Members(dir: posix.fd_t, freezer: ?posix.fd_t, signal: i32, path: []const u8) Backend.Error!void {
    const allocator = std.heap.page_allocator;
    const was_frozen = if (freezer) |fd| try cgroupFrozen(fd, .legacy) else false;
    const owned_freezer = if (!was_frozen) freezer else null;
    defer if (owned_freezer) |fd| {
        const saved_diagnostic = last_diagnostic;
        const saved_len = last_diagnostic_len;
        writeCgroupFile(fd, "freezer.state", "THAWED", path) catch {};
        last_diagnostic = saved_diagnostic;
        last_diagnostic_len = saved_len;
    };
    if (owned_freezer) |fd| {
        try writeCgroupFile(fd, "freezer.state", "FROZEN", path);
        if (!try waitFrozen(fd, .legacy, true, 50)) {
            const saved_diagnostic = last_diagnostic;
            const saved_len = last_diagnostic_len;
            writeCgroupFile(fd, "freezer.state", "THAWED", path) catch {};
            last_diagnostic = saved_diagnostic;
            last_diagnostic_len = saved_len;
        }
    }
    // ponytail: without a frozen cgroup, PID reuse between reading
    // cgroup.procs and kill can signal an unrelated host process. This is the
    // safety ceiling of the fallback; pidfds would pin each process identity.
    const text = try readCgroupFile(allocator, dir, "cgroup.procs");
    defer allocator.free(text);
    var pids = std.mem.tokenizeAny(u8, text, " \t\n");
    while (pids.next()) |text_pid| {
        const pid = std.fmt.parseInt(i32, text_pid, 10) catch return error.CgroupDeleteFailed;
        if (pid <= 0) return error.CgroupDeleteFailed;
        switch (linux.errno(linux.kill(pid, @enumFromInt(@as(u32, @intCast(signal)))))) {
            .SUCCESS, .SRCH => {},
            .PERM => return error.PermissionDenied,
            else => return error.KillFailed,
        }
    }
    // SIGKILL on v1 needs a thaw after signaling, even for a user pause.
    if (was_frozen and signal == @intFromEnum(linux.SIG.KILL))
        try writeCgroupFile(freezer.?, "freezer.state", "THAWED", path);
}

test "linux v1 failed freeze retains its diagnostic and real cgroup path after thaw fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    defer last_diagnostic_len = 0;
    // /dev/full makes both writes fail with values named in the diagnostic.
    checkResult(linux.mknodat(tmp.dir.handle, "freezer.state", linux.S.IFCHR | 0o600, 0x107)) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    const probe = openPath(tmp.dir.handle, "freezer.state", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    closeFd(probe);
    try std.testing.expectError(error.CgroupWriteFailed, killV1Members(tmp.dir.handle, tmp.dir.handle, 9, "igvano/freeze-test"));
    const diagnostic = last_diagnostic[0..last_diagnostic_len];
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "igvano/freeze-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "FROZEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "THAWED") == null);
}

test "linux cgroup member signaling distinguishes kill failures from deletion failures" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "leaf", .fromMode(0o755));
    const members = try std.fmt.allocPrint(std.testing.allocator, "{d}\n", .{linux.getpid()});
    defer std.testing.allocator.free(members);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf/cgroup.procs", .data = members });
    const leaf = try openPath(tmp.dir.handle, "leaf", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(leaf);
    try std.testing.expectError(error.KillFailed, killV1Members(leaf, null, linux.NSIG, "leaf"));
    if (linux.geteuid() != 0) return;
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try checkResult(linux.fchmod(root, 0o755));
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.setuid(65534)) catch linux.exit_group(1);
        killV1Members(leaf, null, 0, "leaf") catch |err| {
            if (err != error.PermissionDenied) linux.exit_group(2);
            removeV1Cgroup(root, "leaf", leaf, null) catch |delete_err|
                linux.exit_group(if (delete_err == error.CgroupDeleteFailed) 0 else 3);
            linux.exit_group(4);
        };
        linux.exit_group(5);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

fn removeV1Cgroups(hierarchies: []const V1Hierarchy, path: []const u8) Backend.Error!void {
    var freezer: ?posix.fd_t = null;
    var failure: ?Backend.Error = null;
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("freezer")) freezer = hierarchy.leaf;
    }
    // Retain the freezer leaf until every other hierarchy has been drained.
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("freezer")) continue;
        if (hierarchy.leaf) |fd| removeV1Cgroup(hierarchy.root.?, path, fd, freezer) catch |err| {
            if (failure == null) failure = err;
        };
    }
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("freezer")) {
            if (hierarchy.leaf) |fd| removeV1Cgroup(hierarchy.root.?, path, fd, freezer) catch |err| {
                if (failure == null) failure = err;
            };
        }
    }
    if (failure) |err| return err;
}

/// Only remove our leaf, checking identity against the pinned fd on every retry.
fn removeV1Cgroup(root: posix.fd_t, path: []const u8, owned_fd: posix.fd_t, freezer: ?posix.fd_t) Backend.Error!void {
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
        var current: linux.Statx = undefined;
        try checkResult(linux.statx(leaf, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &current));
        if (!owned.mask.INO or !current.mask.INO) return error.CgroupDeleteFailed;
        if (owned.dev_major != current.dev_major or owned.dev_minor != current.dev_minor or owned.ino != current.ino) return;
        killV1Members(leaf, freezer, @intFromEnum(linux.SIG.KILL), path) catch |err| return switch (err) {
            error.PermissionDenied, error.KillFailed => error.CgroupDeleteFailed,
            else => err,
        };
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

test "backend cgroup paths must name a normalized child directory" {
    for ([_][]const u8{ "igvano/example", "custom", "a/b/c" }) |path| try validateCgroupPath(path);
    for ([_][]const u8{ "", "/", "/custom", "..", "a/../b", "a/./b", "a//b", "a/", "a\x00b" }) |path| {
        try std.testing.expectError(error.InvalidPath, validateCgroupPath(path));
    }
}

fn cleanupV1TestHierarchies(hierarchies: []const V1Hierarchy, path: []const u8) void {
    removeV1Cgroups(hierarchies, path) catch {};
    for (hierarchies) |hierarchy| {
        if (std.fs.path.dirname(path)) |parent| {
            const fd = (walkCgroup(hierarchy.root.?, parent, false, &.{}) catch null) orelse continue;
            defer closeFd(fd);
            removeV1Cgroup(hierarchy.root.?, parent, fd, null) catch {};
        }
    }
}

test "linux v1 create exposes readonly controller leaves containing init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator);
    defer freeV1Hierarchies(allocator, hierarchies);
    if (hierarchies.len == 0) return error.SkipZigTest;
    var selected = hierarchies[0];
    for (hierarchies) |hierarchy| {
        if (hierarchy.has("memory")) selected = hierarchy;
    }
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-mount-test-{d}", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    // Probe delegation before create, so a failure in mount expansion is fatal.
    for (hierarchies) |hierarchy| {
        const leaf = (walkV1Cgroup(allocator, hierarchy.root.?, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        defer closeFd(leaf);
        try removeV1Cgroup(hierarchy.root.?, path, leaf, null);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fs.path.join(allocator, &.{ absolute, "rootfs" });
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const controller_path = try std.fmt.allocPrintSentinel(allocator, "/sys/fs/cgroup/{s}", .{std.fs.path.basename(selected.mountpoint)}, 0);
    defer allocator.free(controller_path);
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .cgroup } } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = "v1-mount",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = path,
        .mounts = &.{.{
            .destination = "/sys/fs/cgroup",
            .source = "cgroup",
            .type = "cgroup",
            .flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV,
            .propagation = 0,
            .data = "",
        }},
    });
    defer allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    var buffer: [64]u8 = undefined;
    const namespace_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/ns/mnt", .{handle.pid});
    const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    const init_root_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/root", .{handle.pid});
    const init_root = try openPath(linux.AT.FDCWD, init_root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(init_root);
    const checker = try forkProcess();
    if (checker == 0) {
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.fchdir(init_root)) catch linux.exit_group(2);
        checkResult(linux.chroot(".")) catch linux.exit_group(3);
        checkResult(linux.chdir("/")) catch linux.exit_group(4);
        for (hierarchies) |hierarchy| {
            const basename = std.fs.path.basename(hierarchy.mountpoint);
            if (std.mem.indexOfScalar(u8, basename, ',') == null) continue;
            var names = std.mem.tokenizeScalar(u8, basename, ',');
            while (names.next()) |name| {
                var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const link = std.fmt.bufPrintZ(&path_buffer, "/sys/fs/cgroup/{s}", .{name}) catch linux.exit_group(12);
                var target: [256]u8 = undefined;
                const len = linux.readlink(link, &target, target.len);
                checkResult(len) catch linux.exit_group(13);
                if (!std.mem.eql(u8, target[0..len], basename)) linux.exit_group(14);
            }
        }
        const controller = openPath(linux.AT.FDCWD, controller_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(5);
        if (linux.errno(linux.mkdirat(controller, "readonly-probe", 0o755)) != .ROFS) linux.exit_group(6);
        // The tmpfs itself must be readonly after controller binds and links.
        if (linux.errno(linux.mkdir("/sys/fs/cgroup/readonly-probe", 0o755)) != .ROFS) linux.exit_group(7);
        const procs = openPath(controller, "cgroup.procs", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(8);
        var members: [4096]u8 = undefined;
        const count = linux.read(procs, &members, members.len);
        checkResult(count) catch linux.exit_group(9);
        var pids = std.mem.tokenizeAny(u8, members[0..count], " \t\n");
        while (pids.next()) |pid| {
            if ((std.fmt.parseInt(i32, pid, 10) catch linux.exit_group(10)) == handle.pid)
                linux.exit_group(0);
        }
        linux.exit_group(11);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(checker));
}

test "linux v1 creates seeds writes joins and deletes each hierarchy" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator);
    defer freeV1Hierarchies(allocator, hierarchies);
    if (hierarchies.len == 0) return error.SkipZigTest;
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-test-{d}/leaf", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    for (hierarchies) |*hierarchy| {
        hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        try std.testing.expectError(error.CreateFailed, walkV1Cgroup(allocator, hierarchy.root.?, path, true, hierarchy.has("cpuset")));
        if (hierarchy.has("cpuset")) {
            const parent = (try walkCgroup(hierarchy.root.?, std.fs.path.dirname(path).?, false, &.{})).?;
            defer closeFd(parent);
            for ([_][:0]const u8{ "cpuset.cpus", "cpuset.mems" }) |name| {
                const inherited = try readCgroupFile(allocator, hierarchy.root.?, name);
                defer allocator.free(inherited);
                const intermediate = try readCgroupFile(allocator, parent, name);
                defer allocator.free(intermediate);
                const leaf = try readCgroupFile(allocator, hierarchy.leaf.?, name);
                defer allocator.free(leaf);
                try std.testing.expect(std.mem.trim(u8, leaf, "\n").len != 0);
                try std.testing.expectEqualStrings(inherited, intermediate);
                try std.testing.expectEqualStrings(inherited, leaf);
            }
        }
    }
    // A forced concurrent delete/recreate must not make cleanup remove the
    // replacement. Hold the old descriptor so its inode cannot be reused.
    const first = &hierarchies[0];
    const original = first.leaf.?;
    try removeV1Cgroup(first.root.?, path, original, null);
    first.leaf = (try walkV1Cgroup(allocator, first.root.?, path, true, first.has("cpuset"))).?;
    defer closeFd(original);
    try removeV1Cgroup(first.root.?, path, original, null);
    const replacement = (try walkCgroup(first.root.?, path, false, &.{})).?;
    closeFd(replacement);

    const resources: Resources = .{
        .memory = .{ .limit = 67108864, .reservation = 33554432, .swap = 134217728, .swappiness = 50 },
        .cpu = .{ .shares = 1024, .period = 100000, .quota = 50000 },
        .pids = .{ .limit = 32 },
        .block_io = .{ .weight = 100 },
        .hugepage_limits = &.{.{ .page_size = "2MB", .limit = 4194304 }},
        .network = .{ .class_id = 1048577, .priorities = &.{.{ .name = "lo", .priority = 2 }} },
        .devices = &.{.{ .allow = false }},
    };
    const writes = try v1Writes(allocator, resources, &.{});
    defer freeV1Writes(allocator, writes);
    try applyV1Writes(allocator, hierarchies, writes, resources, &.{}, path);
    for (hierarchies) |hierarchy| {
        const cases = [_]struct { controller: []const u8, name: [:0]const u8, value: []const u8 }{
            .{ .controller = "memory", .name = "memory.limit_in_bytes", .value = "67108864" },
            .{ .controller = "memory", .name = "memory.memsw.limit_in_bytes", .value = "134217728" },
            .{ .controller = "cpu", .name = "cpu.shares", .value = "1024" },
            .{ .controller = "cpu", .name = "cpu.cfs_period_us", .value = "100000" },
            .{ .controller = "cpu", .name = "cpu.cfs_quota_us", .value = "50000" },
            .{ .controller = "pids", .name = "pids.max", .value = "32" },
            .{ .controller = "hugetlb", .name = "hugetlb.2MB.limit_in_bytes", .value = "4194304" },
        };
        for (cases) |case| {
            if (!hierarchy.has(case.controller)) continue;
            const value = try readCgroupFile(allocator, hierarchy.leaf.?, case.name);
            defer allocator.free(value);
            try std.testing.expectEqualStrings(case.value, std.mem.trim(u8, value, "\n"));
        }
        if (hierarchy.has("memory")) {
            // Exercise both orders against a real kernel constraint: lower
            // limit+memsw, then raise limit beyond the current memsw.
            const lower: Resources = .{ .memory = .{ .limit = 33554432, .swap = 67108864 } };
            const lower_writes = try v1Writes(allocator, lower, &.{});
            defer freeV1Writes(allocator, lower_writes);
            try applyV1Writes(allocator, hierarchies, lower_writes, lower, &.{}, path);
            const higher: Resources = .{ .memory = .{ .limit = 100663296, .swap = 134217728 } };
            const higher_writes = try v1Writes(allocator, higher, &.{});
            defer freeV1Writes(allocator, higher_writes);
            try applyV1Writes(allocator, hierarchies, higher_writes, higher, &.{}, path);
        }
    }
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    var writer: ?posix.fd_t = pipe[1];
    defer if (writer) |fd| closeFd(fd);
    const child = try forkProcess();
    if (child == 0) {
        closeFd(pipe[0]);
        for (hierarchies) |hierarchy|
            writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", path) catch linux.exit_group(1);
        if (!writeAll(pipe[1], &.{1})) linux.exit_group(2);
        const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
        while (true) _ = linux.nanosleep(&delay, null);
    }
    closeFd(pipe[1]);
    writer = null;
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(child, .KILL);
        _ = waitChild(child) catch {};
    };
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(pipe[0], &byte));
    var pid_buffer: [24]u8 = undefined;
    const pid_line = try std.fmt.bufPrint(&pid_buffer, "{d}\n", .{child});
    for (hierarchies) |hierarchy| {
        const members = try readCgroupFile(allocator, hierarchy.leaf.?, "cgroup.procs");
        defer allocator.free(members);
        try std.testing.expect(std.mem.indexOf(u8, members, pid_line) != null);
        if (hierarchy.has("freezer")) {
            // Failed enumeration must thaw the real cgroup, leaving its
            // member alive for delete's subsequent freeze/kill/thaw cycle.
            try std.testing.expectError(error.CreateFailed, killV1Members(-1, hierarchy.leaf, 9, path));
            const state = try readCgroupFile(allocator, hierarchy.leaf.?, "freezer.state");
            defer allocator.free(state);
            try std.testing.expectEqualStrings("THAWED", std.mem.trim(u8, state, " \t\n"));
            try checkResult(linux.kill(child, @enumFromInt(0)));
        }
    }
    var backend: LinuxBackend = .{};
    try backend.backend().delete(.{ .id = "v1-test", .pid = child, .starttime = "", .cgroup_path = path });
    try std.testing.expectEqual(@as(u32, 9), try waitChild(child));
    reaped = true;
    for (hierarchies) |hierarchy|
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(hierarchy.root.?, path, false, &.{}));
    try backend.backend().delete(.{ .id = "v1-test", .pid = 0, .starttime = "", .cgroup_path = path });
}

test "linux v1 cleanup attempts later hierarchies after the first removal fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const hierarchies = try openV1Hierarchies(allocator);
    defer freeV1Hierarchies(allocator, hierarchies);
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-cleanup-{d}", .{linux.getpid()});
    defer allocator.free(path);
    defer cleanupV1TestHierarchies(hierarchies, path);
    var selected: [2]V1Hierarchy = undefined;
    var count: usize = 0;
    for (hierarchies) |*hierarchy| {
        if (hierarchy.has("freezer")) continue;
        hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, path, true, hierarchy.has("cpuset")) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        }).?;
        selected[count] = hierarchy.*;
        count += 1;
        if (count == selected.len) break;
    }
    if (count < selected.len) return error.SkipZigTest;
    const first_root = selected[0].root.?;
    selected[0].root = -1; // Fail before removing the first owned leaf.
    try std.testing.expectError(error.CreateFailed, removeV1Cgroups(&selected, path));
    const first = (try walkCgroup(first_root, path, false, &.{})) orelse return error.TestUnexpectedResult;
    closeFd(first);
    const second = try walkCgroup(selected[1].root.?, path, false, &.{});
    defer if (second) |fd| closeFd(fd);
    try std.testing.expectEqual(@as(?posix.fd_t, null), second);
}

test "linux v1 container allowlist opens dev null while a denied device fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    try requireTestMountNamespace();
    // Confirm the probe device works before testing the cgroup denial.
    const probe = openPath(linux.AT.FDCWD, "/dev/loop-control", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return error.SkipZigTest;
    closeFd(probe);
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/dev");
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrint(allocator, "{s}/rootfs", .{absolute});
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const denied = try std.fmt.allocPrintSentinel(allocator, "{s}/dev/denied", .{rootfs}, 0);
    defer allocator.free(denied);
    try checkResult(linux.mknod(denied, linux.S.IFCHR | 0o600, (10 << 8) | 237));
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-devices-{d}", .{linux.getpid()});
    defer allocator.free(path);
    const devices = try oci.prepareDevices(allocator, null);
    defer oci.freeDevices(allocator, devices);
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = "v1-devices",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = path,
        .devices = devices,
        .mounts = &.{
            .{ .destination = "/bin", .source = "/bin", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
            .{ .destination = "/lib", .source = "/lib", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
        },
        .resources = .{ .devices = &.{.{ .allow = false }} },
        .start_hooks = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "exec 3< /dev/null || exit 1; if (exec 4< /dev/denied) 2>/dev/null; then exit 2; fi; exit 0" },
            .timeout_seconds = 2,
        }},
    });
    defer allocator.free(handle.starttime);
    defer backend.delete(handle) catch {};
    try std.testing.expect(try backend.alive(handle));
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(reader);
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
    // Delete must rediscover hierarchies even when the saved init PID is gone.
    try backend.delete(.{ .id = handle.id, .pid = 0, .starttime = "", .cgroup_path = path });
    try std.testing.expect(!try backend.alive(handle));
}

test "linux v1 missing optional controllers are ignored and required limits fail" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    for ([_]Resources{
        .{ .memory = .{ .limit = 64 } }, .{ .pids = .{ .limit = 32 } }, .{ .devices = &.{.{ .allow = false }} },
    }) |resources| {
        const writes = try v1Writes(allocator, resources, &.{});
        defer freeV1Writes(allocator, writes);
        try std.testing.expectError(error.CgroupWriteFailed, applyV1Writes(allocator, &.{}, writes, resources, &.{}, "missing"));
    }
    const resources: Resources = .{ .cpu = .{ .shares = 1024 }, .block_io = .{ .weight = 100 } };
    const writes = try v1Writes(allocator, resources, &.{});
    defer freeV1Writes(allocator, writes);
    try applyV1Writes(allocator, &.{}, writes, resources, &.{}, "missing");
}

test "linux cgroup creation reuses parents but rejects existing leaves" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign");
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_][]const u8{ "foreign", "parent/foreign" }) |path| {
        const result = walkCgroup(root, path, true, &.{});
        if (result) |fd| {
            if (fd) |opened| closeFd(opened);
        } else |_| {}
        try std.testing.expectError(error.CreateFailed, result);
        const existing = (try walkCgroup(root, path, false, &.{})).?;
        closeFd(existing);
    }
    const owned = (try walkCgroup(root, "parent/owned", true, &.{})).?;
    closeFd(owned);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "parent/owned", false, &.{}));
}

test "linux cgroup creation enables requested controllers and ordinary lookups leave them alone" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "parent", .default_dir);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const owned = (try walkCgroup(root, "parent/owned", true, &.{.{ .name = "pids.max", .value = "5" }})).?;
    closeFd(owned);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+pids ", enabled);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "sentinel" });
    }
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned/cgroup.subtree_control", .{}));
    // Lookup must not even need the controller files.
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.procs");
    const existing = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    closeFd(existing);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const unchanged = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256));
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings("sentinel", unchanged);
    }
    try tmp.dir.deleteFile(std.testing.io, "cgroup.subtree_control");
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.subtree_control");
    const without_controls = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    closeFd(without_controls);
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "missing", false, &.{}));
}

test "linux cgroup activation never follows subtree control symlinks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "sentinel" });
    try tmp.dir.symLink(std.testing.io, "outside", "cgroup.subtree_control", .{});
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try std.testing.expectError(error.CgroupWriteFailed, walkCgroup(root, "owned", true, &.{.{ .name = "pids.max", .value = "5" }}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned", .{}));
    const unchanged = try tmp.dir.readFileAlloc(std.testing.io, "outside", std.testing.allocator, .limited(256));
    defer std.testing.allocator.free(unchanged);
    try std.testing.expectEqualStrings("sentinel", unchanged);
}

test "linux cgroup activation refuses populated non-root parents even for threaded controllers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "parent", .default_dir);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "1\n" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_]Write{ .{ .name = "pids.max", .value = "5" }, .{ .name = "cpu.weight", .value = "20" } }) |write| {
        for ([_]bool{ true, false }) |create| {
            try std.testing.expectError(error.CgroupWriteFailed, walkCgroup(root, "parent/x", create, &.{write}));
            try std.testing.expect(std.mem.indexOf(u8, last_diagnostic[0..last_diagnostic_len], "has processes") != null);
            const unchanged = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.subtree_control", std.testing.allocator, .limited(64));
            defer std.testing.allocator.free(unchanged);
            try std.testing.expectEqualStrings("", unchanged);
            const kind = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.type", std.testing.allocator, .limited(64));
            defer std.testing.allocator.free(kind);
            try std.testing.expectEqualStrings("domain\n", kind);
            try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/x", .{}));
        }
    }
    // The real hierarchy root has no cgroup.type and is exempt even when populated.
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.type");
    const owned = (try walkCgroup(root, "parent/x", true, &.{.{ .name = "pids.max", .value = "5" }})).?;
    closeFd(owned);
    const enabled = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.subtree_control", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(enabled);
    try std.testing.expectEqualStrings("+pids ", enabled);
    const procs = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.procs", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(procs);
    try std.testing.expectEqualStrings("1\n", procs);
}

test "linux cgroup update walk enables only ancestors without creating missing directories" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned");
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.procs", .data = "1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.subtree_control", .data = "sentinel" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const writes: []const Write = &.{.{ .name = "memory.max", .value = "64" }};
    const owned = (try walkCgroup(root, "parent/owned", false, writes)).?;
    closeFd(owned);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+memory ", enabled);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    }
    const leaf = try tmp.dir.readFileAlloc(std.testing.io, "parent/owned/cgroup.subtree_control", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(leaf);
    try std.testing.expectEqualStrings("sentinel", leaf);
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "parent/missing/child", false, writes));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/missing", .{}));
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+memory ", enabled);
    }
}

test "linux cgroup removal deletes nested children and preserves sibling cgroups" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/other");
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign/keep");
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "parent/foreign/keep", .{});
    try removeCgroup(root, "parent/owned");
    try removeCgroup(root, "missing/container");
}

test "linux create cleanup preserves a replacement cgroup at the same path" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned");
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const original = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    defer closeFd(original);
    try tmp.dir.deleteDir(std.testing.io, "parent/owned");
    try removeCreatedCgroup(root, "parent/owned", original);

    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    try removeCreatedCgroup(root, "parent/owned", original);
    _ = try tmp.dir.statFile(std.testing.io, "parent/owned/child/grandchild", .{});

    const replacement = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    defer closeFd(replacement);
    try removeCreatedCgroup(root, "parent/owned", replacement);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned", .{}));
}

test "linux child cgroup cleanup leaves control files and symlinks untouched" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "outside/keep");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "owned/cgroup.events", .data = "populated 0\n" });
    try tmp.dir.symLink(std.testing.io, "../outside", "owned/escape", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const owned = (try walkCgroup(root, "owned", false, &.{})).?;
    defer closeFd(owned);
    try removeCgroupChildren(owned, "owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned/child", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "owned/cgroup.events", .{});
    _ = try tmp.dir.statFile(std.testing.io, "owned/escape", .{});
    _ = try tmp.dir.statFile(std.testing.io, "outside/keep", .{});
}

/// Walk through pinned directory fds so symlinks cannot redirect cgroup writes.
/// Enable requested controllers in every ancestor before descending to the leaf.
/// Creation requires a new leaf. Nested paths can still change controllers in
/// existing parents, including other containers' cgroups. Like runc, config is trusted.
fn walkCgroup(root: posix.fd_t, path: []const u8, create: bool, writes: []const Write) Backend.Error!?posix.fd_t {
    try validateCgroupPath(path);
    var current = try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var controller_buffer: [64]u8 = undefined;
    const controllers = enabledControllers(&controller_buffer, writes);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (controllers.len != 0) try enableCgroupControllers(current, controllers, path);
        if (create) {
            const result = linux.mkdirat(current, name, 0o755);
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .EXIST => {
                    if (components.peek() == null) {
                        reportDiagnostic("cgroup '{s}' already exists", .{path});
                        return error.CreateFailed;
                    }
                },
                else => try checkResult(result),
            }
        }
        const result = linux.openat(current, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => {
                closeFd(current);
                current = @intCast(result);
            },
            .NOENT => {
                if (create) return error.CreateFailed;
                closeFd(current);
                return null;
            },
            else => try checkResult(result),
        }
    }
    return current;
}

// A populated non-root cgroup cannot hold domain controllers, and threaded
// ones alone would make it a thread root whose new children are invalid.
fn enableCgroupControllers(dir: posix.fd_t, controllers: []const u8, path: []const u8) Backend.Error!void {
    // cgroup.type exists everywhere except the real root, which is exempt.
    if (linux.errno(linux.faccessat(dir, "cgroup.type", linux.F_OK, 0)) == .SUCCESS) {
        const procs = try readCgroupFile(std.heap.page_allocator, dir, "cgroup.procs");
        defer std.heap.page_allocator.free(procs);
        if (std.mem.trim(u8, procs, " \t\n").len != 0) {
            reportDiagnostic("cannot enable cgroup controllers for '{s}': a parent cgroup has processes; move them into a child cgroup first", .{path});
            return error.CgroupWriteFailed;
        }
    }
    try writeCgroupFile(dir, "cgroup.subtree_control", controllers, path);
}

fn writeCgroupFile(dir: posix.fd_t, filename: []const u8, value: []const u8, path: []const u8) Backend.Error!void {
    if (filename.len == 0 or std.mem.indexOfAny(u8, filename, "/\x00") != null or
        std.mem.eql(u8, filename, ".") or std.mem.eql(u8, filename, "..")) return error.InvalidPath;
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{filename}) catch return error.InvalidPath;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cgroup '{s}' cannot open {s}: {s}", .{ path, filename, @tagName(err) });
                return error.CgroupWriteFailed;
            },
        }
    };
    defer closeFd(fd);
    var offset: usize = 0;
    while (offset < value.len) {
        const result = linux.write(fd, value[offset..].ptr, value.len - offset);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.CgroupWriteFailed;
                offset += result;
            },
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cgroup '{s}' cannot write {s} = '{s}': {s}", .{ path, filename, value, @tagName(err) });
                return error.CgroupWriteFailed;
            },
        }
    }
}

fn cgroupPopulated(dir: posix.fd_t) Backend.Error!bool {
    const fd = try openPath(dir, "cgroup.events", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var buffer: [256]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) break;
                used += result;
            },
            .INTR => continue,
            else => return error.CgroupDeleteFailed,
        }
    }
    var fields = std.mem.tokenizeAny(u8, buffer[0..used], " \t\n");
    while (fields.next()) |key| {
        const value = fields.next() orelse return error.CgroupDeleteFailed;
        if (std.mem.eql(u8, key, "populated")) {
            if (std.mem.eql(u8, value, "0")) return false;
            if (std.mem.eql(u8, value, "1")) return true;
            return error.CgroupDeleteFailed;
        }
    }
    return error.CgroupDeleteFailed;
}

fn removeCreatedCgroup(root: posix.fd_t, path: []const u8, cgroup: posix.fd_t) Backend.Error!void {
    var owned: linux.Statx = undefined;
    try checkResult(linux.statx(cgroup, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &owned));
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return error.InvalidPath;
    var current: linux.Statx = undefined;
    const result = linux.statx(root, name, linux.AT.SYMLINK_NOFOLLOW, .{ .INO = true }, &current);
    switch (linux.errno(result)) {
        .NOENT, .NOTDIR => return,
        else => try checkResult(result),
    }
    if (!owned.mask.INO or !current.mask.INO) return error.CgroupDeleteFailed;
    // Forced deletion can let another container reuse this path before create unwinds.
    if (owned.dev_major != current.dev_major or owned.dev_minor != current.dev_minor or owned.ino != current.ino) return;
    try removeCgroup(root, path);
}

fn removeCgroup(root: posix.fd_t, path: []const u8) Backend.Error!void {
    try validateCgroupPath(path);
    const parent = if (std.fs.path.dirname(path)) |parent_path|
        (try walkCgroup(root, parent_path, false, &.{})) orelse return
    else
        try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(parent);
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(path)}) catch return error.InvalidPath;
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..50) |_| {
        const opened = linux.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .SUCCESS => {
                const cgroup: posix.fd_t = @intCast(opened);
                defer closeFd(cgroup);
                try removeCgroupChildren(cgroup, path);
            },
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cannot open cgroup '{s}' for removal: {s}", .{ path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
        const result = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => return,
            .INTR => continue,
            .BUSY, .NOTEMPTY => _ = linux.nanosleep(&delay, null),
            else => |err| {
                reportDiagnostic("cannot remove cgroup '{s}': {s}", .{ path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
    }
    reportDiagnostic("cgroup '{s}' is still busy after waiting for members to exit", .{path});
    return error.CgroupDeleteFailed;
}

/// Remove descendants before their parent, without touching cgroup control files.
fn removeCgroupChildren(dir: posix.fd_t, path: []const u8) Backend.Error!void {
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.getdents64(dir, &buffer, buffer.len);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cannot read child cgroups of '{s}': {s}", .{ path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
        if (result == 0) return;
        var offset: usize = 0;
        while (offset < result) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            offset += entry.reclen;
            if (entry.type != linux.DT.DIR) continue;
            const name_ptr: [*]const u8 = &entry.name;
            const padded_name = name_ptr[0 .. entry.reclen - @offsetOf(linux.dirent64, "name")];
            const name_len = std.mem.indexOfScalar(u8, padded_name, 0).?;
            const name = name_ptr[0..name_len :0];
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            try removeCgroup(dir, name);
        }
    }
}

const CreateResponse = extern struct {
    pid: i32 = 0,
    failure: u32 = 0,
    starttime: u64 = 0,
    rootfs_mount_id: u64 = 0,
    message: [512]u8 = @splat(0),
    message_len: u32 = 0,

    fn failureError(self: *const CreateResponse) ?Backend.Error {
        if (self.failure == 0) return null;
        last_diagnostic_len = @min(self.message_len, last_diagnostic.len);
        @memcpy(last_diagnostic[0..last_diagnostic_len], self.message[0..last_diagnostic_len]);
        return @errorCast(@errorFromInt(@as(u16, @intCast(self.failure))));
    }
};

const ProcStat = struct {
    state: u8,
    starttime: []const u8,

    fn matches(self: ProcStat, starttime: []const u8) bool {
        if (self.state == 'Z' or self.state == 'X') return false;
        return std.mem.eql(u8, starttime, self.starttime);
    }
};

fn parseProcStat(bytes: []const u8) Backend.Error!ProcStat {
    // comm can contain spaces and parentheses; only its final ')' delimits it.
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.LivenessFailed;
    var fields = std.mem.tokenizeAny(u8, bytes[end + 1 ..], " \t\n");
    const state = fields.next() orelse return error.LivenessFailed;
    if (state.len != 1) return error.LivenessFailed;
    // State is field 3; skip fields 4 through 21 to reach starttime.
    for (4..22) |_| _ = fields.next() orelse return error.LivenessFailed;
    const starttime = fields.next() orelse return error.LivenessFailed;
    _ = std.fmt.parseInt(u64, starttime, 10) catch return error.LivenessFailed;
    return .{ .state = state[0], .starttime = starttime };
}

fn readProcStat(pid: i32, buffer: []u8) Backend.Error!ProcStat {
    return readProcStatAt(linux.AT.FDCWD, pid, buffer);
}

fn readProcStatAt(proc_dir: posix.fd_t, pid: i32, buffer: []u8) Backend.Error!ProcStat {
    var path_buffer: [64]u8 = undefined;
    const path = if (proc_dir == linux.AT.FDCWD)
        std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/stat", .{pid}) catch unreachable
    else
        std.fmt.bufPrintZ(&path_buffer, "{d}/stat", .{pid}) catch unreachable;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(proc_dir, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            .NOENT, .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    };
    defer closeFd(fd);
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return parseProcStat(buffer[0..used]);
                used += result;
            },
            .INTR => continue,
            .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    }
    return error.LivenessFailed;
}

fn processString(allocator: std.mem.Allocator, value: []const u8) Backend.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidProcess;
    return allocator.dupeZ(u8, value);
}

fn pathString(allocator: std.mem.Allocator, value: []const u8) Backend.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidPath;
    return allocator.dupeZ(u8, value);
}

fn preparePaths(allocator: std.mem.Allocator, paths: []const []const u8) Backend.Error![]const [:0]const u8 {
    const prepared = try allocator.alloc([:0]const u8, paths.len);
    for (paths, prepared) |path, *value| {
        if (!std.mem.startsWith(u8, path, "/")) return error.InvalidPath;
        value.* = try pathString(allocator, path);
    }
    return prepared;
}

fn checkResult(result: usize) Backend.Error!void {
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .AGAIN, .MFILE, .NFILE => return error.SystemResources,
        .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

// Zig 0.16 exposes fork/pipe/waitpid through std.posix.system.
fn forkProcess() Backend.Error!i32 {
    const result = posix.system.fork();
    switch (posix.errno(result)) {
        .SUCCESS => return @intCast(result),
        .NOMEM, .AGAIN => return error.SystemResources,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

fn makePipe() Backend.Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    switch (posix.errno(posix.system.pipe2(&fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => return fds,
        .MFILE, .NFILE => return error.SystemResources,
        else => return error.CreateFailed,
    }
}

fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

/// Linux descriptor passing, shared by init and the frontend. No allocation
/// or std.Io machinery: these helpers also run after fork.
pub const console = struct {
    const Rights = extern struct {
        header: linux.cmsghdr,
        fd: posix.fd_t,
    };
    const rights_len = @sizeOf(linux.cmsghdr) + @sizeOf(posix.fd_t);

    pub fn socketpair() Backend.Error![2]posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var fds: [2]posix.fd_t = undefined;
        try checkResult(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
        errdefer for (fds) |fd| closeFd(fd);
        for (&fds) |*fd| {
            if (fd.* <= 2) {
                const moved = linux.fcntl(fd.*, linux.F.DUPFD_CLOEXEC, 3);
                try checkResult(moved);
                closeFd(fd.*);
                fd.* = @intCast(moved);
            }
        }
        return fds;
    }

    pub fn sendFd(socket: posix.fd_t, fd: posix.fd_t) Backend.Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        rights.header = .{ .len = rights_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
        rights.fd = fd;
        const data = "ptmx";
        const iov = [_]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
        const message: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        while (true) {
            const result = linux.sendmsg(socket, &message, linux.MSG.NOSIGNAL);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.ConsoleFailed;
                    // Ancillary data is attached to the first byte, even when
                    // a stream write is short. Do not send the rights twice.
                    if (result < data.len and !writeAll(socket, data[result..])) return error.ConsoleFailed;
                    return;
                },
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        }
    }

    pub fn receiveFd(socket: posix.fd_t) Backend.Error!posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        var data: [4]u8 = undefined;
        var iov = [_]posix.iovec{.{ .base = &data, .len = data.len }};
        var message: linux.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        const count = while (true) {
            const result = linux.recvmsg(socket, &message, linux.MSG.CMSG_CLOEXEC | linux.MSG.WAITALL);
            switch (linux.errno(result)) {
                .SUCCESS => break result,
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        };
        if (message.controllen < rights_len or rights.header.level != linux.SOL.SOCKET or
            rights.header.type != linux.SCM.RIGHTS or rights.header.len < rights_len)
            return error.ConsoleFailed;
        // The aligned control buffer can hold a second fd in its padding.
        // Close all delivered rights, including on truncated/malformed input.
        const bytes = std.mem.asBytes(&rights);
        const control_end = @min(message.controllen, @min(rights.header.len, bytes.len));
        var offset: usize = rights_len;
        while (offset + @sizeOf(posix.fd_t) <= control_end) : (offset += @sizeOf(posix.fd_t)) {
            const extra = std.mem.bytesToValue(posix.fd_t, bytes[offset..][0..@sizeOf(posix.fd_t)]);
            closeFd(extra);
        }
        errdefer closeFd(rights.fd);
        if (rights.header.len != rights_len or message.flags & linux.MSG.CTRUNC != 0 or count == 0)
            return error.ConsoleFailed;
        if (count < data.len and !readAll(socket, data[count..])) return error.ConsoleFailed;
        if (!std.mem.eql(u8, &data, "ptmx")) return error.ConsoleFailed;
        return rights.fd;
    }
};

test "linux SCM_RIGHTS roundtrip preserves a descriptor across forwarding" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer for (sockets) |fd| closeFd(fd);
    const forwarded = try console.socketpair();
    defer for (forwarded) |fd| closeFd(fd);
    const pipe = try makePipe();
    defer for (pipe) |fd| closeFd(fd);
    try console.sendFd(sockets[0], pipe[0]);
    const received = try console.receiveFd(sockets[1]);
    defer closeFd(received);
    try std.testing.expect(linux.fcntl(received, linux.F.GETFD, 0) & linux.FD_CLOEXEC != 0);
    try console.sendFd(forwarded[0], received);
    const final = try console.receiveFd(forwarded[1]);
    defer closeFd(final);
    try std.testing.expect(writeAll(pipe[1], "x"));
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(final, &byte));
    try std.testing.expectEqualStrings("x", &byte);
}

test "linux console receiver rejects a message without descriptor rights and EOF" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer closeFd(sockets[0]);
    try std.testing.expect(writeAll(sockets[1], "ptmx"));
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
    closeFd(sockets[1]);
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
}

test "linux namespace descriptors reject a mismatched configured type" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const fd = try openPath(linux.AT.FDCWD, "/proc/self/ns/net", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(fd);
    // Kernels without NS_GET_NSTYPE cannot exercise the type comparison.
    if (linux.errno(linux.ioctl(fd, linux.IOCTL.IO(0xb7, 3), 0)) == .NOTTY) return error.SkipZigTest;
    try validateNamespaceFd(fd, linux.CLONE.NEWNET);
    try std.testing.expectError(error.InvalidConfig, validateNamespaceFd(fd, linux.CLONE.NEWUTS));
}

test "linux console setup binds its slave to dev console and sends its master" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const sockets = try console.socketpair();
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(sockets[0]);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        checkResult(linux.mount("tmpfs", "/dev", "tmpfs", linux.MS.NOSUID, 0)) catch linux.exit_group(1);
        checkResult(linux.mkdir("/dev/pts", 0o755)) catch linux.exit_group(1);
        checkResult(linux.mount("devpts", "/dev/pts", "devpts", linux.MS.NOSUID | linux.MS.NOEXEC, @intFromPtr("newinstance,ptmxmode=666,mode=620"))) catch linux.exit_group(1);
        checkResult(linux.symlink("pts/ptmx", "/dev/ptmx")) catch linux.exit_group(1);
        setupConsole(sockets[1], true) catch linux.exit_group(1);
        closeFd(sockets[1]);
        var console_stat: linux.Statx = undefined;
        var slave_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(1);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &slave_stat)) catch linux.exit_group(1);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != slave_stat.ino or
            console_stat.dev_major != slave_stat.dev_major or console_stat.dev_minor != slave_stat.dev_minor)
            linux.exit_group(1);
        var session: i32 = undefined;
        for (0..3) |fd| {
            checkResult(linux.ioctl(@intCast(fd), linux.T.IOCGSID, @intFromPtr(&session))) catch linux.exit_group(1);
            if (session != linux.getpid()) linux.exit_group(1);
            if (linux.fcntl(@intCast(fd), linux.F.GETFD, 0) != 0) linux.exit_group(1);
        }
        if (!writeAll(1, "console\n")) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(1);
        linux.exit_group(0);
    }
    closeFd(sockets[1]);
    defer closeFd(sockets[0]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    const master = try console.receiveFd(sockets[0]);
    defer closeFd(master);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(master, &output));
    try std.testing.expectEqualStrings("console\r\n", &output);
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
}

fn setupConsole(socket: posix.fd_t, mount_console: bool) Backend.Error!void {
    const pts = consolePath("/dev/pts", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch
        return error.MissingDevpts;
    defer closeFd(pts);
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(pts), @intFromPtr(&fs)));
    if (fs[0] != 0x1cd1) return error.MissingDevpts; // DEVPTS_SUPER_MAGIC
    const master = try consolePath("/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    defer closeFd(master);
    var unlock: i32 = 0;
    try checkResult(linux.ioctl(master, linux.T.IOCSPTLCK, @intFromPtr(&unlock)));
    const slave_flags: linux.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
    var slave_path_buffer: [32]u8 = undefined;
    var slave_path: ?[:0]const u8 = null;
    const opened_slave: posix.fd_t = peer: {
        const result = linux.ioctl(master, linux.T.IOCGPTPEER, @as(u32, @bitCast(slave_flags)));
        switch (linux.errno(result)) {
            .SUCCESS => break :peer @intCast(result),
            .NOTTY, .INVAL, .NOSYS => {
                var number: u32 = undefined;
                try checkResult(linux.ioctl(master, linux.T.IOCGPTN, @intFromPtr(&number)));
                const path = std.fmt.bufPrintZ(&slave_path_buffer, "/dev/pts/{d}", .{number}) catch return error.ConsoleFailed;
                slave_path = path;
                break :peer try openPath(linux.AT.FDCWD, path, slave_flags);
            },
            else => return error.ConsoleFailed,
        }
    };
    const slave = try consoleAboveStdio(opened_slave);
    defer closeFd(slave);
    if (mount_console) {
        const root = try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root);
        const target = try consoleAboveStdio(try mountDestination(root, "/dev/console", true, true));
        defer closeFd(target);
        bind: {
            const cloned = linux.syscall3(.open_tree, @intCast(slave), @intFromPtr(""), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | linux.AT.EMPTY_PATH);
            if (linux.errno(cloned) != .NOSYS and linux.errno(cloned) != .PERM) {
                try checkResult(cloned);
                const tree: posix.fd_t = @intCast(cloned);
                defer closeFd(tree);
                var flags = std.mem.zeroes(linux.MOVE_MOUNT);
                flags.F_EMPTY_PATH = true;
                flags.T_EMPTY_PATH = true;
                const moved = linux.move_mount(tree, "", target, "", flags);
                if (linux.errno(moved) != .NOSYS and linux.errno(moved) != .PERM) {
                    try checkResult(moved);
                    break :bind;
                }
            }
            // Older kernels and seccomp policies still need procfs for the descriptor paths.
            var source_buffer: [64]u8 = undefined;
            var target_buffer: [64]u8 = undefined;
            try checkResult(linux.mount(slave_path orelse fdPath(&source_buffer, slave), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
        }
    }
    try checkResult(linux.setsid());
    try checkResult(linux.ioctl(slave, linux.T.IOCSCTTY, 0));
    for (0..3) |fd| {
        try checkResult(linux.dup2(slave, @intCast(fd)));
        // dup2(fd, fd) preserves CLOEXEC when stdio was initially closed.
        try checkResult(linux.fcntl(@intCast(fd), linux.F.SETFD, 0));
    }
    try console.sendFd(socket, master);
}

fn consoleAboveStdio(fd: posix.fd_t) Backend.Error!posix.fd_t {
    if (fd > 2) return fd;
    defer closeFd(fd);
    const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
    try checkResult(moved);
    return @intCast(moved);
}

fn consolePath(path: [*:0]const u8, flags: linux.O) Backend.Error!posix.fd_t {
    return consoleAboveStdio(try openPath(linux.AT.FDCWD, path, flags));
}

fn childError(message: []const u8, err: anyerror) void {
    reportDiagnostic("{s}{s}", .{ message, @errorName(err) });
}

fn mappedRootID(mappings: []const oci.Spec.IDMapping) Backend.Error!u32 {
    for (mappings) |mapping| {
        if (mapping.containerID == 0 and mapping.size > 0) return mapping.hostID;
    }
    return error.InvalidConfig;
}

fn formatIDMappings(allocator: std.mem.Allocator, mappings: []const oci.Spec.IDMapping) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (mappings) |mapping| {
        try text.print(allocator, "{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
    }
    return text.toOwnedSlice(allocator);
}

/// The runtime parent writes maps from its original user namespace.
fn writeUserMappings(pid: i32, gid_map: []const u8, uid_map: []const u8) Backend.Error!void {
    var path_buffer: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}", .{pid}) catch unreachable;
    const dir = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    // setgroups defaults to "allow"; only rootless setup needs a "deny" write.
    try writeMappingFile(dir, "gid_map", gid_map);
    try writeMappingFile(dir, "uid_map", uid_map);
}

fn writeMappingFile(dir: posix.fd_t, name: [*:0]const u8, text: []const u8) Backend.Error!void {
    const fd = try openPath(dir, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
    defer closeFd(fd);
    // proc ID maps must be supplied in a single write.
    while (true) {
        const result = linux.write(fd, text.ptr, text.len);
        if (linux.errno(result) == .INTR) continue;
        if (linux.errno(result) == .INVAL) return error.InvalidConfig;
        try checkResult(result);
        if (result != text.len) return error.CreateFailed;
        return;
    }
}

/// Filter before fork so warnings and any stderr bookkeeping stay in the parent.
fn kernelCapabilities(configured: Backend.Capabilities) Backend.Error!Backend.Capabilities {
    var supported: u64 = 0;
    for (0..64) |cap| {
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        supported |= @as(u64, 1) << @intCast(cap);
    }
    var result = configured;
    var ignored: u64 = 0;
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
        ignored |= @field(result, field.name) & ~supported;
        @field(result, field.name) &= supported;
    }
    for (0..64) |cap| {
        if (ignored & (@as(u64, 1) << @intCast(cap)) != 0)
            std.debug.print("igvano: warning: ignoring capability {d}, unsupported by this kernel\n", .{cap});
    }
    return result;
}

fn waitChild(pid: i32) Backend.Error!u32 {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => return @bitCast(status),
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

fn readAll(fd: posix.fd_t, bytes: []u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn waitExecReady(fd: posix.fd_t) Backend.Error!void {
    var response: CreateResponse = .{};
    const bytes = std.mem.asBytes(&response);
    while (true) {
        const result = posix.system.read(fd, bytes.ptr, 1);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return;
                if (!readAll(fd, bytes[1..])) return error.CreateFailed;
                return response.failureError() orelse error.CreateFailed;
            },
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn failCreate(fd: posix.fd_t, err: Backend.Error) noreturn {
    var response: CreateResponse = .{ .failure = @intFromError(err), .message_len = @intCast(last_diagnostic_len) };
    @memcpy(response.message[0..last_diagnostic_len], last_diagnostic[0..last_diagnostic_len]);
    _ = writeAll(fd, std.mem.asBytes(&response));
    linux.exit_group(1);
}

const PreparedMount = struct {
    destination: [:0]const u8,
    source: ?[:0]const u8,
    type: ?[:0]const u8,
    flags: u32,
    propagation: u32,
    data: [:0]const u8,
    recursive_readonly: ?bool = null,
    /// Created after this mount, before a following tmpfs readonly remount.
    symlinks: []const Backend.Symlink = &.{},
};

const PreparedDevice = struct {
    path: [:0]const u8,
    mode: u32,
    dev: u32,
    uid: u32 = 0,
    gid: u32 = 0,
};

const CapabilityHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,
};

fn openPath(dir_fd: posix.fd_t, path: [*:0]const u8, flags: linux.O) Backend.Error!posix.fd_t {
    const result = linux.openat(dir_fd, path, flags, 0);
    try checkResult(result);
    return @intCast(result);
}

fn fileType(fd: posix.fd_t) Backend.Error!u16 {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    return stat.mode & linux.S.IFMT;
}

/// Walk beneath a pinned root, rejecting symlinks in every component. Mounting
/// through the returned fd also avoids a destination swap between lookup/mount.
fn mountDestination(root_fd: posix.fd_t, destination: []const u8, is_file: bool, create: bool) Backend.Error!posix.fd_t {
    var current = try openPath(root_fd, ".", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    var component = components.next() orelse {
        if (is_file) return error.InvalidPath;
        return current;
    };
    while (true) {
        // Frontend paths are normalized; reject traversal from library callers too.
        if (std.mem.eql(u8, component, "..") or std.mem.eql(u8, component, ".")) return error.InvalidPath;
        const next = components.next();
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (next == null and is_file) {
            if (create) {
                const created = linux.openat(current, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o644);
                switch (linux.errno(created)) {
                    .SUCCESS => closeFd(@intCast(created)),
                    .EXIST => {},
                    else => try checkResult(created),
                }
            }
            const fd = try openPath(current, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
            errdefer closeFd(fd);
            const kind = try fileType(fd);
            if (kind == linux.S.IFLNK or kind == linux.S.IFDIR) return error.InvalidPath;
            closeFd(current);
            return fd;
        }
        if (create) {
            const created = linux.mkdirat(current, name, 0o755);
            switch (linux.errno(created)) {
                .SUCCESS, .EXIST => {},
                else => try checkResult(created),
            }
        }
        const fd = try openPath(current, name, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        closeFd(current);
        current = fd;
        component = next orelse return current;
    }
}

fn fdPath(buffer: []u8, fd: posix.fd_t) [:0]u8 {
    return std.fmt.bufPrintZ(buffer, "/proc/self/fd/{d}", .{fd}) catch unreachable;
}

fn remountFlags(target_fd: posix.fd_t, requested: u32) Backend.Error!u32 {
    if (comptime builtin.os.tag == .linux) {
        // Linux statfs uses native words, except for the two-int fsid.
        const Statfs = extern struct {
            type: usize,
            bsize: usize,
            blocks: usize,
            bfree: usize,
            bavail: usize,
            files: usize,
            ffree: usize,
            fsid: [2]i32,
            namelen: usize,
            frsize: usize,
            flags: usize,
            spare: [4]usize,
        };
        var fs: Statfs = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(target_fd), @intFromPtr(&fs)));
        return lockedMountFlags(requested, fs.flags);
    } else {
        return error.NotImplemented;
    }
}

fn bindRemount(target_fd: posix.fd_t, target: [*:0]const u8, requested: u32) Backend.Error!void {
    const result = linux.mount(null, target, null, requested, 0);
    if (linux.errno(result) != .PERM) return checkResult(result);
    // Retry locked flags on EPERM, including in an inherited user namespace.
    // Privileged callers may change these flags, so first honor their request.
    const flags = try remountFlags(target_fd, requested);
    try checkResult(linux.mount(null, target, null, flags, 0));
}

const RootfsStep = struct {
    operation: []const u8 = "",
    path: []const u8 = "",
    source: ?[]const u8 = null,
    fs_type: ?[]const u8 = null,

    fn report(self: RootfsStep, err: anyerror) void {
        reportDiagnostic("cannot prepare rootfs: {s}{s}{s}{s}{s}{s}{s}{s}{s}: {s}", .{
            self.operation,
            if (self.source != null) " " else "",
            self.source orelse "",
            if (self.source != null) " ->" else "",
            if (self.path.len != 0) " " else "",
            self.path,
            if (self.fs_type != null) " (" else "",
            self.fs_type orelse "",
            if (self.fs_type != null) ")" else "",
            @errorName(err),
        });
    }
};

fn applyMount(rootfs: [:0]const u8, root_fd: posix.fd_t, mount: PreparedMount, private_mount_namespace: bool, step: *RootfsStep) Backend.Error!void {
    const ms = linux.MS;
    const bind = mount.flags & ms.BIND != 0;
    step.* = .{ .operation = "open bind source", .source = mount.source, .path = mount.destination };
    const source_fd: ?posix.fd_t = if (bind)
        try openPath(linux.AT.FDCWD, (mount.source orelse return error.InvalidConfig).ptr, .{ .PATH = true, .CLOEXEC = true })
    else
        null;
    defer if (source_fd) |fd| closeFd(fd);
    step.operation = "stat bind source";
    const is_file = if (source_fd) |fd| try fileType(fd) != linux.S.IFDIR else false;
    step.* = .{ .operation = "prepare mount destination", .path = mount.destination };
    var target_fd = try mountDestination(root_fd, mount.destination, is_file, true);
    defer closeFd(target_fd);
    var target_buffer: [64]u8 = undefined;
    var source_buffer: [64]u8 = undefined;
    const source: ?[*:0]const u8 = if (source_fd) |fd|
        fdPath(&source_buffer, fd).ptr
    else if (mount.source) |value|
        value.ptr
    else
        null;
    step.* = .{
        .operation = if (bind) "bind" else "mount",
        .path = mount.destination,
        .source = if (bind) mount.source else null,
        .fs_type = if (bind) null else mount.type,
    };
    try checkResult(linux.mount(
        source,
        fdPath(&target_buffer, target_fd),
        if (bind) null else if (mount.type) |value| value.ptr else null,
        if (bind) mount.flags & (ms.BIND | ms.REC) else mount.flags,
        if (bind or mount.data.len == 0) 0 else @intFromPtr(mount.data.ptr),
    ));
    // The original fd pins the covered mount. Reopen to address the new mount
    // for remount and propagation changes, still without following symlinks.
    step.operation = "open mounted destination";
    const mounted_fd = if (std.mem.eql(u8, mount.destination, "/"))
        try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        try mountDestination(root_fd, mount.destination, is_file, false);
    closeFd(target_fd);
    target_fd = mounted_fd;
    // A bind inherits its source's peer groups even under a private parent.
    // Cut them on this copy before restrictions can propagate back to the host.
    step.operation = "mount private propagation";
    if (bind and !private_mount_namespace)
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, ms.PRIVATE | ms.REC, 0));
    if (bind and mount.flags & ~@as(u32, ms.BIND | ms.REC) != 0) {
        step.operation = "bind remount";
        try bindRemount(target_fd, fdPath(&target_buffer, target_fd), (mount.flags & ~@as(u32, ms.REC)) | ms.BIND | ms.REMOUNT);
    }
    if (mount.recursive_readonly) |readonly| {
        step.operation = "mount_setattr";
        const MountAttr = extern struct {
            attr_set: u64,
            attr_clr: u64,
            propagation: u64 = 0,
            userns_fd: u64 = 0,
        };
        const attr: MountAttr = .{
            .attr_set = if (readonly) 1 else 0, // MOUNT_ATTR_RDONLY
            .attr_clr = if (readonly) 0 else 1,
        };
        // Zig 0.16's wrapper omits the attr pointer and size; use the full ABI.
        try checkResult(linux.syscall5(.mount_setattr, @intCast(target_fd), @intFromPtr(""), linux.AT.EMPTY_PATH | linux.AT.RECURSIVE, @intFromPtr(&attr), @sizeOf(MountAttr)));
    }
    if (mount.propagation != 0) {
        step.operation = "mount propagation";
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, mount.propagation, 0));
    }
}

fn validateDeviceNode(fd: posix.fd_t, device: PreparedDevice) Backend.Error!void {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    const kind = device.mode & linux.S.IFMT;
    if (stat.mode & linux.S.IFMT != kind) return error.InvalidPath;
    if (kind == linux.S.IFCHR or kind == linux.S.IFBLK) {
        // Decode the Linux device number passed to mknodat.
        const major = (device.dev >> 8) & 0xfff;
        const minor = (device.dev & 0xff) | ((device.dev >> 12) & 0xfff00);
        if (stat.rdev_major != major or stat.rdev_minor != minor) return error.InvalidPath;
    }
}

fn createDevice(root_fd: posix.fd_t, device: PreparedDevice, private_mount_namespace: bool, step: *RootfsStep) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        step.* = .{ .operation = "prepare device parent", .path = device.path };
        const parent = std.fs.path.dirname(device.path) orelse return error.InvalidPath;
        const dir = try mountDestination(root_fd, parent, false, true);
        defer closeFd(dir);
        var name_buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&name_buffer, "{s}", .{std.fs.path.basename(device.path)}) catch return error.InvalidPath;
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
        step.operation = "mknod";
        const created = linux.mknodat(dir, name, device.mode, device.dev);
        switch (linux.errno(created)) {
            .SUCCESS => {
                // Pin the new node for metadata updates, even if the name changes.
                step.operation = "open device";
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                step.operation = "validate device";
                try validateDeviceNode(node, device);
                step.operation = "chown device";
                try checkResult(linux.fchownat(node, "", device.uid, device.gid, linux.AT.EMPTY_PATH));
                var buffer: [64]u8 = undefined;
                step.operation = "chmod device";
                try checkResult(linux.fchmodat(linux.AT.FDCWD, fdPath(&buffer, node), device.mode & 0o7777));
            },
            // A configured mount may already supply this device. Preserve it
            // only when its type and device number match the requested node.
            .EXIST => {
                // Deliberately keep existing metadata: this node may come
                // from a bind mount, and rewriting it would change the host.
                step.operation = "open existing device";
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                step.operation = "validate existing device";
                try validateDeviceNode(node, device);
            },
            .PERM => {
                // mknod is forbidden in user namespaces. Like runc, retry an
                // EPERM as a bind, including when the runtime inherited a user ns.
                step.operation = "open device bind source";
                const source = try openPath(linux.AT.FDCWD, device.path, .{ .PATH = true, .CLOEXEC = true });
                defer closeFd(source);
                step.operation = "validate device bind source";
                try validateDeviceNode(source, device);
                step.operation = "prepare device bind destination";
                const target = try mountDestination(root_fd, device.path, true, true);
                defer closeFd(target);
                var source_buffer: [64]u8 = undefined;
                var target_buffer: [64]u8 = undefined;
                step.operation = "bind device";
                try checkResult(linux.mount(fdPath(&source_buffer, source), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
                if (!private_mount_namespace) {
                    step.operation = "device private propagation";
                    const mounted = try mountDestination(root_fd, device.path, true, false);
                    defer closeFd(mounted);
                    try checkResult(linux.mount(null, fdPath(&target_buffer, mounted), null, linux.MS.PRIVATE | linux.MS.REC, 0));
                }
                // Like runc, bind fallback inherits host metadata; changing it
                // here would chmod/chown the host device as well.
            },
            else => try checkResult(created),
        }
    } else {
        return error.NotImplemented;
    }
}

fn setupDevices(root_fd: posix.fd_t, devices: []const PreparedDevice, symlinks: []const Backend.Symlink, private_mount_namespace: bool, step: *RootfsStep) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (devices) |device| try createDevice(root_fd, device, private_mount_namespace, step);
        try setupSymlinks(root_fd, symlinks, step);
    } else {
        return error.NotImplemented;
    }
}

fn setupSymlinks(root_fd: posix.fd_t, symlinks: []const Backend.Symlink, step: *RootfsStep) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (symlinks) |link| {
            step.* = .{ .operation = "prepare symlink parent", .path = link.path };
            if (!std.mem.startsWith(u8, link.path, "/")) return error.InvalidPath;
            const parent = std.fs.path.dirname(link.path) orelse return error.InvalidPath;
            const dir = try mountDestination(root_fd, parent, false, true);
            defer closeFd(dir);
            var buffer: [256]u8 = undefined;
            const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(link.path)}) catch return error.InvalidPath;
            step.operation = "symlink";
            const result = linux.symlinkat(link.target, dir, name);
            switch (linux.errno(result)) {
                .SUCCESS, .EXIST => {},
                else => try checkResult(result),
            }
        }
    } else {
        return error.NotImplemented;
    }
}

const RootfsOptions = struct {
    private_mount_namespace: bool = true,
    console_fd: ?posix.fd_t = null,
    fifo_writable: bool = false,
    propagation: u32 = linux.MS.PRIVATE | linux.MS.REC,
    create_hooks: []const hooks.Prepared = &.{},
    create_hook_state: []const u8 = "",
    masked_paths: []const [:0]const u8 = &.{},
    readonly_paths: []const [:0]const u8 = &.{},
    sysctls: []const Backend.Sysctl = &.{},
    runtime_sync: ?struct { ready_fd: posix.fd_t, go_fd: posix.fd_t } = null,
};

fn sysctlDirectory() Backend.Error!posix.fd_t {
    const opened = linux.openat(linux.AT.FDCWD, "/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(opened) == .NOENT or linux.errno(opened) == .NOTDIR or linux.errno(opened) == .LOOP) return error.MissingProcfs;
    try checkResult(opened);
    const proc: posix.fd_t = @intCast(opened);
    defer closeFd(proc);
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(proc), @intFromPtr(&fs)));
    if (fs[0] != 0x9fa0) return error.MissingProcfs; // PROC_SUPER_MAGIC
    const sys = try openPath(proc, "sys", .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    errdefer closeFd(sys);
    try checkResult(linux.syscall2(.fstatfs, @intCast(sys), @intFromPtr(&fs)));
    if (fs[0] != 0x9fa0) return error.MissingProcfs;
    return sys;
}

/// Namespace policy belongs to the frontend. Walk the translated key beneath
/// a pinned /proc/sys, rejecting symlinks in directories and the final file.
fn writeSysctl(sys: posix.fd_t, setting: Backend.Sysctl) Backend.Error!void {
    if (std.mem.indexOfAny(u8, setting.key, "/\x00") != null or
        std.mem.indexOfAny(u8, setting.value, "\x00\n") != null) return error.InvalidConfig;
    var current = try openPath(sys, ".", .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(current);
    var components = std.mem.splitScalar(u8, setting.key, '.');
    while (components.next()) |component| {
        if (component.len == 0) return error.InvalidConfig;
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (components.peek() != null) {
            const next = try openPath(current, name, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
            closeFd(current);
            current = next;
        } else {
            const fd = try openPath(current, name, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true });
            defer closeFd(fd);
            var offset: usize = 0;
            while (offset < setting.value.len) {
                const result = linux.write(fd, setting.value[offset..].ptr, setting.value.len - offset);
                if (linux.errno(result) == .INTR) continue;
                try checkResult(result);
                if (result == 0) return error.CreateFailed;
                offset += result;
            }
        }
    }
}

fn applySysctls(settings: []const Backend.Sysctl) Backend.Error!void {
    if (settings.len == 0) return;
    var key = settings[0].key;
    errdefer |err| reportDiagnostic("cannot set sysctl {s}{s}: {s}", .{
        key,
        if (err == error.MissingProcfs) " (requires procfs mounted at /proc)" else "",
        @errorName(err),
    });
    const sys = try sysctlDirectory();
    defer closeFd(sys);
    for (settings) |setting| {
        key = setting.key;
        try writeSysctl(sys, setting);
    }
}

/// Paths now resolve entirely inside the container rootfs. Missing targets are
/// ignored; other mount failures must not silently weaken isolation.
fn applyPathRestrictions(masked: []const [:0]const u8, readonly: []const [:0]const u8, step: *RootfsStep) Backend.Error!void {
    const ms = linux.MS;
    for (masked) |path| {
        step.* = .{ .operation = "stat masked path", .path = path };
        var stat: linux.Statx = undefined;
        const result = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        if (!stat.mask.TYPE) return error.CreateFailed;
        step.operation = "masked path";
        if (stat.mode & linux.S.IFMT == linux.S.IFDIR) {
            try checkResult(linux.mount("tmpfs", path, "tmpfs", ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC, 0));
        } else {
            try checkResult(linux.mount("/dev/null", path, null, ms.BIND, 0));
        }
    }
    for (readonly) |path| {
        step.* = .{ .operation = "bind readonly path", .path = path };
        const result = linux.mount(path, path, null, ms.BIND | ms.REC, 0);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        step.operation = "open readonly path";
        const fd = try openPath(linux.AT.FDCWD, path, .{ .PATH = true, .CLOEXEC = true });
        defer closeFd(fd);
        step.operation = "remount readonly path";
        try bindRemount(fd, path, ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
}

/// Like runc, walk up to the containing mount. Only that mount must be
/// private for pivot_root; inherited submounts retain their peer groups.
fn makeRootfsParentPrivate(rootfs: [:0]const u8, step: *RootfsStep) Backend.Error!void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (rootfs.len >= buffer.len) return error.InvalidPath;
    @memcpy(buffer[0..rootfs.len], rootfs);
    var end = rootfs.len;
    while (true) {
        buffer[end] = 0;
        const result = linux.mount(null, buffer[0..end :0], null, linux.MS.PRIVATE, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INVAL => {
                if (end == 1) return error.CreateFailed;
                end = (std.fs.path.dirname(buffer[0..end]) orelse return error.InvalidPath).len;
            },
            else => {
                // Report before this stack-backed parent path goes out of scope.
                step.* = .{ .operation = "mount parent private propagation", .path = "" };
                var message: [std.fs.max_path_bytes + 80]u8 = undefined;
                const text = std.fmt.bufPrint(&message, "cannot prepare rootfs: mount parent private propagation {s}: ", .{buffer[0..end]}) catch unreachable;
                checkResult(result) catch |err| {
                    childError(text, err);
                    // The enclosing setupRootfs diagnostic was already emitted.
                    step.operation = "";
                    return err;
                };
            },
        }
    }
}

/// All paths, hook arguments and state buffers are prepared before fork.
/// Allocating in child2 risks inherited allocator locks (POSIX only permits
/// async-signal-safe work after fork). The raw hook runner needs no allocation.
fn setupRootfs(rootfs: [:0]const u8, mounts: []const PreparedMount, devices: []const PreparedDevice, symlinks: []const Backend.Symlink, readonly: bool, options: RootfsOptions) Backend.Error!void {
    const ms = linux.MS;
    var step: RootfsStep = .{ .operation = "mount propagation", .path = "/" };
    errdefer |err| if (step.operation.len != 0) step.report(err);
    if (options.private_mount_namespace)
        try checkResult(linux.mount(null, "/", null, options.propagation, 0));
    // Shared parents prevent pivot_root; make only the containing mount private.
    // Unbindable sources require temporary recursive private propagation.
    const restore_propagation = options.private_mount_namespace and options.propagation & (ms.SHARED | ms.UNBINDABLE) != 0;
    if (options.private_mount_namespace and options.propagation & ms.UNBINDABLE != 0) {
        step.operation = "mount private propagation";
        try checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0));
    } else if (options.private_mount_namespace and options.propagation & ms.SHARED != 0) {
        step = .{ .operation = "mount parent private propagation", .path = rootfs };
        try makeRootfsParentPrivate(rootfs, &step);
    }
    step = .{ .operation = "bind", .source = rootfs, .path = rootfs };
    try checkResult(linux.mount(rootfs, rootfs, null, ms.BIND | ms.REC, 0));
    if (!options.private_mount_namespace) {
        // Report ownership before a configured mount at "/" can cover this bind.
        step = .{ .operation = "open rootfs", .path = rootfs };
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        step.operation = "stat rootfs mount";
        var response: CreateResponse = .{ .rootfs_mount_id = try mountId(root_fd) };
        step = .{ .operation = "report rootfs mount" };
        if (options.runtime_sync) |sync|
            if (!writeAll(sync.ready_fd, std.mem.asBytes(&response))) return error.CreateFailed;
    }
    // The new self-bind can inherit host peer groups. Isolate only this copy,
    // so configured submounts do not also appear beneath the covered directory.
    step = .{ .operation = "mount private propagation", .path = rootfs };
    if (!options.private_mount_namespace)
        try checkResult(linux.mount(null, rootfs, null, ms.PRIVATE | ms.REC, 0));
    for (mounts) |mount| {
        step = .{ .operation = "open rootfs", .path = rootfs };
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        try applyMount(rootfs, root_fd, mount, options.private_mount_namespace, &step);
        try setupSymlinks(root_fd, mount.symlinks, &step);
    }
    if (options.runtime_sync) |sync| {
        step = .{ .operation = "create synchronization" };
        var response: CreateResponse = .{};
        if (!writeAll(sync.ready_fd, std.mem.asBytes(&response))) return error.CreateFailed;
        var byte: [1]u8 = undefined;
        const released = readAll(sync.go_fd, &byte);
        closeFd(sync.go_fd);
        if (!released or byte[0] != 1) return error.CreateFailed;
    }
    // Runtime paths are still reachable; the hook already runs in the new
    // mount namespace and sees all configured mounts before pivot_root.
    step = .{ .operation = "create hooks" };
    hooks.run(options.create_hooks, options.create_hook_state) catch |err| {
        // The hook runner already recorded its captured output.
        step.operation = "";
        return @as(Backend.Error!void, err);
    };
    // runc's fd trick stacks the old root on the new root without a put_old
    // directory. Detach it and close both handles before any container exec.
    // Keep them above stdio, which console setup replaces before they close.
    step = .{ .operation = "open old root", .path = "/" };
    const old_root = if (options.private_mount_namespace)
        try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        null;
    defer if (old_root) |fd| closeFd(fd);
    step = .{ .operation = "open rootfs", .path = rootfs };
    const new_root = try consolePath(rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(new_root);
    // Populate rootfs /dev even without tmpfs, but leave a bind-mounted /dev
    // untouched: device nodes and symlinks there would mutate the host source.
    if (needsSetupDev(mounts)) try setupDevices(new_root, devices, symlinks, options.private_mount_namespace, &step);
    step = .{ .operation = "fchdir rootfs", .path = rootfs };
    try checkResult(linux.fchdir(new_root));
    if (options.private_mount_namespace) {
        step = .{ .operation = "pivot_root" };
        try checkResult(linux.pivot_root(".", "."));
        step = .{ .operation = "fchdir old root" };
        try checkResult(linux.fchdir(old_root.?));
        // Detaching inherited shared submounts must not unmount their host peers.
        step = .{ .operation = "mount old root slave propagation" };
        try checkResult(linux.mount(null, ".", null, ms.SLAVE | ms.REC, 0));
        step = .{ .operation = "umount old root" };
        try checkResult(linux.umount2(".", linux.MNT.DETACH));
    } else {
        step = .{ .operation = "chroot", .path = rootfs };
        try checkResult(linux.chroot("."));
    }
    step = .{ .operation = "chdir", .path = "/" };
    try checkResult(linux.chdir("/"));
    if (options.console_fd) |socket| {
        defer closeFd(socket);
        setupConsole(socket, true) catch |err| {
            childError("cannot set up console (requires devpts mounted at /dev/pts): ", err);
            if (options.runtime_sync) |sync| failCreate(sync.ready_fd, err);
            linux.exit_group(1);
        };
    }
    // Sysctls must precede readonlyPaths (typically including /proc/sys).
    step.operation = "";
    try applySysctls(options.sysctls);
    try applyPathRestrictions(options.masked_paths, options.readonly_paths, &step);
    if (readonly) {
        step = .{ .operation = "remount readonly root", .path = "/" };
        try bindRemount(new_root, "/", ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
    step = .{ .operation = "restore mount propagation", .path = "/" };
    if (restore_propagation)
        try checkResult(linux.mount(null, "/", null, options.propagation, 0));
}

fn runInit(
    spec: *const oci.Spec,
    capabilities: ?Backend.Capabilities,
    rlimits: []const Backend.Rlimit,
    flags: usize,
    rootfs: [:0]const u8,
    mounts: []const PreparedMount,
    devices: []const PreparedDevice,
    symlinks: []const Backend.Symlink,
    cwd: [:0]const u8,
    fifo_fd: posix.fd_t,
    fd_dir: posix.fd_t,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    ready_fd: posix.fd_t,
    rootfs_options: RootfsOptions,
    start_hooks: []const hooks.Prepared,
    start_hook_state: []const u8,
    seccomp_program: ?seccomp.Program,
) noreturn {
    // The inherited host descriptors avoid path access to the state directory
    // or /proc inside the container and are closed before or at exec.
    var fifo_buffer: [32]u8 = undefined;
    const fifo_name = std.fmt.bufPrintZ(&fifo_buffer, "{d}", .{fifo_fd}) catch unreachable;
    // Sysctls in setupRootfs may override the configured hostname.
    if (flags & linux.CLONE.NEWUTS != 0) {
        if (spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch |err| failCreate(ready_fd, err);
        }
    }
    setupRootfs(rootfs, mounts, devices, symlinks, spec.root.readonly, rootfs_options) catch |err| failCreate(ready_fd, err);
    checkResult(linux.chdir(cwd)) catch |err| failCreate(ready_fd, err);
    if (spec.process) |process| {
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.user.uid != 0 and !rootfs_options.fifo_writable)
            checkResult(linux.fchmodat(fd_dir, fifo_name, 0o622)) catch |err| failCreate(ready_fd, err);
        // Without NNP the kernel requires CAP_SYS_ADMIN, which applyProcess
        // may drop. Do not change the OCI noNewPrivileges setting.
        // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
        if (!process.noNewPrivileges) {
            if (seccomp_program) |program|
                installSeccomp(program) catch |err| failCreate(ready_fd, err);
        }
        applyProcess(process, capabilities, rlimits) catch |err| {
            childError("cannot apply process settings: ", err);
            failCreate(ready_fd, err);
        };
    }
    var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = if (spec.process != null)
        resolveExecutable(argv, envp, &executable_buffer) catch |err| failCreate(ready_fd, err)
    else
        null;
    var response: CreateResponse = .{};
    if (!writeAll(ready_fd, std.mem.asBytes(&response))) linux.exit_group(1);
    closeFd(ready_fd);

    // O_WRONLY blocks until start opens a reader; the byte acknowledges that start.
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(fd_dir, fifo_name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => linux.exit_group(1),
        }
    };
    closeFd(fd_dir);
    closeFd(fifo_fd);
    // Opening the writer unblocks start. Acknowledge after hooks pass, then
    // retain the CLOEXEC writer so EOF confirms exec before start succeeds.
    hooks.run(start_hooks, start_hook_state) catch {
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    runProcess(spec, executable, argv, envp, seccomp_program) catch |err| {
        if (err != error.ExecFailed) childError("cannot execute process: ", err);
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
}

fn runProcess(spec: *const oci.Spec, executable: ?[*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, seccomp_program: ?seccomp.Program) !noreturn {
    // A process-less config can be created; it cannot be started.
    if (spec.process == null) return error.InvalidProcess;
    // Linux CLOSE_RANGE_CLOEXEC is 1 << 2; Zig 0.16's packed flags use 1 << 1.
    try checkResult(linux.syscall3(.close_range, 3, std.math.maxInt(u32), 1 << 2));
    // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
    if (spec.process.?.noNewPrivileges) {
        if (seccomp_program) |program| try installSeccomp(program);
    }
    return execResolved(executable orelse return error.InvalidProcess, argv, envp);
}

fn installSeccomp(program: seccomp.Program) Backend.Error!void {
    const result = seccomp.install(program);
    if (result != .SUCCESS) {
        var errno_buffer: [16]u8 = undefined;
        const errno_name = std.enums.tagName(linux.E, result) orelse
            (std.fmt.bufPrint(&errno_buffer, "{d}", .{@intFromEnum(result)}) catch unreachable);
        reportDiagnostic("cannot install seccomp filter: E{s}", .{errno_name});
        return error.CreateFailed;
    }
}

fn applyOomScoreAdj(proc_dir: posix.fd_t, oom_score_adj: ?i32) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        const value = oom_score_adj orelse return;
        var buffer: [12]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable;
        const fd = try openPath(proc_dir, "self/oom_score_adj", .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
        defer closeFd(fd);
        if (!writeAll(fd, text)) return error.CreateFailed;
    } else {
        return error.NotImplemented;
    }
}

const ProcessSettings = struct {
    uid: u32,
    gid: u32,
    additional_gids: []const u32,
    no_new_privileges: bool,
    capabilities: ?Backend.Capabilities,
    rlimits: []const Backend.Rlimit,
};

/// Runs before readiness, without allocating. Keep privileges until limits and
/// bounding drops finish, then retain permitted caps across the UID transition.
// For UID 0, exec recomputes permitted/effective as inheritable | bounding (as in runc).
fn applyProcess(process: oci.Spec.Process, capabilities: ?Backend.Capabilities, rlimits: []const Backend.Rlimit) Backend.Error!void {
    return applyProcessSettings(.{
        .uid = process.user.uid,
        .gid = process.user.gid,
        .additional_gids = process.user.additionalGids orelse &.{},
        .no_new_privileges = process.noNewPrivileges,
        .capabilities = capabilities,
        .rlimits = rlimits,
    });
}

fn applyProcessSettings(process: ProcessSettings) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (process.rlimits) |limit| {
            const value: linux.rlimit = .{ .cur = limit.soft, .max = limit.hard };
            try checkResult(linux.setrlimit(limit.resource, &value));
        }
        if (process.no_new_privileges)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
        if (process.capabilities) |caps| {
            for (0..64) |cap| {
                // EINVAL marks the running kernel's last supported capability.
                const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
                if (linux.errno(result) == .INVAL) break;
                try checkResult(result);
                if (result != 0 and caps.bounding & (@as(u64, 1) << @intCast(cap)) == 0)
                    try checkResult(linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0));
            }
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
        }
        // With a user namespace, additionalGids (like uid/gid) are namespace IDs.
        const groups = process.additional_gids;
        try checkResult(linux.setgroups(groups.len, groups.ptr));
        try checkResult(linux.setgid(process.gid));
        try checkResult(linux.setuid(process.uid));
        if (process.capabilities) |caps| {
            // Linux's header uses a 32-bit pid, unlike Zig 0.16's usize field.
            const header: CapabilityHeader = .{};
            const data = [2]linux.cap_user_data_t{
                .{ .effective = @truncate(caps.effective), .permitted = @truncate(caps.permitted), .inheritable = @truncate(caps.inheritable) },
                .{ .effective = @truncate(caps.effective >> 32), .permitted = @truncate(caps.permitted >> 32), .inheritable = @truncate(caps.inheritable >> 32) },
            };
            try checkResult(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 0, 0, 0, 0));
            // Discard inherited ambient caps even when the configured set is empty.
            try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
            for (0..64) |cap| {
                if (caps.ambient & (@as(u64, 1) << @intCast(cap)) != 0)
                    try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_RAISE, cap, 0, 0));
            }
        }
    } else {
        return error.NotImplemented;
    }
}

fn isExecutable(path: [*:0]const u8) bool {
    if (linux.errno(linux.faccessat(linux.AT.FDCWD, path, linux.X_OK, 0)) != .SUCCESS) return false;
    // Zig 0.16 exposes statx rather than fstatat; follow symlinks and check type.
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat)) != .SUCCESS) return false;
    return stat.mask.TYPE and linux.S.ISREG(stat.mode);
}

fn resolveExecutable(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, buffer: []u8) error{ExecFailed}![*:0]const u8 {
    const executable = argv[0] orelse return error.ExecFailed;
    const name = std.mem.span(executable);
    errdefer reportDiagnostic("exec: \"{s}\": executable file not found in $PATH", .{name});
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        if (isExecutable(executable)) return executable;
        return error.ExecFailed;
    }
    var path: []const u8 = "/bin:/usr/bin";
    var index: usize = 0;
    while (envp[index]) |entry| : (index += 1) {
        const variable = std.mem.span(entry);
        if (std.mem.startsWith(u8, variable, "PATH=")) {
            path = variable["PATH=".len..];
            break;
        }
    }
    // Lookup happens inside the rootfs, without allocating after fork.
    var directories = std.mem.splitScalar(u8, path, ':');
    while (directories.next()) |directory| {
        const candidate = if (directory.len == 0) executable else (std.fmt.bufPrintZ(buffer, "{s}/{s}", .{ directory, name }) catch continue).ptr;
        if (isExecutable(candidate)) return candidate;
    }
    return error.ExecFailed;
}

fn execResolved(executable: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) error{ExecFailed}!noreturn {
    const err = linux.errno(linux.execve(executable, argv, envp));
    // Linux's errno tags omit the E prefix used by runtime diagnostics.
    var errno_buffer: [16]u8 = undefined;
    const errno_name = std.enums.tagName(linux.E, err) orelse
        (std.fmt.bufPrint(&errno_buffer, "{d}", .{@intFromEnum(err)}) catch unreachable);
    reportDiagnostic("cannot execute process: E{s}", .{errno_name});
    return error.ExecFailed;
}

fn execProcess(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) error{ExecFailed}!noreturn {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = try resolveExecutable(argv, envp, &buffer);
    return execResolved(executable, argv, envp);
}

test "proc stat parses field 22 after comm containing spaces and closing parentheses" {
    const stat = try parseProcStat(
        "1234 (init) name (x)) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 987654321 23 24\n",
    );
    try std.testing.expectEqual(@as(u8, 'S'), stat.state);
    try std.testing.expectEqualStrings("987654321", stat.starttime);
}

test "proc stat treats zombie and dead states as not alive" {
    for ([_]u8{ 'Z', 'X', 'S', 'R', 'T' }) |state| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "1234 (init) ) {c} 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345\n", .{state});
        defer std.testing.allocator.free(line);
        const stat = try parseProcStat(line);
        try std.testing.expectEqual(state != 'Z' and state != 'X', stat.matches("12345"));
        try std.testing.expect(!stat.matches("54321"));
    }
}

test "proc stat rejects missing fields and malformed starttime" {
    for ([_][]const u8{
        "1234 init S 4",
        "1234 (init)",
        "1234 (init) SS 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 invalid",
    }) |line| {
        try std.testing.expectError(error.LivenessFailed, parseProcStat(line));
    }
}

test "linux backend is unavailable on other platforms" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234, .starttime = "12345" };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.NotImplemented, backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = "/tmp/bundle/rootfs",
            .exec_fifo = "/tmp/containers/example/exec.fifo",
            .spec = &spec,
        }));
    }
    try std.testing.expectError(error.NotImplemented, backend.alive(handle));
    try std.testing.expectError(error.NotImplemented, backend.kill(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.killAll(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.pids(handle, std.testing.allocator));
    try std.testing.expectError(error.NotImplemented, backend.freeze(handle));
    try std.testing.expectError(error.NotImplemented, backend.thaw(handle));
    try std.testing.expectError(error.NotImplemented, backend.frozen(handle));
    try std.testing.expectError(error.NotImplemented, backend.delete(handle));
}

test "linux liveness and signaling work with a handle loaded by a new backend" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    defer closeFd(pipe[1]);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(pipe[1]);
        var byte: [1]u8 = undefined;
        _ = readAll(pipe[0], &byte);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var stat_buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &stat_buffer);
    const handle: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(try backend.alive(handle));
    const reused: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = "mismatched" };
    try std.testing.expect(!try backend.alive(reused));
    const reused_pids = try backend.pids(reused, std.testing.allocator);
    defer std.testing.allocator.free(reused_pids);
    try std.testing.expectEqual(@as(usize, 0), reused_pids.len);
    const pids = try backend.pids(handle, std.testing.allocator);
    defer std.testing.allocator.free(pids);
    try std.testing.expectEqualSlices(i32, &.{pid}, pids);
    try std.testing.expect(!try backend.frozen(handle));
    try std.testing.expectError(error.Unsupported, backend.freeze(handle));
    try std.testing.expect(std.mem.indexOf(u8, backend.diagnostic().?, "no cgroup freezer") != null);
    try std.testing.expectError(error.Unsupported, backend.thaw(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(reused, 9));
    try backend.killAll(reused, 9);
    try std.testing.expect(try backend.alive(handle));
    try backend.kill(handle, 0);
    try backend.killAll(handle, 0);
    try std.testing.expectError(error.InvalidProcess, backend.kill(.{ .id = "invalid", .pid = 0, .starttime = "" }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.killAll(.{ .id = "invalid", .pid = 0, .starttime = "" }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.alive(.{ .id = "invalid", .pid = -1, .starttime = "" }));
    try std.testing.expectError(error.KillFailed, backend.kill(handle, 65));
    try std.testing.expectError(error.KillFailed, backend.killAll(handle, 65));
    try backend.killAll(handle, 9);
    _ = try waitChild(pid);
    reaped = true;
    try std.testing.expect(!try backend.alive(handle));
    const stopped_pids = try backend.pids(handle, std.testing.allocator);
    defer std.testing.allocator.free(stopped_pids);
    try std.testing.expectEqual(@as(usize, 0), stopped_pids.len);
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
    try backend.killAll(handle, 15);
    try backend.delete(handle);
}

test "linux pid enumeration includes nested descendants and ignores control files and symlinks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "child/grandchild");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = "1234\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "child/cgroup.procs", .data = "1235\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "child/grandchild/cgroup.procs", .data = "1236\n1234\n" });
    try tmp.dir.symLink(std.testing.io, "child", "linked-child", .{ .is_directory = true });
    const dir = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    var pids: std.ArrayList(i32) = .empty;
    defer pids.deinit(allocator);
    try collectCgroupPids(allocator, dir, &pids);
    try std.testing.expectEqualSlices(i32, &.{ 1234, 1235, 1236 }, pids.items);
}

test "linux kill all signals every cgroup member and plain SIGKILL thaws paused v1" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(root.fd);
    const path = try std.fmt.allocPrint(allocator, "igvano-kill-all-test-{d}", .{linux.getpid()});
    defer allocator.free(path);
    const hierarchies: []V1Hierarchy = if (root.mode == .legacy) try openV1Hierarchies(allocator) else &.{};
    defer freeV1Hierarchies(allocator, hierarchies);
    var cgroup: ?posix.fd_t = null;
    defer if (cgroup) |fd| closeFd(fd);
    defer if (root.mode == .legacy) {
        cleanupV1TestHierarchies(hierarchies, path);
    } else {
        removeCgroup(root.fd, path) catch {};
    };
    if (root.mode == .legacy) {
        if (hierarchies.len == 0) return error.SkipZigTest;
        for (hierarchies) |*hierarchy|
            hierarchy.leaf = (walkV1Cgroup(allocator, hierarchy.root.?, path, true, hierarchy.has("cpuset")) catch return error.SkipZigTest).?;
    } else {
        cgroup = (walkCgroup(root.fd, path, true, &.{}) catch return error.SkipZigTest).?;
    }
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    for ([_]struct { signal: i32, paused: bool, all: bool = true }{
        .{ .signal = 9, .paused = false },
        .{ .signal = 15, .paused = false },
        .{ .signal = 9, .paused = true },
        .{ .signal = 15, .paused = true },
        .{ .signal = 9, .paused = true, .all = false },
    }) |case| {
        const signal = case.signal;
        if (case.paused and root.mode == .legacy) {
            var has_freezer = false;
            for (hierarchies) |hierarchy| {
                if (hierarchy.has("freezer")) has_freezer = true;
            }
            if (!has_freezer) continue;
        }
        const ready = try makePipe();
        defer closeFd(ready[0]);
        var writer: ?posix.fd_t = ready[1];
        defer if (writer) |fd| closeFd(fd);
        var children = [_]i32{ 0, 0 };
        defer {
            if (case.paused) backend.thaw(.{ .id = "kill-all", .pid = 0, .starttime = "", .cgroup_path = path }) catch {};
            for (children) |pid| {
                if (pid > 0) {
                    _ = linux.kill(pid, .KILL);
                    _ = waitChild(pid) catch {};
                }
            }
        }
        for (&children) |*child| {
            child.* = try forkProcess();
            if (child.* == 0) {
                closeFd(ready[0]);
                if (cgroup) |fd| {
                    writeCgroupFile(fd, "cgroup.procs", "0", path) catch linux.exit_group(1);
                } else {
                    for (hierarchies) |hierarchy|
                        writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", path) catch linux.exit_group(1);
                }
                if (!writeAll(ready[1], &.{1})) linux.exit_group(2);
                const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
                while (true) _ = linux.nanosleep(&delay, null);
            }
        }
        closeFd(ready[1]);
        writer = null;
        var bytes: [2]u8 = undefined;
        try std.testing.expect(readAll(ready[0], &bytes));
        try std.testing.expectEqualSlices(u8, &.{ 1, 1 }, &bytes);
        var buffer: [4096]u8 = undefined;
        const stat = try readProcStat(children[0], &buffer);
        const handle: Backend.Handle = .{ .id = "kill-all", .pid = children[0], .starttime = stat.starttime, .cgroup_path = path };
        try backend.killAll(handle, 0);
        try std.testing.expect(try backend.alive(handle));
        if (signal == 15) {
            // Init can exit while another member remains in its cgroup.
            try backend.kill(handle, 9);
            const status = try waitChild(children[0]);
            children[0] = 0;
            try std.testing.expectEqual(@as(u32, 9), status);
        }
        if (case.paused) try backend.freeze(handle);
        if (case.all) {
            try backend.killAll(handle, signal);
        } else {
            try backend.kill(handle, signal);
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(children[1], @enumFromInt(0))));
        }
        const stays_frozen = case.paused and (root.mode == .unified or signal != 9);
        if (case.paused and root.mode == .unified) {
            // Exiting tasks can clear the events bit, but kill must retain the user's freeze request.
            const requested = try readCgroupFile(allocator, cgroup.?, "cgroup.freeze");
            defer allocator.free(requested);
            try std.testing.expectEqualStrings("1", std.mem.trim(u8, requested, " \t\n"));
        } else {
            try std.testing.expectEqual(stays_frozen, try backend.frozen(handle));
        }
        if (stays_frozen) try backend.thaw(handle);
        if (!case.all) try backend.killAll(handle, signal);
        if (cgroup) |fd| {
            const thawed = try readCgroupFile(allocator, fd, "cgroup.freeze");
            defer allocator.free(thawed);
            try std.testing.expectEqualStrings("0", std.mem.trim(u8, thawed, " \t\n"));
        } else {
            for (hierarchies) |hierarchy| {
                if (!hierarchy.has("freezer")) continue;
                const thawed = try readCgroupFile(allocator, hierarchy.leaf.?, "freezer.state");
                defer allocator.free(thawed);
                try std.testing.expectEqualStrings("THAWED", std.mem.trim(u8, thawed, " \t\n"));
            }
        }
        for (&children) |*child| {
            if (child.* == 0) continue;
            const status = try waitChild(child.*);
            child.* = 0;
            try std.testing.expectEqual(@as(u32, @intCast(signal)), status);
        }
        const members = try readCgroupFile(allocator, cgroup orelse hierarchies[0].leaf.?, "cgroup.procs");
        defer allocator.free(members);
        try std.testing.expectEqualStrings("", std.mem.trim(u8, members, " \t\n"));
        try backend.killAll(handle, signal);
    }
    const handle: Backend.Handle = .{ .id = "kill-all", .pid = 0, .starttime = "", .cgroup_path = path };
    try backend.delete(handle);
    try backend.killAll(handle, 9);
}

test "linux liveness rejects an unreaped zombie even though kill zero succeeds" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pid = try forkProcess();
    if (pid == 0) linux.exit_group(0);
    defer _ = waitChild(pid) catch {};
    var info: linux.siginfo_t = undefined;
    while (true) {
        switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT, null))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, @enumFromInt(0))));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &buffer);
    const handle: Backend.Handle = .{ .id = "zombie", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(!try backend.alive(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
}

test "linux create rejects hostname without UTS isolation and terminals without a console" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .hostname = "must-not-change-the-host",
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    spec.hostname = null;
    spec.process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .terminal = true, .user = .{ .uid = 0, .gid = 0 } };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
}

test "linux create rejects propagation without mount isolation before acquiring resources" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "/" } };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .rootfs_propagation = linux.MS.PRIVATE | linux.MS.REC,
    }));
}

test "linux inherited mount namespace rejects the runtime root before any mount" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "/" } };
    var implementation: LinuxBackend = .{};
    for ([_][]const u8{ "/", "/./", "/proc/self/root" }) |rootfs| {
        try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            .spec = &spec,
            // An invalid cgroup path prevents mount setup if this guard regresses.
            .cgroup_path = "",
        }));
    }
}

test "linux create rejects joining the runtime's own mount namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount, .path = "/proc/self/ns/mnt" }} },
    };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        // An invalid cgroup path prevents mount setup if the guard regresses.
        .cgroup_path = "",
    }));
}

test "linux create rejects relative process cwd" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // These paths exist under rootfs, so existence alone cannot validate cwd.
    for ([_][]const u8{ "rootfs", ".", "" }) |cwd| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = rootfs },
            .process = .{ .args = &.{"/bin/sh"}, .cwd = cwd, .user = .{ .uid = 0, .gid = 0 } },
        };
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const result = backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            .spec = &spec,
        });
        if (result) |handle| {
            defer std.testing.allocator.free(handle.starttime);
            // Clean up if a regression incorrectly creates an init.
            backend.kill(handle, 9) catch {};
        } else |_| {}
        try std.testing.expectError(
            if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
            result,
        );
    }
}

test "linux create rejects empty process args" {
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
        result,
    );
}

test "linux create rejects a cwd missing from the resolved rootfs" {
    if (comptime builtin.os.tag == .linux) {
        try requireTestMountNamespace();
        const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
        if (cgroup_root.mode != .unified) {
            closeFd(cgroup_root.fd);
            return error.SkipZigTest;
        }
        closeFd(cgroup_root.fd);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // The resolved backend option is authoritative, even when root.path is "/".
    // /proc exists on the Linux host, but not inside this empty rootfs.
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/proc", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = rootfs,
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        // Clean up if a regression incorrectly creates an init.
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.CreateFailed else error.NotImplemented,
        result,
    );
}

test "namespace flags map each namespace and combine flags without system calls" {
    const cases = .{
        .{ .pid, linux.CLONE.NEWPID },
        .{ .network, linux.CLONE.NEWNET },
        .{ .mount, linux.CLONE.NEWNS },
        .{ .ipc, linux.CLONE.NEWIPC },
        .{ .uts, linux.CLONE.NEWUTS },
        .{ .user, linux.CLONE.NEWUSER },
        .{ .cgroup, linux.CLONE.NEWCGROUP },
        .{ .time, linux.CLONE.NEWTIME },
    };
    inline for (cases) |case| {
        try std.testing.expectEqual(@as(usize, case[1]), try namespaceFlags(.{ .namespaces = &.{.{ .type = case[0] }} }));
    }
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(null));
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(.{}));
    try std.testing.expectEqual(
        @as(usize, linux.CLONE.NEWPID | linux.CLONE.NEWUTS | linux.CLONE.NEWNS),
        try namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount } } }),
    );
}

test "namespace flags reject duplicate types" {
    try std.testing.expectError(
        error.InvalidConfig,
        namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount }, .{ .type = .pid } } }),
    );
}

test "namespace flags exclude joins including existing user namespaces" {
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(.{
        .namespaces = &.{.{ .type = .network, .path = "/proc/1234/ns/net" }},
    }));
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWNS), try namespaceFlags(.{
        .namespaces = &.{ .{ .type = .mount }, .{ .type = .user, .path = "/proc/1234/ns/user" } },
    }));
    const mappings: []const oci.Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }};
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWUSER | linux.CLONE.NEWNS), try namespaceFlags(.{
        .namespaces = &.{ .{ .type = .user }, .{ .type = .mount } },
        .uidMappings = mappings,
        .gidMappings = mappings,
    }));
}

test "namespace paths reject empty relative and NUL paths and duplicate joins" {
    for ([_][]const u8{ "", "relative", "/proc/1/ns/net\x00" }) |path| {
        try std.testing.expectError(error.InvalidPath, namespaceFlags(.{
            .namespaces = &.{.{ .type = .network, .path = path }},
        }));
    }
    try std.testing.expectError(error.InvalidConfig, namespaceFlags(.{
        .namespaces = &.{ .{ .type = .network, .path = "/proc/1/ns/net" }, .{ .type = .network } },
    }));
}

test "ID mapping lines preserve order and decimal IDs" {
    const text = try formatIDMappings(std.testing.allocator, &.{
        .{ .containerID = 0, .hostID = 100000, .size = 65536 },
        .{ .containerID = 100000, .hostID = 200000, .size = 1 },
    });
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("0 100000 65536\n100000 200000 1\n", text);
}

test "FIFO ownership uses namespace root's mapped host UID and GID" {
    try std.testing.expectEqual(@as(u32, 100000), try mappedRootID(&.{
        .{ .containerID = 10, .hostID = 300000, .size = 10 },
        .{ .containerID = 0, .hostID = 100000, .size = 10 },
    }));
    try std.testing.expectEqual(@as(u32, 200000), try mappedRootID(&.{.{ .containerID = 0, .hostID = 200000, .size = 10 }}));
    try std.testing.expectEqual(@as(u32, 0), try mappedRootID(&.{.{ .containerID = 0, .hostID = 0, .size = 1 }}));
    for ([_][]const oci.Spec.IDMapping{
        &.{},
        &.{.{ .containerID = 1, .hostID = 100000, .size = 10 }},
        &.{.{ .containerID = 0, .hostID = 100000, .size = 0 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, mappedRootID(mappings));
    }
}

test "linux create reports the frontend ambient capability validation error" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "/" } };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.AmbientCapabilitiesRequirePermittedAndInheritable, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .capabilities = .{ .ambient = 1 },
    }));
}

test "linux capability preparation skips bits unsupported by the running kernel" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), 63, 0, 0, 0)) != .INVAL)
        return error.SkipZigTest;
    const future = @as(u64, 1) << 63;
    try std.testing.expectEqual(Backend.Capabilities{
        .bounding = 1,
        .effective = 1,
        .permitted = 1,
        .inheritable = 1,
        .ambient = 1,
    }, try kernelCapabilities(.{
        .bounding = future | 1,
        .effective = future | 1,
        .permitted = future | 1,
        .inheritable = future | 1,
        .ambient = future | 1,
    }));
}

test "linux exec searches the process PATH and preserves explicit paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct {
        executable: [*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        cwd: [:0]const u8 = "/",
        status: u32 = 0,
    }{
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:/bin:/usr/bin"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"}, .status = 1 << 8 },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{} },
        .{ .executable = "/bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH="}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=:/does-not-exist"}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:"}, .cwd = "/bin" },
    };
    for (cases) |case| {
        const argv = [_:null]?[*:0]const u8{ case.executable, "-c", "exit 0" };
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.chdir(case.cwd)) catch linux.exit_group(2);
            execProcess(&argv, case.envp) catch linux.exit_group(1);
        }
        try std.testing.expectEqual(case.status, try waitChild(pid));
    }
}

test "linux exec failure diagnostics name the errno" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const cases = [_]struct { name: []const u8, data: []const u8, mode: posix.mode_t, expected: []const u8 }{
        .{ .name = "denied", .data = "exit 0\n", .mode = 0o644, .expected = "cannot execute process: EACCES" },
        .{ .name = "bad-format", .data = "not an executable\n", .mode = 0o755, .expected = "cannot execute process: ENOEXEC" },
        .{ .name = "missing-interpreter", .data = "#!/igvano-no-such-interpreter\n", .mode = 0o755, .expected = "cannot execute process: ENOENT" },
    };
    const envp = [_:null]?[*:0]const u8{};
    for (cases) |case| {
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = case.name, .data = case.data, .flags = .{ .permissions = .fromMode(case.mode) } });
        const path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/{s}", .{ base, case.name }, 0);
        defer std.testing.allocator.free(path);
        const argv = [_:null]?[*:0]const u8{path};
        try std.testing.expectError(error.ExecFailed, execResolved(path, &argv, &envp));
        try std.testing.expectEqualStrings(case.expected, last_diagnostic[0..last_diagnostic_len]);
    }
}

test "linux init rejects missing directory and non-executable args before create readiness" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    defer last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "no-execute", .data = "exit 0\n", .flags = .{ .permissions = .fromMode(0o644) } });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    const rootfs_z = try std.testing.allocator.dupeZ(u8, rootfs);
    defer std.testing.allocator.free(rootfs_z);
    for ([_][*:0]const u8{ "igvano-no-such-binary", "/igvano-no-such-binary", "/directory", "/no-execute" }) |arg0| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .process = .{ .args = &.{std.mem.span(arg0)}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        };
        const argv = [_:null]?[*:0]const u8{arg0};
        const envp = [_:null]?[*:0]const u8{"PATH=/bin:/usr/bin"};
        const ready = try makePipe();
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(ready[0]);
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(2);
            runInit(&spec, null, &.{}, linux.CLONE.NEWNS, rootfs_z, &.{}, &.{}, &.{}, "/", -1, -1, &argv, &envp, ready[1], .{}, &.{}, "", null);
        }
        closeFd(ready[1]);
        var response: CreateResponse = .{};
        const received = readAll(ready[0], std.mem.asBytes(&response));
        const status = try waitChild(pid);
        try std.testing.expect(received);
        try std.testing.expectEqual(@as(u32, 1 << 8), status);
        try std.testing.expectEqual(error.ExecFailed, response.failureError().?);
        const expected = try std.fmt.allocPrint(std.testing.allocator, "exec: \"{s}\": executable file not found in $PATH", .{std.mem.span(arg0)});
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, last_diagnostic[0..last_diagnostic_len]);
    }
}

test "linux init applies uid gid and optional supplementary groups before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const cases = [_]struct { user_json: []const u8, expected: []const u8 }{
        .{ .user_json = "{\"uid\":1000,\"gid\":1000}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[]}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[1001,1002]}", .expected = "1000\n1000\n1000 1001 1002\n" },
    };
    for (cases) |case| {
        const user = try std.json.parseFromSlice(oci.Spec.User, std.testing.allocator, case.user_json, .{
            .ignore_unknown_fields = true,
        });
        defer user.deinit();
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "/" },
            .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .user = user.value },
        };
        const argv = [_:null]?[*:0]const u8{ "sh", "-c", "id -u; id -g; id -G" };
        const envp = [_:null]?[*:0]const u8{"PATH=/does-not-exist:/usr/bin:/bin"};
        const output = try makePipe();
        defer closeFd(output[0]);
        const ready = makePipe() catch |err| {
            closeFd(output[1]);
            return err;
        };
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(output[1]);
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(output[0]);
            closeFd(ready[0]);
            checkResult(linux.setgroups(1, &.{42})) catch linux.exit_group(1);
            checkResult(linux.dup2(output[1], posix.STDOUT_FILENO)) catch linux.exit_group(1);
            closeFd(output[1]);
            applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
            var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const executable = resolveExecutable(&argv, &envp, &executable_buffer) catch linux.exit_group(1);
            runProcess(&spec, executable, &argv, &envp, null) catch linux.exit_group(1);
        }
        closeFd(output[1]);
        closeFd(ready[1]);
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        var bytes: [64]u8 = undefined;
        const result = bytes[0..case.expected.len];
        try std.testing.expect(readAll(output[0], result));
        try std.testing.expectEqualStrings(case.expected, result);
    }
}

test "linux init applies oomScoreAdj before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(1);
        execProcess(&argv, &envp) catch linux.exit_group(1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init preserves inherited oomScoreAdj when unset" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(2);
        const child = forkProcess() catch linux.exit_group(2);
        if (child == 0) {
            applyOomScoreAdj(proc_dir, null) catch linux.exit_group(1);
            execProcess(&argv, &envp) catch linux.exit_group(1);
        }
        const status = waitChild(child) catch linux.exit_group(2);
        linux.exit_group(if (status == 0) 0 else 1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init exits nonzero instead of exec for out of range oomScoreAdj" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    for ([_]i32{ 1001, -1001 }) |value| {
        const pid = try forkProcess();
        if (pid == 0) {
            applyOomScoreAdj(proc_dir, value) catch linux.exit_group(1);
            execProcess(&argv, &envp) catch linux.exit_group(1);
        }
        try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
    }
}

test "linux init exits nonzero instead of exec when it cannot apply process user" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{ "/bin/sh", "-c", "exit 0" }, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        if (linux.geteuid() == 0) {
            checkResult(linux.setgid(1000)) catch linux.exit_group(2);
            checkResult(linux.setuid(1000)) catch linux.exit_group(2);
        }
        applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
        runProcess(&spec, argv[0], &argv, &envp, null) catch linux.exit_group(1);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
}

test "linux init marks inherited descriptors CLOEXEC and sets noNewPrivileges" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const command = "test ! -e /proc/self/fd/200 && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status";
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{
            .args = &.{ "/bin/sh", "-c", command },
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0 },
            .noNewPrivileges = true,
        },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        checkResult(linux.dup2(ready[1], 200)) catch linux.exit_group(2);
        applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
        runProcess(&spec, argv[0], &argv, &envp, null) catch linux.exit_group(1);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux process settings apply rlimits without changing inherited capabilities" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    var original: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.NOFILE, &original));
    const hard = @min(original.max, 1024);
    const soft = @min(hard, 512);
    const process: oci.Spec.Process = .{
        .args = &.{"/bin/true"},
        .cwd = "/",
        .user = .{ .uid = linux.geteuid(), .gid = linux.getegid(), .additionalGids = &.{} },
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, null, &.{.{ .resource = .NOFILE, .hard = hard, .soft = soft }}) catch linux.exit_group(1);
        var actual: linux.rlimit = undefined;
        checkResult(linux.getrlimit(.NOFILE, &actual)) catch linux.exit_group(2);
        if (actual.cur != soft or actual.max != hard) linux.exit_group(3);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(4);
        for (inherited, caps) |before, after| {
            if (before.effective != after.effective or before.permitted != after.permitted or
                before.inheritable != after.inheritable) linux.exit_group(5);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux process settings retain configured capabilities across nonzero uid and exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) | (@as(u32, 1) << linux.CAP.SETPCAP) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (inherited[0].effective & required != required) return error.SkipZigTest;
    if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.CHOWN, 0, 0, 0) != 1)
        return error.SkipZigTest;
    const command = "test \"$(id -u)\" = 1000 && grep -q '^CapAmb:[[:space:]]*0000000000000001$' /proc/self/status";
    const process: oci.Spec.Process = .{
        .args = &.{ "/bin/sh", "-c", command },
        .cwd = "/",
        .user = .{ .uid = 1000, .gid = 1000, .additionalGids = &.{} },
        .noNewPrivileges = true,
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, .{
            .bounding = 1,
            .permitted = 1,
            .effective = 1,
            .inheritable = 1,
            .ambient = 1,
        }, &.{}) catch linux.exit_group(1);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(2);
        if (caps[0].effective != 1 or caps[0].permitted != 1 or caps[0].inheritable != 1 or
            caps[1].effective != 0 or caps[1].permitted != 0 or caps[1].inheritable != 0) linux.exit_group(3);
        if (linux.prctl(@intFromEnum(linux.PR.GET_KEEPCAPS), 0, 0, 0, 0) != 0) linux.exit_group(4);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SETUID, 0, 0, 0) != 0) linux.exit_group(5);
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_IS_SET, linux.CAP.CHOWN, 0, 0) != 1)
            linux.exit_group(6);
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
        const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
        execProcess(&argv, &envp) catch linux.exit_group(1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init reopens its root-owned pinned FIFO only for writing after dropping uid" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fifo_fd);
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
        closeFd(proc_dir);
        var buffer: [32]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{d}", .{fifo_fd}) catch unreachable;
        checkResult(linux.fchmodat(fd_dir, name, 0o622)) catch linux.exit_group(2);
        applyProcess(.{
            .args = &.{"/bin/true"},
            .cwd = "/",
            .user = .{ .uid = 1000, .gid = 1000, .additionalGids = &.{} },
        }, null, &.{}) catch linux.exit_group(3);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(7);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(8);
        if (!writeAll(ready[1], &.{1})) linux.exit_group(4);
        const fd = openPath(fd_dir, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch linux.exit_group(5);
        if (!writeAll(fd, &.{1})) linux.exit_group(6);
        linux.exit_group(0);
    }
    closeFd(ready[1]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(ready[0], &byte));
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    const status = try waitChild(pid);
    reaped = true;
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "linux create reports child setup failures without leaving an init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const missing_cwd = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "missing" });
    defer std.testing.allocator.free(missing_cwd);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = missing_cwd, .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    spec.process.?.cwd = "/";
    // Linux rejects NOFILE above fs.nr_open even with CAP_SYS_RESOURCE.
    options.rlimits = &.{.{ .resource = .NOFILE, .hard = std.math.maxInt(u64), .soft = 0 }};
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    options.rlimits = &.{};
    for ([_]i32{ 1001, -1001 }) |value| {
        options.oom_score_adj = value;
        try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    }
    options.oom_score_adj = null;
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    spec.root.path = "rootfs";
    options.rootfs = rootfs;
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/no-execute",
        .data = "exit 0\n",
        .flags = .{ .permissions = .fromMode(0o644) },
    });
    for ([_][]const u8{ "igvano-no-such-binary", "/igvano-no-such-binary", "/", "/no-execute" }) |arg0| {
        spec.process.?.args = &.{arg0};
        try std.testing.expectError(error.ExecFailed, implementation.backend().create(options));
        const expected = try std.fmt.allocPrint(std.testing.allocator, "exec: \"{s}\": executable file not found in $PATH", .{arg0});
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, implementation.backend().diagnostic().?);
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    }
}

test "linux create retains the init child's rootfs diagnostic" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(allocator, "igvano-diagnostic-test-{d}", .{linux.getpid()});
    defer allocator.free(cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fs.path.join(allocator, &.{ absolute, "rootfs" });
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    defer last_diagnostic_len = 0;
    defer backend.delete(.{ .id = "diagnostic", .pid = 0, .starttime = "", .cgroup_path = cgroup_path }) catch {};
    var options: Backend.CreateOptions = .{
        .allocator = allocator,
        .id = "diagnostic",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = cgroup_path,
        .mounts = &.{.{
            .destination = "/proc",
            .source = "proc",
            .type = "igvano-missing-filesystem",
            .flags = 0,
            .propagation = 0,
            .data = "",
        }},
    };
    try std.testing.expectError(error.CreateFailed, backend.create(options));
    try std.testing.expectEqualStrings(
        "cannot prepare rootfs: mount /proc (igvano-missing-filesystem): CreateFailed",
        backend.diagnostic().?,
    );
    // Hooks run after the first ready response; failure must survive cleanup
    // after the runtime has already received the init's PID.
    options.mounts = &.{};
    options.create_hooks = &.{.{ .path = "/igvano-missing-create-hook" }};
    try std.testing.expectError(error.HookFailed, backend.create(options));
    try std.testing.expectEqualStrings("error running hook #0: exit status 1, stdout: , stderr: ", backend.diagnostic().?);
}

test "linux create accepts a prepared executable or process-less rootfs and returns a live blocked init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    const parent_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/parent-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(parent_marker);
    const child_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/child-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(child_marker);
    const Callback = struct {
        parent_marker: [:0]const u8,
        child_marker: [:0]const u8,
        pid: i32 = 0,
        fail: bool = false,

        fn run(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.pid = handle.pid;
            if (linux.errno(linux.access(self.child_marker, linux.F_OK)) != .NOENT)
                return error.InvalidConfig;
            if (self.fail) return error.HookFailed;
            const fd = try openPath(linux.AT.FDCWD, self.parent_marker, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true });
            defer closeFd(fd);
        }
    };
    const specs = [_]oci.Spec{
        .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .linux = .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .cgroup } } },
            .process = .{ .args = &.{"/init"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        },
        .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" }, .linux = .{ .namespaces = &.{.{ .type = .mount }} } },
    };
    for (specs) |spec| {
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        var callback: Callback = .{ .parent_marker = parent_marker, .child_marker = child_marker, .fail = true };
        const options: Backend.CreateOptions = .{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .spec = &spec,
            .cgroup_path = cgroup_path,
            .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
            .device_symlinks = oci.deviceSymlinks(&.{}),
            .on_create = .{ .ptr = &callback, .run = Callback.run },
            .create_hooks = &.{.{
                .path = "/bin/sh",
                // The host shell must remain reachable until this hook finishes.
                .args = &.{ "sh", "-c", "test -e \"$1\" && printf child > \"$2\"", "sh", parent_marker, child_marker },
                .timeout_seconds = 2,
            }},
        };
        try std.testing.expectError(error.HookFailed, backend.create(options));
        try std.testing.expectEqual(linux.E.SRCH, linux.errno(linux.kill(callback.pid, @enumFromInt(0))));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "child-hook", .{}));
        callback.fail = false;
        const handle = try backend.create(options);
        defer std.testing.allocator.free(handle.starttime);
        defer {
            backend.kill(handle, 9) catch {};
            backend.delete(handle) catch {};
        }
        try std.testing.expect(handle.pid > 0);
        try std.testing.expectEqual(handle.pid, callback.pid);
        const child_output = try tmp.dir.readFileAlloc(std.testing.io, "child-hook", std.testing.allocator, .limited(16));
        defer std.testing.allocator.free(child_output);
        try std.testing.expectEqualStrings("child", child_output);
        try tmp.dir.deleteFile(std.testing.io, "parent-hook");
        try tmp.dir.deleteFile(std.testing.io, "child-hook");
        try std.testing.expectEqualStrings("example", handle.id);
        try std.testing.expect(handle.starttime.len != 0);
        try std.testing.expect(try backend.alive(handle));
        const null_device = try tmp.dir.statFile(std.testing.io, "rootfs/dev/null", .{});
        try std.testing.expectEqual(std.Io.File.Kind.character_device, null_device.kind);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(handle.pid, @enumFromInt(0))));
        const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
        try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
        if (spec.process != null) {
            var path_buffer: [64]u8 = undefined;
            const namespace_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/cgroup", .{handle.pid}) catch unreachable;
            const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
            defer closeFd(namespace);
            const membership_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/cgroup", .{handle.pid}) catch unreachable;
            // Read init's membership from its cgroup namespace without changing
            // the test runner's namespace or needing /proc in the empty rootfs.
            const checker = try forkProcess();
            if (checker == 0) {
                checkResult(linux.setns(namespace, linux.CLONE.NEWCGROUP)) catch linux.exit_group(1);
                const membership = openPath(linux.AT.FDCWD, membership_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(1);
                var bytes: [5]u8 = undefined;
                if (!readAll(membership, &bytes)) linux.exit_group(1);
                linux.exit_group(if (std.mem.eql(u8, &bytes, "0::/\n")) 0 else 1);
            }
            try std.testing.expectEqual(@as(u32, 0), try waitChild(checker));
        }
        try backend.kill(handle, 9);
        try backend.delete(handle);
        try backend.delete(handle);
    }
}

test "linux mapped init acknowledges start without path access to its private state directory" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var caps: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (caps[0].effective & required != required) return error.SkipZigTest;
    const namespace_probe = try forkProcess();
    if (namespace_probe == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(namespace_probe) != 0) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-private-fifo-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "state", .fromMode(0o700));
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/state/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .user }, .{ .type = .mount }, .{ .type = .pid } },
            .uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 2 }},
            .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 2 }},
        },
        .process = .{
            .args = &.{"/init"},
            .cwd = "/",
            .user = .{ .uid = 1, .gid = 1 },
        },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = std.testing.allocator,
        .id = "private",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = cgroup_path,
    });
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    const stat = try tmp.dir.statFile(std.testing.io, "state", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o700), stat.permissions.toMode() & 0o7777);
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll_fds = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll_fds, 1, 2000));
    try std.testing.expect(poll_fds[0].revents & linux.POLL.IN != 0);
    var acknowledgement: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &acknowledgement));
    try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
}

test "linux mapped create installs maps outside init and cleans up rejected maps" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const ProcFile = struct {
        fn read(path: []const u8, limit: std.Io.Limit) ![]u8 {
            const file = try std.Io.Dir.cwd().openFile(std.testing.io, path, .{});
            defer file.close(std.testing.io);
            // Proc files report size zero; force reads through EOF.
            var reader = file.readerStreaming(std.testing.io, &.{});
            return reader.interface.allocRemaining(std.testing.allocator, limit);
        }
    };
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var caps: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (caps[0].effective & required != required) return error.SkipZigTest;
    const namespace_probe = try forkProcess();
    if (namespace_probe == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(namespace_probe) != 0) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    if (cgroup_root.mode != .unified) {
        closeFd(cgroup_root.fd);
        return error.SkipZigTest;
    }
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-mapped-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "rootfs/dev", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "rootfs/init",
        .data = "unused until start\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs", .readonly = true },
        .linux = .{
            .namespaces = &.{ .{ .type = .user }, .{ .type = .mount }, .{ .type = .pid } },
            // Distinct container ranges with overlapping host ranges: the
            // kernel rejects uid_map after gid_map is written.
            .uidMappings = &.{
                .{ .containerID = 0, .hostID = 100000, .size = 2 },
                .{ .containerID = 2, .hostID = 100001, .size = 1 },
            },
            .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 10 }},
        },
        .process = .{
            .args = &.{"/init"},
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0, .additionalGids = &.{ 1, 2 } },
        },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "mapped",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        // Creating /dev/pts on the namespace-owned tmpfs needs mapped
        // fsuid/fsgid; unmapped host-root would fail mkdirat with EOVERFLOW.
        .mounts = &.{
            .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/pts", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/host-null", .source = "/dev/null", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
        },
        .devices = &.{
            .{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 },
            .{ .path = "/dev/zero", .kind = .character, .major = 1, .minor = 5 },
            .{ .path = "/dev/pipe", .kind = .fifo, .mode = 0o620, .uid = 1, .gid = 2 },
        },
        .oom_score_adj = 500,
        .device_symlinks = oci.deviceSymlinks(&.{}),
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    spec.linux.?.uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 10 }};
    const handle = try backend.create(options);
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    try std.testing.expect(try backend.alive(handle));
    const oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{handle.pid});
    defer std.testing.allocator.free(oom_path);
    const oom_score_adj = try ProcFile.read(oom_path, .limited(32));
    defer std.testing.allocator.free(oom_score_adj);
    try std.testing.expectEqualStrings("500\n", oom_score_adj);
    for ([_]struct { name: []const u8, tokens: []const []const u8 }{
        .{ .name = "uid_map", .tokens = &.{ "0", "100000", "10" } },
        .{ .name = "gid_map", .tokens = &.{ "0", "200000", "10" } },
        .{ .name = "setgroups", .tokens = &.{"allow"} },
    }) |expected| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/{s}", .{ handle.pid, expected.name });
        defer std.testing.allocator.free(path);
        const text = try ProcFile.read(path, .limited(4096));
        defer std.testing.allocator.free(text);
        var tokens = std.mem.tokenizeAny(u8, text, " \t\n");
        for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
        try std.testing.expect(tokens.next() == null);
    }
    const status_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/status", .{handle.pid});
    defer std.testing.allocator.free(status_path);
    const status = try ProcFile.read(status_path, .limited(16384));
    defer std.testing.allocator.free(status);
    for ([_]struct { prefix: []const u8, tokens: []const []const u8 }{
        .{ .prefix = "Uid:", .tokens = &.{ "100000", "100000", "100000", "100000" } },
        .{ .prefix = "Gid:", .tokens = &.{ "200000", "200000", "200000", "200000" } },
        .{ .prefix = "Groups:", .tokens = &.{ "200001", "200002" } },
    }) |expected| {
        var lines = std.mem.tokenizeScalar(u8, status, '\n');
        var found = false;
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, expected.prefix)) continue;
            var tokens = std.mem.tokenizeAny(u8, line[expected.prefix.len..], " \t");
            for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
            try std.testing.expect(tokens.next() == null);
            found = true;
            break;
        }
        try std.testing.expect(found);
    }
    const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
    {
        // Reuse this mapped user namespace while creating fresh mount/PID
        // namespaces. Root's host UID differs from the runtime's UID.
        const user_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/ns/user", .{handle.pid});
        defer std.testing.allocator.free(user_path);
        const joined_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/joined.fifo", .{absolute}, 0);
        defer std.testing.allocator.free(joined_fifo);
        try checkResult(linux.mknod(joined_fifo, linux.S.IFIFO | 0o600, 0));
        const joined_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-joined", .{cgroup_path});
        defer std.testing.allocator.free(joined_cgroup);
        var joined_spec = spec;
        joined_spec.linux.?.namespaces = &.{ .{ .type = .mount }, .{ .type = .user, .path = user_path }, .{ .type = .pid } };
        joined_spec.linux.?.uidMappings = null;
        joined_spec.linux.?.gidMappings = null;
        var joined_options = options;
        joined_options.id = "joined";
        joined_options.spec = &joined_spec;
        joined_options.exec_fifo = joined_fifo;
        joined_options.cgroup_path = joined_cgroup;
        // Lowering requires host CAP_SYS_RESOURCE even when joining a user
        // namespace whose root maps to a different host UID.
        if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0)
            joined_options.oom_score_adj = -500;
        const joined = try backend.create(joined_options);
        defer std.testing.allocator.free(joined.starttime);
        defer {
            backend.kill(joined, 9) catch {};
            backend.delete(joined) catch {};
        }
        try std.testing.expect(try backend.alive(joined));
        const joined_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{joined.pid});
        defer std.testing.allocator.free(joined_oom_path);
        const joined_oom_score_adj = try ProcFile.read(joined_oom_path, .limited(32));
        defer std.testing.allocator.free(joined_oom_score_adj);
        try std.testing.expectEqualStrings(if (joined_options.oom_score_adj == -500) "-500\n" else "500\n", joined_oom_score_adj);
        const joined_reader = try openPath(linux.AT.FDCWD, joined_fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        defer closeFd(joined_reader);
        var joined_poll = [_]linux.pollfd{.{ .fd = joined_reader, .events = linux.POLL.IN, .revents = 0 }};
        try checkResult(linux.poll(&joined_poll, 1, 2000));
        try std.testing.expect(joined_poll[0].revents & linux.POLL.IN != 0);
        var acknowledgement: [1]u8 = undefined;
        try std.testing.expect(readAll(joined_reader, &acknowledgement));
        try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
    }
    if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0) {
        // Identity maps isolate loss of host CAP_SYS_RESOURCE from the proc
        // ownership failure exercised by the nonidentity maps above.
        var lowered_spec = spec;
        lowered_spec.linux.?.uidMappings = &.{.{ .containerID = 0, .hostID = 0, .size = 10 }};
        lowered_spec.linux.?.gidMappings = &.{.{ .containerID = 0, .hostID = 0, .size = 10 }};
        const lowered_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/lowered.fifo", .{absolute}, 0);
        defer std.testing.allocator.free(lowered_fifo);
        try checkResult(linux.mknod(lowered_fifo, linux.S.IFIFO | 0o600, 0));
        const lowered_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-lowered", .{cgroup_path});
        defer std.testing.allocator.free(lowered_cgroup);
        var lowered_options = options;
        lowered_options.spec = &lowered_spec;
        lowered_options.exec_fifo = lowered_fifo;
        lowered_options.cgroup_path = lowered_cgroup;
        lowered_options.oom_score_adj = -500;
        const lowered = try backend.create(lowered_options);
        defer std.testing.allocator.free(lowered.starttime);
        defer {
            backend.kill(lowered, 9) catch {};
            backend.delete(lowered) catch {};
        }
        const lowered_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{lowered.pid});
        defer std.testing.allocator.free(lowered_oom_path);
        const lowered_oom_score_adj = try ProcFile.read(lowered_oom_path, .limited(32));
        defer std.testing.allocator.free(lowered_oom_score_adj);
        try std.testing.expectEqualStrings("-500\n", lowered_oom_score_adj);
    }
    // Mapped root (host UID 100000) must still acknowledge start on the FIFO.
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll, 1, 2000));
    try std.testing.expect(poll[0].revents & linux.POLL.IN != 0);
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "linux mount destinations reject symlinks without creating host paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "outside", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const outside = try std.fs.path.join(std.testing.allocator, &.{ absolute, "outside" });
    defer std.testing.allocator.free(outside);
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/escape", .{});
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/file", .{});
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const rootfs_z = try std.testing.allocator.dupeZ(u8, rootfs);
    defer std.testing.allocator.free(rootfs_z);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    if (mountDestination(root_fd, "/escape/new", false, true)) |fd| {
        closeFd(fd);
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/file", true, true));
    var step: RootfsStep = .{};
    if (createDevice(root_fd, .{ .path = "/escape/new", .mode = linux.S.IFIFO | 0o600, .dev = 0 }, true, &step)) {
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/new", .{}));
}

test "linux device creation rejects mismatched existing nodes and preserves matching FIFOs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "file", .data = "" });
    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    try tmp.dir.symLink(std.testing.io, "pipe", "link", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try checkResult(linux.mknodat(root, "pipe", linux.S.IFIFO | 0o600, 0));
    const before = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    var step: RootfsStep = .{};
    for ([_][:0]const u8{ "/file", "/directory", "/link" }) |path| {
        try std.testing.expectError(error.InvalidPath, createDevice(root, .{
            .path = path,
            .mode = linux.S.IFIFO | 0o666,
            .dev = 0,
        }, true, &step));
    }
    try createDevice(root, .{ .path = "/pipe", .mode = linux.S.IFIFO | 0o666, .dev = 0 }, true, &step);
    const stat = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    try std.testing.expectEqual(before.permissions.toMode(), stat.permissions.toMode());
}

test "linux device validation rejects mismatched types and device numbers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const source = try openPath(linux.AT.FDCWD, "/dev/null", .{ .PATH = true, .CLOEXEC = true });
    defer closeFd(source);
    try validateDeviceNode(source, .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 });
    for ([_]PreparedDevice{
        .{ .path = "/dev/null", .mode = linux.S.IFBLK | 0o666, .dev = 0x103 },
        .{ .path = "/dev/null", .mode = linux.S.IFIFO | 0o666, .dev = 0 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x203 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x105 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x100103 },
    }) |device| {
        try std.testing.expectError(error.InvalidPath, validateDeviceNode(source, device));
    }
}

test "linux privileged bind remount honors atime changes and clears unrequested flags" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source);
    const ms = linux.MS;
    const cases = [_]struct { source_atime: u32, requested: u32 }{
        .{ .source_atime = ms.RELATIME, .requested = ms.STRICTATIME },
        .{ .source_atime = ms.STRICTATIME, .requested = ms.NOATIME },
        .{ .source_atime = ms.NOATIME, .requested = ms.RELATIME },
    };
    for (cases) |case| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            // Set per-mount readonly without making the superblock readonly.
            checkResult(linux.mount(null, source, null, ms.BIND | ms.REMOUNT | ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC | case.source_atime, 0)) catch linux.exit_group(4);
            const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(5);
            var step: RootfsStep = .{};
            applyMount(rootfs, root_fd, .{
                .destination = "/bound",
                .source = source,
                .type = null,
                .flags = ms.BIND | case.requested,
                .propagation = 0,
                .data = "",
            }, true, &step) catch linux.exit_group(6);
            const target = mountDestination(root_fd, "/bound", false, false) catch linux.exit_group(7);
            const actual = remountFlags(target, 0) catch linux.exit_group(8);
            if (actual != case.requested) linux.exit_group(9);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

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

fn expectNoRootfsMount(rootfs: []const u8) !void {
    const text = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(text);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (lines.next()) |line| {
        const entry = try MountInfo.parse(line);
        const path = try mountinfoPath(&buffer, entry.mountpoint);
        if (std.mem.eql(u8, path, rootfs) or
            (std.mem.startsWith(u8, path, rootfs) and path.len > rootfs.len and path[rootfs.len] == '/'))
        {
            std.debug.print("unexpected mount under rootfs: {s}\n", .{line});
            return error.TestUnexpectedResult;
        }
    }
}

fn expectOutsideRootfsUnchanged(before: []const u8, rootfs: []const u8) !void {
    const after = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(after);
    var outside: std.ArrayList(u8) = .empty;
    defer outside.deinit(std.testing.allocator);
    var lines = std.mem.tokenizeScalar(u8, after, '\n');
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (lines.next()) |line| {
        const path = try mountinfoPath(&buffer, (try MountInfo.parse(line)).mountpoint);
        if (std.mem.eql(u8, path, rootfs) or
            (std.mem.startsWith(u8, path, rootfs) and path.len > rootfs.len and path[rootfs.len] == '/'))
            continue;
        try outside.appendSlice(std.testing.allocator, line);
        try outside.append(std.testing.allocator, '\n');
    }
    try std.testing.expectEqualStrings(before, outside.items);
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
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs", .readonly = true },
        // Deliberately omit linux entirely: every namespace is inherited.
        .process = .{
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
            .user = .{ .uid = 0, .gid = 0 },
        },
    };
    var mounts: [7]Backend.Mount = undefined;
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
        fn fail(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.HookFailed;
        }
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "inherited",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = cgroup_path,
        .mounts = mounts[0..mount_count],
        .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
        .masked_paths = &.{ "/masked-file", "/masked-dir", "/bound/masked-file" },
        .readonly_paths = &.{ "/readonly-file", "/bound/readonly-file" },
        .on_create = .{ .ptr = &implementation, .run = Callback.fail },
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
    try std.testing.expectError(error.CgroupWriteFailed, backend.create(options));
    options.resources = .{};
    spec.linux = .{ .namespaces = &.{.{ .type = .network, .path = "/igvano-missing-namespace" }} };
    try std.testing.expectError(error.CreateFailed, backend.create(options));
    spec.linux = null;
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
    try std.testing.expectError(error.CreateFailed, backend.create(options));
    options.mounts = mounts[0..mount_count];
    try expectNoRootfsMount(rootfs);

    try std.testing.expectError(error.HookFailed, backend.create(options));
    try expectNoRootfsMount(rootfs);
    options.on_create = null;
    // Also exercise a failure after chroot and path restrictions.
    spec.process.?.cwd = "/missing-cwd";
    try std.testing.expectError(error.CreateFailed, backend.create(options));
    try expectNoRootfsMount(rootfs);
    spec.process.?.cwd = "/";
    const handle = try backend.create(options);
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
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
        if (!try backend.alive(handle)) break;
        _ = linux.nanosleep(&delay, null);
    }
    try std.testing.expect(!try backend.alive(handle));
    const result_path = try std.fmt.bufPrintZ(&path_buffer, "{s}/dev/result", .{rootfs});
    {
        const result_fd = try openPath(linux.AT.FDCWD, result_path, .{ .CLOEXEC = true });
        defer closeFd(result_fd);
        var result: ["success".len]u8 = undefined;
        try std.testing.expect(readAll(result_fd, &result));
        try std.testing.expectEqualStrings("success", &result);
    }
    try backend.delete(handle);
    try expectNoRootfsMount(rootfs);
    try backend.delete(handle);
    // Existing mount records, including /'s shared propagation, are unchanged.
    const after = try readMountinfo(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);

    // A configured root mount covers the self-bind whose identity cleanup owns.
    // Exercise both "/" and an OCI destination that normalizes to it.
    for ([_][]const u8{ "/", "/a/.." }) |destination| {
        const normalized = try oci.resolveMountDestination(std.testing.allocator, destination);
        defer std.testing.allocator.free(normalized);
        const stacked_mounts = [_]Backend.Mount{
            .{
                .destination = normalized,
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
        try std.testing.expectError(error.CreateFailed, backend.create(options));
        try expectNoRootfsMount(rootfs);
        options.mounts = &stacked_mounts;
        options.on_create = .{ .ptr = &implementation, .run = Callback.fail };
        try std.testing.expectError(error.HookFailed, backend.create(options));
        try expectNoRootfsMount(rootfs);
        options.on_create = null;
        spec.process.?.cwd = "/missing-cwd";
        try std.testing.expectError(error.CreateFailed, backend.create(options));
        try expectNoRootfsMount(rootfs);
        spec.process.?.cwd = "/";
        const stacked_handle = try backend.create(options);
        defer std.testing.allocator.free(stacked_handle.starttime);
        defer {
            backend.kill(stacked_handle, 9) catch {};
            backend.delete(stacked_handle) catch {};
        }
        const top_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(top_fd);
        try std.testing.expect(stacked_handle.rootfs_mount_id.? != try mountId(top_fd));
        try expectOutsideRootfsUnchanged(before, rootfs);
        try backend.kill(stacked_handle, 9);
        try backend.delete(stacked_handle);
        try expectNoRootfsMount(rootfs);
        try backend.delete(stacked_handle);
    }
    options.mounts = mounts[0..mount_count];

    // Delete must preserve a replacement mount that is not our self-bind.
    try checkResult(linux.mount("tmpfs", rootfs, "tmpfs", 0, 0));
    var replacement: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &replacement));
    try backend.delete(handle);
    var retained: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));

    // A replacement self-bind also belongs to someone else.
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &replacement));
    try backend.delete(handle);
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    var legacy_handle = handle;
    legacy_handle.rootfs_mount_id = null;
    try backend.delete(legacy_handle);
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID = true }, &retained));
    try std.testing.expectEqual(replacement.mnt_id, retained.mnt_id);
    try checkResult(linux.umount2(rootfs, linux.MNT.DETACH));
}

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
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    try checkResult(linux.mount(rootfs, rootfs, null, linux.MS.BIND | linux.MS.REC, 0));
    const handle: Backend.Handle = .{
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
    try backend.delete(handle);
    const current_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(current_fd);
    try std.testing.expectEqual(replacement_id, try mountId(current_fd));
    var reboot_handle = handle;
    reboot_handle.rootfs_mount_id = replacement_id;
    reboot_handle.rootfs_mount_boot_id.?[0] ^= 1;
    try backend.delete(reboot_handle);
    var legacy_handle = handle;
    legacy_handle.rootfs_mount_id = replacement_id;
    legacy_handle.rootfs_mount_boot_id = null;
    try backend.delete(legacy_handle);
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, rootfs, 0, .{ .MNT_ID_UNIQUE = true }, &stat));
    try std.testing.expectEqual(replacement_id, stat.mnt_id);
    var replacement_handle = handle;
    replacement_handle.rootfs_mount_id = replacement_id;
    try backend.delete(replacement_handle);
    try expectNoRootfsMount(rootfs);
    try backend.delete(replacement_handle);
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
    const symlinks = [_]Backend.Symlink{.{ .path = "/dev/ptmx", .target = "pts/ptmx" }};
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
        var slave_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/", 0, .BASIC_STATS, &root_stat)) catch linux.exit_group(7);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev", 0, .BASIC_STATS, &dev_stat)) catch linux.exit_group(7);
        if (root_stat.dev_major != dev_stat.dev_major or root_stat.dev_minor != dev_stat.dev_minor)
            linux.exit_group(8);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(9);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &slave_stat)) catch linux.exit_group(9);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != slave_stat.ino or
            console_stat.dev_major != slave_stat.dev_major or console_stat.dev_minor != slave_stat.dev_minor)
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
    const master = try console.receiveFd(sockets[0]);
    defer closeFd(master);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(master, &output));
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
            setupRootfs(rootfs, &.{case.mount}, &.{}, &.{}, false, .{}) catch |err|
                linux.exit_group(if (err == error.CreateFailed) 0 else 3);
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

test "linux sysctls precede readonly restrictions and preserve the runtime network namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const allocator = std.testing.allocator;
    const host = try openPath(linux.AT.FDCWD, "/proc/sys/net/ipv4", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(host);
    const before = try readCgroupFile(allocator, host, "ip_forward");
    defer allocator.free(before);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(allocator, "{s}/rootfs", .{absolute}, 0);
    defer allocator.free(rootfs);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    var ready_writer: ?posix.fd_t = ready[1];
    defer if (ready_writer) |fd| closeFd(fd);
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(ready[0]);
        closeFd(go[1]);
        closeFd(host);
        checkResult(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWNET | linux.CLONE.NEWIPC)) catch linux.exit_group(77);
        if (!writeAll(ready[1], &.{1})) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(2);
        const mounts = [_]PreparedMount{
            .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
        };
        setupRootfs(rootfs, &mounts, &.{}, &.{}, true, .{
            .sysctls = &.{.{ .key = "net.ipv4.ip_forward", .value = "1" }},
            .readonly_paths = &.{"/proc/sys"},
        }) catch linux.exit_group(3);
        const fd = openPath(linux.AT.FDCWD, "/proc/sys/net/ipv4/ip_forward", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(4);
        var value: [2]u8 = undefined;
        if (!readAll(fd, &value) or !std.mem.eql(u8, &value, "1\n")) linux.exit_group(5);
        closeFd(fd);
        if (linux.errno(linux.open("/proc/sys/net/ipv4/ip_forward", .{ .ACCMODE = .WRONLY }, 0)) != .ROFS)
            linux.exit_group(6);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    closeFd(ready[1]);
    ready_writer = null;
    var byte: [1]u8 = undefined;
    if (!readAll(ready[0], &byte)) {
        const status = try waitChild(pid);
        reaped = true;
        if (status == 77) return error.SkipZigTest;
        return error.TestUnexpectedResult;
    }
    // Joined namespaces also validate when their inode differs from ours.
    for ([_]struct { kind: @FieldType(oci.Spec.Namespace, "type"), name: []const u8, key: []const u8 }{
        .{ .kind = .network, .name = "net", .key = "net.ipv4.ip_forward" },
        .{ .kind = .ipc, .name = "ipc", .key = "kernel.msgmax" },
    }) |case| {
        const path = try std.fmt.allocPrint(allocator, "/proc/{d}/ns/{s}", .{ pid, case.name });
        defer allocator.free(path);
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(allocator);
        try sysctl.map.put(allocator, case.key, "1");
        try oci.validateSysctls(.{ .sysctl = sysctl, .namespaces = &.{.{ .type = case.kind, .path = path }} });
    }
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
    const after = try readCgroupFile(allocator, host, "ip_forward");
    defer allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
}

test "linux sysctl writes reject symlinks in every path component" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "net/ipv4");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "unchanged" });
    try tmp.dir.symLink(std.testing.io, "../../outside", "net/ipv4/ip_forward", .{});
    try tmp.dir.symLink(std.testing.io, "net", "alias", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_][]const u8{ "net.ipv4.ip_forward", "alias.ipv4.ip_forward", "net..outside" }) |key| {
        if (writeSysctl(root, .{ .key = key, .value = "1" })) return error.TestUnexpectedResult else |_| {}
    }
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "outside", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("unchanged", contents);
}

test "linux sysctls require procfs mounted inside the rootfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/proc/sys");
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
        .{ .destination = "/proc/sys", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" },
    };
    for ([_]bool{ false, true }) |overmount_sys| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            setupRootfs(rootfs, if (overmount_sys) &mounts else &.{}, &.{}, &.{}, false, .{
                .sysctls = &.{.{ .key = "net.ipv4.ip_forward", .value = "1" }},
            }) catch |err| linux.exit_group(if (err == error.MissingProcfs) 0 else 2);
            linux.exit_group(3);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
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
    const symlinks = oci.deviceSymlinks(&.{.{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }});
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

fn requireTestMountNamespace() !void {
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(pid) != 0) return error.SkipZigTest;
}

fn requireTestUniqueMountIds() !void {
    const fd = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(fd);
    const id = mountId(fd) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    _ = statMount(id) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
}

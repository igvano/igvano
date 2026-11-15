// SPDX-License-Identifier: Apache-2.0
// Portions derived from opencontainers/cgroups (https://github.com/opencontainers/cgroups), Copyright The runc Authors, Apache-2.0:
// utils.go (ConvertCPUSharesToCgroupV2Value, ConvertMemorySwapToCgroupV2Value)
// and fs2/create.go (CreateCgroupPath).
// Translated to Zig and modified. See NOTICE.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const Resources = libcontainer.Resources;
const diagnostics = @import("diagnostic.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const createCgroupDirectory = @import("cgroup.zig").createCgroupDirectory;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const tryV1Write = @import("cgroup_v1.zig").tryV1Write;
const readCgroupFile = @import("cgroup.zig").readCgroupFile;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const killV1Members = @import("cgroup_v1.zig").killV1Members;
const MountInfo = @import("mountinfo.zig").MountInfo;
const mountinfoPath = @import("mountinfo.zig").mountinfoPath;
const cgroupFrozen = @import("freezer.zig").cgroupFrozen;
const waitFrozen = @import("freezer.zig").waitFrozen;

pub const Write = struct {
    name: []const u8,
    value: []const u8,
    /// Like runc: the kernel may refuse this write (EINVAL) until the named
    /// later write lands, e.g. a burst above the old quota. Retry after it.
    retry_after: ?[]const u8 = null,
    /// `optional` skips a file the kernel lacks (hugetlb rsvd). runc's setIo:
    /// a `bfq` weight goes to io.bfq.weight when the file exists; a
    /// `fallback` io.weight write lands only when it does not; a
    /// `bfq_device` weight needs per-device BFQ support (Linux 5.4+).
    mode: enum { plain, optional, bfq, fallback, bfq_device } = .plain,
};

/// Pure cgroup v2 mapping. The caller owns the slice and both strings.
pub fn v2Writes(allocator: std.mem.Allocator, resources: Resources) libcontainer.Error![]Write {
    var writes: std.ArrayList(Write) = .empty;
    defer writes.deinit(allocator);
    errdefer for (writes.items) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    };
    if (resources.memory) |memory| try appendV2MemoryWrites(allocator, &writes, memory);
    if (resources.cpu) |cpu| try appendV2CpuWrites(allocator, &writes, cpu);
    if (resources.pids) |pids| try appendV2PidsWrites(allocator, &writes, pids);
    if (resources.block_io) |block| try appendV2BlockIOWrites(allocator, &writes, block);
    try appendV2HugepageWrites(allocator, &writes, resources.hugepage_limits);
    try appendV2UnifiedWrites(allocator, &writes, resources.unified);
    return writes.toOwnedSlice(allocator);
}

fn appendV2MemoryWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), memory: Resources.Memory) libcontainer.Error!void {
    if (memory.limit) |limit| {
        if (limit != 0)
            try appendWrite(allocator, writes, "memory.max", try cgroupLimit(allocator, limit));
    }
    if (memory.reservation) |reservation|
        try appendWrite(allocator, writes, "memory.low", try cgroupLimit(allocator, reservation));
    if (try swapMax(memory.limit orelse 0, memory.swap orelse 0)) |swap|
        try appendWrite(allocator, writes, "memory.swap.max", try cgroupLimit(allocator, swap));
}

/// runc's ConvertMemorySwapToCgroupV2Value: spec swap is memory+swap, and
/// cgroup2 swap is separate. Null writes nothing.
fn swapMax(limit: i64, swap: i64) libcontainer.Error!?i64 {
    if (swap < -1) return error.InvalidConfig;
    // Unlimited memory without a swap value means unlimited swap too.
    if (limit == -1 and swap == 0) return -1;
    if (swap == -1) return -1;
    if (swap == 0) return null;
    if (limit == -1) return swap;
    if (limit <= 0) {
        reportDiagnostic("swap limit requires a memory limit", .{});
        return error.InvalidConfig;
    }
    if (swap < limit) {
        reportDiagnostic("memory+swap limit should be >= memory limit", .{});
        return error.InvalidConfig;
    }
    return swap - limit;
}

test "v2 swap follows runc's memory+swap conversion" {
    const cases = [_]struct { limit: i64, swap: i64, max: ?i64 }{
        .{ .limit = -1, .swap = 0, .max = -1 },
        .{ .limit = 64, .swap = -1, .max = -1 },
        .{ .limit = 64, .swap = 0, .max = null },
        .{ .limit = -1, .swap = 128, .max = 128 },
        .{ .limit = 64, .swap = 128, .max = 64 },
        .{ .limit = 64, .swap = 64, .max = 0 },
    };
    for (cases) |case| try std.testing.expectEqual(case.max, try swapMax(case.limit, case.swap));
    defer @import("diagnostic.zig").last_diagnostic_len = 0;
    try std.testing.expectError(error.InvalidConfig, swapMax(0, 128));
    try std.testing.expectError(error.InvalidConfig, swapMax(64, 32));
}

fn appendV2CpuWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), cpu: Resources.Cpu) libcontainer.Error!void {
    // Like runc, cpu.idle goes first; the kernel validates the value.
    if (cpu.idle) |idle|
        try appendWrite(allocator, writes, "cpu.idle", try std.fmt.allocPrint(allocator, "{d}", .{idle}));
    // Like runc's fs2 setCPU, any quota below 1 means "max".
    const quota = cpu.quota orelse -1;
    const period = if ((cpu.period orelse 0) == 0) 100000 else cpu.period.?;
    const writes_max = cpu.quota != null or cpu.period != null;
    // Like runc, burst goes first, then again after cpu.max if refused.
    if (cpu.burst) |burst| {
        try appendWrite(allocator, writes, "cpu.max.burst", try std.fmt.allocPrint(allocator, "{d}", .{burst}));
        if (writes_max) writes.items[writes.items.len - 1].retry_after = "cpu.max";
    }
    if (writes_max) {
        const value = if (quota <= 0)
            try std.fmt.allocPrint(allocator, "max {d}", .{period})
        else
            try std.fmt.allocPrint(allocator, "{d} {d}", .{ quota, period });
        try appendWrite(allocator, writes, "cpu.max", value);
    }
    if (cpu.shares) |shares| {
        const weight = try cpuWeight(shares);
        if (weight != 0)
            try appendWrite(allocator, writes, "cpu.weight", try std.fmt.allocPrint(allocator, "{d}", .{weight}));
    }
    if (cpu.cpus) |cpus|
        try appendWrite(allocator, writes, "cpuset.cpus", try allocator.dupe(u8, cpus));
    if (cpu.mems) |mems|
        try appendWrite(allocator, writes, "cpuset.mems", try allocator.dupe(u8, mems));
}

fn appendV2PidsWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), pids: Resources.Pids) libcontainer.Error!void {
    if (pids.limit) |limit| {
        if (limit != 0)
            try appendWrite(allocator, writes, "pids.max", try cgroupLimit(allocator, limit));
    }
}

fn appendV2BlockIOWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), block: Resources.BlockIO) libcontainer.Error!void {
    if (block.weight) |weight| {
        const converted = try ioWeight(weight);
        if (converted != 0) {
            try appendWrite(allocator, writes, "io.bfq.weight", try std.fmt.allocPrint(allocator, "{d}", .{weight}));
            writes.items[writes.items.len - 1].mode = .bfq;
            try appendWrite(allocator, writes, "io.weight", try std.fmt.allocPrint(allocator, "{d}", .{converted}));
            writes.items[writes.items.len - 1].mode = .fallback;
        }
    }
    // Like runc, per-device weights need BFQ device support; else they are skipped.
    for (block.weight_device) |device| {
        if (device.weight) |weight| {
            if (try ioWeight(weight) != 0) {
                try appendWrite(allocator, writes, "io.bfq.weight", try std.fmt.allocPrint(allocator, "{d}:{d} {d}", .{ device.major, device.minor, weight }));
                writes.items[writes.items.len - 1].mode = .bfq_device;
            }
        }
    }
    inline for (.{
        .{ "throttle_read_bps", "rbps" },
        .{ "throttle_write_bps", "wbps" },
        .{ "throttle_read_iops", "riops" },
        .{ "throttle_write_iops", "wiops" },
    }) |throttle| {
        for (@field(block, throttle[0])) |device|
            try appendWrite(allocator, writes, "io.max", try std.fmt.allocPrint(allocator, "{d}:{d} {s}={d}", .{ device.major, device.minor, throttle[1], device.rate }));
    }
}

fn appendV2HugepageWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), pages: []const Resources.HugepageLimit) libcontainer.Error!void {
    for (pages) |page| {
        if (page.page_size.len == 0 or std.mem.indexOfAny(u8, page.page_size, "/\x00") != null)
            return error.InvalidConfig;
        const name = try std.fmt.allocPrint(allocator, "hugetlb.{s}.max", .{page.page_size});
        defer allocator.free(name);
        try appendWrite(allocator, writes, name, try std.fmt.allocPrint(allocator, "{d}", .{page.limit}));
        // Like runc, the reservation limit follows when the kernel has it.
        const rsvd = try std.fmt.allocPrint(allocator, "hugetlb.{s}.rsvd.max", .{page.page_size});
        defer allocator.free(rsvd);
        try appendWrite(allocator, writes, rsvd, try std.fmt.allocPrint(allocator, "{d}", .{page.limit}));
        writes.items[writes.items.len - 1].mode = .optional;
    }
}

fn appendV2UnifiedWrites(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), entries: []const Resources.Unified) libcontainer.Error!void {
    // Raw settings are last so they override any typed resource mapping.
    // Like runc's WriteFileByLine, a multi-line value is written line by
    // line: files such as io.max take one device per write.
    for (entries) |entry| {
        var rest = entry.value;
        while (true) {
            const end = if (std.mem.indexOfScalar(u8, rest, '\n')) |i| i + 1 else rest.len;
            try appendWrite(allocator, writes, entry.key, try allocator.dupe(u8, rest[0..end]));
            rest = rest[end..];
            if (rest.len == 0) break;
        }
    }
}

pub fn cgroupLimit(allocator: std.mem.Allocator, limit: i64) libcontainer.Error![]u8 {
    if (limit < -1) return error.InvalidConfig;
    if (limit == -1) return allocator.dupe(u8, "max");
    return std.fmt.allocPrint(allocator, "{d}", .{limit});
}

/// Zero shares means unset. runc's quadratic fit (opencontainers/cgroups
/// ConvertCPUSharesToCgroupV2Value) maps 2, 1024 and 262144 to the weights
/// 1, 100 and 10000, so the default shares give the default weight; values
/// outside 2..262144 clamp, as in runc.
pub fn cpuWeight(shares: u64) libcontainer.Error!u64 {
    if (shares == 0) return 0;
    if (shares <= 2) return 1;
    if (shares >= 262144) return 10000;
    const l = std.math.log2(@as(f64, @floatFromInt(shares)));
    const exponent = (l * l + 125 * l) / 612.0 - 7.0 / 34.0;
    return @intFromFloat(@ceil(std.math.pow(f64, 10, exponent)));
}

pub fn ioWeight(weight: u16) libcontainer.Error!u64 {
    if (weight == 0) return 0;
    if (weight < 10 or weight > 1000) return error.InvalidConfig;
    return 1 + (@as(u64, weight - 10) * 9999) / 990;
}

fn appendWrite(allocator: std.mem.Allocator, writes: *std.ArrayList(Write), name: []const u8, value: []u8) libcontainer.Error!void {
    errdefer allocator.free(value);
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    try writes.append(allocator, .{ .name = owned_name, .value = value });
}

pub fn freeWrites(allocator: std.mem.Allocator, writes: []const Write) void {
    for (writes) |write| {
        allocator.free(write.name);
        allocator.free(write.value);
    }
    allocator.free(writes);
}

pub fn v2IgnoredFields(allocator: std.mem.Allocator, resources: Resources) ![]u8 {
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

fn enabledControllers(allocator: std.mem.Allocator, available: []const u8, writes: []const Write) libcontainer.Error![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var controllers = std.mem.tokenizeAny(u8, available, " \t\n");
    while (controllers.next()) |controller| {
        for (writes) |write| {
            const dot = std.mem.indexOfScalar(u8, write.name, '.') orelse continue;
            if (std.mem.eql(u8, write.name[0..dot], controller)) {
                try result.append(allocator, '+');
                try result.appendSlice(allocator, controller);
                try result.append(allocator, ' ');
                break;
            }
        }
    }
    return result.toOwnedSlice(allocator);
}

test "cpu shares map to cgroup2 weights without underflow or overflow" {
    const cases = [_]struct { shares: u64, weight: u64 }{
        .{ .shares = 0, .weight = 0 },
        .{ .shares = 2, .weight = 1 },
        .{ .shares = 100, .weight = 17 },
        .{ .shares = 1024, .weight = 100 },
        .{ .shares = 262144, .weight = 10000 },
    };
    for (cases) |case| try std.testing.expectEqual(case.weight, try cpuWeight(case.shares));
    for ([_][2]u64{ .{ 1, 1 }, .{ 262145, 10000 }, .{ std.math.maxInt(u64), 10000 } }) |case|
        try std.testing.expectEqual(case[1], try cpuWeight(case[0]));
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
        .{ .name = "cpu.weight", .value = "100" },
        .{ .name = "pids.max", .value = "32" },
    }, writes);
}

test "v2 writes preserve unlimited values and CPU defaults" {
    const cases = [_]struct { resources: Resources, name: []const u8, value: []const u8 }{
        .{ .resources = .{ .pids = .{ .limit = -1 } }, .name = "pids.max", .value = "max" },
        .{ .resources = .{ .cpu = .{ .quota = -1, .period = 200000 } }, .name = "cpu.max", .value = "max 200000" },
        .{ .resources = .{ .cpu = .{ .period = 200000 } }, .name = "cpu.max", .value = "max 200000" },
        .{ .resources = .{ .cpu = .{ .quota = 50000 } }, .name = "cpu.max", .value = "50000 100000" },
        .{ .resources = .{ .cpu = .{ .quota = 0, .period = 0 } }, .name = "cpu.max", .value = "max 100000" },
        .{ .resources = .{ .cpu = .{ .idle = 1 } }, .name = "cpu.idle", .value = "1" },
        .{ .resources = .{ .cpu = .{ .idle = 0 } }, .name = "cpu.idle", .value = "0" },
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
    try std.testing.expectEqualDeep(&[_]Write{.{ .name = "cpu.weight", .value = "100" }}, writes);
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
            try std.testing.expectEqual(@as(usize, 18), writes.len);
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
        // Like runc, unlimited memory without a swap value unlimits swap too.
        .{ .memory = .{ .limit = -1 }, .expected = &.{
            .{ .name = "memory.max", .value = "max" }, .{ .name = "memory.swap.max", .value = "max" },
        } },
        .{ .memory = .{ .limit = -1, .swap = 64 }, .expected = &.{
            .{ .name = "memory.max", .value = "max" }, .{ .name = "memory.swap.max", .value = "64" },
        } },
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
    defer diagnostics.last_diagnostic_len = 0;
    for ([_]?i64{ null, 0 }) |limit| {
        diagnostics.last_diagnostic_len = 0;
        try std.testing.expectError(error.InvalidConfig, v2Writes(std.testing.allocator, .{ .memory = .{ .limit = limit, .swap = 128 } }));
        try std.testing.expectEqualStrings("swap limit requires a memory limit", diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
    }
}

test "v2 writes convert global and per-device block IO weights" {
    const cases = [_]struct { weight: u16, expected: []const u8 }{
        .{ .weight = 10, .expected = "1" },
        .{ .weight = 100, .expected = "910" },
        .{ .weight = 500, .expected = "4950" },
        .{ .weight = 1000, .expected = "10000" },
    };
    var weight_buffer: [8]u8 = undefined;
    for (cases) |case| {
        const writes = try v2Writes(std.testing.allocator, .{ .block_io = .{ .weight = case.weight } });
        defer freeWrites(std.testing.allocator, writes);
        try std.testing.expectEqualDeep(&[_]Write{
            .{ .name = "io.bfq.weight", .value = try std.fmt.bufPrint(&weight_buffer, "{d}", .{case.weight}), .mode = .bfq },
            .{ .name = "io.weight", .value = case.expected, .mode = .fallback },
        }, writes);
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
        .{ .name = "io.bfq.weight", .value = "8:0 10", .mode = .bfq_device },
        .{ .name = "io.bfq.weight", .value = "8:1 1000", .mode = .bfq_device },
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

test "v2 unified values with several lines are written line by line" {
    const writes = try v2Writes(std.testing.allocator, .{ .unified = &.{.{ .key = "io.max", .value = "8:0 riops=1\n8:16 riops=2\n" }} });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "io.max", .value = "8:0 riops=1\n" },
        .{ .name = "io.max", .value = "8:16 riops=2\n" },
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
        .{ .name = "hugetlb.2MB.rsvd.max", .value = "4194304", .mode = .optional },
        .{ .name = "hugetlb.1GB.max", .value = "0" },
        .{ .name = "hugetlb.1GB.rsvd.max", .value = "0", .mode = .optional },
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
    const allocator = std.testing.allocator;
    const available = "memory cpu pids cpuset io hugetlb rdma misc\n";
    const selected = try enabledControllers(allocator, available, &.{
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
        .{ .name = "cgroup.max.depth", .value = "8" },
        .{ .name = "rdma.max", .value = "mlx5_0 hca_handle=1" },
        .{ .name = "misc.max", .value = "sev 1" },
        .{ .name = "unknown.max", .value = "1" },
        .{ .name = "cpu", .value = "1" },
    });
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("+memory +cpu +pids +cpuset +io +hugetlb +rdma +misc ", selected);
    const empty = try enabledControllers(allocator, available, &.{});
    defer allocator.free(empty);
    try std.testing.expectEqualStrings("", empty);
    const writes = try v2Writes(allocator, .{ .unified = &.{.{ .key = "io.max", .value = "8:0 rbps=1" }} });
    defer freeWrites(allocator, writes);
    const io = try enabledControllers(allocator, available, writes);
    defer allocator.free(io);
    try std.testing.expectEqualStrings("+io ", io);
    const unavailable = try enabledControllers(allocator, "memory\n", writes);
    defer allocator.free(unavailable);
    try std.testing.expectEqualStrings("", unavailable);
}

pub fn v2MountRoot(allocator: std.mem.Allocator, text: []const u8) libcontainer.Error![]u8 {
    var root: ?[]const u8 = null;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const separator = std.mem.indexOf(u8, line, " - ") orelse return error.CreateFailed;
        var fields = std.mem.tokenizeScalar(u8, line[separator + 3 ..], ' ');
        if (!std.mem.eql(u8, fields.next() orelse return error.CreateFailed, "cgroup2")) continue;
        const mount = try MountInfo.parse(line);
        if (std.mem.eql(u8, try mountinfoPath(&buffer, mount.mountpoint), "/sys/fs/cgroup"))
            root = mount.root;
    }
    return allocator.dupe(u8, try mountinfoPath(&buffer, root orelse return error.CreateFailed));
}

test "v2 mount roots are unescaped and use the last mount at the cgroup root" {
    for ([_]struct { text: []const u8, root: []const u8 }{
        .{ .text = "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw", .root = "/" },
        .{ .text = "1 0 0:1 /docker/cid /sys/fs/cgroup rw - cgroup2 cgroup rw", .root = "/docker/cid" },
        .{ .text = "1 0 0:1 /docker/a\\040b /sys/fs/cgr\\157up rw - cgroup2 cgroup rw", .root = "/docker/a b" },
        .{
            .text =
            \\1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw
            \\2 1 0:2 /docker/cid /sys/fs/cgroup rw - cgroup2 cgroup rw
            \\3 2 0:3 /other /sys/fs/cgroup/other rw - cgroup2 cgroup rw
            \\4 2 0:4 /legacy /sys/fs/cgroup rw - cgroup cgroup rw,cpu
            ,
            .root = "/docker/cid",
        },
    }) |case| {
        const root = try v2MountRoot(std.testing.allocator, case.text);
        defer std.testing.allocator.free(root);
        try std.testing.expectEqualStrings(case.root, root);
    }
    for ([_][]const u8{
        "",
        "1 0 0:1 / /sys/fs/cgroup rw - tmpfs tmpfs rw",
        "1 0 0:1 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw",
    }) |text| try std.testing.expectError(error.CreateFailed, v2MountRoot(std.testing.allocator, text));
}

pub fn killV2Members(dir: posix.fd_t, signal: i32, mount_root: []const u8, path: []const u8) libcontainer.Error!void {
    const was_frozen = try cgroupFrozen(dir, .unified);
    // Only undo a freeze owned by this operation.
    defer if (!was_frozen) {
        const saved_diagnostic = diagnostics.last_diagnostic;
        const saved_len = diagnostics.last_diagnostic_len;
        writeCgroupFile(dir, "cgroup.freeze", "0", path) catch {};
        diagnostics.last_diagnostic = saved_diagnostic;
        diagnostics.last_diagnostic_len = saved_len;
    };
    if (!was_frozen) {
        try writeCgroupFile(dir, "cgroup.freeze", "1", path);
        _ = try waitFrozen(dir, .unified, true, 50);
    }
    // The v1 helper also enumerates cgroup.procs without a freezer.
    try killV1Members(dir, null, signal, mount_root, path, "");
}

/// Walk through pinned directory fds so symlinks cannot redirect cgroup writes.
/// Enable requested controllers in every ancestor before descending to the leaf.
/// Creation requires a new leaf. Nested paths can still change controllers in
/// existing parents, including other containers' cgroups. Like runc, config is trusted.
pub fn walkCgroup(root: posix.fd_t, path: []const u8, create: bool, writes: []const Write) libcontainer.Error!?posix.fd_t {
    try validateCgroupPath(path);
    var current = try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    const needs_controller = needsCgroupController(writes);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (needs_controller) try enableRequestedControllers(current, writes, path);
        if (create) {
            enableAllControllers(current);
            _ = try createCgroupDirectory(current, name, path, components.peek() == null);
        }
        const result = linux.openat(current, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => {
                closeFd(current);
                current = @intCast(result);
                if (create) try checkCgroupType(current, writes, path);
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

/// Like runc's CreateCgroupPath: offer every available controller to the
/// new cgroup, best effort (all at once, then one by one), so a later
/// update or a nested runtime can use them. Errors are ignored, as in runc.
fn enableAllControllers(dir: posix.fd_t) void {
    var scratch: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
    // Unlike runc, skip a non-root cgroup with member processes: its
    // thread-aware controllers would leave new children "domain invalid".
    if (hasInternalProcesses(dir)) return;
    const available = readCgroupFile(fixed.allocator(), dir, "cgroup.controllers") catch return;
    var all: [4096]u8 = undefined;
    var used: usize = 0;
    var names = std.mem.tokenizeAny(u8, available, " \n");
    while (names.next()) |name| {
        const entry = std.fmt.bufPrint(all[used..], "{s}+{s}", .{ if (used == 0) "" else " ", name }) catch return;
        used += entry.len;
    }
    if (used == 0 or tryV1Write(dir, "cgroup.subtree_control", all[0..used]) == .SUCCESS) return;
    names.reset();
    while (names.next()) |name| {
        var one: [64]u8 = undefined;
        _ = tryV1Write(dir, "cgroup.subtree_control", std.fmt.bufPrint(&one, "+{s}", .{name}) catch continue);
    }
}

/// runc's CreateCgroupPath: a cgroup made under one with processes is
/// "domain invalid". It can still serve thread-aware controllers in
/// threaded mode; domain controllers (memory, io, cpu, hugetlb) cannot.
fn checkCgroupType(dir: posix.fd_t, writes: []const Write, path: []const u8) libcontainer.Error!void {
    var scratch: [1024]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
    const text = readCgroupFile(fixed.allocator(), dir, "cgroup.type") catch return;
    const kind = std.mem.trim(u8, text, " \n");
    const invalid = std.mem.eql(u8, kind, "domain invalid");
    if (!invalid and !std.mem.eql(u8, kind, "threaded") and !std.mem.eql(u8, kind, "domain threaded")) return;
    if (needsDomainController(writes)) {
        reportDiagnostic("cannot enter cgroupv2 \"{s}\" with domain controllers -- it is in {s}", .{ path, if (invalid) "an invalid state" else kind });
        return error.CgroupWriteFailed;
    }
    if (invalid) _ = tryV1Write(dir, "cgroup.type", "threaded");
}

fn needsDomainController(writes: []const Write) bool {
    for (writes) |write| {
        const dot = std.mem.indexOfScalar(u8, write.name, '.') orelse continue;
        const controller = write.name[0..dot];
        for ([_][]const u8{ "memory", "io", "cpu", "hugetlb" }) |name| {
            if (std.mem.eql(u8, controller, name)) return true;
        }
    }
    return false;
}

/// The real root has no cgroup.type and may mix processes and controllers.
fn hasInternalProcesses(dir: posix.fd_t) bool {
    if (linux.errno(linux.faccessat(dir, "cgroup.type", linux.F_OK, 0)) != .SUCCESS) return false;
    var buffer: [1]u8 = undefined;
    const fd = openPath(dir, "cgroup.procs", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return false;
    defer closeFd(fd);
    const result = linux.read(fd, &buffer, 1);
    return linux.errno(result) == .SUCCESS and result == 1;
}

fn needsCgroupController(writes: []const Write) bool {
    return for (writes) |write| {
        const dot = std.mem.indexOfScalar(u8, write.name, '.') orelse continue;
        if (!std.mem.eql(u8, write.name[0..dot], "cgroup")) break true;
    } else false;
}

fn enableRequestedControllers(dir: posix.fd_t, writes: []const Write, path: []const u8) libcontainer.Error!void {
    // 8 KiB bounds controller discovery and the enabled-name list.
    // This runs after fork too: exhaustion is a policy-size failure,
    // not heap OOM, and must retain a useful cgroup diagnostic.
    var scratch: [8192]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
    const allocator = fixed.allocator();
    const available = readCgroupFile(allocator, dir, "cgroup.controllers") catch |err|
        return controllerBufferError(err, path);
    defer allocator.free(available);
    const controllers = enabledControllers(allocator, available, writes) catch |err|
        return controllerBufferError(err, path);
    defer allocator.free(controllers);
    if (controllers.len != 0) try enableCgroupControllers(dir, controllers, path);
}

fn controllerBufferError(err: libcontainer.Error, path: []const u8) libcontainer.Error {
    if (err != error.OutOfMemory) return err;
    reportDiagnostic("cannot enable cgroup controllers for '{s}': controller data exceeds the 8 KiB buffer", .{path});
    return error.CgroupWriteFailed;
}

// A populated non-root cgroup cannot hold domain controllers, and threaded
// ones alone would make it a thread root whose new children are invalid.
fn enableCgroupControllers(dir: posix.fd_t, controllers: []const u8, path: []const u8) libcontainer.Error!void {
    // cgroup.type exists everywhere except the real root, which is exempt.
    if (linux.errno(linux.faccessat(dir, "cgroup.type", linux.F_OK, 0)) == .SUCCESS) {
        const procs = try readCgroupFile(std.heap.page_allocator, dir, "cgroup.procs");
        defer std.heap.page_allocator.free(procs);
        if (std.mem.trim(u8, procs, " \t\n").len != 0) {
            reportDiagnostic("cannot enable cgroup controllers for '{s}': a parent cgroup has processes; move them into a child cgroup first", .{path});
            return error.CgroupWriteFailed;
        }
    }
    // A rootless runtime cannot write a delegated cgroup's root-owned
    // parents; that is fine when the controllers are enabled already.
    if (controllersEnabled(dir, controllers) catch false) return;
    try writeCgroupFile(dir, "cgroup.subtree_control", controllers, path);
}

fn controllersEnabled(dir: posix.fd_t, controllers: []const u8) libcontainer.Error!bool {
    const enabled = try readCgroupFile(std.heap.page_allocator, dir, "cgroup.subtree_control");
    defer std.heap.page_allocator.free(enabled);
    var wanted = std.mem.tokenizeScalar(u8, controllers, ' ');
    outer: while (wanted.next()) |entry| {
        var names = std.mem.tokenizeAny(u8, enabled, " \n");
        while (names.next()) |name| if (std.mem.eql(u8, name, entry[1..])) continue :outer;
        return false;
    }
    return true;
}

test "v2 burst goes before cpu.max and retries after it, like runc" {
    const writes = try v2Writes(std.testing.allocator, .{ .cpu = .{ .quota = 50000, .period = 100000, .burst = 20000 } });
    defer freeWrites(std.testing.allocator, writes);
    try std.testing.expectEqualDeep(&[_]Write{
        .{ .name = "cpu.max.burst", .value = "20000", .retry_after = "cpu.max" },
        .{ .name = "cpu.max", .value = "50000 100000" },
    }, writes);
    const alone = try v2Writes(std.testing.allocator, .{ .cpu = .{ .burst = 0 } });
    defer freeWrites(std.testing.allocator, alone);
    try std.testing.expectEqualDeep(&[_]Write{.{ .name = "cpu.max.burst", .value = "0" }}, alone);
}

const std = @import("std");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const backendResult = @import("diagnostic.zig").backendResult;
const Config = @import("args.zig").Config;
const parseArgs = @import("args.zig").parseArgs;
const optionValue = @import("args.zig").optionValue;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const loadDeviceNodes = @import("state.zig").loadDeviceNodes;
const readLiveState = @import("state.zig").readLiveState;
const LockTestBackend = @import("tests/helpers.zig").LockTestBackend;

pub fn parseUpdateArgs(args: []const []const u8, start_index: usize) !struct {
    index: usize,
    resources_file: ?[]const u8,
    resource_flags: oci.Spec.Resources,
} {
    var index = start_index;
    var resources_file: ?[]const u8 = null;
    var resource_flags: oci.Spec.Resources = .{};
    var has_resource_flags = false;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
        const flag = args[index];
        const name = flag[0 .. std.mem.indexOfScalar(u8, flag, '=') orelse flag.len];
        if (std.mem.eql(u8, name, "--resources") or std.mem.eql(u8, name, "-r")) {
            resources_file = try optionValue(args, &index, error.MissingResources);
            continue;
        }
        const matched = flag: {
            inline for (.{
                .{ "--memory", "limit" },
                .{ "--memory-reservation", "reservation" },
                .{ "--memory-swap", "swap" },
                .{ "--kernel-memory", "kernel" },
            }) |entry| {
                if (std.mem.eql(u8, name, entry[0])) {
                    const value = try optionValue(args, &index, error.MissingResourceValue);
                    if (resource_flags.memory == null) resource_flags.memory = .{};
                    @field(resource_flags.memory.?, entry[1]) = parseMemoryBytes(value) catch
                        return oci.validationError(error.InvalidResourceValue, "{s}: invalid memory size '{s}'", .{ name, value });
                    break :flag true;
                }
            }
            inline for (.{
                .{ "--cpu-shares", "shares", u64 },
                .{ "--cpu-share", "shares", u64 },
                .{ "--cpu-period", "period", u64 },
                .{ "--cpu-quota", "quota", i64 },
                .{ "--cpu-rt-period", "realtimePeriod", u64 },
                .{ "--cpu-rt-runtime", "realtimeRuntime", i64 },
            }) |entry| {
                if (std.mem.eql(u8, name, entry[0])) {
                    const value = try optionValue(args, &index, error.MissingResourceValue);
                    if (resource_flags.cpu == null) resource_flags.cpu = .{};
                    @field(resource_flags.cpu.?, entry[1]) = try resourceNumber(entry[2], name, value);
                    break :flag true;
                }
            }
            inline for (.{ .{ "--cpuset-cpus", "cpus" }, .{ "--cpuset-mems", "mems" } }) |entry| {
                if (std.mem.eql(u8, name, entry[0])) {
                    if (resource_flags.cpu == null) resource_flags.cpu = .{};
                    @field(resource_flags.cpu.?, entry[1]) = try optionValue(args, &index, error.MissingResourceValue);
                    break :flag true;
                }
            }
            if (std.mem.eql(u8, name, "--pids-limit")) {
                resource_flags.pids = .{ .limit = try resourceNumber(i64, name, try optionValue(args, &index, error.MissingResourceValue)) };
                break :flag true;
            }
            if (std.mem.eql(u8, name, "--blkio-weight")) {
                resource_flags.blockIO = .{ .weight = try resourceNumber(u16, name, try optionValue(args, &index, error.MissingResourceValue)) };
                break :flag true;
            }
            break :flag false;
        };
        if (!matched) return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        has_resource_flags = true;
    }
    if (resources_file == null and !has_resource_flags) return oci.validationError(error.MissingResources, "update: requires --resources <file|-> or resource flags", .{});
    return .{ .index = index, .resources_file = resources_file, .resource_flags = resource_flags };
}

fn resourceNumber(comptime T: type, flag: []const u8, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10) catch
        oci.validationError(error.InvalidResourceValue, "{s}: invalid integer '{s}'", .{ flag, value });
}

// Decimal digits[.digits], with RAMInBytes' binary, case-insensitive b/k/m/g/t/p
// units and optional b/ib after k/m/g/t/p. One space may precede a unit.
fn parseMemoryBytes(value: []const u8) !i64 {
    // runc also accepts -1 for an unlimited limit.
    if (std.mem.eql(u8, value, "-1")) return -1;
    var number_end: usize = 0;
    while (number_end < value.len and std.ascii.isDigit(value[number_end])) : (number_end += 1) {}
    if (number_end == 0) return error.InvalidResourceValue;
    if (number_end < value.len and value[number_end] == '.') {
        number_end += 1;
        const fraction_start = number_end;
        while (number_end < value.len and std.ascii.isDigit(value[number_end])) : (number_end += 1) {}
        if (number_end == fraction_start) return error.InvalidResourceValue;
    }
    var suffix_start = number_end;
    if (suffix_start < value.len and value[suffix_start] == ' ') {
        suffix_start += 1;
        if (suffix_start == value.len) return error.InvalidResourceValue;
    }
    const suffix = value[suffix_start..];
    var amount = std.fmt.parseFloat(f64, value[0..number_end]) catch return error.InvalidResourceValue;
    if (suffix.len > 0) {
        if (suffix.len > 3) return error.InvalidResourceValue;
        if (std.ascii.toLower(suffix[0]) == 'b') {
            if (suffix.len != 1) return error.InvalidResourceValue;
        } else {
            const power: u6 = switch (std.ascii.toLower(suffix[0])) {
                'k' => 10,
                'm' => 20,
                'g' => 30,
                't' => 40,
                'p' => 50,
                else => return error.InvalidResourceValue,
            };
            if ((suffix.len == 2 and std.ascii.toLower(suffix[1]) != 'b') or
                (suffix.len == 3 and !std.ascii.eqlIgnoreCase(suffix[1..], "ib"))) return error.InvalidResourceValue;
            amount *= @floatFromInt(@as(u64, 1) << power);
        }
    }
    if (!std.math.isFinite(amount) or amount < 0 or amount >= 0x1p63) return error.InvalidResourceValue;
    return @intFromFloat(amount);
}

pub fn updateContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
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
    const state = try readLiveState(allocator, io, backend, config, locked);
    defer state.deinit();
    try oci.requireUpdate(state.parsed.value.status);
    var handle = state.handle.?;
    if (resources.devices.len != 0)
        handle.device_nodes = try loadDeviceNodes(allocator, io, config.root, config.id);
    defer oci.freeDevices(allocator, handle.device_nodes);
    try backendResult(backend, backend.update(handle, resources));
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
    var implementation: backend_module.LinuxBackend = .{};
    const config: Config = .{ .root = root, .subcommand = .update, .id = "missing", .resources_file = path };
    try std.testing.expectError(error.InvalidConfig, updateContainer(allocator, io, implementation.backend(), config));
}

test "update parsing accepts resource files stdin and shim global flags" {
    for ([_][]const []const u8{
        &.{ "igvano", "update", "--resources", "resources.json", "example" },
        &.{ "igvano", "update", "--resources=resources.json", "example" },
        &.{ "igvano", "update", "-r", "resources.json", "example" },
        &.{ "igvano", "update", "--resources", "-", "example" },
        &.{ "igvano", "update", "-r", "-", "example" },
        &.{ "igvano", "--root", "/tmp/containers", "--log", "/tmp/runtime.log", "--log-format", "json", "update", "--resources=-", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("update", @tagName(config.subcommand));
        try std.testing.expectEqualStrings("example", config.id);
        const value = args[args.len - 2];
        try std.testing.expectEqualStrings(if (std.mem.indexOfScalar(u8, value, '=')) |equals|
            value[equals + 1 ..]
        else
            value, config.resources_file.?);
    }
}

test "update parsing accepts every per-field flag with separate and equals values" {
    const flags = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "--memory", .value = "64m" },
        .{ .name = "--memory-reservation", .value = "32MiB" },
        .{ .name = "--memory-swap", .value = "-1" },
        .{ .name = "--kernel-memory", .value = "1g" },
        .{ .name = "--cpu-shares", .value = "512" },
        .{ .name = "--cpu-period", .value = "100000" },
        .{ .name = "--cpu-quota", .value = "-1" },
        .{ .name = "--cpu-rt-period", .value = "1000000" },
        .{ .name = "--cpu-rt-runtime", .value = "-1" },
        .{ .name = "--cpuset-cpus", .value = "0-2" },
        .{ .name = "--cpuset-mems", .value = "0" },
        .{ .name = "--pids-limit", .value = "-1" },
        .{ .name = "--blkio-weight", .value = "500" },
    };
    for (flags) |flag| {
        const separate = try parseArgs(&.{ "igvano", "update", flag.name, flag.value, "example" });
        try std.testing.expectEqualStrings("example", separate.id);
        const equals = try std.fmt.allocPrint(std.testing.allocator, "{s}={s}", .{ flag.name, flag.value });
        defer std.testing.allocator.free(equals);
        _ = try parseArgs(&.{ "igvano", "update", equals, "example" });
        _ = try parseArgs(&.{ "igvano", "update", "--resources=r.json", flag.name, flag.value, "example" });
        _ = try parseArgs(&.{ "igvano", "update", flag.name, flag.value, "--resources=r.json", "example" });
    }
}

test "update flags translate units unlimited and explicit zero to OCI resource fields" {
    const config = try parseArgs(&.{
        "igvano",                  "update",              "--memory=64m",      "--memory-reservation", "1.5 MiB",
        "--memory-swap=-1",        "--kernel-memory=1g",  "--cpu-shares=512",  "--cpu-period=100000",  "--cpu-quota=-1",
        "--cpu-rt-period=1000000", "--cpu-rt-runtime=-1", "--cpuset-cpus=0-2", "--cpuset-mems=0",      "--pids-limit=-1",
        "--blkio-weight=500",      "example",
    });
    const resources = try oci.cgroupResources(std.testing.allocator, config.resource_flags);
    defer oci.freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqual(@as(?i64, 67108864), resources.memory.?.limit);
    try std.testing.expectEqual(@as(?i64, 1572864), resources.memory.?.reservation);
    try std.testing.expectEqual(@as(?i64, -1), resources.memory.?.swap);
    try std.testing.expectEqual(@as(?i64, 1073741824), resources.memory.?.kernel);
    try std.testing.expectEqual(@as(?u64, 512), resources.cpu.?.shares);
    for ([_][]const []const u8{
        &.{ "igvano", "update", "--cpu-share", "512", "example" },
        &.{ "igvano", "update", "--cpu-share=512", "example" },
    }) |args| {
        const alias = try parseArgs(args);
        try std.testing.expectEqual(config.resource_flags.cpu.?.shares, alias.resource_flags.cpu.?.shares);
    }
    try std.testing.expectEqual(@as(?u64, 100000), resources.cpu.?.period);
    try std.testing.expectEqual(@as(?i64, -1), resources.cpu.?.quota);
    try std.testing.expectEqual(@as(?u64, 1000000), resources.cpu.?.realtime_period);
    try std.testing.expectEqual(@as(?i64, -1), resources.cpu.?.realtime_runtime);
    try std.testing.expectEqualStrings("0-2", resources.cpu.?.cpus.?);
    try std.testing.expectEqualStrings("0", resources.cpu.?.mems.?);
    try std.testing.expectEqual(@as(?i64, -1), resources.pids.?.limit);
    try std.testing.expectEqual(@as(?u16, 500), resources.block_io.?.weight);
    const zero = try parseArgs(&.{ "igvano", "update", "--memory=0", "--pids-limit=0", "example" });
    try std.testing.expectEqual(@as(?i64, 0), zero.resource_flags.memory.?.limit);
    try std.testing.expectEqual(@as(?i64, 0), zero.resource_flags.pids.?.limit);
    for ([_][]const u8{ "--memory", "--memory-reservation", "--memory-swap", "--kernel-memory" }) |name| {
        const unlimited = try parseArgs(&.{ "igvano", "update", name, "-1", "example" });
        const translated = try oci.cgroupResources(std.testing.allocator, unlimited.resource_flags);
        defer oci.freeCgroupResources(std.testing.allocator, translated);
    }
}

test "memory flags use decimal quantities and RAMInBytes units" {
    const cases = [_]struct { value: []const u8, bytes: i64 }{
        .{ .value = "64", .bytes = 64 },
        .{ .value = "64b", .bytes = 64 },
        .{ .value = "64 B", .bytes = 64 },
        .{ .value = "1k", .bytes = 1024 },
        .{ .value = "1KB", .bytes = 1024 },
        .{ .value = "1KiB", .bytes = 1024 },
        .{ .value = "1 KIB", .bytes = 1024 },
        .{ .value = "1.5m", .bytes = 1572864 },
        .{ .value = "1.5 MiB", .bytes = 1572864 },
        .{ .value = "1G", .bytes = 1073741824 },
        .{ .value = "1t", .bytes = 1099511627776 },
        .{ .value = "1p", .bytes = 1125899906842624 },
        .{ .value = "0.5b", .bytes = 0 },
        .{ .value = "-1", .bytes = -1 },
    };
    for (cases) |case| {
        const config = try parseArgs(&.{ "igvano", "update", "--memory", case.value, "example" });
        try std.testing.expectEqual(@as(?i64, case.bytes), config.resource_flags.memory.?.limit);
    }
    for ([_][]const u8{
        "-2",     "64mbb",               "1ki",  "1e",    "nan",   "inf",
        "8192p",  "9223372036854775808", "1 m ", "1e5",   "1e5kb", "0x10",
        "0x10b",  "1 ",                  "1.5 ", "1kb ",  "1.",    ".5m",
        "1.2.3m", "+1",                  " 1",   "1  kb", "1\tkb", "1_000",
        "1bkb",
    }) |value|
        try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", "--memory", value, "example" }));
    for ([_][]const u8{ "--cpu-shares", "--cpu-period", "--cpu-rt-period", "--blkio-weight" }) |name|
        try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", name, "-1", "example" }));
    try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", "--blkio-weight=65536", "example" }));
    try std.testing.expectError(error.MissingResourceValue, parseArgs(&.{ "igvano", "update", "--memory=", "example" }));
    try std.testing.expectError(error.MissingResourceValue, parseArgs(&.{ "igvano", "update", "--memory", "--cpu-shares=512", "example" }));
}

test "resource JSON ignores individual flags regardless of argument order" {
    defer oci.clearDiagnostic();
    const TestBackend = struct {
        var empty = false;
        var memory_only = false;

        fn update(_: *anyopaque, handle: Backend.Handle, resources: Backend.Resources) Backend.Error!void {
            if (handle.device_nodes.len != 0) return error.InvalidConfig;
            check(resources) catch return error.InvalidConfig;
        }

        fn check(resources: Backend.Resources) !void {
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
    var implementation: LockTestBackend = .{};
    var vtable = LockTestBackend.vtable;
    vtable.update = TestBackend.update;
    const backend: Backend = .{ .ptr = &implementation, .vtable = &vtable };
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
        TestBackend.empty = false;
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = json });
        try updateContainer(std.testing.allocator, std.testing.io, backend, config);
        TestBackend.empty = true;
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = "{}" });
        try updateContainer(std.testing.allocator, std.testing.io, backend, config);
    }
    TestBackend.memory_only = true;
    try updateContainer(std.testing.allocator, std.testing.io, backend, .{
        .root = root,
        .subcommand = .update,
        .id = "example",
        .resource_flags = .{ .memory = .{ .limit = 64 } },
    });
    // Explicit device updates still require a readable device snapshot.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "r.json", .data = "{\"devices\":[{\"allow\":true}]}" });
    try std.testing.expectError(error.InvalidState, updateContainer(std.testing.allocator, std.testing.io, backend, .{
        .root = root,
        .subcommand = .update,
        .id = "example",
        .resources_file = path,
    }));
}

test "update parsing requires resources or flags and rejects malformed options" {
    const cases = [_]struct { args: []const []const u8, expected: anyerror }{
        .{ .args = &.{ "igvano", "update", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources=", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "-r", "", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources", "--other", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources=-" }, .expected = error.MissingId },
        .{ .args = &.{ "igvano", "update", "--resources=-", "../example" }, .expected = error.InvalidId },
        .{ .args = &.{ "igvano", "update", "--resources=-", "example", "extra" }, .expected = error.UnexpectedArgument },
        .{ .args = &.{ "igvano", "update", "--resources=-", "--unknown", "64m", "example" }, .expected = error.UnknownOption },
        .{ .args = &.{ "igvano", "--resources=-", "update", "example" }, .expected = error.UnknownOption },
    };
    for (cases) |case| try std.testing.expectError(case.expected, parseArgs(case.args));
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
    var implementation: backend_module.LinuxBackend = .{};
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "resources.json", .data = "{}" });
    const resources_file = try std.fs.path.join(std.testing.allocator, &.{ root, "resources.json" });
    defer std.testing.allocator.free(resources_file);
    const config = try parseArgs(&.{ "igvano", "--root", root, "update", "--resources", resources_file, "example" });
    try std.testing.expectError(error.InvalidStatus, updateContainer(std.testing.allocator, std.testing.io, implementation.backend(), config));
}

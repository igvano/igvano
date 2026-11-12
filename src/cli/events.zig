const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Config = @import("args.zig").Config;
const ContainerOverride = @import("state.zig").ContainerOverride;
const ContainerInstance = @import("state.zig").ContainerInstance;
const bindContainer = @import("state.zig").bindContainer;
const readLiveState = @import("state.zig").readLiveState;
const containerResult = @import("diagnostic.zig").containerResult;

/// How often the loop checks liveness and the OOM count between stats events.
const poll_ns = 100 * std.time.ns_per_ms;

/// runc events: one JSON event per line. --stats prints one stats event; the
/// default streams stats every --interval plus an "oom" event per new OOM
/// kill, until the container stops.
pub fn eventsContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    const state = try readLiveState(allocator, io, injected, config, false);
    defer state.deinit();
    if (state.parsed.value.status == .stopped or state.container_state == null)
        return oci.validationError(error.ContainerNotRunning, "container with id {s} is not running", .{config.id});
    var instance: ContainerInstance = undefined;
    const container = bindContainer(&instance, injected, state.container_state.?);
    if (config.events_stats) {
        try emitStats(allocator, io, config.id, container);
        return;
    }
    var oom_kills = (try readStats(allocator, container)).oom_kills;
    const started = std.Io.Clock.awake.now(io);
    var next_stats: i96 = config.events_interval_ns;
    // ponytail: polls cgroup files every 100 ms instead of inotify on
    // memory.events; OOM events may arrive up to one poll late.
    while (try containerResult(container, container.alive())) {
        try std.Io.sleep(io, .fromNanoseconds(@min(poll_ns, config.events_interval_ns)), .awake);
        var arena: std.heap.ArenaAllocator = .init(allocator);
        defer arena.deinit();
        const stats = container.stats(arena.allocator()) catch |err| {
            // The cgroup goes away when the container stops; exit quietly then.
            if (err == error.ProcessNotFound or !(try containerResult(container, container.alive()))) break;
            return containerResult(container, @as(libcontainer.Error!void, err));
        };
        // One event per kill, like runc's per-notification events.
        // ponytail: capped so a runaway counter cannot flood stdout in one poll.
        for (0..@min(stats.oom_kills -| oom_kills, 64)) |_|
            try writeEvent(arena.allocator(), io, .{ .type = "oom", .id = config.id });
        oom_kills = @max(oom_kills, stats.oom_kills);
        if (started.untilNow(io, .awake).nanoseconds >= next_stats) {
            next_stats += config.events_interval_ns;
            try writeEvent(arena.allocator(), io, .{ .type = "stats", .id = config.id, .data = statsJson(arena.allocator(), stats) });
        }
    }
}

fn readStats(allocator: std.mem.Allocator, container: libcontainer.Container) !libcontainer.Stats {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const stats = try containerResult(container, container.stats(arena.allocator()));
    var copy = stats;
    copy.memory.raw = &.{};
    return copy;
}

fn emitStats(allocator: std.mem.Allocator, io: std.Io, id: []const u8, container: libcontainer.Container) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const stats = try containerResult(container, container.stats(arena.allocator()));
    try writeEvent(arena.allocator(), io, .{ .type = "stats", .id = id, .data = statsJson(arena.allocator(), stats) });
}

/// runc's types.Event; data is omitted for "oom".
const Event = struct {
    type: []const u8,
    id: []const u8,
    data: ?StatsJson = null,
};

/// runc's types.Stats with its JSON names and field order. igvano fills cpu,
/// memory usage and pids; the rest keep runc's zero-value encoding.
const StatsJson = struct {
    cpu: struct {
        usage: struct { total: u64, kernel: u64, user: u64 },
        throttling: struct { periods: u64, throttledPeriods: u64, throttledTime: u64 },
        psi: ?libcontainer.Stats.Psi,
    },
    cpuset: struct {
        cpu_exclusive: u64 = 0,
        mem_hardwall: u64 = 0,
        mem_exclusive: u64 = 0,
        memory_migrate: u64 = 0,
        memory_spread_page: u64 = 0,
        memory_spread_slab: u64 = 0,
        memory_pressure: u64 = 0,
        sched_load_balance: u64 = 0,
        sched_relax_domain_level: i64 = 0,
    } = .{},
    memory: struct {
        cache: u64,
        usage: MemoryEntry,
        swap: MemoryEntry = .{},
        kernel: MemoryEntry = .{},
        kernelTCP: MemoryEntry = .{},
        raw: std.json.ArrayHashMap(u64),
        psi: ?libcontainer.Stats.Psi,
    },
    pids: struct { current: u64, limit: u64 },
    blkio: struct {} = .{},
    hugetlb: struct {} = .{},
    intel_rdt: struct {} = .{},
    /// Go encodes runc's nil slice as null.
    network_interfaces: std.json.Value = .null,

    const MemoryEntry = struct { limit: u64 = 0, usage: u64 = 0, max: u64 = 0, failcnt: u64 = 0 };
};

fn statsJson(arena: std.mem.Allocator, stats: libcontainer.Stats) StatsJson {
    var raw: std.json.ArrayHashMap(u64) = .{};
    for (stats.memory.raw) |entry| raw.map.put(arena, entry.name, entry.value) catch break;
    return .{
        .cpu = .{
            .usage = .{ .total = stats.cpu.total, .kernel = stats.cpu.kernel, .user = stats.cpu.user },
            .throttling = .{ .periods = stats.cpu.periods, .throttledPeriods = stats.cpu.throttled_periods, .throttledTime = stats.cpu.throttled_time },
            .psi = stats.cpu.psi,
        },
        .memory = .{
            .cache = stats.memory.cache,
            .usage = .{ .limit = stats.memory.limit, .usage = stats.memory.usage, .max = stats.memory.max_usage, .failcnt = stats.memory.failcnt },
            .raw = raw,
            .psi = stats.memory.psi,
        },
        .pids = .{ .current = stats.pids.current, .limit = stats.pids.limit },
    };
}

fn writeEvent(arena: std.mem.Allocator, io: std.Io, event: Event) !void {
    const json = try std.json.Stringify.valueAlloc(arena, event, .{ .emit_null_optional_fields = false });
    try std.Io.File.stdout().writeStreamingAll(io, try std.fmt.allocPrint(arena, "{s}\n", .{json}));
}

/// Go time.ParseDuration for the forms runc users pass: "5s", "100ms",
/// "1m30s", "1.5s", "+1s". Units: ns, us (or µs, μs), ms, s, m, h. Must be positive.
/// ponytail: sums in f64, so values near 2^63 ns (~292 years) may round.
pub fn parseDuration(text: []const u8) !u64 {
    const units = [_]struct { []const u8, u64 }{
        // Two-letter units first, so "ms" is not read as "m" then "s".
        .{ "ns", 1 },                       .{ "us", std.time.ns_per_us },       .{ "ms", std.time.ns_per_ms },
        .{ "\u{b5}s", std.time.ns_per_us }, .{ "\u{3bc}s", std.time.ns_per_us }, .{ "s", std.time.ns_per_s },
        .{ "m", std.time.ns_per_min },      .{ "h", std.time.ns_per_hour },
    };
    // Go accepts one leading '+'; a '-' could only yield a non-positive interval.
    var rest = if (std.mem.startsWith(u8, text, "+")) text[1..] else text;
    var total: f64 = 0;
    if (rest.len == 0) return error.InvalidDuration;
    while (rest.len > 0) {
        var end: usize = 0;
        while (end < rest.len and (std.ascii.isDigit(rest[end]) or rest[end] == '.')) end += 1;
        if (end == 0) return error.InvalidDuration;
        const number = std.fmt.parseFloat(f64, rest[0..end]) catch return error.InvalidDuration;
        rest = rest[end..];
        const scale = for (units) |unit| {
            if (std.mem.startsWith(u8, rest, unit[0])) break unit;
        } else return error.InvalidDuration;
        total += number * @as(f64, @floatFromInt(scale[1]));
        rest = rest[scale[0].len..];
    }
    if (!(total >= 1) or total >= 0x1p63) return error.InvalidDuration;
    return @intFromFloat(total);
}

test "events durations follow Go's ParseDuration" {
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), try parseDuration("5s"));
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), try parseDuration("100ms"));
    try std.testing.expectEqual(@as(u64, 90 * std.time.ns_per_s), try parseDuration("1m30s"));
    try std.testing.expectEqual(@as(u64, 1500 * std.time.ns_per_ms), try parseDuration("1.5s"));
    try std.testing.expectEqual(@as(u64, 2 * std.time.ns_per_hour), try parseDuration("2h"));
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s), try parseDuration("+1s"));
    try std.testing.expectEqual(@as(u64, 500 * std.time.ns_per_ms), try parseDuration(".5s"));
    try std.testing.expectEqual(@as(u64, 3 * std.time.ns_per_us), try parseDuration("3\u{b5}s"));
    try std.testing.expectEqual(@as(u64, 3 * std.time.ns_per_us), try parseDuration("3\u{3bc}s"));
    for ([_][]const u8{ "", "5", "s", "0s", "-1s", "5x", "1.2.3s", "++1s", "1e3s" }) |bad|
        try std.testing.expectError(error.InvalidDuration, parseDuration(bad));
}

test "events JSON matches runc's event shape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const oom = try std.json.Stringify.valueAlloc(scratch, Event{ .type = "oom", .id = "c" }, .{ .emit_null_optional_fields = false });
    try std.testing.expectEqualStrings("{\"type\":\"oom\",\"id\":\"c\"}", oom);
    var stats: libcontainer.Stats = .{};
    stats.pids.current = 3;
    stats.memory.raw = &.{.{ .name = "anon", .value = 9 }};
    const json = try std.json.Stringify.valueAlloc(scratch, Event{ .type = "stats", .id = "c", .data = statsJson(scratch, stats) }, .{ .emit_null_optional_fields = false });
    try std.testing.expect(std.mem.startsWith(u8, json, "{\"type\":\"stats\",\"id\":\"c\",\"data\":{\"cpu\":{"));
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pids\":{\"current\":3,") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"raw\":{\"anon\":9}") != null);
    // runc's top-level and memory keys, in runc's order.
    var at: usize = 0;
    for ([_][]const u8{ "\"cpu\":", "\"cpuset\":", "\"memory\":", "\"swap\":", "\"kernel\":", "\"kernelTCP\":", "\"raw\":", "\"pids\":", "\"blkio\":{}", "\"hugetlb\":{}", "\"intel_rdt\":{}", "\"network_interfaces\":null" }) |key| {
        at += std.mem.indexOf(u8, json[at..], key) orelse return error.TestUnexpectedResult;
    }
}

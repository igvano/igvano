const std = @import("std");
const libcontainer = @import("libcontainer");
const validationError = @import("diagnostic.zig").validationError;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const Spec = @import("spec.zig").Spec;

pub fn processConfig(process: Spec.Process) libcontainer.Process {
    return .{
        .args = process.args,
        .env = process.env orelse &.{},
        .cwd = process.cwd,
        .terminal = process.terminal orelse false,
        .console_size = if (process.consoleSize) |size| .{ .height = size.height, .width = size.width } else null,
        .uid = process.user.uid,
        .gid = process.user.gid,
        .additional_gids = process.user.additionalGids orelse &.{},
        .umask = process.user.umask,
        .no_new_privileges = process.noNewPrivileges,
    };
}

/// runc's ToSchedAttr plus its scheduler validation.
pub fn processScheduler(scheduler: ?Spec.Scheduler) error{InvalidConfig}!?libcontainer.Scheduler {
    const value = scheduler orelse return null;
    const policies = [_][]const u8{ "SCHED_OTHER", "SCHED_FIFO", "SCHED_RR", "SCHED_BATCH", "SCHED_ISO", "SCHED_IDLE", "SCHED_DEADLINE" };
    if (value.policy.len == 0) return invalidConfig("process.scheduler.policy: is required", .{});
    const policy = for (policies, 0..) |name, i| {
        if (std.mem.eql(u8, name, value.policy)) break i;
    } else return invalidConfig("process.scheduler.policy: invalid scheduler policy: {s}", .{value.policy});
    try validateSchedulerFields(value, policy);
    return .{
        .policy = @intCast(policy),
        .flags = try schedulerFlags(value.flags orelse &.{}),
        .nice = value.nice,
        .priority = @intCast(value.priority),
        .runtime = value.runtime,
        .deadline = value.deadline,
        .period = value.period,
    };
}

fn validateSchedulerFields(value: Spec.Scheduler, policy: usize) error{InvalidConfig}!void {
    const other_or_batch = policy == 0 or policy == 3;
    if (other_or_batch and (value.nice < -20 or value.nice > 19))
        return invalidConfig("process.scheduler.nice: invalid scheduler.nice: {d} when scheduler.policy is {s}", .{ value.nice, value.policy });
    if (value.priority != 0 and policy != 1 and policy != 2)
        return invalidConfig("process.scheduler.priority: can only be specified for SchedFIFO or SchedRR policy", .{});
    if (value.priority < 0) return invalidConfig("process.scheduler.priority: must not be negative", .{});
    if (policy != 6 and (value.runtime != 0 or value.deadline != 0 or value.period != 0))
        return invalidConfig("process.scheduler: runtime/deadline/period can only be specified for SchedDeadline policy", .{});
}

fn schedulerFlags(names: []const []const u8) error{InvalidConfig}!u64 {
    const flag_names = [_][]const u8{ "SCHED_FLAG_RESET_ON_FORK", "SCHED_FLAG_RECLAIM", "SCHED_FLAG_DL_OVERRUN", "SCHED_FLAG_KEEP_POLICY", "SCHED_FLAG_KEEP_PARAMS", "SCHED_FLAG_UTIL_CLAMP_MIN", "SCHED_FLAG_UTIL_CLAMP_MAX" };
    var flags: u64 = 0;
    for (names) |flag| {
        const bit = for (flag_names, 0..) |name, i| {
            if (std.mem.eql(u8, name, flag)) break i;
        } else return invalidConfig("process.scheduler.flags: invalid scheduler flag: {s}", .{flag});
        flags |= @as(u64, 1) << @intCast(bit);
    }
    return flags;
}

/// runc's ioPriority validation.
pub fn processIOPriority(priority: ?Spec.IOPriority) error{InvalidConfig}!?libcontainer.IOPriority {
    const value = priority orelse return null;
    if (value.priority < 0 or value.priority > 7) return invalidConfig("process.ioPriority.priority: invalid ioPriority.Priority: {d}", .{value.priority});
    const classes = [_][]const u8{ "IOPRIO_CLASS_RT", "IOPRIO_CLASS_BE", "IOPRIO_CLASS_IDLE" };
    for (classes, 1..) |name, class| {
        if (std.mem.eql(u8, name, value.class)) return .{ .class = @intCast(class), .priority = @intCast(value.priority) };
    }
    return invalidConfig("process.ioPriority.class: invalid ioPriority.Class: \"{s}\"", .{value.class});
}

test "scheduler and I/O priority follow runc's conversion and validation" {
    defer @import("diagnostic.zig").clearDiagnostic();
    const deadline = (try processScheduler(.{ .policy = "SCHED_DEADLINE", .flags = &.{"SCHED_FLAG_RESET_ON_FORK"}, .nice = 19, .runtime = 42000, .deadline = 100000, .period = 1000000 })).?;
    try std.testing.expectEqual(libcontainer.Scheduler{ .policy = 6, .flags = 1, .nice = 19, .runtime = 42000, .deadline = 100000, .period = 1000000 }, deadline);
    try std.testing.expectEqual(@as(u32, 3), (try processScheduler(.{ .policy = "SCHED_BATCH", .nice = 19 })).?.policy);
    for ([_]Spec.Scheduler{
        .{ .policy = "" },
        .{ .policy = "SCHED_NOPE" },
        .{ .policy = "SCHED_OTHER", .nice = 20 },
        .{ .policy = "SCHED_BATCH", .priority = 1 },
        .{ .policy = "SCHED_FIFO", .runtime = 1 },
        .{ .policy = "SCHED_RR", .flags = &.{"nope"} },
    }) |bad| try std.testing.expectError(error.InvalidConfig, processScheduler(bad));
    try std.testing.expectEqual(libcontainer.IOPriority{ .class = 2, .priority = 4 }, (try processIOPriority(.{ .class = "IOPRIO_CLASS_BE", .priority = 4 })).?);
    try std.testing.expectEqual(libcontainer.IOPriority{ .class = 3, .priority = 0 }, (try processIOPriority(.{ .class = "IOPRIO_CLASS_IDLE" })).?);
    try std.testing.expectError(error.InvalidConfig, processIOPriority(.{ .class = "IOPRIO_CLASS_BE", .priority = 8 }));
    try std.testing.expectError(error.InvalidConfig, processIOPriority(.{ .class = "best-effort" }));
}

/// Like runc, an affinity with neither list set is no affinity at all.
pub fn cpuAffinity(affinity: ?Spec.CPUAffinity) error{InvalidConfig}!?libcontainer.CPUAffinity {
    const value = affinity orelse return null;
    const result: libcontainer.CPUAffinity = .{
        .initial = try cpuSet("initial", value.initial),
        .final = try cpuSet("final", value.final),
    };
    return if (result.initial == null and result.final == null) null else result;
}

/// A Linux CPU list such as "0-3,7", with runc's tolerance for spaces and empty items.
fn cpuSet(comptime field: []const u8, list: ?[]const u8) error{InvalidConfig}!?libcontainer.CpuSet {
    const text = list orelse return null;
    if (text.len == 0) return null;
    const bad = "process.execCPUAffinity." ++ field ++ ": ";
    const max = @bitSizeOf(libcontainer.CpuSet);
    var set: libcontainer.CpuSet = @splat(0);
    var items = std.mem.splitScalar(u8, text, ',');
    var count: usize = 0;
    while (items.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t");
        if (item.len == 0) continue;
        const dash = std.mem.indexOfScalar(u8, item, '-');
        const first = try cpuNumber(bad, if (dash) |i| item[0..i] else item, max);
        const last = if (dash) |i| try cpuNumber(bad, item[i + 1 ..], max) else first;
        if (first > last) return invalidConfig(bad ++ "invalid range: {s}", .{item});
        for (first..last + 1) |cpu| {
            set[cpu / 64] |= @as(u64, 1) << @intCast(cpu % 64);
            count += 1;
        }
    }
    if (count == 0) return invalidConfig(bad ++ "no CPUs found in \"{s}\"", .{text});
    return set;
}

fn cpuNumber(comptime bad: []const u8, text: []const u8, max: usize) error{InvalidConfig}!usize {
    const value = std.fmt.parseUnsigned(u32, text, 10) catch return invalidConfig(bad ++ "invalid CPU '{s}'", .{text});
    if (value >= max) return invalidConfig(bad ++ "values larger than {d} are not supported", .{max - 1});
    return value;
}

test "exec CPU affinity parses runc CPU lists" {
    defer @import("diagnostic.zig").clearDiagnostic();
    try std.testing.expectEqual(@as(?libcontainer.CPUAffinity, null), try cpuAffinity(null));
    try std.testing.expectEqual(@as(?libcontainer.CPUAffinity, null), try cpuAffinity(.{ .initial = "", .final = "" }));
    const value = (try cpuAffinity(.{ .initial = " 0-2, ,5", .final = "1023" })).?;
    try std.testing.expectEqual(@as(u64, 0b100111), value.initial.?[0]);
    try std.testing.expectEqual(@as(u64, 1) << 63, value.final.?[15]);
    for ([_][]const u8{ "1024", "3-1", "a", ",", "1-", "-1" }) |list|
        try std.testing.expectError(error.InvalidConfig, cpuAffinity(.{ .initial = list }));
}

pub const capability_names = names: {
    var result: [std.os.linux.CAP.LAST_CAP + 1][]const u8 = undefined;
    for (std.meta.declarations(std.os.linux.CAP)) |decl| {
        if (!std.mem.eql(u8, decl.name, "LAST_CAP") and
            @TypeOf(@field(std.os.linux.CAP, decl.name)) == comptime_int)
        {
            result[@field(std.os.linux.CAP, decl.name)] = "CAP_" ++ decl.name;
        }
    }
    break :names result;
};

/// Null means a well-formed CAP_* name unknown to our table, possibly a newer cap.
/// Linux constants are available on every build host; no syscalls are made.
pub fn capabilityNumber(name: []const u8) error{InvalidConfig}!?u6 {
    if (!std.mem.startsWith(u8, name, "CAP_") or name.len == 4) return invalidConfig("process.capabilities: invalid name '{s}'", .{name});
    for (name[4..]) |c| {
        if (!std.ascii.isUpper(c) and !std.ascii.isDigit(c) and c != '_') return invalidConfig("process.capabilities: invalid name '{s}'", .{name});
    }
    for (capability_names, 0..) |known, number| {
        if (std.mem.eql(u8, name, known)) return @intCast(number);
    }
    return null;
}

pub fn rlimitResource(name: []const u8) error{InvalidConfig}!std.os.linux.rlimit_resource {
    if (!std.mem.startsWith(u8, name, "RLIMIT_")) return invalidConfig("process.rlimits.type: invalid name '{s}'", .{name});
    return std.meta.stringToEnum(std.os.linux.rlimit_resource, name["RLIMIT_".len..]) orelse invalidConfig("process.rlimits.type: unknown name '{s}'", .{name});
}

/// Like runc, unknown capability names are ignored with a warning, and
/// ambient caps that cannot be raised only warn at exec time.
pub fn processCapabilities(config: Spec.Capabilities) !libcontainer.Capabilities {
    var result: libcontainer.Capabilities = .{};
    inline for (std.meta.fields(libcontainer.Capabilities)) |field| {
        for (@field(config, field.name) orelse &.{}) |name| {
            const number = (capabilityNumber(name) catch null) orelse {
                if (!@import("builtin").is_test)
                    std.debug.print("igvano: warning: ignoring unknown or unavailable capabilities: [{s}]\n", .{name});
                continue;
            };
            @field(result, field.name) |= @as(u64, 1) << number;
        }
    }
    return result;
}

pub fn processRlimits(allocator: std.mem.Allocator, config: ?[]const Spec.Rlimit) ![]libcontainer.Rlimit {
    const limits = config orelse &.{};
    const result = try allocator.alloc(libcontainer.Rlimit, limits.len);
    errdefer allocator.free(result);
    for (limits, result, 0..) |limit, *prepared, i| {
        if (limit.soft > limit.hard) return invalidConfig("process.rlimits[{d}]: soft exceeds hard", .{i});
        const resource = try rlimitResource(limit.type);
        for (result[0..i]) |previous| {
            if (previous.resource == resource) return invalidConfig("process.rlimits[{d}]: duplicate {s}", .{ i, limit.type });
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
    inline for (std.meta.fields(libcontainer.Capabilities)) |field|
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

test "ambient capabilities convert like the other sets" {
    const cap: u64 = @as(u64, 1) << std.os.linux.CAP.NET_BIND_SERVICE;
    const valid = try processCapabilities(.{
        .bounding = &.{"CAP_NET_BIND_SERVICE"},
        .effective = &.{"CAP_NET_BIND_SERVICE"},
        .permitted = &.{"CAP_NET_BIND_SERVICE"},
        .inheritable = &.{"CAP_NET_BIND_SERVICE"},
        .ambient = &.{"CAP_NET_BIND_SERVICE"},
    });
    try std.testing.expectEqual(libcontainer.Capabilities{
        .bounding = cap,
        .effective = cap,
        .permitted = cap,
        .inheritable = cap,
        .ambient = cap,
    }, valid);
    try std.testing.expectEqual(libcontainer.Capabilities{}, try processCapabilities(.{}));
    // Like runc, an ambient cap outside permitted or inheritable is kept and
    // only warns when it cannot be raised.
    try std.testing.expectEqual(cap, (try processCapabilities(.{ .ambient = &.{"CAP_NET_BIND_SERVICE"} })).ambient);
    const upper = try processCapabilities(.{ .bounding = &.{ "CAP_CHECKPOINT_RESTORE", "CAP_CHECKPOINT_RESTORE" } });
    try std.testing.expectEqual(@as(u64, 1) << 40, upper.bounding);
}

test "process capabilities ignore unknown names in every set, like runc" {
    inline for (std.meta.fields(Spec.Capabilities)) |field| {
        var config: Spec.Capabilities = .{};
        @field(config, field.name) = &.{ "CAP_CHOWN", "CAP_FUTURE", "NOT_A_CAP" };
        var expected: libcontainer.Capabilities = .{};
        @field(expected, field.name) = 1;
        try std.testing.expectEqual(expected, try processCapabilities(config));
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
    try std.testing.expectEqual(libcontainer.Rlimit{ .resource = .NOFILE, .hard = 1024, .soft = 512 }, limits[0]);
    try std.testing.expectEqual(libcontainer.Rlimit{ .resource = .CORE, .hard = std.math.maxInt(u64), .soft = 0 }, limits[1]);
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

const mpol_f_numa_balancing = 1 << 13;
const mpol_f_relative_nodes = 1 << 14;
const mpol_f_static_nodes = 1 << 15;

/// linux.memoryPolicy, checked like youki's validate_memory_policy.
pub fn memoryPolicy(policy: ?Spec.MemoryPolicy) error{InvalidConfig}!?libcontainer.MemoryPolicy {
    const value = policy orelse return null;
    const modes = [_][]const u8{ "MPOL_DEFAULT", "MPOL_PREFERRED", "MPOL_BIND", "MPOL_INTERLEAVE", "MPOL_LOCAL", "MPOL_PREFERRED_MANY", "MPOL_WEIGHTED_INTERLEAVE" };
    const mode: i32 = for (modes, 0..) |name, i| {
        if (std.mem.eql(u8, name, value.mode)) break @intCast(i);
    } else return invalidConfig("linux.memoryPolicy.mode: invalid mode {s}", .{value.mode});
    const flags = try memoryPolicyFlags(value.flags orelse &.{}, mode);
    var result: libcontainer.MemoryPolicy = .{ .mode = mode | flags };
    const nodes = std.mem.trim(u8, value.nodes orelse "", " ");
    const has_nodes = try parseNodes(nodes, &result);
    switch (mode) {
        0, 4 => {
            if (has_nodes) return invalidConfig("linux.memoryPolicy.nodes: {s} takes no nodes", .{value.mode});
            if (flags != 0) return invalidConfig("linux.memoryPolicy.flags: {s} takes no flags", .{value.mode});
        },
        1 => if (!has_nodes and flags & (mpol_f_relative_nodes | mpol_f_static_nodes) != 0)
            return invalidConfig("linux.memoryPolicy.flags: MPOL_PREFERRED with no nodes cannot use MPOL_F_STATIC_NODES or MPOL_F_RELATIVE_NODES", .{}),
        else => if (!has_nodes) return invalidConfig("linux.memoryPolicy.nodes: {s} needs nodes", .{value.mode}),
    }
    return result;
}

fn memoryPolicyFlags(names: []const []const u8, mode: i32) error{InvalidConfig}!i32 {
    var flags: i32 = 0;
    for (names) |name| {
        flags |= if (std.mem.eql(u8, name, "MPOL_F_NUMA_BALANCING"))
            mpol_f_numa_balancing
        else if (std.mem.eql(u8, name, "MPOL_F_RELATIVE_NODES"))
            mpol_f_relative_nodes
        else if (std.mem.eql(u8, name, "MPOL_F_STATIC_NODES"))
            mpol_f_static_nodes
        else
            return invalidConfig("linux.memoryPolicy.flags: invalid flag {s}", .{name});
    }
    if (flags & mpol_f_numa_balancing != 0 and mode != 2) return invalidConfig("linux.memoryPolicy.flags: MPOL_F_NUMA_BALANCING needs MPOL_BIND", .{});
    if (flags & mpol_f_relative_nodes != 0 and flags & mpol_f_static_nodes != 0) return invalidConfig("linux.memoryPolicy.flags: MPOL_F_STATIC_NODES and MPOL_F_RELATIVE_NODES exclude each other", .{});
    return flags;
}

/// "0-3,7" into the nodemask; returns whether any node was set.
fn parseNodes(nodes: []const u8, policy: *libcontainer.MemoryPolicy) error{InvalidConfig}!bool {
    var highest: ?u32 = null;
    var ranges = std.mem.splitScalar(u8, nodes, ',');
    while (ranges.next()) |raw| {
        const range = std.mem.trim(u8, raw, " ");
        if (range.len == 0) continue;
        const dash = std.mem.indexOfScalar(u8, range, '-');
        const first = nodeNumber(if (dash) |i| range[0..i] else range) orelse return invalidConfig("linux.memoryPolicy.nodes: invalid node {s}", .{range});
        const last = if (dash) |i| nodeNumber(range[i + 1 ..]) orelse return invalidConfig("linux.memoryPolicy.nodes: invalid node {s}", .{range}) else first;
        if (first > last) return invalidConfig("linux.memoryPolicy.nodes: invalid range {s}", .{range});
        for (first..last + 1) |node| policy.nodemask[node / @bitSizeOf(usize)] |= @as(usize, 1) << @intCast(node % @bitSizeOf(usize));
        highest = @max(highest orelse 0, last);
    }
    const top = highest orelse return false;
    policy.maxnode = (top / @bitSizeOf(usize) + 1) * @bitSizeOf(usize) + 1;
    return true;
}

fn nodeNumber(text: []const u8) ?u32 {
    const node = std.fmt.parseUnsigned(u32, std.mem.trim(u8, text, " "), 10) catch return null;
    return if (node < libcontainer.MemoryPolicy.max_numa_nodes) node else null;
}

/// runc's getLinuxPersonalityFromStr: PER_LINUX or PER_LINUX32.
pub fn personality(value: ?Spec.Personality) error{InvalidConfig}!?u32 {
    const domain = (value orelse return null).domain;
    if (std.mem.eql(u8, domain, "LINUX")) return 0;
    if (std.mem.eql(u8, domain, "LINUX32")) return 8;
    return invalidConfig("linux.personality.domain: invalid personality domain {s}", .{domain});
}

test "memory policies parse modes, flags and node ranges like youki" {
    defer @import("diagnostic.zig").clearDiagnostic();
    const bind = (try memoryPolicy(.{ .mode = "MPOL_BIND", .nodes = "0-2,65", .flags = &.{"MPOL_F_STATIC_NODES"} })).?;
    try std.testing.expectEqual(@as(i32, 2 | mpol_f_static_nodes), bind.mode);
    try std.testing.expectEqual(@as(usize, 0b111), bind.nodemask[0]);
    try std.testing.expectEqual(@as(usize, 2), bind.nodemask[1]);
    try std.testing.expectEqual(@as(usize, 129), bind.maxnode);
    // The kernel drops the last of maxnode bits, so maxnode is one past a
    // whole number of words and the mask is never read past its end.
    for ([_]struct { []const u8, usize }{ .{ "63", 65 }, .{ "64", 129 }, .{ "1023", 1025 } }) |case| {
        const policy = (try memoryPolicy(.{ .mode = "MPOL_BIND", .nodes = case[0] })).?;
        try std.testing.expectEqual(case[1], policy.maxnode);
        try std.testing.expect((policy.maxnode - 1) / @bitSizeOf(usize) <= policy.nodemask.len);
    }
    try std.testing.expectEqual(@as(usize, 0), (try memoryPolicy(.{ .mode = "MPOL_DEFAULT", .nodes = "" })).?.maxnode);
    for ([_]Spec.MemoryPolicy{
        .{ .mode = "INTERLEAVE", .nodes = "0" },
        .{ .mode = "MPOL_BIND" },
        .{ .mode = "MPOL_DEFAULT", .nodes = "0-7" },
        .{ .mode = "MPOL_BIND", .nodes = "0-9876543210" },
        .{ .mode = "MPOL_BIND", .nodes = "3-1" },
        .{ .mode = "MPOL_INTERLEAVE", .nodes = "0", .flags = &.{"MPOL_F_NUMA_BALANCING"} },
        .{ .mode = "MPOL_BIND", .nodes = "0", .flags = &.{ "MPOL_F_STATIC_NODES", "MPOL_F_RELATIVE_NODES" } },
        .{ .mode = "MPOL_BIND", .nodes = "0", .flags = &.{"MPOL_F_BOGUS"} },
    }) |policy| try std.testing.expectError(error.InvalidConfig, memoryPolicy(policy));
}

test "personality domains map to runc's values" {
    defer @import("diagnostic.zig").clearDiagnostic();
    try std.testing.expectEqual(@as(?u32, 8), try personality(.{ .domain = "LINUX32" }));
    try std.testing.expectEqual(@as(?u32, 0), try personality(.{ .domain = "LINUX" }));
    try std.testing.expectError(error.InvalidConfig, personality(.{ .domain = "SOLARIS" }));
}

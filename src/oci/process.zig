const std = @import("std");
const Backend = @import("../backend.zig").Backend;
const validationError = @import("diagnostic.zig").validationError;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const Spec = @import("spec.zig").Spec;

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

pub fn processCapabilities(config: Spec.Capabilities) !Backend.Capabilities {
    var result: Backend.Capabilities = .{};
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
        for (@field(config, field.name) orelse &.{}) |name| {
            const number = try capabilityNumber(name) orelse {
                return invalidConfig("process.capabilities.{s}: unknown capability {s}", .{ field.name, name });
            };
            @field(result, field.name) |= @as(u64, 1) << number;
        }
    }
    if (result.ambient & ~(result.permitted & result.inheritable) != 0)
        return validationError(error.AmbientCapabilitiesRequirePermittedAndInheritable, "process.capabilities.ambient: must be permitted and inheritable", .{});
    return result;
}

pub fn processRlimits(allocator: std.mem.Allocator, config: ?[]const Spec.Rlimit) ![]Backend.Rlimit {
    const limits = config orelse &.{};
    const result = try allocator.alloc(Backend.Rlimit, limits.len);
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

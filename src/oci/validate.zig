const std = @import("std");
const clearDiagnostic = @import("diagnostic.zig").clearDiagnostic;
const diagnostic = @import("diagnostic.zig").diagnostic;
const diagnosticFor = @import("diagnostic.zig").diagnosticFor;
const validationError = @import("diagnostic.zig").validationError;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const diagnosticContext = @import("diagnostic.zig").diagnosticContext;
const Spec = @import("spec.zig").Spec;
const cgroupResources = @import("resources.zig").cgroupResources;
const rootfsPropagation = @import("mounts.zig").rootfsPropagation;
const validateMountDestination = @import("mounts.zig").validateMountDestination;
const validateIDMappings = @import("mounts.zig").validateIDMappings;
const mountMappingConfig = @import("mounts.zig").mountMappingConfig;
const prepareSeccomp = @import("seccomp.zig").prepareSeccomp;
const validateHooks = @import("hooks.zig").validateHooks;
const validateSysctls = @import("sysctl.zig").validateSysctls;

/// Omitted namespace types are inherited from the runtime.
pub fn requireCreate(spec: Spec) !void {
    _ = std.SemanticVersion.parse(spec.ociVersion) catch return invalidConfig("ociVersion: invalid semantic version", .{});
    try validateHooks(spec.hooks);
    const settings: Spec.Linux = spec.linux orelse .{};
    try validateSysctls(settings);
    try validateNamespaces(settings);
    if (spec.root.path.len == 0) return invalidConfig("root.path: must not be empty", .{});
    if (spec.process) |process| try validateProcess(process);
    for (spec.mounts orelse &.{}, 0..) |mount, i| {
        errdefer diagnosticContext("mounts[{d}]", .{i});
        try validateMountDestination(mount.destination);
        _ = try mountMappingConfig(mount, settings);
    }
    try validateRestrictionPaths(settings.maskedPaths, "linux.maskedPaths");
    try validateRestrictionPaths(settings.readonlyPaths, "linux.readonlyPaths");
}

fn validateNamespaces(settings: Spec.Linux) !void {
    const namespaces = settings.namespaces orelse &.{};
    var has_mount = false;
    var has_user = false;
    var joined_user = false;
    for (namespaces) |namespace| {
        if (namespace.type == .mount) has_mount = true;
        if (namespace.type == .user) {
            has_user = true;
            joined_user = namespace.path != null;
        }
    }
    try validateUserMappings(settings, has_user, joined_user);
    if (!has_mount and settings.rootfsPropagation != null) {
        return invalidConfig("linux.rootfsPropagation: requires a mount namespace", .{});
    }
}

fn validateUserMappings(settings: Spec.Linux, has_user: bool, joined_user: bool) !void {
    const uid_mappings: []const Spec.IDMapping = settings.uidMappings orelse &.{};
    const gid_mappings: []const Spec.IDMapping = settings.gidMappings orelse &.{};
    if (has_user) {
        for ([_][]const Spec.IDMapping{ uid_mappings, gid_mappings }, [_][]const u8{ "linux.uidMappings", "linux.gidMappings" }) |mappings, field| {
            if (joined_user and mappings.len == 0) continue;
            validateIDMappings(mappings) catch |err| {
                diagnosticContext("{s}", .{field});
                return err;
            };
            // OCI does not require a root mapping; our init, like runc, needs one.
            for (mappings) |mapping| {
                if (mapping.containerID == 0) break;
            } else return invalidConfig("{s}: container root must be mapped", .{field});
        }
    } else if (uid_mappings.len > 0 or gid_mappings.len > 0) {
        return invalidConfig("linux.uidMappings/gidMappings: require a user namespace", .{});
    }
}

fn validateRestrictionPaths(configured: ?[]const []const u8, comptime field: []const u8) !void {
    for (configured orelse &.{}, 0..) |path, i| {
        errdefer diagnosticContext(field ++ "[{d}]", .{i});
        try validateMountDestination(path);
    }
}

pub fn validateEnv(entry: []const u8) !void {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return validationError(error.InvalidProcess, "process.env: expected NAME=value", .{});
    if (equals == 0 or std.mem.indexOfScalar(u8, entry, 0) != null) return validationError(error.InvalidProcess, "process.env: require a nonempty name and NUL-free value", .{});
}

pub fn validateProcess(process: Spec.Process) !void {
    if (!std.mem.startsWith(u8, process.cwd, "/") or
        std.mem.indexOfScalar(u8, process.cwd, 0) != null) return validationError(error.InvalidProcess, "process.cwd: must be absolute and NUL-free", .{});
    if (process.args.len == 0 or process.args[0].len == 0) return validationError(error.InvalidProcess, "process.args: executable must not be empty", .{});
    for (process.args) |arg| {
        if (std.mem.indexOfScalar(u8, arg, 0) != null) return validationError(error.InvalidProcess, "process.args: must not contain NUL", .{});
    }
    for (process.env orelse &.{}) |entry| try validateEnv(entry);
    if (process.apparmorProfile) |profile| {
        if (std.mem.indexOfScalar(u8, profile, 0) != null) return validationError(error.InvalidProcess, "process.apparmorProfile: must not contain NUL", .{});
    }
    if (process.oomScoreAdj) |value| {
        if (value < -1000 or value > 1000) return invalidConfig("process.oomScoreAdj: expected -1000..1000", .{});
    }
}

test "process accepts an AppArmor profile" {
    const parsed = try std.json.parseFromSlice(Spec.Process, std.testing.allocator,
        \\{"args":["/probe"],"cwd":"/","user":{"uid":0,"gid":0},"apparmorProfile":"igvano-deny-write"}
    , .{});
    defer parsed.deinit();
    try validateProcess(parsed.value);
    try std.testing.expectEqualStrings("igvano-deny-write", parsed.value.apparmorProfile.?);
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

test "create accepts new user namespaces with maps and joins with or without maps" {
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
    try requireCreate(spec);
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

test "create accepts joined user namespaces with optional mappings" {
    const mappings: []const Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 1000, .size = 100000 }};
    var spec: Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{.{ .type = .user, .path = "/proc/123/ns/user" }},
            .uidMappings = mappings,
            .gidMappings = mappings,
        },
    };
    try requireCreate(spec);
    spec.linux.?.uidMappings = null;
    try requireCreate(spec);
    spec.linux.?.gidMappings = null;
    try requireCreate(spec);
}

test "frontend validation failures retain specific diagnostics" {
    defer clearDiagnostic();
    const root: Spec.Root = .{ .path = "rootfs" };
    const cases = [_]struct { spec: Spec, reason: []const u8 }{
        .{ .spec = .{ .ociVersion = "invalid", .root = root }, .reason = "ociVersion:" },
        .{ .spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "" } }, .reason = "root.path:" },
        .{ .spec = .{ .ociVersion = "1.0.2", .root = root, .linux = .{ .namespaces = &.{.{ .type = .user }} } }, .reason = "linux.uidMappings:" },
        .{ .spec = .{ .ociVersion = "1.0.2", .root = root, .mounts = &.{.{ .destination = "relative" }} }, .reason = "mounts[0]:" },
        .{ .spec = .{ .ociVersion = "1.0.2", .root = root, .hooks = .{ .prestart = &.{.{ .path = "relative" }} } }, .reason = "hooks.prestart[0]:" },
        .{ .spec = .{ .ociVersion = "1.0.2", .root = root, .process = .{
            .args = &.{"/init"},
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0 },
            .oomScoreAdj = 1001,
        } }, .reason = "process.oomScoreAdj:" },
    };
    for (cases) |case| {
        clearDiagnostic();
        try std.testing.expectError(error.InvalidConfig, requireCreate(case.spec));
        const detail = diagnosticFor(error.InvalidConfig).?;
        try std.testing.expect(std.mem.indexOf(u8, detail, case.reason) != null);
        try std.testing.expect(diagnosticFor(error.OutOfMemory) == null);
    }
    clearDiagnostic();
    try std.testing.expectError(error.InvalidConfig, prepareSeccomp(std.testing.allocator, .{ .defaultAction = "unknown" }));
    try std.testing.expect(std.mem.startsWith(u8, diagnostic().?, "linux.seccomp:"));
    clearDiagnostic();
    try std.testing.expectError(error.InvalidProcess, validateEnv("INVALID"));
    try std.testing.expect(std.mem.startsWith(u8, diagnostic().?, "process.env:"));
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

test "create rejects incomplete non-bind and invalid mount ID mappings" {
    for ([_][]const u8{
        \\{"destination":"/data","type":"tmpfs","uidMappings":[{"containerID":0,"hostID":1000,"size":1}],"gidMappings":[{"containerID":0,"hostID":1000,"size":1}]}
        ,
        \\{"destination":"/data","source":"/host","options":["bind"],"uidMappings":[{"containerID":0,"hostID":1000,"size":1}]}
        ,
        \\{"destination":"/data","source":"/host","options":["bind"],"gidMappings":[{"containerID":0,"hostID":1000,"size":1}]}
        ,
        \\{"destination":"/data","source":"/host","options":["bind"],"uidMappings":[],"gidMappings":[]}
        ,
        \\{"destination":"/data","source":"/host","options":["bind"],"uidMappings":[{"containerID":0,"hostID":1000,"size":0}],"gidMappings":[{"containerID":0,"hostID":1000,"size":1}]}
        ,
        \\{"destination":"/data","source":"/host","options":["bind","idmap"]}
        ,
        \\{"destination":"/data","type":"tmpfs","options":["ridmap"]}
        ,
    }) |mount| {
        const json = try std.fmt.allocPrint(std.testing.allocator, "{{\"ociVersion\":\"1.2.0\",\"root\":{{\"path\":\"rootfs\"}},\"mounts\":[{s}]}}", .{mount});
        defer std.testing.allocator.free(json);
        const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator, json, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidConfig, requireCreate(parsed.value));
    }
}

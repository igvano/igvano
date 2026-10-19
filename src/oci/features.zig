const std = @import("std");
const oci_version_min = @import("spec.zig").oci_version_min;
const oci_version_max = @import("spec.zig").oci_version_max;
const Spec = @import("spec.zig").Spec;
const mount_option_table = @import("mounts.zig").mount_option_table;
const parseMountOptions = @import("mounts.zig").parseMountOptions;
const capability_names = @import("process.zig").capability_names;
const capabilityNumber = @import("process.zig").capabilityNumber;
const prepareSeccomp = @import("seccomp.zig").prepareSeccomp;
const freeSeccomp = @import("seccomp.zig").freeSeccomp;
const seccomp_actions = @import("seccomp.zig").seccomp_actions;
const seccomp_arches = @import("seccomp.zig").seccomp_arches;
const seccomp_ops = @import("seccomp.zig").seccomp_ops;
const seccomp_flags = @import("seccomp.zig").seccomp_flags;

/// Runtime build capabilities, independent of the host kernel and privileges.
pub fn featuresJson(allocator: std.mem.Allocator) ![]u8 {
    const mount_options = comptime names: {
        var names: [mount_option_table.len][]const u8 = undefined;
        for (mount_option_table, 0..) |entry, i| names[i] = entry.name;
        break :names names;
    };
    return std.json.Stringify.valueAlloc(allocator, .{
        .ociVersionMin = oci_version_min,
        .ociVersionMax = oci_version_max,
        .hooks = std.meta.fieldNames(Spec.Hooks),
        .mountOptions = &mount_options,
        .linux = .{
            .namespaces = std.meta.fieldNames(@FieldType(Spec.Namespace, "type")),
            .capabilities = &capability_names,
            .cgroup = .{ .v1 = true, .v2 = true, .systemd = true, .systemdUser = false, .rdma = false },
            .seccomp = .{
                .enabled = true,
                .actions = seccomp_actions.keys(),
                .operators = seccomp_ops.keys(),
                .archs = seccomp_arches.keys(),
                .knownFlags = seccomp_flags.keys(),
                .supportedFlags = seccomp_flags.keys(),
            },
            .apparmor = .{ .enabled = true },
            .selinux = .{ .enabled = false },
            .intelRdt = .{ .enabled = false },
            .mountExtensions = .{ .idmap = .{ .enabled = true } },
        },
    }, .{});
}

test "features JSON reports parser tables and supported isolation" {
    const allocator = std.testing.allocator;
    const json = try featuresJson(allocator);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(oci_version_min, root.get("ociVersionMin").?.string);
    try std.testing.expectEqualStrings(oci_version_max, root.get("ociVersionMax").?.string);
    try expectFeatureMounts(allocator, root.get("mountOptions").?.array.items);
    const hooks = root.get("hooks").?.array.items;
    const hook_names = std.meta.fieldNames(Spec.Hooks);
    try std.testing.expectEqual(hook_names.len, hooks.len);
    for (hook_names, hooks) |name, reported| try std.testing.expectEqualStrings(name, reported.string);
    const linux = root.get("linux").?.object;
    const namespaces = linux.get("namespaces").?.array.items;
    const namespace_names = std.meta.fieldNames(@FieldType(Spec.Namespace, "type"));
    try std.testing.expectEqual(namespace_names.len, namespaces.len);
    for (namespace_names, namespaces) |name, reported| try std.testing.expectEqualStrings(name, reported.string);
    var has_user = false;
    for (namespaces) |namespace| {
        if (std.mem.eql(u8, namespace.string, "user")) has_user = true;
    }
    try std.testing.expect(has_user);
    const caps = linux.get("capabilities").?.array.items;
    try std.testing.expectEqual(capability_names.len, caps.len);
    for (capability_names, caps, 0..) |name, reported, number| {
        try std.testing.expectEqualStrings(name, reported.string);
        try std.testing.expectEqual(@as(?u6, @intCast(number)), try capabilityNumber(reported.string));
    }
    const cgroup = linux.get("cgroup").?.object;
    try std.testing.expect(cgroup.get("v1").?.bool);
    try std.testing.expect(cgroup.get("v2").?.bool);
    try std.testing.expect(cgroup.get("systemd").?.bool);
    for ([_][]const u8{ "systemdUser", "rdma" }) |name|
        try std.testing.expect(!cgroup.get(name).?.bool);
    try expectFeatureSeccomp(allocator, linux.get("seccomp").?.object);
    try std.testing.expect(linux.get("apparmor").?.object.get("enabled").?.bool);
    for ([_][]const u8{ "selinux", "intelRdt" }) |name|
        try std.testing.expect(!linux.get(name).?.object.get("enabled").?.bool);
    try std.testing.expect(linux.get("mountExtensions").?.object.get("idmap").?.object.get("enabled").?.bool);
}

fn expectFeatureMounts(allocator: std.mem.Allocator, reported_mounts: []const std.json.Value) !void {
    try std.testing.expectEqual(mount_option_table.len, reported_mounts.len);
    var has_rro = false;
    var has_idmap = false;
    var has_ridmap = false;
    for (mount_option_table, reported_mounts) |entry, reported| {
        try std.testing.expectEqualStrings(entry.name, reported.string);
        const options = try parseMountOptions(allocator, &.{reported.string}, null);
        defer allocator.free(options.data);
        try std.testing.expectEqualStrings("", options.data);
        if (std.mem.eql(u8, reported.string, "rro")) {
            has_rro = true;
            try std.testing.expectEqual(@as(?bool, true), options.recursive_readonly);
        }
        if (std.mem.eql(u8, reported.string, "idmap")) has_idmap = true;
        if (std.mem.eql(u8, reported.string, "ridmap")) has_ridmap = true;
    }
    try std.testing.expect(has_rro);
    try std.testing.expect(has_idmap and has_ridmap);
}

fn expectFeatureSeccomp(allocator: std.mem.Allocator, seccomp: std.json.ObjectMap) !void {
    try std.testing.expect(seccomp.get("enabled").?.bool);
    const lists = [_]struct { name: []const u8, count: usize }{
        .{ .name = "actions", .count = 8 },
        .{ .name = "operators", .count = 7 },
        .{ .name = "archs", .count = 24 },
        .{ .name = "knownFlags", .count = 4 },
        .{ .name = "supportedFlags", .count = 4 },
    };
    for (lists) |list| {
        const reported = seccomp.get(list.name).?.array.items;
        try std.testing.expectEqual(list.count, reported.len);
        for (reported) |item| {
            var profile: Spec.Seccomp = .{ .defaultAction = "SCMP_ACT_ALLOW" };
            if (std.mem.eql(u8, list.name, "actions")) {
                try std.testing.expect(!std.mem.eql(u8, item.string, "SCMP_ACT_NOTIFY"));
                profile.defaultAction = item.string;
            } else if (std.mem.eql(u8, list.name, "operators")) {
                profile.syscalls = &.{.{ .names = &.{"personality"}, .action = "SCMP_ACT_ERRNO", .args = &.{.{
                    .index = 0,
                    .value = 1,
                    .op = item.string,
                }} }};
            } else if (std.mem.eql(u8, list.name, "archs")) {
                profile.architectures = &.{item.string};
            } else {
                profile.flags = &.{item.string};
            }
            const prepared = try prepareSeccomp(allocator, profile);
            defer freeSeccomp(allocator, prepared);
        }
    }
}

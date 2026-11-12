const std = @import("std");
const oci = @import("igvano").oci;
const Config = @import("args.zig").Config;

/// runc v1.3.3's `runc spec` output on cgroup v2, byte for byte, so bundles
/// and tests written against runc see the same defaults.
pub const default_spec = @embedFile("spec.json");
/// runc adds the cgroup namespace only on a cgroup v2 host.
const cgroup_namespace = ",\n\t\t\t{\n\t\t\t\t\"type\": \"cgroup\"\n\t\t\t}";

/// runc spec: writes the starter config.json into the bundle, never over an existing one.
pub fn writeSpec(allocator: std.mem.Allocator, io: std.Io, config: Config) !void {
    const path = try std.fs.path.join(allocator, &.{ config.bundle orelse ".", "config.json" });
    defer allocator.free(path);
    const unified = if (std.Io.Dir.cwd().access(io, "/sys/fs/cgroup/cgroup.controllers", .{})) true else |_| false;
    const json = try starterSpec(allocator, unified);
    defer allocator.free(json);
    const file = std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true }) catch |err| {
        if (err == error.PathAlreadyExists) return oci.validationError(err, "File config.json exists. Remove it first", .{});
        return err;
    };
    defer file.close(io);
    try file.writeStreamingAll(io, json);
}

fn starterSpec(allocator: std.mem.Allocator, unified: bool) ![]u8 {
    if (unified) return allocator.dupe(u8, default_spec);
    return std.mem.replaceOwned(u8, allocator, default_spec, cgroup_namespace, "");
}

test "spec drops the cgroup namespace off cgroup v2" {
    const v1 = try starterSpec(std.testing.allocator, false);
    defer std.testing.allocator.free(v1);
    try std.testing.expect(std.mem.indexOf(u8, default_spec, cgroup_namespace) != null);
    try std.testing.expect(std.mem.indexOf(u8, v1, "\"cgroup\"\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, v1, "\"type\": \"mount\"\n\t\t\t}\n\t\t],") != null);
    const parsed = try std.json.parseFromSlice(oci.Spec, std.testing.allocator, v1, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 5), parsed.value.linux.?.namespaces.?.len);
}

test "spec writes the starter config once and parses as an OCI spec" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    const config: Config = .{ .root = "/unused", .subcommand = .spec, .id = "", .bundle = bundle };
    try writeSpec(std.testing.allocator, std.testing.io, config);
    try std.testing.expectError(error.PathAlreadyExists, writeSpec(std.testing.allocator, std.testing.io, config));
    const parsed = try oci.loadSpec(std.testing.allocator, std.testing.io, bundle);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.process.?.args.len);
    try std.testing.expectEqualStrings("sh", parsed.value.process.?.args[0]);
    try std.testing.expectEqualStrings("rootfs", parsed.value.root.path);
}

// SPDX-License-Identifier: Apache-2.0
// Portions derived from opencontainers/cgroups (https://github.com/opencontainers/cgroups), Copyright The runc Authors, Apache-2.0:
// systemd/common.go (ExpandSlice).
// Translated to Zig and modified. See NOTICE.
const std = @import("std");
const clearDiagnostic = @import("diagnostic.zig").clearDiagnostic;
const diagnosticFor = @import("diagnostic.zig").diagnosticFor;
const validationError = @import("diagnostic.zig").validationError;
const invalidConfig = @import("diagnostic.zig").invalidConfig;

pub const SystemdCgroup = struct {
    slice: []const u8,
    unit: []u8,
    path: []u8,

    pub fn deinit(self: SystemdCgroup, allocator: std.mem.Allocator) void {
        allocator.free(self.unit);
        allocator.free(self.path);
    }
};

/// runc's ExpandSlice: a-b.slice is /a.slice/a-b.slice; -.slice is root.
pub fn expandSystemdSlice(allocator: std.mem.Allocator, slice: []const u8) ![]u8 {
    if (!std.mem.endsWith(u8, slice, ".slice") or slice.len <= ".slice".len or
        !systemdUnitCharacters(slice))
        return invalidConfig("linux.cgroupsPath: invalid systemd slice name '{s}'", .{slice});
    if (slice.len > 255) return invalidConfig("linux.cgroupsPath: systemd slice name is too long", .{});
    const name = slice[0 .. slice.len - ".slice".len];
    if (std.mem.eql(u8, name, "-")) return allocator.dupe(u8, "/");
    var path: std.ArrayList(u8) = .empty;
    errdefer path.deinit(allocator);
    var components = std.mem.splitScalar(u8, name, '-');
    var end: usize = 0;
    while (components.next()) |component| {
        if (component.len == 0) return invalidConfig("linux.cgroupsPath: invalid systemd slice name '{s}'", .{slice});
        end += component.len;
        if (end + ".slice".len > 255) return invalidConfig("linux.cgroupsPath: systemd slice name is too long", .{});
        try path.append(allocator, '/');
        try path.appendSlice(allocator, name[0..end]);
        try path.appendSlice(allocator, ".slice");
        end += 1;
    }
    return path.toOwnedSlice(allocator);
}

fn systemdUnitCharacters(name: []const u8) bool {
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, ":_.\\@-", byte) == null)
            return false;
    }
    return true;
}

/// OCI's slice:prefix:name syntax is interpreted only by the frontend.
/// The default slice is runc's: system.slice, or user.slice when rootless.
pub fn parseSystemdCgroupPath(allocator: std.mem.Allocator, configured: ?[]const u8, id: []const u8, default_slice: []const u8) !SystemdCgroup {
    var slice = default_slice;
    var prefix: []const u8 = "igvano";
    var name = id;
    if (configured) |path| {
        if (path.len != 0) {
            var parts = std.mem.splitScalar(u8, path, ':');
            const parent = parts.next().?;
            prefix = parts.next() orelse return invalidConfig("linux.cgroupsPath: expected slice:prefix:name for systemd", .{});
            name = parts.next() orelse return invalidConfig("linux.cgroupsPath: expected slice:prefix:name for systemd", .{});
            if (parts.next() != null) return invalidConfig("linux.cgroupsPath: expected slice:prefix:name for systemd", .{});
            if (parent.len != 0) slice = parent;
        }
    }
    if (std.mem.endsWith(u8, name, ".slice"))
        return validationError(error.Unsupported, "linux.cgroupsPath: transient systemd slice units are not supported; use a scope name", .{});
    if (!systemdUnitCharacters(prefix) or !systemdUnitCharacters(name))
        return invalidConfig("linux.cgroupsPath: invalid systemd scope name", .{});
    const expanded = try expandSystemdSlice(allocator, slice);
    defer allocator.free(expanded);
    const unit = try std.fmt.allocPrint(allocator, "{s}-{s}.scope", .{ prefix, name });
    errdefer allocator.free(unit);
    if (unit.len > 255) return invalidConfig("linux.cgroupsPath: systemd scope name is too long", .{});
    const path = if (expanded.len == 1)
        try allocator.dupe(u8, unit)
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}", .{ expanded[1..], unit });
    return .{ .slice = slice, .unit = unit, .path = path };
}

test "systemd slices expand like runc and reject malformed components" {
    for ([_]struct { input: []const u8, path: []const u8 }{
        .{ .input = "-.slice", .path = "/" },
        .{ .input = "system.slice", .path = "/system.slice" },
        .{ .input = "test-a-b.slice", .path = "/test.slice/test-a.slice/test-a-b.slice" },
        .{ .input = "kubepods-besteffort-pod123.slice", .path = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice" },
    }) |case| {
        const expanded = try expandSystemdSlice(std.testing.allocator, case.input);
        defer std.testing.allocator.free(expanded);
        try std.testing.expectEqualStrings(case.path, expanded);
    }
    for ([_][]const u8{ "", "system", ".slice", "test--a.slice", "-test.slice", "test-.slice", "test/a.slice", "x\x00.slice" }) |slice|
        try std.testing.expectError(error.InvalidConfig, expandSystemdSlice(std.testing.allocator, slice));
}

test "systemd cgroupsPath resolves defaults scope names and nested slices" {
    for ([_]struct { configured: ?[]const u8, slice: []const u8, unit: []const u8, path: []const u8 }{
        .{ .configured = null, .slice = "system.slice", .unit = "igvano-id.scope", .path = "system.slice/igvano-id.scope" },
        .{ .configured = "", .slice = "system.slice", .unit = "igvano-id.scope", .path = "system.slice/igvano-id.scope" },
        .{ .configured = "system.slice:cri-containerd:abc", .slice = "system.slice", .unit = "cri-containerd-abc.scope", .path = "system.slice/cri-containerd-abc.scope" },
        .{ .configured = ":test:abc", .slice = "system.slice", .unit = "test-abc.scope", .path = "system.slice/test-abc.scope" },
        .{ .configured = "a-b.slice:test:abc", .slice = "a-b.slice", .unit = "test-abc.scope", .path = "a.slice/a-b.slice/test-abc.scope" },
        .{ .configured = "-.slice:test:abc", .slice = "-.slice", .unit = "test-abc.scope", .path = "test-abc.scope" },
    }) |case| {
        const result = try parseSystemdCgroupPath(std.testing.allocator, case.configured, "id", "system.slice");
        defer result.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(case.slice, result.slice);
        try std.testing.expectEqualStrings(case.unit, result.unit);
        try std.testing.expectEqualStrings(case.path, result.path);
    }
    for ([_][]const u8{ "/x", "x:y", "a.slice:p:n:extra", "bad:p:n", "a.slice:p:../escape", "a.slice:p:n\x00" }) |configured|
        try std.testing.expectError(error.InvalidConfig, parseSystemdCgroupPath(std.testing.allocator, configured, "id", "system.slice"));
    try std.testing.expectError(error.Unsupported, parseSystemdCgroupPath(std.testing.allocator, "system.slice:test:foo.slice", "id", "system.slice"));
    const rootless = try parseSystemdCgroupPath(std.testing.allocator, null, "id", "user.slice");
    defer rootless.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("user.slice/igvano-id.scope", rootless.path);
}

test "systemd cgroupsPath validates component characters and unit length limits" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "bad space.slice:p:n",       "bad!.slice:p:n",
        "system.slice:bad prefix:n", "system.slice:p:bad name",
        "system.slice:p:n\n",
        "system.slice:p:日本語",
        "system.slice:p:n?",         "system.slice:p:n*",
        "system.slice:p:n%",
    }) |configured| {
        clearDiagnostic();
        try std.testing.expectError(error.InvalidConfig, parseSystemdCgroupPath(allocator, configured, "id", "system.slice"));
        try std.testing.expect(diagnosticFor(error.InvalidConfig) != null);
    }
    const valid = try parseSystemdCgroupPath(allocator, "test_A.0\\x40.slice:prefix_1:Name.2@x\\x2d", "id", "system.slice");
    defer valid.deinit(allocator);
    try std.testing.expectEqualStrings("prefix_1-Name.2@x\\x2d.scope", valid.unit);
    const scope = try parseSystemdCgroupPath(allocator, "system.slice:p:" ++ "n" ** 247, "id", "system.slice");
    defer scope.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 255), scope.unit.len);
    try std.testing.expectError(error.InvalidConfig, parseSystemdCgroupPath(allocator, "system.slice:p:" ++ "n" ** 248, "id", "system.slice"));
    const slice = try expandSystemdSlice(allocator, "s" ** 249 ++ ".slice");
    defer allocator.free(slice);
    try std.testing.expectError(error.InvalidConfig, expandSystemdSlice(allocator, "s" ** 250 ++ ".slice"));
    try std.testing.expectError(error.InvalidConfig, parseSystemdCgroupPath(allocator, null, "bad id", "system.slice"));
}

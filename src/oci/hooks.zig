const std = @import("std");
const Backend = @import("libcontainer").Backend;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const Spec = @import("spec.zig").Spec;

pub fn validateHooks(configured: ?Spec.Hooks) error{InvalidConfig}!void {
    const hooks = configured orelse return;
    inline for (std.meta.fields(Spec.Hooks)) |field| {
        for (@field(hooks, field.name) orelse &.{}, 0..) |hook, i| {
            if (!std.mem.startsWith(u8, hook.path, "/") or
                std.mem.indexOfScalar(u8, hook.path, 0) != null or
                hook.timeout == 0) return invalidConfig("hooks.{s}[{d}]: require an absolute NUL-free path and positive timeout", .{ field.name, i });
            for (hook.args orelse &.{}) |arg|
                if (std.mem.indexOfScalar(u8, arg, 0) != null) return invalidConfig("hooks.{s}[{d}].args: must not contain NUL", .{ field.name, i });
            for (hook.env orelse &.{}) |env|
                if (std.mem.indexOfScalar(u8, env, 0) != null) return invalidConfig("hooks.{s}[{d}].env: must not contain NUL", .{ field.name, i });
        }
    }
}

/// Translate OCI hook entries; all slices are borrowed from the parsed spec.
pub fn prepareHooks(allocator: std.mem.Allocator, configured: ?[]const Spec.Hook) ![]Backend.Hook {
    const entries = configured orelse &.{};
    const hooks = try allocator.alloc(Backend.Hook, entries.len);
    for (entries, hooks) |entry, *hook| hook.* = .{
        .path = entry.path,
        .args = entry.args orelse &.{},
        .env = entry.env orelse &.{},
        .timeout_seconds = entry.timeout,
    };
    return hooks;
}

test "hooks parse all lifecycle stages and preserve their optional settings" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"hooks":{
        \\ "prestart":[{"path":"/compat"}],"createRuntime":[{"path":"/runtime","args":["custom","arg"],"env":["ONLY=hook"],"timeout":2}],
        \\ "createContainer":[{"path":"/create"}],"startContainer":[{"path":"/start"}],
        \\ "poststart":[{"path":"/started"}],"poststop":[{"path":"/stopped"}]}}
    , .{});
    defer parsed.deinit();
    try validateHooks(parsed.value.hooks);
    const hooks = parsed.value.hooks.?;
    try std.testing.expectEqualStrings("/compat", hooks.prestart.?[0].path);
    try std.testing.expectEqualStrings("custom", hooks.createRuntime.?[0].args.?[0]);
    try std.testing.expectEqualStrings("ONLY=hook", hooks.createRuntime.?[0].env.?[0]);
    try std.testing.expectEqual(@as(?u64, 2), hooks.createRuntime.?[0].timeout);
    try std.testing.expectEqualStrings("/create", hooks.createContainer.?[0].path);
    try std.testing.expectEqualStrings("/start", hooks.startContainer.?[0].path);
    try std.testing.expectEqualStrings("/started", hooks.poststart.?[0].path);
    try std.testing.expectEqualStrings("/stopped", hooks.poststop.?[0].path);
    try std.testing.expect(hooks.prestart.?[0].args == null);
    try std.testing.expect(hooks.prestart.?[0].env == null);
    try std.testing.expect(hooks.prestart.?[0].timeout == null);
}

test "hook validation rejects missing relative and NUL paths and zero timeout" {
    try std.testing.expectError(error.MissingField, std.json.parseFromSlice(Spec.Hook, std.testing.allocator, "{}", .{}));
    for ([_][]const u8{
        "{\"path\":\"relative\"}",
        "{\"path\":\"\"}",
        "{\"path\":\"/hook\\u0000\"}",
        "{\"path\":\"/hook\",\"timeout\":0}",
        "{\"path\":\"/hook\",\"args\":[\"bad\\u0000\"]}",
        "{\"path\":\"/hook\",\"env\":[\"bad\\u0000\"]}",
    }) |json| {
        const parsed = try std.json.parseFromSlice(Spec.Hook, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidConfig, validateHooks(.{ .poststop = &.{parsed.value} }));
    }
    try validateHooks(null);
    try validateHooks(.{ .prestart = &.{} });
    try validateHooks(.{ .startContainer = &.{.{ .path = "/hook", .timeout = 1 }} });
}

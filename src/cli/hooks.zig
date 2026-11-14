const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const diagnostics = @import("diagnostic.zig");

/// State stays frontend-owned. The container only inserts a decimal host PID
/// into these opaque fragments, using a buffer allocated before fork.
pub fn hookStateTemplate(allocator: std.mem.Allocator, state: oci.State) !libcontainer.HookState {
    var template = state;
    template.pid = 0;
    const json = try oci.stateJson(allocator, template);
    defer allocator.free(json);
    const field = "\"pid\":0";
    const index = std.mem.indexOf(u8, json, field) orelse return oci.validationError(error.InvalidState, "hook state: missing pid field", .{});
    const prefix = try allocator.dupe(u8, json[0 .. index + field.len - 1]);
    errdefer allocator.free(prefix);
    return .{ .prefix = prefix, .suffix = try allocator.dupe(u8, json[index + field.len ..]) };
}

pub fn runHooks(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Hook, state: oci.State, name: []const u8) !void {
    const entries = configured orelse return;
    if (entries.len == 0) return;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const hook_allocator = arena.allocator();
    const hooks = try oci.prepareHooks(hook_allocator, entries);
    const prepared = try libcontainer.hooks.prepare(hook_allocator, hooks);
    const json = try oci.stateJson(hook_allocator, state);
    // Keep "error running <name> hook #N" for the frontend's error report.
    const result = libcontainer.hooks.run(prepared, json, name);
    try diagnostics.resultWithDetail(libcontainer.linux.diagnostic(), result);
}

pub fn warnHooks(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Hook, state: oci.State, stage: []const u8) void {
    // Best-effort hooks remain ordered even if an earlier hook failed.
    for (configured orelse &.{}) |hook| {
        runHooks(allocator, &.{hook}, state, stage) catch |err| {
            std.debug.print("igvano: warning: {s} hook '{s}' failed: {s}\n", .{ stage, hook.path, @errorName(err) });
            diagnostics.last_container_detail = null;
        };
    }
}

test "hook state templates reproduce state stdout with a host PID" {
    const state: oci.State = .{ .id = "hook-test", .status = .creating, .pid = 1234, .bundle = "/bundle" };
    const template = try hookStateTemplate(std.testing.allocator, state);
    defer std.testing.allocator.free(template.prefix);
    defer std.testing.allocator.free(template.suffix);
    const actual = try std.fmt.allocPrint(std.testing.allocator, "{s}{d}{s}", .{ template.prefix, 1234, template.suffix });
    defer std.testing.allocator.free(actual);
    const expected = try oci.stateJson(std.testing.allocator, state);
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, actual);
}

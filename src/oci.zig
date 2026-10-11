const std = @import("std");

pub const Status = enum {
    creating,
    created,
    running,
    stopped,
};

pub const State = struct {
    ociVersion: []const u8,
    id: []const u8,
    status: Status,
    pid: ?i32 = null,
    bundle: []const u8,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,
};

pub fn writeState(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const path = try std.fs.path.join(allocator, &.{ root, id, "state.json" });
    defer allocator.free(path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(State, allocator, json, .{});
    defer parsed.deinit();
    try std.json.Stringify.value(parsed.value, .{ .emit_null_optional_fields = false }, writer);
    try writer.writeByte('\n');
}

test "state JSON round-trips a running container with annotations" {
    const json =
        \\{"ociVersion":"1.0.2","id":"example","status":"running","pid":1234,"bundle":"/tmp/bundle","annotations":{"org.example.description":"hello"}}
    ;
    const parsed = try std.json.parseFromSlice(State, std.testing.allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("1.0.2", parsed.value.ociVersion);
    try std.testing.expectEqualStrings("example", parsed.value.id);
    try std.testing.expectEqual(Status.running, parsed.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), parsed.value.pid);
    try std.testing.expectEqualStrings("/tmp/bundle", parsed.value.bundle);
    try std.testing.expectEqualStrings("hello", parsed.value.annotations.?.map.get("org.example.description").?);

    const output = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(json, output);
}

test "state JSON accepts lifecycle statuses and omits absent optional fields" {
    for ([_]Status{ .creating, .created, .stopped }) |status| {
        const pid: ?i32 = if (status == .created) 1234 else null;
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"ociVersion\":\"1.0.2\",\"id\":\"example\",\"status\":\"{s}\"{s},\"bundle\":\"/tmp/bundle\"}}",
            .{ @tagName(status), if (pid != null) ",\"pid\":1234" else "" },
        );
        defer std.testing.allocator.free(json);
        const parsed = try std.json.parseFromSlice(State, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(status, parsed.value.status);
        try std.testing.expectEqual(pid, parsed.value.pid);
        try std.testing.expect(parsed.value.annotations == null);

        const output = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{
            .emit_null_optional_fields = false,
        });
        defer std.testing.allocator.free(output);
        try std.testing.expectEqualStrings(json, output);
    }
}

test "state JSON rejects an unknown lifecycle status" {
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSlice(State, std.testing.allocator,
        \\{"ociVersion":"1.0.2","id":"example","status":"paused","bundle":"/tmp/bundle"}
    , .{}));
}

test "state reads a fixture from the selected root and writes JSON" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/state.json",
        .data =
        \\{
        \\  "bundle": "/tmp/bundle",
        \\  "status": "created",
        \\  "pid": 1234,
        \\  "id": "example",
        \\  "ociVersion": "1.0.2",
        \\  "annotations": {"org.example.description": "hello"}
        \\}
        ,
    });

    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeState(std.testing.allocator, std.testing.io, root, "example", &output.writer);
    try std.testing.expectEqualStrings(
        "{\"ociVersion\":\"1.0.2\",\"id\":\"example\",\"status\":\"created\",\"pid\":1234,\"bundle\":\"/tmp/bundle\",\"annotations\":{\"org.example.description\":\"hello\"}}\n",
        output.written(),
    );
}

test "state reports a missing container without writing output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(error.FileNotFound, writeState(std.testing.allocator, std.testing.io, root, "missing", &output.writer));
    try std.testing.expectEqualStrings("", output.written());
}

test "state rejects files larger than one MiB without writing output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const data = try std.testing.allocator.alloc(u8, (1 << 20) + 1);
    defer std.testing.allocator.free(data);
    @memset(data, ' ');
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/state.json",
        .data = data,
    });

    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(error.StreamTooLong, writeState(std.testing.allocator, std.testing.io, root, "example", &output.writer));
    try std.testing.expectEqualStrings("", output.written());
}

const std = @import("std");
const validationError = @import("diagnostic.zig").validationError;
const recordDiagnostic = @import("diagnostic.zig").recordDiagnostic;
const runtime_oci_version = @import("spec.zig").runtime_oci_version;

pub const state_file_name = "state.json";
pub const lock_file_name = "lock";
pub const exec_fifo_name = "exec.fifo";
pub const starttime_file_name = "starttime";
pub const process_file_name = "process";
pub const cgroup_file_name = "cgroup";
pub const cgroup_driver_file_name = "cgroup-driver";
pub const rootfs_mount_file_name = "rootfs_mount";
pub const hooks_file_name = "hooks.json";

pub const Status = enum {
    creating,
    created,
    running,
    paused,
    stopped,
};

pub fn requireStart(status: Status, has_process: bool) !void {
    if (status != .created) return validationError(error.InvalidStatus, "start: requires created state; found {s}", .{@tagName(status)});
    if (!has_process) return validationError(error.MissingProcess, "start: container has no process", .{});
}

pub fn requireKill(status: Status) !void {
    if (status != .created and status != .running and status != .paused) return validationError(error.InvalidStatus, "kill: requires created, running or paused state; found {s}", .{@tagName(status)});
}

pub fn requireUpdate(status: Status) !void {
    if (status != .created and status != .running and status != .paused) return validationError(error.InvalidStatus, "update: requires created, running or paused state; found {s}", .{@tagName(status)});
}

pub fn requirePause(status: Status) !void {
    // ponytail: runc also allows pausing created containers; containerd only pauses running containers.
    if (status != .running) return validationError(error.InvalidStatus, "pause: requires running state; found {s}", .{@tagName(status)});
}

pub fn requireResume(status: Status) !void {
    if (status != .paused) return validationError(error.InvalidStatus, "resume: requires paused state; found {s}", .{@tagName(status)});
}

pub fn requireDelete(status: Status) !void {
    if (status != .stopped) return validationError(error.InvalidStatus, "delete: requires stopped state; found {s}", .{@tagName(status)});
}

pub const State = struct {
    ociVersion: []const u8 = runtime_oci_version,
    id: []const u8,
    status: Status,
    pid: ?i32 = null,
    bundle: []const u8,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,
};

/// Used by state stdout and every hook, with identical optional-field handling.
pub fn stateJson(allocator: std.mem.Allocator, state: State) ![]u8 {
    const json = try std.json.Stringify.valueAlloc(allocator, state, .{ .emit_null_optional_fields = false });
    defer allocator.free(json);
    return std.fmt.allocPrint(allocator, "{s}\n", .{json});
}

/// A named temporary file in the destination directory is renamed after writing.
pub fn atomicWrite(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .replace = true });
    defer file.deinit(io);
    try file.file.writeStreamingAll(io, bytes);
    try file.file.sync(io);
    try file.replace(io);
}

pub fn saveState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, state: State) !void {
    const path = try std.fs.path.join(allocator, &.{ root, state.id, state_file_name });
    defer allocator.free(path);
    const json = try stateJson(allocator, state);
    defer allocator.free(json);
    try atomicWrite(io, path, json);
}

/// The caller owns the returned state and must call deinit().
pub fn loadState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !std.json.Parsed(State) {
    const path = try std.fs.path.join(allocator, &.{ root, id, state_file_name });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20)) catch |err| {
        if (err == error.StreamTooLong) recordDiagnostic(err, "state.json: exceeds 1 MiB", .{});
        return err;
    };
    defer allocator.free(json);
    return std.json.parseFromSlice(State, allocator, json, .{ .allocate = .alloc_always }) catch |err| {
        if (err != error.OutOfMemory) recordDiagnostic(err, "state.json: invalid JSON or schema ({s})", .{@errorName(err)});
        return err;
    };
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
    for ([_]Status{ .creating, .created, .paused, .stopped }) |status| {
        const pid: ?i32 = if (status == .created or status == .paused) 1234 else null;
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
        \\{"ociVersion":"1.0.2","id":"example","status":"unknown","bundle":"/tmp/bundle"}
    , .{}));
}

test "state reads a fixture from the selected root" {
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
    const parsed = try loadState(std.testing.allocator, std.testing.io, root, "example");
    defer parsed.deinit();
    try std.testing.expectEqualStrings("example", parsed.value.id);
    try std.testing.expectEqual(Status.created, parsed.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), parsed.value.pid);
    try std.testing.expectEqualStrings("hello", parsed.value.annotations.?.map.get("org.example.description").?);
}

test "state reports a missing container" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.FileNotFound, loadState(std.testing.allocator, std.testing.io, root, "missing"));
}

test "state rejects files larger than one MiB" {
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
    try std.testing.expectError(error.StreamTooLong, loadState(std.testing.allocator, std.testing.io, root, "example"));
}

test "lifecycle operations enforce their legal statuses" {
    for ([_]Status{ .creating, .created, .running, .paused, .stopped }) |status| {
        if (status == .created) {
            try requireStart(status, true);
            try std.testing.expectError(error.MissingProcess, requireStart(status, false));
        } else {
            try std.testing.expectError(error.InvalidStatus, requireStart(status, true));
        }
        if (status == .created or status == .running or status == .paused) {
            try requireKill(status);
            try requireUpdate(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireKill(status));
            try std.testing.expectError(error.InvalidStatus, requireUpdate(status));
        }
        if (status == .stopped) {
            try requireDelete(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireDelete(status));
        }
        if (status == .running) {
            try requirePause(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requirePause(status));
        }
        if (status == .paused) {
            try requireResume(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireResume(status));
        }
    }
}

test "atomic write replaces complete contents and cleans up after a failed rename" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "state.json" });
    defer std.testing.allocator.free(path);
    const original = "first, longer contents";
    try atomicWrite(std.testing.io, path, original);
    const old_file = try tmp.dir.openFile(std.testing.io, "state.json", .{});
    defer old_file.close(std.testing.io);
    try atomicWrite(std.testing.io, path, "second");
    // Readers that already opened the old state keep seeing its complete contents.
    var old_contents: [original.len]u8 = undefined;
    try std.testing.expectEqual(original.len, try old_file.readPositionalAll(std.testing.io, &old_contents, 0));
    try std.testing.expectEqualStrings(original, &old_contents);
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("second", contents);

    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    const directory = try std.fs.path.join(std.testing.allocator, &.{ root, "directory" });
    defer std.testing.allocator.free(directory);
    if (atomicWrite(std.testing.io, directory, "cannot replace a directory")) {
        return error.TestUnexpectedResult;
    } else |_| {}
    var entries = tmp.dir.iterate();
    var count: usize = 0;
    while (try entries.next(std.testing.io)) |entry| {
        try std.testing.expect(std.mem.eql(u8, entry.name, "state.json") or std.mem.eql(u8, entry.name, "directory"));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

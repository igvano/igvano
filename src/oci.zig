const std = @import("std");

pub const state_file_name = "state.json";
pub const exec_fifo_name = "exec.fifo";
pub const starttime_file_name = "starttime";
pub const runtime_oci_version = "1.0.2";

/// Parsed config.json values needed by a namespace backend.
pub const Spec = struct {
    ociVersion: []const u8,
    root: Root,
    process: ?Process = null,
    hostname: ?[]const u8 = null,
    mounts: ?[]const Mount = null,
    linux: ?Linux = null,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,

    pub const Root = struct {
        path: []const u8,
        readonly: bool = false,
    };

    pub const Process = struct {
        args: []const []const u8,
        env: ?[]const []const u8 = null,
        cwd: []const u8,
        terminal: ?bool = null,
        noNewPrivileges: bool = false,
        user: User,
    };

    pub const User = struct {
        uid: u32,
        gid: u32,
        additionalGids: ?[]const u32 = null,
    };

    pub const Mount = struct {
        destination: []const u8,
        type: ?[]const u8 = null,
        source: ?[]const u8 = null,
        options: ?[]const []const u8 = null,
    };

    pub const Linux = struct {
        namespaces: ?[]const Namespace = null,
        uidMappings: ?[]const IDMapping = null,
        gidMappings: ?[]const IDMapping = null,
    };

    pub const Namespace = struct {
        type: enum { pid, network, mount, ipc, uts, user, cgroup, time },
        path: ?[]const u8 = null,
    };

    pub const IDMapping = struct {
        containerID: u32,
        hostID: u32,
        size: u32,
    };
};

/// Linux mount constants are available on every build host; this performs no I/O.
/// The caller owns data, including when there are no filesystem-specific options.
pub const MountOptions = struct {
    flags: u32,
    propagation: u32,
    data: [:0]u8,
};

pub fn parseMountOptions(allocator: std.mem.Allocator, options: []const []const u8) !MountOptions {
    const ms = std.os.linux.MS;
    const atime = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
    const flag_options = [_]struct { name: []const u8, set: u32 = 0, clear: u32 = 0 }{
        .{ .name = "defaults" },
        .{ .name = "ro", .set = ms.RDONLY },
        .{ .name = "rw", .clear = ms.RDONLY },
        .{ .name = "nosuid", .set = ms.NOSUID },
        .{ .name = "suid", .clear = ms.NOSUID },
        .{ .name = "nodev", .set = ms.NODEV },
        .{ .name = "dev", .clear = ms.NODEV },
        .{ .name = "noexec", .set = ms.NOEXEC },
        .{ .name = "exec", .clear = ms.NOEXEC },
        .{ .name = "bind", .set = ms.BIND, .clear = ms.REC },
        .{ .name = "rbind", .set = ms.BIND | ms.REC },
        .{ .name = "relatime", .set = ms.RELATIME, .clear = atime },
        .{ .name = "noatime", .set = ms.NOATIME, .clear = atime },
        .{ .name = "strictatime", .set = ms.STRICTATIME, .clear = atime },
        .{ .name = "atime", .clear = ms.NOATIME },
        .{ .name = "nodiratime", .set = ms.NODIRATIME },
        .{ .name = "diratime", .clear = ms.NODIRATIME },
        .{ .name = "sync", .set = ms.SYNCHRONOUS },
        .{ .name = "async", .clear = ms.SYNCHRONOUS },
        .{ .name = "dirsync", .set = ms.DIRSYNC },
    };
    const propagation_options = [_]struct { name: []const u8, flags: u32 }{
        .{ .name = "private", .flags = ms.PRIVATE },
        .{ .name = "rprivate", .flags = ms.PRIVATE | ms.REC },
        .{ .name = "slave", .flags = ms.SLAVE },
        .{ .name = "rslave", .flags = ms.SLAVE | ms.REC },
        .{ .name = "shared", .flags = ms.SHARED },
        .{ .name = "rshared", .flags = ms.SHARED | ms.REC },
    };
    var flags: u32 = 0;
    var propagation: u32 = 0;
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    option: for (options) |option| {
        if (std.mem.indexOfScalar(u8, option, 0) != null) return error.InvalidConfig;
        for (flag_options) |entry| {
            if (std.mem.eql(u8, option, entry.name)) {
                flags = (flags & ~entry.clear) | entry.set;
                continue :option;
            }
        }
        // Propagation changes require their own mount syscall.
        for (propagation_options) |entry| {
            if (std.mem.eql(u8, option, entry.name)) {
                propagation = entry.flags;
                continue :option;
            }
        }
        if (data.items.len != 0) try data.append(allocator, ',');
        try data.appendSlice(allocator, option);
    }
    return .{ .flags = flags, .propagation = propagation, .data = try data.toOwnedSliceSentinel(allocator, 0) };
}

pub fn validateMountDestination(destination: []const u8) !void {
    if (!std.mem.startsWith(u8, destination, "/") or
        std.mem.indexOfScalar(u8, destination, 0) != null) return error.InvalidConfig;
    var depth: usize = 0;
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (depth == 0) return error.InvalidConfig;
            depth -= 1;
        } else {
            depth += 1;
        }
    }
}

/// Returns an absolute, normalized container path, never a host path.
pub fn resolveMountDestination(allocator: std.mem.Allocator, destination: []const u8) ![]u8 {
    try validateMountDestination(destination);
    return std.fs.path.resolve(allocator, &.{destination});
}

/// Rootfs isolation always needs a mount namespace, even with an empty mount list.
pub fn requireCreate(spec: Spec) !void {
    const settings = spec.linux orelse return error.InvalidConfig;
    const namespaces = settings.namespaces orelse return error.InvalidConfig;
    var has_mount = false;
    for (namespaces) |namespace| {
        if (namespace.type == .mount) has_mount = true;
    }
    if (!has_mount or spec.root.path.len == 0) return error.InvalidConfig;
    if (spec.process) |process| {
        if (!std.mem.startsWith(u8, process.cwd, "/") or
            std.mem.indexOfScalar(u8, process.cwd, 0) != null) return error.InvalidProcess;
    }
    for (spec.mounts orelse &.{}) |mount| try validateMountDestination(mount.destination);
}

test "mount options translate flags propagation and filesystem data" {
    const ms = std.os.linux.MS;
    const cases = [_]struct {
        options: []const []const u8,
        flags: u32 = 0,
        propagation: u32 = 0,
        data: []const u8 = "",
    }{
        .{ .options = &.{} },
        .{ .options = &.{"ro"}, .flags = ms.RDONLY },
        .{ .options = &.{ "ro", "rw" } },
        .{ .options = &.{ "rw", "ro" }, .flags = ms.RDONLY },
        .{ .options = &.{ "nosuid", "nodev", "noexec" }, .flags = ms.NOSUID | ms.NODEV | ms.NOEXEC },
        .{ .options = &.{ "nosuid", "suid", "nodev", "dev", "noexec", "exec", "defaults" } },
        .{ .options = &.{"bind"}, .flags = ms.BIND },
        .{ .options = &.{ "ro", "rbind" }, .flags = ms.RDONLY | ms.BIND | ms.REC },
        .{ .options = &.{ "rbind", "bind" }, .flags = ms.BIND },
        .{ .options = &.{"private"}, .propagation = ms.PRIVATE },
        .{ .options = &.{"rprivate"}, .propagation = ms.PRIVATE | ms.REC },
        .{ .options = &.{"slave"}, .propagation = ms.SLAVE },
        .{ .options = &.{"rslave"}, .propagation = ms.SLAVE | ms.REC },
        .{ .options = &.{"shared"}, .propagation = ms.SHARED },
        .{ .options = &.{"rshared"}, .propagation = ms.SHARED | ms.REC },
        .{ .options = &.{ "rshared", "private" }, .propagation = ms.PRIVATE },
        .{ .options = &.{ "rbind", "private" }, .flags = ms.BIND | ms.REC, .propagation = ms.PRIVATE },
        .{ .options = &.{"relatime"}, .flags = ms.RELATIME },
        .{ .options = &.{"noatime"}, .flags = ms.NOATIME },
        .{ .options = &.{"strictatime"}, .flags = ms.STRICTATIME },
        .{ .options = &.{ "noatime", "relatime", "strictatime" }, .flags = ms.STRICTATIME },
        .{ .options = &.{ "ro", "size=65536k", "nosuid", "mode=755", "custom" }, .flags = ms.RDONLY | ms.NOSUID, .data = "size=65536k,mode=755,custom" },
    };
    for (cases) |case| {
        const result = try parseMountOptions(std.testing.allocator, case.options);
        defer std.testing.allocator.free(result.data);
        try std.testing.expectEqual(case.flags, result.flags);
        try std.testing.expectEqual(case.propagation, result.propagation);
        try std.testing.expectEqualStrings(case.data, result.data);
    }
    try std.testing.expectError(error.InvalidConfig, parseMountOptions(std.testing.allocator, &.{"mode=7\x0055"}));
}

test "mount destinations normalize within the root and reject escapes" {
    const cases = [_]struct { destination: []const u8, expected: []const u8 }{
        .{ .destination = "/", .expected = "/" },
        .{ .destination = "/proc", .expected = "/proc" },
        .{ .destination = "//dev/./pts/", .expected = "/dev/pts" },
        .{ .destination = "/a/../mnt", .expected = "/mnt" },
        .{ .destination = "/a/b/../../", .expected = "/" },
    };
    for (cases) |case| {
        const destination = try resolveMountDestination(std.testing.allocator, case.destination);
        defer std.testing.allocator.free(destination);
        try std.testing.expectEqualStrings(case.expected, destination);
    }
    for ([_][]const u8{ "", "proc", "../proc", "/..", "/../proc", "/a/../../outside", "/a/../..", "/proc\x00/../outside" }) |destination| {
        try std.testing.expectError(error.InvalidConfig, resolveMountDestination(std.testing.allocator, destination));
    }
}

test "create validation requires mount isolation with or without mounts" {
    var spec: Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" } };
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux = .{};
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
    spec.linux = .{ .namespaces = &.{.{ .type = .pid }} };
    spec.mounts = &.{.{ .destination = "/proc", .type = "proc" }};
    try std.testing.expectError(error.InvalidConfig, requireCreate(spec));
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

/// Loads <bundle>/config.json. The caller owns the result and must call deinit().
pub fn loadSpec(allocator: std.mem.Allocator, io: std.Io, bundle_dir: []const u8) !std.json.Parsed(Spec) {
    const path = try std.fs.path.join(allocator, &.{ bundle_dir, "config.json" });
    defer allocator.free(path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(json);
    return std.json.parseFromSlice(Spec, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

/// Resolves root.path against an absolute bundle directory. The caller owns the path.
pub fn resolveRootfs(allocator: std.mem.Allocator, bundle_dir: []const u8, root_path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(bundle_dir)) return error.RelativeBundle;
    if (std.fs.path.isAbsolute(root_path)) return allocator.dupe(u8, root_path);
    return std.fs.path.join(allocator, &.{ bundle_dir, root_path });
}

pub const Status = enum {
    creating,
    created,
    running,
    stopped,
};

pub fn requireStart(status: Status, has_process: bool) !void {
    if (status != .created) return error.InvalidStatus;
    if (!has_process) return error.MissingProcess;
}

pub fn requireKill(status: Status) !void {
    if (status != .created and status != .running) return error.InvalidStatus;
}

pub fn requireDelete(status: Status) !void {
    if (status != .stopped) return error.InvalidStatus;
}

pub const State = struct {
    ociVersion: []const u8 = runtime_oci_version,
    id: []const u8,
    status: Status,
    pid: ?i32 = null,
    bundle: []const u8,
    annotations: ?std.json.ArrayHashMap([]const u8) = null,
};

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
    const json = try std.json.Stringify.valueAlloc(allocator, state, .{ .emit_null_optional_fields = false });
    defer allocator.free(json);
    try atomicWrite(io, path, json);
}

/// The caller owns the returned state and must call deinit().
pub fn loadState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !std.json.Parsed(State) {
    const path = try std.fs.path.join(allocator, &.{ root, id, state_file_name });
    defer allocator.free(path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(json);
    return std.json.parseFromSlice(State, allocator, json, .{ .allocate = .alloc_always });
}

pub fn writeState(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    id: []const u8,
    writer: *std.Io.Writer,
) !void {
    const parsed = try loadState(allocator, io, root, id);
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

test "loadSpec parses a runc-style config and tolerates unknown fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "config.json",
        .data =
        \\{
        \\  "ociVersion": "1.0.2",
        \\  "root": {"path": "rootfs", "readonly": true},
        \\  "process": {
        \\    "terminal": true,
        \\    "user": {"uid": 1000, "gid": 1001, "additionalGids": [1002]},
        \\    "args": ["/bin/sh", "-c", "echo hello"],
        \\    "env": ["PATH=/usr/bin:/bin", "TERM=xterm"],
        \\    "cwd": "/",
        \\    "capabilities": {"bounding": ["CAP_CHOWN"]},
        \\    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        \\    "noNewPrivileges": true
        \\  },
        \\  "hostname": "example",
        \\  "mounts": [{
        \\    "destination": "/proc",
        \\    "type": "proc",
        \\    "source": "proc",
        \\    "options": ["nosuid", "noexec", "nodev"]
        \\  }],
        \\  "linux": {
        \\    "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "uts"}],
        \\    "resources": {"devices": [{"allow": false, "access": "rwm"}]},
        \\    "maskedPaths": ["/proc/kcore"]
        \\  },
        \\  "annotations": {"org.example.description": "hello"}
        \\}
        ,
    });

    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    const parsed = try loadSpec(std.testing.allocator, std.testing.io, bundle);
    defer parsed.deinit();
    const spec = parsed.value;
    try std.testing.expectEqualStrings("1.0.2", spec.ociVersion);
    try std.testing.expectEqualStrings("rootfs", spec.root.path);
    try std.testing.expect(spec.root.readonly);
    const process = spec.process.?;
    try std.testing.expectEqual(@as(usize, 3), process.args.len);
    try std.testing.expectEqualStrings("/bin/sh", process.args[0]);
    try std.testing.expectEqualStrings("-c", process.args[1]);
    try std.testing.expectEqualStrings("echo hello", process.args[2]);
    try std.testing.expectEqual(@as(usize, 2), process.env.?.len);
    try std.testing.expectEqualStrings("PATH=/usr/bin:/bin", process.env.?[0]);
    try std.testing.expectEqualStrings("TERM=xterm", process.env.?[1]);
    try std.testing.expectEqualStrings("/", process.cwd);
    try std.testing.expectEqual(@as(?bool, true), process.terminal);
    try std.testing.expect(process.noNewPrivileges);
    try std.testing.expectEqual(@as(u32, 1000), process.user.uid);
    try std.testing.expectEqual(@as(u32, 1001), process.user.gid);
    try std.testing.expectEqualStrings("example", spec.hostname.?);
    try std.testing.expectEqual(@as(usize, 1), spec.mounts.?.len);
    const mount = spec.mounts.?[0];
    try std.testing.expectEqualStrings("/proc", mount.destination);
    try std.testing.expectEqualStrings("proc", mount.type.?);
    try std.testing.expectEqualStrings("proc", mount.source.?);
    try std.testing.expectEqual(@as(usize, 3), mount.options.?.len);
    try std.testing.expectEqualStrings("nosuid", mount.options.?[0]);
    try std.testing.expectEqualStrings("noexec", mount.options.?[1]);
    try std.testing.expectEqualStrings("nodev", mount.options.?[2]);
    const namespaces = spec.linux.?.namespaces.?;
    try std.testing.expectEqual(@as(usize, 3), namespaces.len);
    try std.testing.expectEqual(.pid, namespaces[0].type);
    try std.testing.expectEqual(.mount, namespaces[1].type);
    try std.testing.expectEqual(.uts, namespaces[2].type);
    try std.testing.expect(namespaces[0].path == null);
    try std.testing.expectEqualStrings("hello", spec.annotations.?.map.get("org.example.description").?);
}

test "spec defaults omitted optional fields" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try std.testing.expect(!parsed.value.root.readonly);
    try std.testing.expect(parsed.value.process.?.env == null);
    try std.testing.expect(parsed.value.process.?.terminal == null);
    try std.testing.expect(!parsed.value.process.?.noNewPrivileges);
    try std.testing.expect(parsed.value.process.?.user.additionalGids == null);
    try std.testing.expect(parsed.value.hostname == null);
    try std.testing.expect(parsed.value.mounts == null);
    try std.testing.expect(parsed.value.linux == null);
    try std.testing.expect(parsed.value.annotations == null);
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

test "spec parses namespace paths and user id mappings" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{
        \\  "ociVersion": "1.0.2",
        \\  "root": {"path": "rootfs"},
        \\  "process": {"args": ["/bin/sh"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
        \\  "mounts": [{"destination": "/mnt"}],
        \\  "linux": {
        \\    "namespaces": [
        \\      {"type": "network", "path": "/proc/1234/ns/net"},
        \\      {"type": "ipc"}, {"type": "user"}, {"type": "cgroup"}
        \\    ],
        \\    "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
        \\    "gidMappings": [{"containerID": 0, "hostID": 1001, "size": 1}]
        \\  }
        \\}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const namespaces = parsed.value.linux.?.namespaces.?;
    try std.testing.expectEqual(.network, namespaces[0].type);
    try std.testing.expectEqualStrings("/proc/1234/ns/net", namespaces[0].path.?);
    try std.testing.expectEqual(.ipc, namespaces[1].type);
    try std.testing.expectEqual(.user, namespaces[2].type);
    try std.testing.expectEqual(.cgroup, namespaces[3].type);
    const uid_mapping = parsed.value.linux.?.uidMappings.?[0];
    try std.testing.expectEqual(@as(u32, 0), uid_mapping.containerID);
    try std.testing.expectEqual(@as(u32, 1000), uid_mapping.hostID);
    try std.testing.expectEqual(@as(u32, 1), uid_mapping.size);
    const gid_mapping = parsed.value.linux.?.gidMappings.?[0];
    try std.testing.expectEqual(@as(u32, 0), gid_mapping.containerID);
    try std.testing.expectEqual(@as(u32, 1001), gid_mapping.hostID);
    try std.testing.expectEqual(@as(u32, 1), gid_mapping.size);
    const mount = parsed.value.mounts.?[0];
    try std.testing.expect(mount.type == null);
    try std.testing.expect(mount.source == null);
    try std.testing.expect(mount.options == null);
}

test "loadSpec reports a missing config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    try std.testing.expectError(error.FileNotFound, loadSpec(std.testing.allocator, std.testing.io, bundle));
}

test "loadSpec rejects files larger than one MiB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try std.testing.allocator.alloc(u8, (1 << 20) + 1);
    defer std.testing.allocator.free(data);
    @memset(data, ' ');
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "config.json", .data = data });
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    try std.testing.expectError(error.StreamTooLong, loadSpec(std.testing.allocator, std.testing.io, bundle));
}

test "rootfs resolution uses the bundle only for relative paths" {
    const cases = [_]struct { bundle: []const u8, root_path: []const u8, expected: []const u8 }{
        .{ .bundle = "/b", .root_path = "rootfs", .expected = "/b/rootfs" },
        .{ .bundle = "/b", .root_path = "/var/lib/rootfs", .expected = "/var/lib/rootfs" },
    };
    for (cases) |case| {
        const rootfs = try resolveRootfs(std.testing.allocator, case.bundle, case.root_path);
        defer std.testing.allocator.free(rootfs);
        try std.testing.expectEqualStrings(case.expected, rootfs);
    }
}

test "spec accepts an omitted process and a time namespace" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"time"}]}}
    , .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.process == null);
    try std.testing.expectEqual(.time, parsed.value.linux.?.namespaces.?[0].type);
}

test "rootfs resolution rejects a relative bundle even for an absolute rootfs" {
    try std.testing.expectError(error.RelativeBundle, resolveRootfs(std.testing.allocator, "bundle", "rootfs"));
    try std.testing.expectError(error.RelativeBundle, resolveRootfs(std.testing.allocator, "bundle", "/rootfs"));
}

test "lifecycle operations enforce their legal statuses" {
    for ([_]Status{ .creating, .created, .running, .stopped }) |status| {
        if (status == .created) {
            try requireStart(status, true);
            try std.testing.expectError(error.MissingProcess, requireStart(status, false));
        } else {
            try std.testing.expectError(error.InvalidStatus, requireStart(status, true));
        }
        if (status == .created or status == .running) {
            try requireKill(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireKill(status));
        }
        if (status == .stopped) {
            try requireDelete(status);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireDelete(status));
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

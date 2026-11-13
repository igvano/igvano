const std = @import("std");
const validationError = @import("diagnostic.zig").validationError;
const recordDiagnostic = @import("diagnostic.zig").recordDiagnostic;
const requireCreate = @import("validate.zig").requireCreate;
const loadResources = @import("resources.zig").loadResources;
const rootfsPropagation = @import("mounts.zig").rootfsPropagation;
const validateHooks = @import("hooks.zig").validateHooks;

pub const runtime_oci_version = "1.0.2";

// Recognized schema revisions reported by features do not gate config loading.
pub const oci_version_min = "1.0.0";
pub const oci_version_max = "1.2.1";

/// Parsed config.json values translated by the frontend for libcontainer.
pub const Spec = struct {
    ociVersion: []const u8,
    root: Root,
    process: ?Process = null,
    hostname: ?[]const u8 = null,
    mounts: ?[]const Mount = null,
    hooks: ?Hooks = null,
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
        apparmorProfile: ?[]const u8 = null,
        oomScoreAdj: ?i32 = null,
        user: User,
        capabilities: ?Capabilities = null,
        rlimits: ?[]const Rlimit = null,
    };

    pub const Capabilities = struct {
        bounding: ?[]const []const u8 = null,
        effective: ?[]const []const u8 = null,
        inheritable: ?[]const []const u8 = null,
        permitted: ?[]const []const u8 = null,
        ambient: ?[]const []const u8 = null,
    };

    pub const Rlimit = struct {
        type: []const u8,
        hard: u64,
        soft: u64,
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
        uidMappings: ?[]const IDMapping = null,
        gidMappings: ?[]const IDMapping = null,
    };

    pub const Linux = struct {
        namespaces: ?[]const Namespace = null,
        sysctl: ?std.json.ArrayHashMap([]const u8) = null,
        uidMappings: ?[]const IDMapping = null,
        gidMappings: ?[]const IDMapping = null,
        cgroupsPath: ?[]const u8 = null,
        resources: ?Resources = null,
        devices: ?[]const Device = null,
        maskedPaths: ?[]const []const u8 = null,
        readonlyPaths: ?[]const []const u8 = null,
        rootfsPropagation: ?Propagation = null,
        seccomp: ?Seccomp = null,
        timeOffsets: ?TimeOffsets = null,
    };

    pub const TimeOffsets = struct {
        monotonic: ?TimeOffset = null,
        boottime: ?TimeOffset = null,
    };
    pub const TimeOffset = struct { secs: i64 = 0, nanosecs: u32 = 0 };

    pub const Seccomp = struct {
        defaultAction: []const u8,
        defaultErrnoRet: ?u32 = null,
        architectures: ?[]const []const u8 = null,
        flags: ?[]const []const u8 = null,
        listenerPath: ?[]const u8 = null,
        listenerMetadata: ?[]const u8 = null,
        syscalls: ?[]const Syscall = null,

        pub const Syscall = struct {
            names: []const []const u8,
            action: []const u8,
            errnoRet: ?u32 = null,
            args: ?[]const Arg = null,
        };
        pub const Arg = struct { index: u32, value: u64, valueTwo: u64 = 0, op: []const u8 };
    };

    pub const Propagation = enum { shared, rshared, slave, rslave, private, rprivate, unbindable, runbindable };

    pub const Hook = struct {
        path: []const u8,
        args: ?[]const []const u8 = null,
        env: ?[]const []const u8 = null,
        timeout: ?u64 = null,
    };

    pub const Hooks = struct {
        prestart: ?[]const Hook = null,
        createRuntime: ?[]const Hook = null,
        createContainer: ?[]const Hook = null,
        startContainer: ?[]const Hook = null,
        poststart: ?[]const Hook = null,
        poststop: ?[]const Hook = null,
    };

    pub const Device = struct {
        path: []const u8,
        type: []const u8,
        major: ?i64 = null,
        minor: ?i64 = null,
        fileMode: ?u32 = null,
        uid: ?u32 = null,
        gid: ?u32 = null,
    };

    pub const Resources = struct {
        memory: ?Memory = null,
        cpu: ?Cpu = null,
        pids: ?Pids = null,
        blockIO: ?BlockIO = null,
        hugepageLimits: ?[]const HugepageLimit = null,
        network: ?Network = null,
        devices: ?[]const DeviceRule = null,
        unified: ?std.json.ArrayHashMap([]const u8) = null,

        pub const Memory = struct {
            limit: ?i64 = null,
            reservation: ?i64 = null,
            swap: ?i64 = null,
            kernel: ?i64 = null,
            kernelTCP: ?i64 = null,
            swappiness: ?u64 = null,
            disableOOMKiller: ?bool = null,
        };
        pub const Cpu = struct {
            quota: ?i64 = null,
            period: ?u64 = null,
            shares: ?u64 = null,
            realtimeRuntime: ?i64 = null,
            realtimePeriod: ?u64 = null,
            idle: ?i64 = null,
            cpus: ?[]const u8 = null,
            mems: ?[]const u8 = null,
        };
        pub const Pids = struct { limit: ?i64 = null };
        pub const BlockIO = struct {
            weight: ?u16 = null,
            leafWeight: ?u16 = null,
            weightDevice: ?[]const WeightDevice = null,
            throttleReadBpsDevice: ?[]const ThrottleDevice = null,
            throttleWriteBpsDevice: ?[]const ThrottleDevice = null,
            throttleReadIOPSDevice: ?[]const ThrottleDevice = null,
            throttleWriteIOPSDevice: ?[]const ThrottleDevice = null,
        };
        pub const WeightDevice = struct {
            major: i64,
            minor: i64,
            weight: ?u16 = null,
            leafWeight: ?u16 = null,
        };
        pub const ThrottleDevice = struct { major: i64, minor: i64, rate: u64 };
        pub const HugepageLimit = struct { pageSize: []const u8, limit: u64 };
        pub const Network = struct {
            classID: ?u32 = null,
            priorities: ?[]const Priority = null,
        };
        pub const Priority = struct { name: []const u8, priority: u32 };
        pub const DeviceRule = struct {
            allow: bool,
            type: []const u8 = "a",
            major: ?i64 = null,
            minor: ?i64 = null,
            access: []const u8 = "rwm",
        };
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

pub const json_size_limit: std.Io.Limit = .limited(1 << 20);

/// Loads <bundle>/config.json. The caller owns the result and must call deinit().
pub fn loadSpec(allocator: std.mem.Allocator, io: std.Io, bundle_dir: []const u8) !std.json.Parsed(Spec) {
    const path = try std.fs.path.join(allocator, &.{ bundle_dir, "config.json" });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, json_size_limit) catch |err| {
        if (err == error.StreamTooLong) recordDiagnostic(err, "config.json: exceeds 1 MiB", .{});
        return err;
    };
    defer allocator.free(json);
    const parsed = std.json.parseFromSlice(Spec, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        if (err != error.OutOfMemory) recordDiagnostic(err, "config.json: invalid JSON or schema ({s})", .{@errorName(err)});
        return err;
    };
    errdefer parsed.deinit();
    try validateHooks(parsed.value.hooks);
    return parsed;
}

/// Resolves root.path against an absolute bundle directory. The caller owns the path.
pub fn resolveRootfs(allocator: std.mem.Allocator, bundle_dir: []const u8, root_path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(bundle_dir)) return validationError(error.RelativeBundle, "bundle: must be absolute", .{});
    if (std.fs.path.isAbsolute(root_path)) return allocator.dupe(u8, root_path);
    return std.fs.path.join(allocator, &.{ bundle_dir, root_path });
}

test "loadSpec accepts version strings and create validates semantic version syntax" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const bundle = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(bundle);
    const cases = [_]struct { version: []const u8, accepted: bool }{
        .{ .version = "1.0.0", .accepted = true },
        .{ .version = "1.0.2", .accepted = true },
        .{ .version = "1.1.0", .accepted = true },
        .{ .version = "1.2.0", .accepted = true },
        .{ .version = "1.2.1", .accepted = true },
        .{ .version = "1.2.1+build", .accepted = true },
        .{ .version = "0.9.0", .accepted = true },
        .{ .version = "1.0.0-rc.1", .accepted = true },
        .{ .version = "1.2.2", .accepted = true },
        .{ .version = "1.3.0", .accepted = true },
        .{ .version = "2.0.0", .accepted = true },
        .{ .version = "9.9.9", .accepted = true },
        .{ .version = "invalid", .accepted = false },
    };
    for (cases) |case| {
        const spec: Spec = .{ .ociVersion = case.version, .root = .{ .path = "rootfs" } };
        const json = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false });
        defer allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "config.json", .data = json });
        const parsed = try loadSpec(allocator, std.testing.io, bundle);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(case.version, parsed.value.ociVersion);
        if (case.accepted) {
            try requireCreate(parsed.value);
        } else {
            try std.testing.expectError(error.InvalidConfig, requireCreate(parsed.value));
        }
    }
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
    try std.testing.expect(parsed.value.process.?.oomScoreAdj == null);
    try std.testing.expect(parsed.value.process.?.capabilities == null);
    try std.testing.expect(parsed.value.process.?.rlimits == null);
    try std.testing.expect(parsed.value.process.?.user.additionalGids == null);
    try std.testing.expect(parsed.value.hostname == null);
    try std.testing.expect(parsed.value.mounts == null);
    try std.testing.expect(parsed.value.linux == null);
    try std.testing.expect(parsed.value.annotations == null);
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
    const resources_path = try std.fs.path.join(std.testing.allocator, &.{ bundle, "config.json" });
    defer std.testing.allocator.free(resources_path);
    try std.testing.expectError(error.StreamTooLong, loadResources(std.testing.allocator, std.testing.io, resources_path));
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

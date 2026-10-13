const std = @import("std");

test "cgroup paths are relative to the mount root and reject escapes" {
    const cases = [_]struct { path: ?[]const u8, expected: []const u8 }{
        .{ .path = null, .expected = "igvano/example" },
        .{ .path = "/custom/example", .expected = "custom/example" },
        .{ .path = "custom/example", .expected = "custom/example" },
        .{ .path = "//custom/./nested/../example/", .expected = "custom/example" },
    };
    for (cases) |case| {
        const path = try resolveCgroupPath(std.testing.allocator, case.path, "example");
        defer std.testing.allocator.free(path);
        try std.testing.expectEqualStrings(case.expected, path);
    }
    for ([_][]const u8{ "", "/", ".", "..", "../outside", "/../outside", "a/../../outside", "a/..", "a\x00b" }) |path| {
        try std.testing.expectError(error.InvalidConfig, resolveCgroupPath(std.testing.allocator, path, "example"));
    }
    try std.testing.expectError(error.InvalidConfig, resolveCgroupPath(std.testing.allocator, null, "../outside"));
}

test "cpu shares map to cgroup2 weights without underflow or overflow" {
    const cases = [_]struct { shares: u64, weight: u64 }{
        .{ .shares = 0, .weight = 0 },
        .{ .shares = 2, .weight = 1 },
        .{ .shares = 1024, .weight = 39 },
        .{ .shares = 262144, .weight = 10000 },
    };
    for (cases) |case| try std.testing.expectEqual(case.weight, try cpuWeight(case.shares));
    for ([_]u64{ 1, 262145, std.math.maxInt(u64) }) |shares| {
        try std.testing.expectError(error.InvalidConfig, cpuWeight(shares));
    }
}

test "OCI resources parse and map to cgroup2 writes" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"cgroupsPath":"/custom/example","resources":{"memory":{"limit":67108864},"cpu":{"quota":50000,"period":100000,"shares":1024},"pids":{"limit":32},"devices":[]}}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/custom/example", parsed.value.cgroupsPath.?);
    const writes = try cgroupWrites(std.testing.allocator, parsed.value.resources);
    defer freeCgroupWrites(std.testing.allocator, writes);
    const expected = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "memory.max", .value = "67108864" },
        .{ .name = "cpu.max", .value = "50000 100000" },
        .{ .name = "cpu.weight", .value = "39" },
        .{ .name = "pids.max", .value = "32" },
    };
    try std.testing.expectEqual(expected.len, writes.len);
    for (expected, writes) |want, actual| {
        try std.testing.expectEqualStrings(want.name, actual.name);
        try std.testing.expectEqualStrings(want.value, actual.value);
    }
}

test "cgroup writes preserve unlimited values and CPU defaults" {
    const cases = [_]struct { json: []const u8, name: []const u8, value: []const u8 }{
        .{ .json = "{\"memory\":{\"limit\":-1}}", .name = "memory.max", .value = "max" },
        .{ .json = "{\"pids\":{\"limit\":-1}}", .name = "pids.max", .value = "max" },
        .{ .json = "{\"cpu\":{\"quota\":-1,\"period\":200000}}", .name = "cpu.max", .value = "max 200000" },
        .{ .json = "{\"cpu\":{\"period\":200000}}", .name = "cpu.max", .value = "max 200000" },
        .{ .json = "{\"cpu\":{\"quota\":50000}}", .name = "cpu.max", .value = "50000 100000" },
        .{ .json = "{\"cpu\":{\"quota\":0,\"period\":0}}", .name = "cpu.max", .value = "max 100000" },
    };
    for (cases) |case| {
        const parsed = try std.json.parseFromSlice(Spec.Resources, std.testing.allocator, case.json, .{});
        defer parsed.deinit();
        const writes = try cgroupWrites(std.testing.allocator, parsed.value);
        defer freeCgroupWrites(std.testing.allocator, writes);
        try std.testing.expectEqual(@as(usize, 1), writes.len);
        try std.testing.expectEqualStrings(case.name, writes[0].name);
        try std.testing.expectEqualStrings(case.value, writes[0].value);
    }
    for ([_]?Spec.Resources{
        null,
        .{},
        .{ .cpu = .{ .shares = 0 } },
        .{ .memory = .{} },
        .{ .memory = .{ .limit = 0 } },
        .{ .pids = .{ .limit = 0 } },
        .{ .memory = .{ .limit = 0 }, .pids = .{ .limit = 0 } },
    }) |resources| {
        const writes = try cgroupWrites(std.testing.allocator, resources);
        defer freeCgroupWrites(std.testing.allocator, writes);
        try std.testing.expectEqual(@as(usize, 0), writes.len);
    }
    for ([_]Spec.Resources{
        .{ .memory = .{ .limit = -2 } },
        .{ .pids = .{ .limit = -2 } },
        .{ .cpu = .{ .quota = -2 } },
        .{ .cpu = .{ .shares = 1 } },
        .{ .memory = .{ .limit = 64 }, .cpu = .{ .shares = 1 } },
    }) |resources| {
        try std.testing.expectError(error.InvalidConfig, cgroupWrites(std.testing.allocator, resources));
    }
}

test "zero memory and pids limits are unset without suppressing other resources" {
    const parsed = try std.json.parseFromSlice(Spec.Resources, std.testing.allocator,
        \\{"memory":{"limit":0},"pids":{"limit":0},"cpu":{"shares":1024}}
    , .{});
    defer parsed.deinit();
    const writes = try cgroupWrites(std.testing.allocator, parsed.value);
    defer freeCgroupWrites(std.testing.allocator, writes);
    try std.testing.expectEqual(@as(usize, 1), writes.len);
    try std.testing.expectEqualStrings("cpu.weight", writes[0].name);
    try std.testing.expectEqualStrings("39", writes[0].value);
}

test "bind mount recursive read-only options are explicit and ordered" {
    const cases = [_]struct { options: []const []const u8, recursive: ?bool }{
        .{ .options = &.{ "ro", "rbind" }, .recursive = null },
        .{ .options = &.{ "rbind", "rro" }, .recursive = true },
        .{ .options = &.{ "bind", "rrw" }, .recursive = false },
        .{ .options = &.{ "rbind", "rro", "rrw" }, .recursive = false },
        .{ .options = &.{ "rbind", "rrw", "rro" }, .recursive = true },
    };
    for (cases) |case| {
        const options = try parseMountOptions(std.testing.allocator, case.options, null);
        defer std.testing.allocator.free(options.data);
        try std.testing.expectEqual(case.recursive, options.recursive_readonly);
        try std.testing.expectEqualStrings("", options.data);
    }
}

test "cgroup resource mapping frees partially allocated writes on allocation failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const writes = try cgroupWrites(allocator, .{
                .memory = .{ .limit = 67108864 },
                .cpu = .{ .quota = 50000, .period = 100000, .shares = 1024 },
                .pids = .{ .limit = 32 },
            });
            defer freeCgroupWrites(allocator, writes);
            try std.testing.expectEqual(@as(usize, 4), writes.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

pub const state_file_name = "state.json";
pub const exec_fifo_name = "exec.fifo";
pub const starttime_file_name = "starttime";
pub const cgroup_file_name = "cgroup";
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
    };

    pub const Linux = struct {
        namespaces: ?[]const Namespace = null,
        uidMappings: ?[]const IDMapping = null,
        gidMappings: ?[]const IDMapping = null,
        cgroupsPath: ?[]const u8 = null,
        resources: ?Resources = null,
        devices: ?[]const Device = null,
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

        pub const Memory = struct { limit: ?i64 = null };
        pub const Cpu = struct {
            quota: ?i64 = null,
            period: ?u64 = null,
            shares: ?u64 = null,
        };
        pub const Pids = struct { limit: i64 };
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

/// Resolve absolute OCI paths relative to the cgroup mount, never the host root.
/// Root itself is forbidden, since delete must only remove a container cgroup.
pub fn resolveCgroupPath(allocator: std.mem.Allocator, configured: ?[]const u8, id: []const u8) ![]u8 {
    if (configured == null and (id.len == 0 or
        std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or
        std.mem.indexOfScalar(u8, id, 0) != null)) return error.InvalidConfig;
    const path = if (configured) |value|
        try std.fmt.allocPrint(allocator, "/{s}", .{value})
    else
        try std.fmt.allocPrint(allocator, "/igvano/{s}", .{id});
    defer allocator.free(path);
    const normalized = try resolveMountDestination(allocator, path);
    defer allocator.free(normalized);
    if (normalized.len == 1) return error.InvalidConfig;
    return allocator.dupe(u8, normalized[1..]);
}

/// Zero shares means unset; the remaining OCI range maps to [1, 10000].
pub fn cpuWeight(shares: u64) !u64 {
    if (shares == 0) return 0;
    if (shares < 2 or shares > 262144) return error.InvalidConfig;
    return 1 + ((shares - 2) * 9999) / 262142;
}

const Backend = @import("backend.zig").Backend;
const CgroupWrite = Backend.CgroupWrite;

const default_devices = [_]Backend.Device{
    .{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3, .required = false },
    .{ .path = "/dev/zero", .kind = .character, .major = 1, .minor = 5, .required = false },
    .{ .path = "/dev/full", .kind = .character, .major = 1, .minor = 7, .required = false },
    .{ .path = "/dev/random", .kind = .character, .major = 1, .minor = 8, .required = false },
    .{ .path = "/dev/urandom", .kind = .character, .major = 1, .minor = 9, .required = false },
    .{ .path = "/dev/tty", .kind = .character, .major = 5, .minor = 0, .required = false },
};

/// Configured devices take precedence over defaults. Paths are owned by the result.
pub fn prepareDevices(allocator: std.mem.Allocator, configured: ?[]const Spec.Device) ![]Backend.Device {
    var devices: std.ArrayList(Backend.Device) = .empty;
    errdefer {
        for (devices.items) |device| allocator.free(device.path);
        devices.deinit(allocator);
    }
    for (configured orelse &.{}) |device| {
        const kind: Backend.Device.Kind = if (std.mem.eql(u8, device.type, "c") or std.mem.eql(u8, device.type, "u"))
            .character
        else if (std.mem.eql(u8, device.type, "b"))
            .block
        else if (std.mem.eql(u8, device.type, "p"))
            .fifo
        else
            return error.InvalidConfig;
        const major = device.major orelse if (kind == .fifo) 0 else return error.InvalidConfig;
        const minor = device.minor orelse if (kind == .fifo) 0 else return error.InvalidConfig;
        // Linux mknod encodes 12 major bits and 20 minor bits.
        if (major < 0 or major > 0xfff or minor < 0 or minor > 0xfffff)
            return error.InvalidConfig;
        const mode = device.fileMode orelse 0o666;
        const uid = device.uid orelse 0;
        const gid = device.gid orelse 0;
        if (mode & ~@as(u32, 0o7777) != 0 or
            uid == std.math.maxInt(u32) or gid == std.math.maxInt(u32))
            return error.InvalidConfig;
        const path = try resolveMountDestination(allocator, device.path);
        errdefer allocator.free(path);
        if (path.len == 1) return error.InvalidConfig;
        for (devices.items) |previous| {
            if (std.mem.eql(u8, previous.path, path)) return error.InvalidConfig;
        }
        try devices.append(allocator, .{
            .path = path,
            .kind = kind,
            .major = @intCast(major),
            .minor = @intCast(minor),
            .mode = mode,
            .uid = uid,
            .gid = gid,
        });
    }
    for (default_devices) |device| {
        for (devices.items) |existing| {
            if (std.mem.eql(u8, existing.path, device.path)) break;
        } else {
            const path = try allocator.dupe(u8, device.path);
            errdefer allocator.free(path);
            var prepared = device;
            prepared.path = path;
            try devices.append(allocator, prepared);
        }
    }
    return devices.toOwnedSlice(allocator);
}

pub fn freeDevices(allocator: std.mem.Allocator, devices: []const Backend.Device) void {
    for (devices) |device| allocator.free(device.path);
    allocator.free(devices);
}

const default_device_symlinks = [_]Backend.Symlink{
    .{ .path = "/dev/fd", .target = "/proc/self/fd" },
    .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
    .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
    .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
    .{ .path = "/dev/ptmx", .target = "pts/ptmx" },
};

pub fn deviceSymlinks(mounts: []const Backend.Mount) []const Backend.Symlink {
    for (mounts) |mount| {
        if (std.mem.eql(u8, mount.destination, "/dev/pts") and
            mount.flags & std.os.linux.MS.BIND == 0 and
            std.mem.eql(u8, mount.type orelse "", "devpts"))
            return &default_device_symlinks;
    }
    return default_device_symlinks[0..4];
}

test "linux devices parse all types and default permissions and ownership" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"devices":[{"path":"/dev/custom","type":"c","major":1,"minor":3},{"path":"/disk","type":"b","major":8,"minor":0,"fileMode":416,"uid":1000,"gid":1001},{"path":"/dev/alias","type":"u","major":1,"minor":5,"fileMode":0},{"path":"/run/pipe","type":"p"}]}
    , .{});
    defer parsed.deinit();
    const devices = try prepareDevices(std.testing.allocator, parsed.value.devices);
    defer freeDevices(std.testing.allocator, devices);
    try std.testing.expectEqual(@as(usize, 10), devices.len);
    try std.testing.expectEqual(Backend.Device.Kind.character, devices[0].kind);
    try std.testing.expectEqual(@as(u32, 0o666), devices[0].mode);
    try std.testing.expectEqual(@as(u32, 0), devices[0].uid);
    try std.testing.expectEqual(@as(u32, 0), devices[0].gid);
    try std.testing.expectEqual(Backend.Device.Kind.block, devices[1].kind);
    try std.testing.expectEqualStrings("/disk", devices[1].path);
    try std.testing.expectEqual(@as(u32, 0o640), devices[1].mode);
    try std.testing.expectEqual(@as(u32, 1000), devices[1].uid);
    try std.testing.expectEqual(@as(u32, 1001), devices[1].gid);
    try std.testing.expectEqual(Backend.Device.Kind.character, devices[2].kind);
    try std.testing.expectEqual(@as(u32, 0), devices[2].mode);
    try std.testing.expectEqual(Backend.Device.Kind.fifo, devices[3].kind);
    try std.testing.expectEqual(@as(u32, 0), devices[3].major);
    try std.testing.expectEqual(@as(u32, 0), devices[3].minor);
}

test "linux devices reject invalid types paths numbers and duplicates" {
    const cases = [_][]const u8{
        \\[{"path":"/dev/custom","type":"a","major":1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"","major":1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"char","major":1,"minor":3}]
        ,
        \\[{"path":"dev/custom","type":"c","major":1,"minor":3}]
        ,
        \\[{"path":"","type":"p"}]
        ,
        \\[{"path":"/","type":"p"}]
        ,
        \\[{"path":"/../outside","type":"p"}]
        ,
        \\[{"path":"/dev/custom\u0000","type":"p"}]
        ,
        \\[{"path":"/dev/custom","type":"c","minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"b","major":8}]
        ,
        \\[{"path":"/dev/custom","type":"u","major":-1,"minor":3}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":1,"minor":-1}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":4096,"minor":0}]
        ,
        \\[{"path":"/dev/custom","type":"c","major":1,"minor":1048576}]
        ,
        \\[{"path":"/dev/custom","type":"p","fileMode":4096}]
        ,
        \\[{"path":"/dev/custom","type":"p","uid":4294967295}]
        ,
        \\[{"path":"/dev/custom","type":"p","gid":4294967295}]
        ,
        \\[{"path":"/dev/custom","type":"p"},{"path":"/dev/custom","type":"p"}]
        ,
        \\[{"path":"/dev/custom","type":"p"},{"path":"/dev/./custom","type":"p"}]
        ,
    };
    for (cases) |json| {
        const parsed = try std.json.parseFromSlice([]const Spec.Device, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidConfig, prepareDevices(std.testing.allocator, parsed.value));
    }
}

test "linux configured devices override default paths and preserve other defaults" {
    const devices = try prepareDevices(std.testing.allocator, &.{.{
        .path = "//dev/./null",
        .type = "u",
        .major = 1,
        .minor = 3,
        .fileMode = 0o600,
        .uid = 123,
        .gid = 456,
    }});
    defer freeDevices(std.testing.allocator, devices);
    try std.testing.expectEqual(@as(usize, 6), devices.len);
    try std.testing.expectEqualStrings("/dev/null", devices[0].path);
    try std.testing.expectEqual(@as(u32, 0o600), devices[0].mode);
    try std.testing.expectEqual(@as(u32, 123), devices[0].uid);
    try std.testing.expectEqual(@as(u32, 456), devices[0].gid);
    try std.testing.expect(devices[0].required);
    for (devices[1..]) |device| try std.testing.expect(!device.required);
    const defaults = try prepareDevices(std.testing.allocator, null);
    defer freeDevices(std.testing.allocator, defaults);
    const expected = [_]struct { path: []const u8, major: u32, minor: u32 }{
        .{ .path = "/dev/null", .major = 1, .minor = 3 },
        .{ .path = "/dev/zero", .major = 1, .minor = 5 },
        .{ .path = "/dev/full", .major = 1, .minor = 7 },
        .{ .path = "/dev/random", .major = 1, .minor = 8 },
        .{ .path = "/dev/urandom", .major = 1, .minor = 9 },
        .{ .path = "/dev/tty", .major = 5, .minor = 0 },
    };
    try std.testing.expectEqual(expected.len, defaults.len);
    for (expected, defaults) |want, actual| {
        try std.testing.expectEqualStrings(want.path, actual.path);
        try std.testing.expectEqual(want.major, actual.major);
        try std.testing.expectEqual(want.minor, actual.minor);
        try std.testing.expectEqual(Backend.Device.Kind.character, actual.kind);
        try std.testing.expectEqual(@as(u32, 0o666), actual.mode);
        try std.testing.expectEqual(@as(u32, 0), actual.uid);
        try std.testing.expectEqual(@as(u32, 0), actual.gid);
        try std.testing.expect(!actual.required);
    }
}

test "default device symlinks include ptmx only for a devpts mount" {
    const expected = [_]Backend.Symlink{
        .{ .path = "/dev/fd", .target = "/proc/self/fd" },
        .{ .path = "/dev/stdin", .target = "/proc/self/fd/0" },
        .{ .path = "/dev/stdout", .target = "/proc/self/fd/1" },
        .{ .path = "/dev/stderr", .target = "/proc/self/fd/2" },
        .{ .path = "/dev/ptmx", .target = "pts/ptmx" },
    };
    for ([_][]const Backend.Mount{
        &.{},
        &.{.{ .destination = "/dev/pts", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" }},
        &.{.{ .destination = "/elsewhere", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }},
        &.{.{ .destination = "/dev/pts", .source = "/dev/pts", .type = "devpts", .flags = std.os.linux.MS.BIND, .propagation = 0, .data = "" }},
    }) |mounts| {
        const links = deviceSymlinks(mounts);
        try std.testing.expectEqual(@as(usize, 4), links.len);
        for (expected[0..4], links) |want, actual| {
            try std.testing.expectEqualStrings(want.path, actual.path);
            try std.testing.expectEqualStrings(want.target, actual.target);
        }
    }
    const links = deviceSymlinks(&.{.{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }});
    try std.testing.expectEqual(@as(usize, 5), links.len);
    for (expected, links) |want, actual| {
        try std.testing.expectEqualStrings(want.path, actual.path);
        try std.testing.expectEqualStrings(want.target, actual.target);
    }
}

test "device preparation frees paths on allocation failure including default overrides" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const devices = try prepareDevices(allocator, &.{
                .{ .path = "/dev/null", .type = "c", .major = 1, .minor = 3 },
                .{ .path = "/run/pipe", .type = "p" },
            });
            defer freeDevices(allocator, devices);
            try std.testing.expectEqual(@as(usize, 7), devices.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

/// Null means a well-formed CAP_* name unknown to our table, possibly a newer cap.
/// Linux constants are available on every build host; no syscalls are made.
pub fn capabilityNumber(name: []const u8) error{InvalidConfig}!?u6 {
    if (!std.mem.startsWith(u8, name, "CAP_") or name.len == 4) return error.InvalidConfig;
    for (name[4..]) |c| {
        if (!std.ascii.isUpper(c) and !std.ascii.isDigit(c) and c != '_') return error.InvalidConfig;
    }
    inline for (comptime std.meta.declarations(std.os.linux.CAP)) |decl| {
        if (comptime !std.mem.eql(u8, decl.name, "LAST_CAP") and
            @TypeOf(@field(std.os.linux.CAP, decl.name)) == comptime_int)
        {
            if (std.mem.eql(u8, name, "CAP_" ++ decl.name))
                return @intCast(@field(std.os.linux.CAP, decl.name));
        }
    }
    return null;
}

pub fn rlimitResource(name: []const u8) error{InvalidConfig}!std.os.linux.rlimit_resource {
    if (!std.mem.startsWith(u8, name, "RLIMIT_")) return error.InvalidConfig;
    return std.meta.stringToEnum(std.os.linux.rlimit_resource, name["RLIMIT_".len..]) orelse error.InvalidConfig;
}

pub fn processCapabilities(config: Spec.Capabilities) !Backend.Capabilities {
    var result: Backend.Capabilities = .{};
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
        for (@field(config, field.name) orelse &.{}) |name| {
            const number = try capabilityNumber(name) orelse {
                // OCI 1.1 says runtimes SHOULD NOT fail on unknown capabilities.
                std.debug.print("igvano: warning: ignoring unknown capability {s}\n", .{name});
                continue;
            };
            @field(result, field.name) |= @as(u64, 1) << number;
        }
    }
    if (result.ambient & ~(result.permitted & result.inheritable) != 0)
        return error.AmbientCapabilitiesRequirePermittedAndInheritable;
    return result;
}

pub fn processRlimits(allocator: std.mem.Allocator, config: ?[]const Spec.Rlimit) ![]Backend.Rlimit {
    const limits = config orelse &.{};
    const result = try allocator.alloc(Backend.Rlimit, limits.len);
    errdefer allocator.free(result);
    for (limits, result, 0..) |limit, *prepared, i| {
        if (limit.soft > limit.hard) return error.InvalidConfig;
        const resource = try rlimitResource(limit.type);
        for (result[0..i]) |previous| {
            if (previous.resource == resource) return error.InvalidConfig;
        }
        prepared.* = .{
            .resource = resource,
            .hard = limit.hard,
            .soft = limit.soft,
        };
    }
    return result;
}

test "capability names map the complete Linux set and reject malformed names" {
    const names = [_][]const u8{
        "CAP_CHOWN",           "CAP_DAC_OVERRIDE",       "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",          "CAP_FSETID",             "CAP_KILL",
        "CAP_SETGID",          "CAP_SETUID",             "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE",   "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",       "CAP_NET_RAW",            "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",       "CAP_SYS_MODULE",         "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",      "CAP_SYS_PTRACE",         "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",       "CAP_SYS_BOOT",           "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",    "CAP_SYS_TIME",           "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",           "CAP_LEASE",              "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",   "CAP_SETFCAP",            "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",       "CAP_SYSLOG",             "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",   "CAP_AUDIT_READ",         "CAP_PERFMON",
        "CAP_BPF",             "CAP_CHECKPOINT_RESTORE",
    };
    for (names, 0..) |name, number|
        try std.testing.expectEqual(@as(?u6, @intCast(number)), try capabilityNumber(name));
    for ([_][]const u8{ "", "CHOWN", "cap_chown", "CAP_", "CAP_chown", "CAP_CHOWN\x00", "CAP_CHOWN!" }) |name|
        try std.testing.expectError(error.InvalidConfig, capabilityNumber(name));
    try std.testing.expectEqual(@as(?u6, null), try capabilityNumber("CAP_FUTURE"));
}

test "rlimit names map every Linux resource and reject unknown names" {
    const cases = .{
        .{ "RLIMIT_CPU", .CPU },           .{ "RLIMIT_FSIZE", .FSIZE },
        .{ "RLIMIT_DATA", .DATA },         .{ "RLIMIT_STACK", .STACK },
        .{ "RLIMIT_CORE", .CORE },         .{ "RLIMIT_RSS", .RSS },
        .{ "RLIMIT_NPROC", .NPROC },       .{ "RLIMIT_NOFILE", .NOFILE },
        .{ "RLIMIT_MEMLOCK", .MEMLOCK },   .{ "RLIMIT_AS", .AS },
        .{ "RLIMIT_LOCKS", .LOCKS },       .{ "RLIMIT_SIGPENDING", .SIGPENDING },
        .{ "RLIMIT_MSGQUEUE", .MSGQUEUE }, .{ "RLIMIT_NICE", .NICE },
        .{ "RLIMIT_RTPRIO", .RTPRIO },     .{ "RLIMIT_RTTIME", .RTTIME },
    };
    inline for (cases) |case|
        try std.testing.expectEqual(@as(std.os.linux.rlimit_resource, case[1]), try rlimitResource(case[0]));
    for ([_][]const u8{ "", "NOFILE", "rlimit_nofile", "RLIMIT_UNKNOWN", "RLIMIT_", "RLIMIT_NOFILE\x00" }) |name|
        try std.testing.expectError(error.InvalidConfig, rlimitResource(name));
}

test "ambient capabilities require membership in both permitted and inheritable" {
    const cap: u64 = @as(u64, 1) << std.os.linux.CAP.NET_BIND_SERVICE;
    const valid = try processCapabilities(.{
        .bounding = &.{"CAP_NET_BIND_SERVICE"},
        .effective = &.{"CAP_NET_BIND_SERVICE"},
        .permitted = &.{"CAP_NET_BIND_SERVICE"},
        .inheritable = &.{"CAP_NET_BIND_SERVICE"},
        .ambient = &.{"CAP_NET_BIND_SERVICE"},
    });
    try std.testing.expectEqual(Backend.Capabilities{
        .bounding = cap,
        .effective = cap,
        .permitted = cap,
        .inheritable = cap,
        .ambient = cap,
    }, valid);
    try std.testing.expectEqual(Backend.Capabilities{}, try processCapabilities(.{}));
    for ([_]Spec.Capabilities{
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .permitted = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .inheritable = &.{"CAP_NET_BIND_SERVICE"} },
        .{ .ambient = &.{"CAP_NET_BIND_SERVICE"}, .permitted = &.{"CAP_NET_BIND_SERVICE"}, .inheritable = &.{"CAP_CHOWN"} },
    }) |config| {
        try std.testing.expectError(error.AmbientCapabilitiesRequirePermittedAndInheritable, processCapabilities(config));
    }
    inline for (std.meta.fields(Spec.Capabilities)) |field| {
        var config: Spec.Capabilities = .{};
        @field(config, field.name) = &.{"not-a-capability"};
        try std.testing.expectError(error.InvalidConfig, processCapabilities(config));
    }
    const upper = try processCapabilities(.{ .bounding = &.{ "CAP_CHECKPOINT_RESTORE", "CAP_CHECKPOINT_RESTORE" } });
    try std.testing.expectEqual(@as(u64, 1) << 40, upper.bounding);
}

test "process capabilities skip well formed names unknown to the capability table" {
    const caps = try processCapabilities(.{
        .bounding = &.{ "CAP_CHOWN", "CAP_FUTURE" },
        .ambient = &.{"CAP_FUTURE"},
    });
    try std.testing.expectEqual(Backend.Capabilities{ .bounding = 1 }, caps);
}

test "process parses capabilities rlimits and supplementary groups" {
    const parsed = try std.json.parseFromSlice(Spec.Process, std.testing.allocator,
        \\{"args":["/bin/sh"],"cwd":"/","user":{"uid":1000,"gid":1001,"additionalGids":[1002,1003]},"capabilities":{"bounding":["CAP_CHOWN"],"effective":[],"permitted":["CAP_CHOWN"],"inheritable":[],"ambient":[]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":512},{"type":"RLIMIT_CORE","hard":18446744073709551615,"soft":0}]}
    , .{});
    defer parsed.deinit();
    const process = parsed.value;
    try std.testing.expectEqualSlices(u32, &.{ 1002, 1003 }, process.user.additionalGids.?);
    const caps = try processCapabilities(process.capabilities.?);
    try std.testing.expectEqual(@as(u64, 1), caps.bounding);
    try std.testing.expectEqual(@as(u64, 1), caps.permitted);
    try std.testing.expectEqual(@as(u64, 0), caps.effective);
    const limits = try processRlimits(std.testing.allocator, process.rlimits);
    defer std.testing.allocator.free(limits);
    try std.testing.expectEqual(@as(usize, 2), limits.len);
    try std.testing.expectEqual(Backend.Rlimit{ .resource = .NOFILE, .hard = 1024, .soft = 512 }, limits[0]);
    try std.testing.expectEqual(Backend.Rlimit{ .resource = .CORE, .hard = std.math.maxInt(u64), .soft = 0 }, limits[1]);
}

test "rlimit preparation rejects invalid names inverted limits and duplicates without leaking" {
    for ([_]Spec.Rlimit{
        .{ .type = "RLIMIT_UNKNOWN", .hard = 1024, .soft = 512 },
        .{ .type = "RLIMIT_NOFILE", .hard = 512, .soft = 1024 },
        .{ .type = "RLIMIT_NOFILE", .hard = 2048, .soft = 1024 },
    }) |invalid| {
        try std.testing.expectError(error.InvalidConfig, processRlimits(std.testing.allocator, &.{
            .{ .type = "RLIMIT_NOFILE", .hard = 1024, .soft = 512 },
            invalid,
        }));
    }
    const omitted = try processRlimits(std.testing.allocator, null);
    defer std.testing.allocator.free(omitted);
    try std.testing.expectEqual(@as(usize, 0), omitted.len);
}

/// The caller owns the slice and each value; filenames are static strings.
pub fn cgroupWrites(allocator: std.mem.Allocator, resources: ?Spec.Resources) ![]CgroupWrite {
    var writes: std.ArrayList(CgroupWrite) = .empty;
    defer writes.deinit(allocator);
    errdefer for (writes.items) |write| allocator.free(write.value);
    if (resources) |settings| {
        if (settings.memory) |memory| {
            if (memory.limit) |limit| {
                if (limit != 0)
                    try appendCgroupWrite(allocator, &writes, "memory.max", try cgroupLimit(allocator, limit));
            }
        }
        if (settings.cpu) |cpu| {
            const quota = cpu.quota orelse -1;
            if (quota < -1) return error.InvalidConfig;
            const period = if ((cpu.period orelse 0) == 0) 100000 else cpu.period.?;
            if (cpu.quota != null or cpu.period != null) {
                const value = if (quota <= 0)
                    try std.fmt.allocPrint(allocator, "max {d}", .{period})
                else
                    try std.fmt.allocPrint(allocator, "{d} {d}", .{ quota, period });
                try appendCgroupWrite(allocator, &writes, "cpu.max", value);
            }
            if (cpu.shares) |shares| {
                const weight = try cpuWeight(shares);
                if (weight != 0)
                    try appendCgroupWrite(allocator, &writes, "cpu.weight", try std.fmt.allocPrint(allocator, "{d}", .{weight}));
            }
        }
        if (settings.pids) |pids| {
            if (pids.limit != 0)
                try appendCgroupWrite(allocator, &writes, "pids.max", try cgroupLimit(allocator, pids.limit));
        }
    }
    return writes.toOwnedSlice(allocator);
}

fn cgroupLimit(allocator: std.mem.Allocator, limit: i64) ![]u8 {
    if (limit < -1) return error.InvalidConfig;
    if (limit == -1) return allocator.dupe(u8, "max");
    return std.fmt.allocPrint(allocator, "{d}", .{limit});
}

fn appendCgroupWrite(allocator: std.mem.Allocator, writes: *std.ArrayList(CgroupWrite), name: []const u8, value: []u8) !void {
    errdefer allocator.free(value);
    try writes.append(allocator, .{ .name = name, .value = value });
}

pub fn freeCgroupWrites(allocator: std.mem.Allocator, writes: []const CgroupWrite) void {
    for (writes) |write| allocator.free(write.value);
    allocator.free(writes);
}

/// Linux mount constants are available on every build host; this performs no I/O.
/// The caller owns data, including when there are no filesystem-specific options.
pub const MountOptions = struct {
    flags: u32,
    propagation: u32,
    data: [:0]u8,
    recursive_readonly: ?bool = null,
};

pub fn parseMountOptions(allocator: std.mem.Allocator, options: []const []const u8, mount_type: ?[]const u8) !MountOptions {
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
    var flags: u32 = if (mount_type != null and std.mem.eql(u8, mount_type.?, "bind")) ms.BIND else 0;
    var propagation: u32 = 0;
    var recursive_readonly: ?bool = null;
    var has_unknown_option = false;
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    option: for (options) |option| {
        if (std.mem.indexOfScalar(u8, option, 0) != null) return error.InvalidConfig;
        if (std.mem.eql(u8, option, "rro") or std.mem.eql(u8, option, "rrw")) {
            recursive_readonly = std.mem.eql(u8, option, "rro");
            continue;
        }
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
        has_unknown_option = true;
        if (data.items.len != 0) try data.append(allocator, ',');
        try data.appendSlice(allocator, option);
    }
    // Bind mounts ignore filesystem data, so unknown options cannot be honored.
    if (flags & ms.BIND != 0 and has_unknown_option) return error.InvalidConfig;
    return .{
        .flags = flags,
        .propagation = propagation,
        .data = try data.toOwnedSliceSentinel(allocator, 0),
        .recursive_readonly = recursive_readonly,
    };
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

/// Map ranges are half-open; widen before adding to avoid wrapping u32 IDs.
pub fn validateIDMappings(mappings: []const Spec.IDMapping) error{InvalidConfig}!void {
    if (mappings.len == 0 or mappings.len > 340) return error.InvalidConfig;
    var text_size: usize = 0;
    for (mappings, 0..) |mapping, i| {
        const end = @as(u64, mapping.containerID) + mapping.size;
        const host_end = @as(u64, mapping.hostID) + mapping.size;
        // Linux reserves (uid_t)-1 and (gid_t)-1 as unmapped IDs.
        if (mapping.size == 0 or end > std.math.maxInt(u32) or host_end > std.math.maxInt(u32))
            return error.InvalidConfig;
        text_size += std.fmt.count("{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
        if (text_size >= 4096) return error.InvalidConfig; // Linux requires a write smaller than one page.
        for (mappings[0..i]) |previous| {
            const previous_end = @as(u64, previous.containerID) + previous.size;
            const previous_host_end = @as(u64, previous.hostID) + previous.size;
            if ((mapping.containerID < previous_end and previous.containerID < end) or
                (mapping.hostID < previous_host_end and previous.hostID < host_end))
                return error.InvalidConfig;
        }
    }
}

/// Rootfs isolation always needs a mount namespace, even with an empty mount list.
pub fn requireCreate(spec: Spec) !void {
    _ = std.SemanticVersion.parse(spec.ociVersion) catch return error.InvalidConfig;
    const settings = spec.linux orelse return error.MissingMountNamespace;
    const uid_mappings: []const Spec.IDMapping = settings.uidMappings orelse &.{};
    const gid_mappings: []const Spec.IDMapping = settings.gidMappings orelse &.{};
    const namespaces = settings.namespaces orelse &.{};
    var has_mount = false;
    var has_user = false;
    for (namespaces) |namespace| {
        if (namespace.type == .mount) has_mount = true;
        if (namespace.type == .user) {
            if (namespace.path != null) return error.Unsupported;
            has_user = true;
        }
    }
    if (has_user) {
        for ([_][]const Spec.IDMapping{ uid_mappings, gid_mappings }) |mappings| {
            try validateIDMappings(mappings);
            // OCI does not require a root mapping; our init, like runc, needs one.
            for (mappings) |mapping| {
                if (mapping.containerID == 0) break;
            } else return error.InvalidConfig;
        }
    } else if (uid_mappings.len > 0 or gid_mappings.len > 0) {
        return error.InvalidConfig;
    }
    if (!has_mount) return error.MissingMountNamespace;
    if (spec.root.path.len == 0) return error.InvalidConfig;
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
        const result = try parseMountOptions(std.testing.allocator, case.options, null);
        defer std.testing.allocator.free(result.data);
        try std.testing.expectEqual(case.flags, result.flags);
        try std.testing.expectEqual(case.propagation, result.propagation);
        try std.testing.expectEqualStrings(case.data, result.data);
    }
    try std.testing.expectError(error.InvalidConfig, parseMountOptions(std.testing.allocator, &.{"mode=7\x0055"}, null));
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

test "bind mounts reject unknown options regardless of option order" {
    const cases = [_][]const []const u8{
        &.{ "bind", "custom" },
        &.{ "custom", "bind" },
        &.{ "rbind", "size=65536k", "ro" },
        &.{ "mode=755", "rbind", "rprivate" },
        &.{ "bind", "" },
    };
    for (cases) |options| {
        try std.testing.expectError(error.InvalidConfig, parseMountOptions(std.testing.allocator, options, null));
    }
    try std.testing.expectError(error.InvalidConfig, parseMountOptions(std.testing.allocator, &.{"custom"}, "bind"));
    const bind = try parseMountOptions(std.testing.allocator, &.{ "ro", "rprivate" }, "bind");
    defer std.testing.allocator.free(bind.data);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.BIND | std.os.linux.MS.RDONLY), bind.flags);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.PRIVATE | std.os.linux.MS.REC), bind.propagation);
}

test "create validation requires mount isolation with or without mounts" {
    var spec: Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" } };
    try std.testing.expectError(error.MissingMountNamespace, requireCreate(spec));
    spec.linux = .{};
    try std.testing.expectError(error.MissingMountNamespace, requireCreate(spec));
    spec.linux = .{ .namespaces = &.{.{ .type = .pid }} };
    spec.mounts = &.{.{ .destination = "/proc", .type = "proc" }};
    try std.testing.expectError(error.MissingMountNamespace, requireCreate(spec));
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

test "create accepts user namespaces with UID and GID mappings and rejects joins" {
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
    try std.testing.expectError(error.Unsupported, requireCreate(spec));
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

test "mapping validation rejects empty zero sized overlapping and oversized maps" {
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&.{}));
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&.{.{ .containerID = 0, .hostID = 1000, .size = 0 }}));
    for ([_][]const Spec.IDMapping{
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 9, .hostID = 2000, .size = 2 } },
        &.{ .{ .containerID = 9, .hostID = 2000, .size = 2 }, .{ .containerID = 0, .hostID = 1000, .size = 10 } },
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 2, .hostID = 2000, .size = 1 } },
        &.{.{ .containerID = std.math.maxInt(u32) - 1, .hostID = 0, .size = 3 }},
        &.{.{ .containerID = 0, .hostID = std.math.maxInt(u32) - 1, .size = 3 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, validateIDMappings(mappings));
    }
    var mappings: [341]Spec.IDMapping = undefined;
    for (&mappings, 0..) |*mapping, i| {
        mapping.* = .{ .containerID = @intCast(i), .hostID = @intCast(1000 + i), .size = 1 };
    }
    try validateIDMappings(mappings[0..340]);
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
    try validateIDMappings(&.{
        .{ .containerID = 10, .hostID = 2000, .size = 2 },
        .{ .containerID = 0, .hostID = 1000, .size = 10 },
    });
}

test "mapping validation rejects overlapping host ranges in either order" {
    for ([_][]const Spec.IDMapping{
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 10, .hostID = 1009, .size = 2 } },
        &.{ .{ .containerID = 10, .hostID = 1009, .size = 2 }, .{ .containerID = 0, .hostID = 1000, .size = 10 } },
        &.{ .{ .containerID = 0, .hostID = 1000, .size = 10 }, .{ .containerID = 20, .hostID = 1002, .size = 1 } },
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, validateIDMappings(mappings));
    }
    try validateIDMappings(&.{
        .{ .containerID = 10, .hostID = 1010, .size = 2 },
        .{ .containerID = 0, .hostID = 1000, .size = 10 },
    });
}

test "mapping validation requires formatted text smaller than 4096 bytes" {
    var mappings: [171]Spec.IDMapping = undefined;
    for (&mappings, 0..) |*mapping, i| {
        // Each line is 24 bytes; 170 lines fit, but 171 exceed the limit.
        mapping.* = .{ .containerID = @intCast(1000000000 + i), .hostID = @intCast(2000000000 + i), .size = 1 };
    }
    try validateIDMappings(mappings[0..170]);
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
    // The final line brings the total to 4095 bytes, then exactly 4096.
    mappings[170] = .{ .containerID = 0, .hostID = 1000000000, .size = 1 };
    try validateIDMappings(&mappings);
    mappings[170].containerID = 10;
    try std.testing.expectError(error.InvalidConfig, validateIDMappings(&mappings));
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
    try std.testing.expect(parsed.value.process.?.capabilities == null);
    try std.testing.expect(parsed.value.process.?.rlimits == null);
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

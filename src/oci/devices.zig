const std = @import("std");
const Backend = @import("libcontainer").Backend;
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const diagnosticContext = @import("diagnostic.zig").diagnosticContext;
const Spec = @import("spec.zig").Spec;
const resolveMountDestination = @import("mounts.zig").resolveMountDestination;

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
    for (configured orelse &.{}, 0..) |device, i| {
        const prepared = try prepareDevice(allocator, device, i, devices.items);
        errdefer allocator.free(prepared.path);
        try devices.append(allocator, prepared);
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

fn deviceKind(device: Spec.Device, i: usize) !Backend.Device.Kind {
    return if (std.mem.eql(u8, device.type, "c") or std.mem.eql(u8, device.type, "u"))
        .character
    else if (std.mem.eql(u8, device.type, "b"))
        .block
    else if (std.mem.eql(u8, device.type, "p"))
        .fifo
    else
        return invalidConfig("linux.devices[{d}].type: expected c, u, b or p", .{i});
}

fn deviceNumbers(device: Spec.Device, kind: Backend.Device.Kind, i: usize) !struct { major: u32, minor: u32 } {
    const major = device.major orelse if (kind == .fifo) 0 else return invalidConfig("linux.devices[{d}].major: required", .{i});
    const minor = device.minor orelse if (kind == .fifo) 0 else return invalidConfig("linux.devices[{d}].minor: required", .{i});
    // Linux mknod encodes 12 major bits and 20 minor bits.
    if (major < 0 or major > 0xfff or minor < 0 or minor > 0xfffff)
        return invalidConfig("linux.devices[{d}]: major or minor exceeds Linux device range", .{i});
    return .{ .major = @intCast(major), .minor = @intCast(minor) };
}

fn prepareDevice(allocator: std.mem.Allocator, device: Spec.Device, i: usize, previous_devices: []const Backend.Device) !Backend.Device {
    const kind = try deviceKind(device, i);
    const numbers = try deviceNumbers(device, kind, i);
    const mode = device.fileMode orelse 0o666;
    const uid = device.uid orelse 0;
    const gid = device.gid orelse 0;
    if (mode & ~@as(u32, 0o7777) != 0 or
        uid == std.math.maxInt(u32) or gid == std.math.maxInt(u32))
        return invalidConfig("linux.devices[{d}]: invalid fileMode, uid or gid", .{i});
    const path = resolveMountDestination(allocator, device.path) catch |err| {
        diagnosticContext("linux.devices[{d}].path", .{i});
        return err;
    };
    errdefer allocator.free(path);
    if (path.len == 1) return invalidConfig("linux.devices[{d}].path: must not be /", .{i});
    for (previous_devices) |previous| {
        if (std.mem.eql(u8, previous.path, path)) return invalidConfig("linux.devices[{d}].path: duplicate {s}", .{ i, path });
    }
    return .{
        .path = path,
        .kind = kind,
        .major = numbers.major,
        .minor = numbers.minor,
        .mode = mode,
        .uid = uid,
        .gid = gid,
    };
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
        try std.testing.expect(!actual.required);
        try std.testing.expectEqual(@as(u32, 0), actual.uid);
        try std.testing.expectEqual(@as(u32, 0), actual.gid);
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

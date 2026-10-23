const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const diagnostics = @import("diagnostic.zig");
const pathString = @import("syscall.zig").pathString;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const fileType = @import("syscall.zig").fileType;
const fdPath = @import("syscall.zig").fdPath;
const OpenHow = @import("syscall.zig").OpenHow;
const openat2 = @import("syscall.zig").openat2;
const RESOLVE_IN_ROOT = @import("syscall.zig").RESOLVE_IN_ROOT;
const RESOLVE_NO_MAGICLINKS = @import("syscall.zig").RESOLVE_NO_MAGICLINKS;
const RESOLVE_NO_SYMLINKS = @import("syscall.zig").RESOLVE_NO_SYMLINKS;
const statfsType = @import("syscall.zig").statfsType;
const PROC_SUPER_MAGIC = @import("syscall.zig").PROC_SUPER_MAGIC;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const V1Hierarchy = @import("cgroup_v1.zig").V1Hierarchy;
const v1Hierarchies = @import("cgroup_v1.zig").v1Hierarchies;
const RootfsStep = @import("rootfs.zig").RootfsStep;

const ST_NOATIME: usize = 1024;
const ST_RELATIME: usize = 4096; // Unlike MS_RELATIME.
pub const OPEN_TREE_CLONE: u32 = 1;
pub const OPEN_TREE_CLOEXEC: u32 = 1 << @bitOffsetOf(linux.O, "CLOEXEC");
pub const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
pub const MountAttr = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};

/// EPERM fallback preserves flags even in an inherited user namespace.
/// Strict atime is implicit in statfs; never combine incompatible atime modes.
pub fn lockedMountFlags(requested: u32, fs_flags: usize) libcontainer.Error!u32 {
    const ms = linux.MS;
    const common = ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC | ms.NODIRATIME;
    const atime_mask = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
    const atime: u32 = (if (fs_flags & ST_NOATIME != 0) @as(u32, ms.NOATIME) else 0) |
        (if (fs_flags & ST_RELATIME != 0) @as(u32, ms.RELATIME) else 0) |
        (if (fs_flags & (ST_NOATIME | ST_RELATIME) == 0) @as(u32, ms.STRICTATIME) else 0);
    const requested_atime = requested & atime_mask;
    if (requested_atime != 0 and requested_atime != atime) return error.InvalidConfig;
    return requested | @as(u32, @intCast(fs_flags & common)) |
        (if (requested_atime == 0) atime else 0);
}

test "user namespace remount flags retain only locked statfs flags" {
    const ms = linux.MS;
    const requested: u32 = ms.BIND | ms.REMOUNT | ms.RDONLY;
    const cases = [_]struct { statfs: usize, expected: u32 }{
        .{ .statfs = 0, .expected = requested | ms.STRICTATIME },
        .{ .statfs = 2, .expected = requested | ms.NOSUID | ms.STRICTATIME },
        .{ .statfs = 4, .expected = requested | ms.NODEV | ms.STRICTATIME },
        .{ .statfs = 8, .expected = requested | ms.NOEXEC | ms.STRICTATIME },
        .{ .statfs = 1024, .expected = requested | ms.NOATIME },
        .{ .statfs = 2048, .expected = requested | ms.NODIRATIME | ms.STRICTATIME },
        .{ .statfs = 4096, .expected = requested | ms.RELATIME },
        .{ .statfs = 2 | 4 | 8 | 1024 | 2048 | 4096, .expected = requested | ms.NOSUID | ms.NODEV | ms.NOEXEC | ms.NOATIME | ms.NODIRATIME | ms.RELATIME },
        .{ .statfs = 1 | 16 | 32 | 64 | 128 | 256 | 512 | 8192, .expected = requested | ms.STRICTATIME },
    };
    for (cases) |case|
        try std.testing.expectEqual(case.expected, try lockedMountFlags(requested, case.statfs));
    try std.testing.expectEqual(ms.NOEXEC | ms.NOSUID | ms.STRICTATIME, try lockedMountFlags(ms.NOEXEC, 2));
    try std.testing.expectEqual(ms.RDONLY | ms.RELATIME, try lockedMountFlags(0, 1 | 4096));
}

test "locked atime modes are inherited only when absent and conflicts are rejected" {
    const ms = linux.MS;
    try std.testing.expectEqual(@as(u32, ms.RELATIME), try lockedMountFlags(ms.RELATIME, 4096));
    try std.testing.expectEqual(@as(u32, ms.NOATIME), try lockedMountFlags(ms.NOATIME, 1024));
    try std.testing.expectEqual(@as(u32, ms.STRICTATIME), try lockedMountFlags(ms.STRICTATIME, 0));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.STRICTATIME, 4096));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.RELATIME, 1024));
    try std.testing.expectError(error.InvalidConfig, lockedMountFlags(ms.NOATIME, 0));
}

/// Legacy cgroup mounts are expanded during parent-side mount preparation.
pub fn cgroupMountType(mount_type: []const u8, host_fs_type: usize) libcontainer.Error![]const u8 {
    if (!std.mem.eql(u8, mount_type, "cgroup") and !std.mem.eql(u8, mount_type, "cgroup2")) return mount_type;
    if (host_fs_type != 0x63677270) {
        if (std.mem.eql(u8, mount_type, "cgroup2")) {
            reportDiagnostic("cannot mount cgroup2 on a cgroup v1 host", .{});
            return error.Unsupported;
        }
        return "cgroup";
    }
    return "cgroup2";
}

/// Strings and symlinks are owned by the caller's preparation arena.
pub fn prepareMounts(allocator: std.mem.Allocator, mounts: []const libcontainer.Mount, host_fs_type: usize, hierarchies: []const V1Hierarchy, cgroup_path: []const u8) libcontainer.Error![]PreparedMount {
    var prepared: std.ArrayList(PreparedMount) = .empty;
    defer prepared.deinit(allocator);
    for (mounts) |mount| {
        if (!std.mem.startsWith(u8, mount.destination, "/")) return error.InvalidPath;
        try validateMountMappings(mount);
        var mount_type = mount.type;
        if (mount_type != null and mount.flags & linux.MS.BIND == 0)
            mount_type = try cgroupMountType(mount_type.?, host_fs_type);
        if (mount_type != null and std.mem.eql(u8, mount_type.?, "cgroup") and mount.flags & linux.MS.BIND == 0) {
            try prepareV1CgroupMount(allocator, &prepared, mount, hierarchies, cgroup_path);
            continue;
        }
        try prepared.append(allocator, .{
            .destination = try pathString(allocator, mount.destination),
            .source = if (mount.source) |source| try pathString(allocator, source) else null,
            .type = if (mount_type) |value| try pathString(allocator, value) else null,
            .flags = mount.flags,
            .propagation = mount.propagation,
            .data = try pathString(allocator, mount.data),
            .recursive_readonly = mount.recursive_readonly,
            .mappings = mount.mappings,
        });
    }
    return prepared.toOwnedSlice(allocator);
}

fn validateMountMappings(mount: libcontainer.Mount) libcontainer.Error!void {
    const mappings = mount.mappings orelse return;
    if (mount.flags & linux.MS.BIND == 0) {
        reportDiagnostic("idmapped mount '{s}' must be a bind mount", .{mount.destination});
        return error.InvalidConfig;
    }
    if (if (mappings.userns_path) |path|
        path.len == 0 or !std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null or
            mappings.uid.len != 0 or mappings.gid.len != 0
    else
        mappings.uid.len == 0 or mappings.gid.len == 0)
    {
        reportDiagnostic("idmapped mount '{s}' requires both uid and gid mappings, or a user namespace path", .{mount.destination});
        return error.InvalidConfig;
    }
}

fn prepareV1CgroupMount(allocator: std.mem.Allocator, prepared: *std.ArrayList(PreparedMount), mount: libcontainer.Mount, hierarchies: []const V1Hierarchy, cgroup_path: []const u8) libcontainer.Error!void {
    const destination = try pathString(allocator, mount.destination);
    try prepared.append(allocator, .{
        .destination = destination,
        .source = "tmpfs",
        .type = "tmpfs",
        .flags = mount.flags & ~@as(u32, linux.MS.RDONLY),
        .propagation = mount.propagation,
        .data = "mode=755",
    });
    var symlinks: std.ArrayList(libcontainer.Symlink) = .empty;
    defer symlinks.deinit(allocator);
    // ponytail: bind the leaf even with a cgroup namespace; runc mounts
    // cgroupfs with subsystem options there. Use that if needed.
    for (hierarchies) |hierarchy| {
        const basename = std.fs.path.basename(hierarchy.mountpoint);
        try prepared.append(allocator, .{
            .destination = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ destination, basename }, 0),
            .source = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ hierarchy.mountpoint, cgroup_path }, 0),
            .type = null,
            .flags = mount.flags | linux.MS.BIND,
            .propagation = 0,
            .data = "",
            .recursive_readonly = mount.recursive_readonly,
        });
        if (std.mem.indexOfScalar(u8, basename, ',') != null) {
            var names = std.mem.tokenizeScalar(u8, basename, ',');
            while (names.next()) |name| try symlinks.append(allocator, .{
                .path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ destination, name }, 0),
                .target = try allocator.dupeZ(u8, basename),
            });
        }
    }
    // Finish links after all bind targets exist, preserving any names
    // already present, then make only the covering tmpfs readonly.
    prepared.items[prepared.items.len - 1].symlinks = try symlinks.toOwnedSlice(allocator);
    if (mount.flags & linux.MS.RDONLY != 0) try prepared.append(allocator, .{
        .destination = destination,
        .source = null,
        .type = null,
        .flags = mount.flags | linux.MS.REMOUNT,
        .propagation = 0,
        .data = "",
    });
}

test "cgroup mounts map to cgroup2 only on unified hosts" {
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup", 0x63677270));
    for ([_]usize{ 0x01021994, 0x27e0eb, 0 }) |host_fs_type| {
        try std.testing.expectEqualStrings("cgroup", try cgroupMountType("cgroup", host_fs_type));
    }
    try std.testing.expectEqualStrings("tmpfs", try cgroupMountType("tmpfs", 0x01021994));
    try std.testing.expectError(error.Unsupported, cgroupMountType("cgroup2", 0x01021994));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "cgroup2") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "v1") != null);
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup2", 0x63677270));
}

test "mount preparation rejects invalid idmapped bind configurations" {
    defer diagnostics.last_diagnostic_len = 0;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const mapping: []const libcontainer.IDMapping = &.{.{ .container_id = 0, .host_id = 1000, .size = 1 }};
    for ([_]libcontainer.MountMappings{
        .{ .uid = mapping },
        .{ .gid = mapping },
        .{},
        .{ .uid = mapping, .gid = mapping, .userns_path = "/proc/self/ns/user" },
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, prepareMounts(arena.allocator(), &.{.{
            .destination = "/data",
            .source = "/host",
            .type = null,
            .flags = linux.MS.BIND,
            .propagation = 0,
            .data = "",
            .mappings = mappings,
        }}, 0, &.{}, ""));
    }
    try std.testing.expectError(error.InvalidConfig, prepareMounts(arena.allocator(), &.{.{
        .destination = "/data",
        .source = "tmpfs",
        .type = "tmpfs",
        .flags = 0,
        .propagation = 0,
        .data = "",
        .mappings = .{ .uid = mapping, .gid = mapping },
    }}, 0, &.{}, ""));
}

test "v1 cgroup mount expansion binds leaves and links comounted controllers before readonly remount" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const hierarchies = try v1Hierarchies(allocator,
        \\1 0 0:1 / /sys/fs/cgroup rw - tmpfs tmpfs rw
        \\2 1 0:2 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
        \\3 1 0:3 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
        \\4 1 0:4 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd
        \\5 1 0:5 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw
    );
    const restrictions = linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV;
    for ([_]bool{ false, true }) |readonly| {
        const flags = restrictions | @as(u32, if (readonly) linux.MS.RDONLY else 0);
        const mounts = try prepareMounts(allocator, &.{.{
            .destination = "/custom/cgroups",
            .source = "cgroup",
            .type = "cgroup",
            .flags = flags,
            .propagation = linux.MS.PRIVATE,
            .data = "",
        }}, 0x01021994, hierarchies, "igvano/example");
        try std.testing.expectEqual(@as(usize, if (readonly) 4 else 3), mounts.len);
        try std.testing.expectEqualStrings("/custom/cgroups", mounts[0].destination);
        try std.testing.expectEqualStrings("tmpfs", mounts[0].type.?);
        try std.testing.expectEqualStrings("mode=755", mounts[0].data);
        try std.testing.expectEqual(restrictions, mounts[0].flags);
        try std.testing.expectEqual(@as(u32, linux.MS.PRIVATE), mounts[0].propagation);
        for ([_]struct { source: []const u8, destination: []const u8 }{
            .{ .source = "/sys/fs/cgroup/cpu,cpuacct/igvano/example", .destination = "/custom/cgroups/cpu,cpuacct" },
            .{ .source = "/sys/fs/cgroup/memory/igvano/example", .destination = "/custom/cgroups/memory" },
        }, mounts[1..3]) |expected, mount| {
            try std.testing.expectEqualStrings(expected.source, mount.source.?);
            try std.testing.expectEqualStrings(expected.destination, mount.destination);
            try std.testing.expectEqual(flags | linux.MS.BIND, mount.flags);
            try std.testing.expect(mount.type == null);
        }
        const links = mounts[2].symlinks;
        try std.testing.expectEqual(@as(usize, 2), links.len);
        try std.testing.expectEqualStrings("/custom/cgroups/cpu", links[0].path);
        try std.testing.expectEqualStrings("/custom/cgroups/cpuacct", links[1].path);
        for (links) |link| try std.testing.expectEqualStrings("cpu,cpuacct", link.target);
        if (readonly) {
            try std.testing.expectEqualStrings("/custom/cgroups", mounts[3].destination);
            try std.testing.expectEqual(flags | linux.MS.REMOUNT, mounts[3].flags);
            try std.testing.expect(mounts[3].source == null and mounts[3].type == null);
        }
    }
}

pub fn needsSetupDev(mounts: anytype) bool {
    var setup = true;
    for (mounts) |mount| {
        if (std.mem.eql(u8, mount.destination, "/dev"))
            setup = mount.flags & linux.MS.BIND == 0;
    }
    return setup;
}

pub fn validateDeviceMounts(mounts: []const libcontainer.Mount, devices: []const libcontainer.Device) libcontainer.Error!void {
    if (needsSetupDev(mounts)) return;
    for (devices) |device| {
        if (device.required) return error.Unsupported;
    }
}

test "bind-mounted dev skips defaults and rejects explicit devices" {
    const bind: libcontainer.Mount = .{ .destination = "/dev", .source = "/dev", .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" };
    const tmpfs: libcontainer.Mount = .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" };
    const cases = [_]struct { mounts: []const libcontainer.Mount, setup: bool }{
        .{ .mounts = &.{}, .setup = true },
        .{ .mounts = &.{bind}, .setup = false },
        .{ .mounts = &.{ tmpfs, bind }, .setup = false },
        .{ .mounts = &.{ bind, tmpfs }, .setup = true },
    };
    const defaults = [_]libcontainer.Device{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3, .required = false }};
    for (cases) |case| {
        try std.testing.expectEqual(case.setup, needsSetupDev(case.mounts));
        try validateDeviceMounts(case.mounts, &defaults);
        const explicit = [_]libcontainer.Device{.{ .path = "/dev/custom", .kind = .fifo }};
        if (case.setup)
            try validateDeviceMounts(case.mounts, &explicit)
        else
            try std.testing.expectError(error.Unsupported, validateDeviceMounts(case.mounts, &explicit));
    }
}

pub const PreparedMount = struct {
    destination: [:0]const u8,
    source: ?[:0]const u8,
    type: ?[:0]const u8,
    flags: u32,
    propagation: u32,
    data: [:0]const u8,
    recursive_readonly: ?bool = null,
    mappings: ?libcontainer.MountMappings = null,
    /// O_PATH source opened with host credentials in init's mount namespace.
    source_fd: ?posix.fd_t = null,
    /// Detached idmapped tree cloned from init's locked mount namespace.
    mount_fd: ?posix.fd_t = null,
    userns_fd: ?posix.fd_t = null,
    /// Created after this mount, before a following tmpfs readonly remount.
    symlinks: []const libcontainer.Symlink = &.{},
};

/// Follow symlinks within a pinned root, including absolute targets and ".."
/// in symlink contents. Mount through the returned fd to avoid destination swaps.
pub fn mountDestination(root_fd: posix.fd_t, destination: []const u8, is_file: bool, create: bool) libcontainer.Error!posix.fd_t {
    var path_buffer: [linux.PATH_MAX]u8 = undefined;
    const path = try mountDestinationPath(&path_buffer, destination);
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    var component = components.next() orelse {
        if (is_file) return invalidMountPath("file destination resolves to root");
        return openMountPath(root_fd, ".", false);
    };
    var current = try openMountPath(root_fd, ".", false);
    defer closeFd(current);
    while (true) {
        const next = components.next();
        const final_file = next == null and is_file;
        const end = @intFromPtr(component.ptr) - @intFromPtr(destination.ptr) + component.len;
        path_buffer[end] = 0;
        defer path_buffer[end] = if (end < destination.len) destination[end] else 0;
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return invalidMountPath("component exceeds NAME_MAX");
        if (create) try createMountComponent(current, name, final_file);
        // Resolve the whole prefix from root_fd, never from current: an absolute
        // symlink (or ".." in its target) must be scoped to the container root.
        // Reopening also confines a component swapped to a symlink after mkdir.
        const fd = (try findMountPath(root_fd, path.ptr, final_file, false)) orelse {
            if (!create) return missingMountPath(path.ptr);
            // Restore the full destination before replaying the dangling prefix.
            path_buffer[end] = if (end < destination.len) destination[end] else 0;
            return createMissingMountDestination(root_fd, path, is_file);
        };
        if (next == null) return verifyMountDestination(fd, is_file);
        closeFd(current);
        current = fd;
        component = next.?;
    }
}

fn invalidMountPath(reason: []const u8) libcontainer.Error {
    reportDiagnostic("invalid mount destination: {s}", .{reason});
    return error.InvalidPath;
}

fn missingMountPath(path: [*:0]const u8) libcontainer.Error {
    reportDiagnostic("cannot resolve mount destination '{s}': NOENT", .{std.mem.span(path)});
    return error.CreateFailed;
}

fn mountDestinationPath(buffer: []u8, destination: []const u8) libcontainer.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, destination, 0) != null) return invalidMountPath("embedded NUL");
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    while (components.next()) |component| {
        // Only symlink contents may contain traversal, never caller input.
        if (std.mem.eql(u8, component, "..") or std.mem.eql(u8, component, "."))
            return invalidMountPath("original path contains '.' or '..'");
    }
    return std.fmt.bufPrintZ(buffer, "{s}", .{destination}) catch return invalidMountPath("path exceeds Linux PATH_MAX");
}

const mount_destination_retry_failure = "resolve mount destination (openat2 EAGAIN after 32 attempts)";

fn openMountPath(root_fd: posix.fd_t, path: [*:0]const u8, is_file: bool) libcontainer.Error!posix.fd_t {
    return (try findMountPath(root_fd, path, is_file, false)) orelse return missingMountPath(path);
}

fn findMountPath(root_fd: posix.fd_t, path: [*:0]const u8, is_file: bool, nofollow: bool) libcontainer.Error!?posix.fd_t {
    const flags: linux.O = .{ .PATH = true, .DIRECTORY = !is_file, .NOFOLLOW = nofollow, .CLOEXEC = true };
    const how: OpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | (if (nofollow) RESOLVE_NO_SYMLINKS else @as(u64, 0)),
    };
    const result = try openat2(root_fd, path, how);
    switch (linux.errno(result)) {
        .NOENT => return null,
        .LOOP => return invalidMountPath("symlink loop or forbidden symlink"),
        .NAMETOOLONG => return invalidMountPath("path exceeds Linux PATH_MAX or NAME_MAX"),
        else => try checkResult(result),
    }
    return @intCast(result);
}

fn createMountComponent(dir: posix.fd_t, name: [:0]const u8, is_file: bool) libcontainer.Error!void {
    if (is_file) {
        const created = linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o644);
        switch (linux.errno(created)) {
            .SUCCESS => closeFd(@intCast(created)),
            .EXIST => {},
            else => try checkResult(created),
        }
        return;
    }
    const created = linux.mkdirat(dir, name, 0o755);
    switch (linux.errno(created)) {
        .SUCCESS, .EXIST => {},
        else => try checkResult(created),
    }
}

fn verifyMountDestination(fd: posix.fd_t, is_file: bool) libcontainer.Error!posix.fd_t {
    errdefer closeFd(fd);
    const kind = try fileType(fd);
    if (is_file and kind == linux.S.IFDIR) return invalidMountPath("file destination is a directory");
    if (!is_file and kind != linux.S.IFDIR) return invalidMountPath("directory destination is not a directory");
    return fd;
}

/// Lexical state for the ENOENT fallback; buffers include space for the NUL.
const MissingMountPath = struct {
    pending: [linux.PATH_MAX]u8 = undefined,
    pending_len: usize,
    prefix: [linux.PATH_MAX]u8 = undefined,
    prefix_len: usize = 0,
    expansions: usize = 0,
    created: bool = false,

    fn next(self: *MissingMountPath, name_buffer: []u8) libcontainer.Error!?[:0]u8 {
        const remaining = std.mem.trimStart(u8, self.pending[0..self.pending_len], "/");
        if (remaining.len == 0) return null;
        const end = std.mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
        const name = std.fmt.bufPrintZ(name_buffer, "{s}", .{remaining[0..end]}) catch return invalidMountPath("component exceeds NAME_MAX");
        const rest = std.mem.trimStart(u8, remaining[end..], "/");
        std.mem.copyForwards(u8, &self.pending, rest);
        self.pending_len = rest.len;
        return name;
    }

    fn path(self: *MissingMountPath) [:0]const u8 {
        self.prefix[self.prefix_len] = 0;
        return if (self.prefix_len == 0) "." else self.prefix[0..self.prefix_len :0];
    }

    fn append(self: *MissingMountPath, name: []const u8) libcontainer.Error!void {
        const len = self.prefix_len + 1 + name.len;
        if (len >= linux.PATH_MAX) return invalidMountPath("expanded path exceeds Linux PATH_MAX");
        self.prefix[self.prefix_len] = '/';
        @memcpy(self.prefix[self.prefix_len + 1 .. len], name);
        self.prefix_len = len;
    }

    fn parent(self: *MissingMountPath) void {
        // Never open ".." against a directory fd: it could leave the root.
        self.prefix_len = std.mem.lastIndexOfScalar(u8, self.prefix[0..self.prefix_len], '/') orelse 0;
    }

    fn expand(self: *MissingMountPath, link_fd: posix.fd_t) libcontainer.Error!bool {
        if (self.expansions == 40) return invalidMountPath("more than 40 symlink expansions");
        self.expansions += 1;
        var fs: [32]usize = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(link_fd), @intFromPtr(&fs)));
        // O_PATH|O_NOFOLLOW can pin a magic link even with NO_MAGICLINKS.
        // Do not reinterpret procfs links as ordinary lexical symlink targets.
        if (statfsType(&fs) == PROC_SUPER_MAGIC) return invalidMountPath("procfs symlink in dangling destination");
        var target: [linux.PATH_MAX]u8 = undefined;
        const read = linux.readlinkat(link_fd, "", &target, target.len);
        try checkResult(read);
        if (read == 0 or read == target.len) return invalidMountPath("symlink target exceeds Linux PATH_MAX");
        const absolute = target[0] == '/';
        const base_len = if (absolute) 0 else self.prefix_len + 1;
        const separator: usize = if (self.pending_len == 0) 0 else 1;
        const len = read + separator + self.pending_len;
        if (base_len + len >= linux.PATH_MAX) return invalidMountPath("expanded path exceeds Linux PATH_MAX");
        std.mem.copyBackwards(u8, self.pending[read + separator .. len], self.pending[0..self.pending_len]);
        @memcpy(self.pending[0..read], target[0..read]);
        if (separator != 0) self.pending[read] = '/';
        self.pending_len = len;
        if (absolute) self.prefix_len = 0;
        return absolute;
    }
};

fn createMissingMountDestination(root_fd: posix.fd_t, destination: [:0]const u8, is_file: bool) libcontainer.Error!posix.fd_t {
    var path: MissingMountPath = .{ .pending_len = destination.len };
    @memcpy(path.pending[0..destination.len], destination);
    var current = try openMountPath(root_fd, ".", false);
    defer closeFd(current);
    var name_buffer: [256]u8 = undefined;
    // Replay the existing prefix without following links to learn its lexical
    // position (a parent may itself be an alias). Continue creating from the
    // deepest existing confined directory, with only canonical prefixes.
    while (try path.next(&name_buffer)) |name| {
        if (std.mem.eql(u8, name, ".")) continue;
        if (std.mem.eql(u8, name, "..")) {
            if (path.created) return invalidMountPath("'..' after a missing component");
            path.parent();
            try reopenMountParent(root_fd, &current, &path);
            continue;
        }
        const parent_len = path.prefix_len;
        try path.append(name);
        const fd = try missingMountComponent(root_fd, current, &path, name, is_file and path.pending_len == 0);
        defer closeFd(fd);
        if (try fileType(fd) == linux.S.IFLNK) {
            path.prefix_len = parent_len;
            if (try path.expand(fd)) try reopenMountParent(root_fd, &current, &path);
            continue;
        }
        if (path.pending_len != 0) try reopenMountParent(root_fd, &current, &path);
    }
    // Resolve the original destination once more, including aliases and mount
    // changes, and mount through this pinned fd rather than a lexical pathname.
    return verifyMountDestination(try openMountPath(root_fd, destination.ptr, is_file), is_file);
}

fn reopenMountParent(root_fd: posix.fd_t, current: *posix.fd_t, path: *MissingMountPath) libcontainer.Error!void {
    const fd = (try findMountPath(root_fd, path.path().ptr, false, true)) orelse return missingMountPath(path.path().ptr);
    closeFd(current.*);
    current.* = fd;
}

fn missingMountComponent(root_fd: posix.fd_t, parent: posix.fd_t, path: *MissingMountPath, name: [:0]const u8, is_file: bool) libcontainer.Error!posix.fd_t {
    const prefix = path.path();
    if (try findMountPath(root_fd, prefix.ptr, true, true)) |fd| return fd;
    // Like securejoin's MkdirAll, reject traversal in the unresolved remainder
    // before creating anything the kernel could not originally walk through.
    var remaining = std.mem.tokenizeScalar(u8, path.pending[0..path.pending_len], '/');
    while (remaining.next()) |component| {
        if (std.mem.eql(u8, component, ".."))
            return invalidMountPath("'..' after a missing component");
    }
    path.created = true;
    try createMountComponent(parent, name, is_file);
    // EXCL/NOFOLLOW and mkdirat cannot follow a swapped final symlink. Reopen
    // from root without following any prefix swapped after the inspection.
    return (try findMountPath(root_fd, prefix.ptr, true, true)) orelse return missingMountPath(prefix.ptr);
}

fn mountDestinationStep(root_fd: posix.fd_t, destination: []const u8, is_file: bool, create: bool, step: *RootfsStep) libcontainer.Error!posix.fd_t {
    return mountDestination(root_fd, destination, is_file, create) catch |err| {
        // setupRootfs replaces the thread-local diagnostic with this step.
        if (err == error.Unsupported) step.operation = "resolve mount destination (openat2 is required)";
        if (err == error.ResolveRetryExhausted)
            step.operation = mount_destination_retry_failure;
        return err;
    };
}

pub fn remountFlags(target_fd: posix.fd_t, requested: u32) libcontainer.Error!u32 {
    if (comptime builtin.os.tag == .linux) {
        // s390x uses u32 for metadata words and native words for counters.
        const Word = if (builtin.cpu.arch == .s390x) u32 else usize;
        const Statfs = extern struct {
            type: Word,
            bsize: Word,
            blocks: usize,
            bfree: usize,
            bavail: usize,
            files: usize,
            ffree: usize,
            fsid: [2]i32,
            namelen: Word,
            frsize: Word,
            flags: Word,
            spare: [if (builtin.cpu.arch == .s390x) 5 else 4]Word,
        };
        var fs: Statfs = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(target_fd), @intFromPtr(&fs)));
        return lockedMountFlags(requested, fs.flags);
    } else {
        return error.NotImplemented;
    }
}

pub fn bindRemount(target_fd: posix.fd_t, target: [*:0]const u8, requested: u32) libcontainer.Error!void {
    const result = linux.mount(null, target, null, requested, 0);
    if (linux.errno(result) != .PERM) return checkResult(result);
    // Retry locked flags on EPERM, including in an inherited user namespace.
    // Privileged callers may change these flags, so first honor their request.
    const flags = try remountFlags(target_fd, requested);
    try checkResult(linux.mount(null, target, null, flags, 0));
}

pub fn applyMount(rootfs: [:0]const u8, root_fd: posix.fd_t, mount: PreparedMount, private_mount_namespace: bool, rootfs_propagation: u32, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    const bind = mount.flags & ms.BIND != 0;
    step.* = .{ .operation = "open bind source", .source = mount.source, .path = mount.destination };
    const source_fd: ?posix.fd_t = if (bind)
        mount.mount_fd orelse mount.source_fd orelse try openPath(linux.AT.FDCWD, (mount.source orelse return error.InvalidConfig).ptr, .{ .PATH = true, .CLOEXEC = true })
    else
        null;
    defer if (mount.mount_fd == null and mount.source_fd == null) {
        if (source_fd) |fd| closeFd(fd);
    };
    step.operation = "stat bind source";
    const is_file = if (source_fd) |fd| try fileType(fd) != linux.S.IFDIR else false;
    step.* = .{ .operation = "prepare mount destination", .path = mount.destination };
    var target_fd = try mountDestinationStep(root_fd, mount.destination, is_file, true, step);
    defer closeFd(target_fd);
    var source_buffer: [64]u8 = undefined;
    const source: ?[*:0]const u8 = if (source_fd) |fd|
        fdPath(&source_buffer, fd).ptr
    else if (mount.source) |value|
        value.ptr
    else
        null;
    try attachMount(mount, source, target_fd, step);
    // The original fd pins the covered mount. Reopen to address the new mount
    // for remount and propagation changes, with symlinks still scoped to rootfs.
    step.operation = "open mounted destination";
    const mounted_fd = if (std.mem.eql(u8, mount.destination, "/"))
        try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        try mountDestinationStep(root_fd, mount.destination, is_file, false, step);
    closeFd(target_fd);
    target_fd = mounted_fd;
    try isolateBindMount(mount, target_fd, private_mount_namespace, rootfs_propagation, step);
    try applyMountAttributes(mount, target_fd, step);
}

fn attachMount(mount: PreparedMount, source: ?[*:0]const u8, target_fd: posix.fd_t, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    const bind = mount.flags & ms.BIND != 0;
    var target_buffer: [64]u8 = undefined;
    step.* = .{
        .operation = if (bind) "bind" else "mount",
        .path = mount.destination,
        .source = if (bind) mount.source else null,
        .fs_type = if (bind) null else mount.type,
    };
    if (mount.mount_fd) |fd| {
        step.operation = "move detached mount";
        var flags = std.mem.zeroes(linux.MOVE_MOUNT);
        flags.F_EMPTY_PATH = true;
        flags.T_EMPTY_PATH = true;
        try checkResult(linux.move_mount(fd, "", target_fd, "", flags));
    } else {
        try checkResult(linux.mount(
            source,
            fdPath(&target_buffer, target_fd),
            if (bind) null else if (mount.type) |value| value.ptr else null,
            if (bind) mount.flags & (ms.BIND | ms.REC) else mount.flags,
            if (bind or mount.data.len == 0) 0 else @intFromPtr(mount.data.ptr),
        ));
    }
}

fn isolateBindMount(mount: PreparedMount, target_fd: posix.fd_t, private_mount_namespace: bool, rootfs_propagation: u32, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    const bind = mount.flags & ms.BIND != 0;
    var target_buffer: [64]u8 = undefined;
    // Detached trees retain host peer groups even under a private parent.
    // Use one-way propagation before remounts to stop propagation to the host while
    // retaining the host propagation source when root or mount propagation needs it.
    if (bind and mount.mount_fd != null) {
        step.operation = "mount slave propagation";
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, ms.SLAVE | ms.REC, 0));
        if ((rootfs_propagation | mount.propagation) & (ms.SLAVE | ms.SHARED) == 0) {
            step.operation = "mount private propagation";
            try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, ms.PRIVATE | ms.REC, 0));
        }
    } else if (bind and !private_mount_namespace) {
        step.operation = "mount private propagation";
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, ms.PRIVATE | ms.REC, 0));
    }
}

fn applyMountAttributes(mount: PreparedMount, target_fd: posix.fd_t, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    var target_buffer: [64]u8 = undefined;
    if (mount.flags & ms.BIND != 0 and mount.flags & ~@as(u32, ms.BIND | ms.REC) != 0) {
        step.operation = "bind remount";
        const requested = (mount.flags & ~@as(u32, ms.REC)) | ms.BIND | ms.REMOUNT;
        try bindRemount(target_fd, fdPath(&target_buffer, target_fd), requested);
    }
    if (mount.recursive_readonly) |readonly| {
        step.operation = "mount_setattr";
        const attr: MountAttr = .{
            .attr_set = if (readonly) 1 else 0, // MOUNT_ATTR_RDONLY
            .attr_clr = if (readonly) 0 else 1,
        };
        // Zig 0.16's wrapper omits the attr pointer and size; use the full ABI.
        try checkResult(linux.syscall5(.mount_setattr, @intCast(target_fd), @intFromPtr(""), linux.AT.EMPTY_PATH | linux.AT.RECURSIVE, @intFromPtr(&attr), @sizeOf(MountAttr)));
    }
    if (mount.propagation != 0) {
        step.operation = "mount propagation";
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, mount.propagation, 0));
    }
}

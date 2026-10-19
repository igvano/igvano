const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const diagnostics = @import("diagnostic.zig");
const pathString = @import("syscall.zig").pathString;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const fileType = @import("syscall.zig").fileType;
const fdPath = @import("syscall.zig").fdPath;
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
pub fn lockedMountFlags(requested: u32, fs_flags: usize) Backend.Error!u32 {
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
pub fn cgroupMountType(mount_type: []const u8, host_fs_type: usize) Backend.Error![]const u8 {
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
pub fn prepareMounts(allocator: std.mem.Allocator, mounts: []const Backend.Mount, host_fs_type: usize, hierarchies: []const V1Hierarchy, cgroup_path: []const u8) Backend.Error![]PreparedMount {
    var prepared: std.ArrayList(PreparedMount) = .empty;
    defer prepared.deinit(allocator);
    for (mounts) |mount| {
        if (!std.mem.startsWith(u8, mount.destination, "/")) return error.InvalidPath;
        if (mount.mappings) |mappings| {
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
        var mount_type = mount.type;
        if (mount_type != null and mount.flags & linux.MS.BIND == 0)
            mount_type = try cgroupMountType(mount_type.?, host_fs_type);
        if (mount_type != null and std.mem.eql(u8, mount_type.?, "cgroup") and mount.flags & linux.MS.BIND == 0) {
            const destination = try pathString(allocator, mount.destination);
            try prepared.append(allocator, .{
                .destination = destination,
                .source = "tmpfs",
                .type = "tmpfs",
                .flags = mount.flags & ~@as(u32, linux.MS.RDONLY),
                .propagation = mount.propagation,
                .data = "mode=755",
            });
            var symlinks: std.ArrayList(Backend.Symlink) = .empty;
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
    const mapping: []const Backend.IDMapping = &.{.{ .container_id = 0, .host_id = 1000, .size = 1 }};
    for ([_]Backend.MountMappings{
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

pub fn validateDeviceMounts(mounts: []const Backend.Mount, devices: []const Backend.Device) Backend.Error!void {
    if (needsSetupDev(mounts)) return;
    for (devices) |device| {
        if (device.required) return error.Unsupported;
    }
}

test "bind-mounted dev skips defaults and rejects explicit devices" {
    const bind: Backend.Mount = .{ .destination = "/dev", .source = "/dev", .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" };
    const tmpfs: Backend.Mount = .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "" };
    const cases = [_]struct { mounts: []const Backend.Mount, setup: bool }{
        .{ .mounts = &.{}, .setup = true },
        .{ .mounts = &.{bind}, .setup = false },
        .{ .mounts = &.{ tmpfs, bind }, .setup = false },
        .{ .mounts = &.{ bind, tmpfs }, .setup = true },
    };
    const defaults = [_]Backend.Device{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3, .required = false }};
    for (cases) |case| {
        try std.testing.expectEqual(case.setup, needsSetupDev(case.mounts));
        try validateDeviceMounts(case.mounts, &defaults);
        const explicit = [_]Backend.Device{.{ .path = "/dev/custom", .kind = .fifo }};
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
    mappings: ?Backend.MountMappings = null,
    /// O_PATH source opened with host credentials in init's mount namespace.
    source_fd: ?posix.fd_t = null,
    /// Detached idmapped tree cloned from init's locked mount namespace.
    mount_fd: ?posix.fd_t = null,
    userns_fd: ?posix.fd_t = null,
    /// Created after this mount, before a following tmpfs readonly remount.
    symlinks: []const Backend.Symlink = &.{},
};

/// Walk beneath a pinned root, rejecting symlinks in every component. Mounting
/// through the returned fd also avoids a destination swap between lookup/mount.
pub fn mountDestination(root_fd: posix.fd_t, destination: []const u8, is_file: bool, create: bool) Backend.Error!posix.fd_t {
    var current = try openPath(root_fd, ".", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    var component = components.next() orelse {
        if (is_file) return error.InvalidPath;
        return current;
    };
    while (true) {
        // Frontend paths are normalized; reject traversal from library callers too.
        if (std.mem.eql(u8, component, "..") or std.mem.eql(u8, component, ".")) return error.InvalidPath;
        const next = components.next();
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (next == null and is_file) {
            if (create) {
                const created = linux.openat(current, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o644);
                switch (linux.errno(created)) {
                    .SUCCESS => closeFd(@intCast(created)),
                    .EXIST => {},
                    else => try checkResult(created),
                }
            }
            const fd = try openPath(current, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
            errdefer closeFd(fd);
            const kind = try fileType(fd);
            if (kind == linux.S.IFLNK or kind == linux.S.IFDIR) return error.InvalidPath;
            closeFd(current);
            return fd;
        }
        if (create) {
            const created = linux.mkdirat(current, name, 0o755);
            switch (linux.errno(created)) {
                .SUCCESS, .EXIST => {},
                else => try checkResult(created),
            }
        }
        const fd = try openPath(current, name, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        closeFd(current);
        current = fd;
        component = next orelse return current;
    }
}

pub fn remountFlags(target_fd: posix.fd_t, requested: u32) Backend.Error!u32 {
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

pub fn bindRemount(target_fd: posix.fd_t, target: [*:0]const u8, requested: u32) Backend.Error!void {
    const result = linux.mount(null, target, null, requested, 0);
    if (linux.errno(result) != .PERM) return checkResult(result);
    // Retry locked flags on EPERM, including in an inherited user namespace.
    // Privileged callers may change these flags, so first honor their request.
    const flags = try remountFlags(target_fd, requested);
    try checkResult(linux.mount(null, target, null, flags, 0));
}

pub fn applyMount(rootfs: [:0]const u8, root_fd: posix.fd_t, mount: PreparedMount, private_mount_namespace: bool, rootfs_propagation: u32, step: *RootfsStep) Backend.Error!void {
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
    var target_fd = try mountDestination(root_fd, mount.destination, is_file, true);
    defer closeFd(target_fd);
    var target_buffer: [64]u8 = undefined;
    var source_buffer: [64]u8 = undefined;
    const source: ?[*:0]const u8 = if (source_fd) |fd|
        fdPath(&source_buffer, fd).ptr
    else if (mount.source) |value|
        value.ptr
    else
        null;
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
    // The original fd pins the covered mount. Reopen to address the new mount
    // for remount and propagation changes, still without following symlinks.
    step.operation = "open mounted destination";
    const mounted_fd = if (std.mem.eql(u8, mount.destination, "/"))
        try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        try mountDestination(root_fd, mount.destination, is_file, false);
    closeFd(target_fd);
    target_fd = mounted_fd;
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
    if (bind and mount.flags & ~@as(u32, ms.BIND | ms.REC) != 0) {
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

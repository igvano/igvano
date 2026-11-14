const std = @import("std");
const libcontainer = @import("libcontainer");
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const diagnosticContext = @import("diagnostic.zig").diagnosticContext;
const Spec = @import("spec.zig").Spec;
const requireCreate = @import("validate.zig").requireCreate;

pub fn rootfsPropagation(mode: ?Spec.Propagation) u32 {
    const ms = std.os.linux.MS;
    // runc uses the same mapping for rootfs and individual mounts.
    return switch (mode orelse .rprivate) {
        .shared => ms.SHARED,
        .rshared => ms.SHARED | ms.REC,
        .slave => ms.SLAVE,
        .rslave => ms.SLAVE | ms.REC,
        .private => ms.PRIVATE,
        .rprivate => ms.PRIVATE | ms.REC,
        .unbindable => ms.UNBINDABLE,
        .runbindable => ms.UNBINDABLE | ms.REC,
    };
}

/// Linux mount constants are available on every build host; this performs no I/O.
/// The caller owns data, including when there are no filesystem-specific options.
pub const MountOptions = struct {
    flags: u32,
    propagation: u32,
    data: [:0]u8,
    recursive_attr: ?libcontainer.RecursiveAttr = null,
    /// runc's tmpcopyup extension: copy the covered directory into a tmpfs.
    copy_up: bool = false,
    /// runc's ClearedFlags: flags an option such as "dev" or "rw" asked to
    /// clear. A bind mount is remounted when any are set.
    cleared: u32 = 0,
};

/// MS_NOSYMFOLLOW (Linux 5.10); Zig 0.16's MS has no name for it.
pub const ms_nosymfollow: u32 = 0x100;

/// MOUNT_ATTR_* values from linux/mount.h.
pub const mount_attr = struct {
    pub const rdonly: u64 = 0x1;
    pub const nosuid: u64 = 0x2;
    pub const nodev: u64 = 0x4;
    pub const noexec: u64 = 0x8;
    pub const atime_mask: u64 = 0x70;
    pub const relatime: u64 = 0x0;
    pub const noatime: u64 = 0x10;
    pub const strictatime: u64 = 0x20;
    pub const nodiratime: u64 = 0x80;
    pub const nosymfollow: u64 = 0x200000;
};

const RecursiveOption = struct { clear: bool, flag: u64 };

pub const mount_option_table = options: {
    const ms = std.os.linux.MS;
    const atime = ms.NOATIME | ms.RELATIME | ms.STRICTATIME;
    const a = mount_attr;
    break :options [_]struct {
        name: []const u8,
        set: u32 = 0,
        clear: u32 = 0,
        propagation: u32 = 0,
        recursive: ?RecursiveOption = null,
        idmap: ?bool = null,
        copy_up: bool = false,
    }{
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
        .{ .name = "norelatime", .clear = ms.RELATIME },
        .{ .name = "nostrictatime", .clear = ms.STRICTATIME },
        .{ .name = "nosymfollow", .set = ms_nosymfollow },
        .{ .name = "symfollow", .clear = ms_nosymfollow },
        .{ .name = "private", .propagation = ms.PRIVATE },
        .{ .name = "rprivate", .propagation = ms.PRIVATE | ms.REC },
        .{ .name = "slave", .propagation = ms.SLAVE },
        .{ .name = "rslave", .propagation = ms.SLAVE | ms.REC },
        .{ .name = "shared", .propagation = ms.SHARED },
        .{ .name = "rshared", .propagation = ms.SHARED | ms.REC },
        .{ .name = "unbindable", .propagation = ms.UNBINDABLE },
        .{ .name = "runbindable", .propagation = ms.UNBINDABLE | ms.REC },
        // runc's recAttrFlags, applied with mount_setattr(AT_RECURSIVE).
        .{ .name = "rro", .recursive = .{ .clear = false, .flag = a.rdonly } },
        .{ .name = "rrw", .recursive = .{ .clear = true, .flag = a.rdonly } },
        .{ .name = "rnosuid", .recursive = .{ .clear = false, .flag = a.nosuid } },
        .{ .name = "rsuid", .recursive = .{ .clear = true, .flag = a.nosuid } },
        .{ .name = "rnodev", .recursive = .{ .clear = false, .flag = a.nodev } },
        .{ .name = "rdev", .recursive = .{ .clear = true, .flag = a.nodev } },
        .{ .name = "rnoexec", .recursive = .{ .clear = false, .flag = a.noexec } },
        .{ .name = "rexec", .recursive = .{ .clear = true, .flag = a.noexec } },
        .{ .name = "rnodiratime", .recursive = .{ .clear = false, .flag = a.nodiratime } },
        .{ .name = "rdiratime", .recursive = .{ .clear = true, .flag = a.nodiratime } },
        .{ .name = "rrelatime", .recursive = .{ .clear = false, .flag = a.relatime } },
        .{ .name = "rnorelatime", .recursive = .{ .clear = true, .flag = a.relatime } },
        .{ .name = "rnoatime", .recursive = .{ .clear = false, .flag = a.noatime } },
        .{ .name = "ratime", .recursive = .{ .clear = true, .flag = a.noatime } },
        .{ .name = "rstrictatime", .recursive = .{ .clear = false, .flag = a.strictatime } },
        .{ .name = "rnostrictatime", .recursive = .{ .clear = true, .flag = a.strictatime } },
        .{ .name = "rnosymfollow", .recursive = .{ .clear = false, .flag = a.nosymfollow } },
        .{ .name = "rsymfollow", .recursive = .{ .clear = true, .flag = a.nosymfollow } },
        .{ .name = "idmap", .idmap = false },
        .{ .name = "ridmap", .idmap = true },
        .{ .name = "tmpcopyup", .copy_up = true },
    };
};

pub fn parseMountOptions(allocator: std.mem.Allocator, options: []const []const u8, mount_type: ?[]const u8) !MountOptions {
    const ms = std.os.linux.MS;
    var result: MountOptions = .{ .flags = if (mount_type != null and std.mem.eql(u8, mount_type.?, "bind")) ms.BIND else 0, .propagation = 0, .data = undefined };
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    for (options) |option| {
        if (std.mem.indexOfScalar(u8, option, 0) != null) return invalidConfig("mount options: must not contain NUL", .{});
        if (applyMountOption(&result, option)) continue;
        if (data.items.len != 0) try data.append(allocator, ',');
        try data.appendSlice(allocator, option);
    }
    // Discard filesystem data for bind mounts because the kernel ignores it.
    if (result.flags & ms.BIND != 0) {
        if (data.items.len != 0)
            std.debug.print("igvano: warning: bind mount ignores options: {s}\n", .{data.items});
        data.clearRetainingCapacity();
    }
    // Like runc, an all-zero change (only "rnorelatime") does nothing.
    if (result.recursive_attr) |attr| {
        if (attr.set == 0 and attr.clear == 0) result.recursive_attr = null;
    }
    result.data = try data.toOwnedSliceSentinel(allocator, 0);
    return result;
}

fn applyRecursiveOption(result: *MountOptions, option: RecursiveOption) void {
    var attr = result.recursive_attr orelse libcontainer.RecursiveAttr{};
    if (option.clear) {
        attr.clear |= option.flag;
        attr.set &= ~option.flag;
        // runc fails "ratime" with EINVAL: the kernel only clears the whole mask.
        // Like youki, clear it all, which leaves the default relatime.
        if (option.flag != 0 and option.flag & mount_attr.atime_mask == option.flag) attr.clear |= mount_attr.atime_mask;
    } else {
        attr.set |= option.flag;
        attr.clear &= ~option.flag;
        // mount_setattr(2): an access-time mode in attr_set needs the whole mask cleared.
        if (option.flag & mount_attr.atime_mask == option.flag) attr.clear |= mount_attr.atime_mask;
    }
    result.recursive_attr = attr;
}

/// False for an option outside the table, which is filesystem data.
fn applyMountOption(result: *MountOptions, option: []const u8) bool {
    for (mount_option_table) |entry| {
        if (!std.mem.eql(u8, option, entry.name)) continue;
        result.flags = (result.flags & ~entry.clear) | entry.set;
        // "bind" and the atime modes clear only to stay exclusive.
        if (entry.set == 0) result.cleared |= entry.clear else result.cleared &= ~entry.set;
        if (entry.propagation != 0) result.propagation = entry.propagation;
        if (entry.recursive) |recursive| applyRecursiveOption(result, recursive);
        if (entry.copy_up) result.copy_up = true;
        return true;
    }
    return false;
}

pub fn validateMountDestination(destination: []const u8) !void {
    if (!std.mem.startsWith(u8, destination, "/") or
        std.mem.indexOfScalar(u8, destination, 0) != null) return invalidConfig("container path: must be absolute and NUL-free", .{});
    var depth: usize = 0;
    var components = std.mem.tokenizeScalar(u8, destination, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (depth == 0) return invalidConfig("container path: must not escape the container root", .{});
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

/// Like runc, a destination spelled as a host path lexically inside the rootfs
/// means that path relative to the rootfs; any other path is inside the rootfs.
pub fn resolveContainerMountDestination(allocator: std.mem.Allocator, rootfs: []const u8, destination: []const u8) ![]u8 {
    const resolved = try resolveMountDestination(allocator, destination);
    errdefer allocator.free(resolved);
    const root = try std.fs.path.resolve(allocator, &.{rootfs});
    defer allocator.free(root);
    if (root.len <= 1 or !std.mem.startsWith(u8, resolved, root)) return resolved;
    if (resolved.len != root.len and resolved[root.len] != '/') return resolved;
    const inside = try allocator.dupe(u8, if (resolved.len == root.len) "/" else resolved[root.len..]);
    allocator.free(resolved);
    return inside;
}

test "mount destinations under the rootfs host path are taken relative to it" {
    const allocator = std.testing.allocator;
    for ([_][3][]const u8{
        .{ "/b/rootfs", "/b/rootfs/mnt/x", "/mnt/x" },
        .{ "/b/rootfs/", "/b/rootfs", "/" },
        .{ "/b/rootfs", "/b/rootfs/../rootfs/mnt", "/mnt" },
        .{ "/b/rootfs", "/b/rootfsx/mnt", "/b/rootfsx/mnt" },
        .{ "/b/rootfs", "/mnt", "/mnt" },
        .{ "/", "/mnt", "/mnt" },
    }) |case| {
        const got = try resolveContainerMountDestination(allocator, case[0], case[1]);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(case[2], got);
    }
}

/// Map ranges are half-open; widen before adding to avoid wrapping u32 IDs.
pub fn validateIDMappings(mappings: []const Spec.IDMapping) error{InvalidConfig}!void {
    if (mappings.len == 0 or mappings.len > 340) return invalidConfig("ID mappings: expected 1..340 ranges", .{});
    var text_size: usize = 0;
    for (mappings, 0..) |mapping, i| {
        const end = @as(u64, mapping.containerID) + mapping.size;
        const host_end = @as(u64, mapping.hostID) + mapping.size;
        // Linux reserves (uid_t)-1 and (gid_t)-1 as unmapped IDs.
        if (mapping.size == 0 or end > std.math.maxInt(u32) or host_end > std.math.maxInt(u32))
            return invalidConfig("ID mappings[{d}]: range is empty or includes a reserved ID", .{i});
        text_size += std.fmt.count("{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
        if (text_size >= 4096) return invalidConfig("ID mappings: formatted map must be smaller than 4096 bytes", .{});
        for (mappings[0..i]) |previous| {
            const previous_end = @as(u64, previous.containerID) + previous.size;
            const previous_host_end = @as(u64, previous.hostID) + previous.size;
            if ((mapping.containerID < previous_end and previous.containerID < end) or
                (mapping.hostID < previous_host_end and previous.hostID < host_end))
                return invalidConfig("ID mappings[{d}]: overlapping container or host ranges", .{i});
        }
    }
}

const MountMappingConfig = struct {
    uid: []const Spec.IDMapping = &.{},
    gid: []const Spec.IDMapping = &.{},
    userns_path: ?[]const u8 = null,
    recursive: bool = false,
};

pub fn mountMappingConfig(mount: Spec.Mount, settings: Spec.Linux) !?MountMappingConfig {
    const options = mountMappingOptions(mount);
    const explicit = mount.uidMappings != null or mount.gidMappings != null;
    if (!explicit and options.recursive == null) return null;
    if (!options.bind) {
        return invalidConfig("mount '{s}': idmapping requires a bind mount", .{mount.destination});
    }
    var config: MountMappingConfig = .{ .recursive = options.recursive orelse false };
    if (explicit) {
        config.uid = mount.uidMappings orelse &.{};
        config.gid = mount.gidMappings orelse &.{};
    } else {
        inheritMountMappings(&config, settings);
        if (config.userns_path != null) return config;
    }
    if (config.uid.len == 0 or config.gid.len == 0) {
        return invalidConfig("mount '{s}': idmapping requires both uid and gid mappings", .{mount.destination});
    }
    for ([_][]const Spec.IDMapping{ config.uid, config.gid }) |mappings| {
        validateIDMappings(mappings) catch |err| {
            diagnosticContext("mount '{s}' mappings", .{mount.destination});
            return err;
        };
    }
    return config;
}

fn mountMappingOptions(mount: Spec.Mount) struct { bind: bool, recursive: ?bool } {
    var bind = mount.type != null and std.mem.eql(u8, mount.type.?, "bind");
    var recursive: ?bool = null;
    for (mount.options orelse &.{}) |option| {
        if (std.mem.eql(u8, option, "bind") or std.mem.eql(u8, option, "rbind")) bind = true;
        for (mount_option_table) |entry| {
            if (std.mem.eql(u8, option, entry.name) and entry.idmap != null) recursive = entry.idmap;
        }
    }
    return .{ .bind = bind, .recursive = recursive };
}

fn inheritMountMappings(config: *MountMappingConfig, settings: Spec.Linux) void {
    for (settings.namespaces orelse &.{}) |namespace| {
        if (namespace.type != .user) continue;
        if (namespace.joinPath()) |path| {
            config.userns_path = path;
            return;
        }
        config.uid = settings.uidMappings orelse &.{};
        config.gid = settings.gidMappings orelse &.{};
        break;
    }
}

/// Translate to libcontainer types; the caller owns both mapping slices.
pub fn mountMappings(allocator: std.mem.Allocator, mount: Spec.Mount, settings: Spec.Linux) !?libcontainer.MountMappings {
    const config = (try mountMappingConfig(mount, settings)) orelse return null;
    const uid = try containerIDMappings(allocator, config.uid);
    errdefer allocator.free(uid);
    const gid = try containerIDMappings(allocator, config.gid);
    return .{ .uid = uid, .gid = gid, .userns_path = config.userns_path, .recursive = config.recursive };
}

pub fn containerIDMappings(allocator: std.mem.Allocator, mappings: []const Spec.IDMapping) ![]libcontainer.IDMapping {
    const result = try allocator.alloc(libcontainer.IDMapping, mappings.len);
    for (mappings, result) |mapping, *converted| converted.* = .{
        .container_id = mapping.containerID,
        .host_id = mapping.hostID,
        .size = mapping.size,
    };
    return result;
}

test "linux path restrictions parse ordered string lists and propagation modes" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"maskedPaths":["/proc/kcore","/secret"],"readonlyPaths":["/proc/sys"],"rootfsPropagation":"slave"}
    , .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.maskedPaths.?.len);
    try std.testing.expectEqualStrings("/proc/kcore", parsed.value.maskedPaths.?[0]);
    try std.testing.expectEqualStrings("/secret", parsed.value.maskedPaths.?[1]);
    try std.testing.expectEqualStrings("/proc/sys", parsed.value.readonlyPaths.?[0]);
    try std.testing.expectEqual(Spec.Propagation.slave, parsed.value.rootfsPropagation.?);
    const ms = std.os.linux.MS;
    try std.testing.expectEqual(@as(u32, ms.PRIVATE | ms.REC), rootfsPropagation(null));
    const cases = [_]struct { mode: []const u8, expected: u32 }{
        .{ .mode = "shared", .expected = ms.SHARED },
        .{ .mode = "rshared", .expected = ms.SHARED | ms.REC },
        .{ .mode = "slave", .expected = ms.SLAVE },
        .{ .mode = "rslave", .expected = ms.SLAVE | ms.REC },
        .{ .mode = "private", .expected = ms.PRIVATE },
        .{ .mode = "rprivate", .expected = ms.PRIVATE | ms.REC },
        .{ .mode = "unbindable", .expected = ms.UNBINDABLE },
        .{ .mode = "runbindable", .expected = ms.UNBINDABLE | ms.REC },
    };
    for (cases) |case| {
        const json = try std.fmt.allocPrint(std.testing.allocator, "{{\"rootfsPropagation\":\"{s}\"}}", .{case.mode});
        defer std.testing.allocator.free(json);
        const spec = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator, json, .{});
        defer spec.deinit();
        try std.testing.expectEqual(case.expected, rootfsPropagation(spec.value.rootfsPropagation));
    }
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"rootfsPropagation":"unknown"}
    , .{}));
    try std.testing.expectError(error.UnexpectedToken, std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"maskedPaths":[1]}
    , .{}));
}

test "recursive mount options build runc's mount_setattr change in order" {
    const a = mount_attr;
    const R = libcontainer.RecursiveAttr;
    const cases = [_]struct { options: []const []const u8, recursive: ?R }{
        .{ .options = &.{ "ro", "rbind" }, .recursive = null },
        .{ .options = &.{ "rbind", "rro" }, .recursive = .{ .set = a.rdonly } },
        .{ .options = &.{ "bind", "rrw" }, .recursive = .{ .clear = a.rdonly } },
        .{ .options = &.{ "rbind", "rro", "rrw" }, .recursive = .{ .clear = a.rdonly } },
        .{ .options = &.{ "rbind", "rrw", "rro" }, .recursive = .{ .set = a.rdonly } },
        .{ .options = &.{ "mode=755", "rbind", "rro" }, .recursive = .{ .set = a.rdonly } },
        .{ .options = &.{ "rbind", "rnosuid", "rnodev" }, .recursive = .{ .set = a.nosuid | a.nodev } },
        .{ .options = &.{ "rbind", "rnoatime" }, .recursive = .{ .set = a.noatime, .clear = a.atime_mask } },
        .{ .options = &.{ "rbind", "rrelatime" }, .recursive = .{ .clear = a.atime_mask } },
        .{ .options = &.{ "rbind", "rnorelatime" }, .recursive = null },
        .{ .options = &.{ "rbind", "ratime" }, .recursive = .{ .clear = a.atime_mask } },
        .{ .options = &.{ "rbind", "rnosymfollow", "rsymfollow" }, .recursive = .{ .clear = a.nosymfollow } },
    };
    for (cases) |case| {
        const options = try parseMountOptions(std.testing.allocator, case.options, null);
        defer std.testing.allocator.free(options.data);
        try std.testing.expectEqual(case.recursive, options.recursive_attr);
        try std.testing.expectEqualStrings("", options.data);
    }
}

test "mount options translate flags propagation and filesystem data" {
    {
        const copy = try parseMountOptions(std.testing.allocator, &.{ "tmpcopyup", "ro", "mode=755" }, "tmpfs");
        defer std.testing.allocator.free(copy.data);
        try std.testing.expect(copy.copy_up);
        try std.testing.expectEqual(@as(u32, std.os.linux.MS.RDONLY), copy.flags);
        // tmpcopyup is runc's extension, never tmpfs data.
        try std.testing.expectEqualStrings("mode=755", copy.data);
    }
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
        .{ .options = &.{"unbindable"}, .propagation = ms.UNBINDABLE },
        .{ .options = &.{"runbindable"}, .propagation = ms.UNBINDABLE | ms.REC },
        .{ .options = &.{ "rshared", "private" }, .propagation = ms.PRIVATE },
        .{ .options = &.{ "runbindable", "shared" }, .propagation = ms.SHARED },
        .{ .options = &.{ "rbind", "private" }, .flags = ms.BIND | ms.REC, .propagation = ms.PRIVATE },
        .{ .options = &.{ "nosuid", "strictatime", "mode=755", "size=1k", "bind", "shared" }, .flags = ms.NOSUID | ms.STRICTATIME | ms.BIND, .propagation = ms.SHARED },
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

test "bind mounts discard filesystem data regardless of option order" {
    const cases = [_][]const []const u8{
        &.{ "bind", "custom" },
        &.{ "custom", "bind" },
        &.{ "rbind", "size=65536k", "ro" },
        &.{ "mode=755", "rbind", "rprivate" },
        &.{ "bind", "" },
        &.{ "bind", "nosuid", "nosiud", "mode=755", "size=1k" },
    };
    for (cases) |options| {
        const bind = try parseMountOptions(std.testing.allocator, options, null);
        defer std.testing.allocator.free(bind.data);
        try std.testing.expectEqualStrings("", bind.data);
    }
    const custom = try parseMountOptions(std.testing.allocator, &.{"custom"}, "bind");
    defer std.testing.allocator.free(custom.data);
    try std.testing.expectEqualStrings("", custom.data);
    const bind = try parseMountOptions(std.testing.allocator, &.{ "ro", "rprivate" }, "bind");
    defer std.testing.allocator.free(bind.data);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.BIND | std.os.linux.MS.RDONLY), bind.flags);
    try std.testing.expectEqual(@as(u32, std.os.linux.MS.PRIVATE | std.os.linux.MS.REC), bind.propagation);
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

test "mount ID mappings parse without being silently ignored" {
    const parsed = try std.json.parseFromSlice(Spec, std.testing.allocator,
        \\{"ociVersion":"1.2.0","root":{"path":"rootfs"},"mounts":[{
        \\"destination":"/data","source":"/host","options":["bind"],
        \\"uidMappings":[{"containerID":100000,"hostID":0,"size":1}],
        \\"gidMappings":[{"containerID":200000,"hostID":0,"size":1}]}]}
    , .{});
    defer parsed.deinit();
    try requireCreate(parsed.value);
}

test "idmap and ridmap are runtime mount options" {
    for ([_][]const u8{ "idmap", "ridmap" }) |option| {
        const parsed = try parseMountOptions(std.testing.allocator, &.{option}, null);
        defer std.testing.allocator.free(parsed.data);
        try std.testing.expectEqualStrings("", parsed.data);
    }
}

test "mount mapping translation selects explicit container and joined namespace mappings" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const settings: Spec.Linux = .{
        .namespaces = &.{.{ .type = .user }},
        .uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 65536 }},
        .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 65536 }},
    };
    var mount: Spec.Mount = .{ .destination = "/data", .source = "/host", .type = "bind" };
    try std.testing.expectEqual(@as(?libcontainer.MountMappings, null), try mountMappings(arena.allocator(), mount, settings));
    mount.options = &.{ "rbind", "ridmap", "idmap" };
    const container = (try mountMappings(arena.allocator(), mount, settings)).?;
    try std.testing.expect(!container.recursive);
    try std.testing.expectEqualDeep(libcontainer.IDMapping{ .container_id = 0, .host_id = 100000, .size = 65536 }, container.uid[0]);
    try std.testing.expectEqualDeep(libcontainer.IDMapping{ .container_id = 0, .host_id = 200000, .size = 65536 }, container.gid[0]);
    mount.options = &.{ "idmap", "ridmap" };
    mount.uidMappings = &.{.{ .containerID = 100000, .hostID = 0, .size = 1 }};
    mount.gidMappings = &.{.{ .containerID = 200000, .hostID = 0, .size = 1 }};
    const explicit = (try mountMappings(arena.allocator(), mount, settings)).?;
    try std.testing.expect(explicit.recursive);
    try std.testing.expectEqualDeep(libcontainer.IDMapping{ .container_id = 100000, .host_id = 0, .size = 1 }, explicit.uid[0]);
    try std.testing.expectEqualDeep(libcontainer.IDMapping{ .container_id = 200000, .host_id = 0, .size = 1 }, explicit.gid[0]);
    // Explicit mappings also work without any container user namespace.
    _ = try mountMappings(arena.allocator(), mount, .{});
    mount.uidMappings = null;
    mount.gidMappings = null;
    const joined = (try mountMappings(arena.allocator(), mount, .{ .namespaces = &.{.{ .type = .user, .path = "/proc/123/ns/user" }} })).?;
    try std.testing.expectEqualStrings("/proc/123/ns/user", joined.userns_path.?);
    try std.testing.expectEqual(@as(usize, 0), joined.uid.len);
    try std.testing.expectEqual(@as(usize, 0), joined.gid.len);
    try std.testing.expect(joined.recursive);
    var joined_settings = settings;
    joined_settings.namespaces = &.{.{ .type = .user, .path = "/proc/123/ns/user" }};
    const joined_with_mappings = (try mountMappings(arena.allocator(), mount, joined_settings)).?;
    try std.testing.expectEqualDeep(joined, joined_with_mappings);
    try requireCreate(.{
        .ociVersion = "1.2.0",
        .root = .{ .path = "rootfs" },
        .linux = joined_settings,
        .mounts = &.{mount},
    });
}

test "mount mapping translation frees partial allocations" {
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const result = (try mountMappings(allocator, .{
                .destination = "/data",
                .type = "bind",
                .uidMappings = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }},
                .gidMappings = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }},
            }, .{})).?;
            defer allocator.free(result.uid);
            defer allocator.free(result.gid);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
}

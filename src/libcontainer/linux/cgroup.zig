const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const Resources = libcontainer.Resources;
const devicefilter = @import("../devicefilter.zig");
const v2DeviceRules = @import("devices.zig").v2DeviceRules;
const applyV2DeviceFilter = @import("devices.zig").applyV2DeviceFilter;
const statfsType = @import("syscall.zig").statfsType;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const Write = @import("cgroup_v2.zig").Write;
const v2Writes = @import("cgroup_v2.zig").v2Writes;
const freeWrites = @import("cgroup_v2.zig").freeWrites;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const V1Write = @import("cgroup_v1.zig").V1Write;
const freeV1Writes = @import("cgroup_v1.zig").freeV1Writes;
const v1Writes = @import("cgroup_v1.zig").v1Writes;
const V1Hierarchy = @import("cgroup_v1.zig").V1Hierarchy;
const walkV1Cgroup = @import("cgroup_v1.zig").walkV1Cgroup;
const applyV1Writes = @import("cgroup_v1.zig").applyV1Writes;

pub const CgroupMode = enum { unified, legacy };
pub const CgroupRoot = struct { fd: posix.fd_t, fs_type: usize, mode: CgroupMode };

test "cgroup mode detects unified and legacy roots" {
    try std.testing.expectEqual(CgroupMode.unified, try cgroupMode(0x63677270));
    try std.testing.expectEqual(CgroupMode.legacy, try cgroupMode(0x01021994));
    try std.testing.expectError(error.Unsupported, cgroupMode(0x27e0eb));
}

test "resource updates write only requested limits and replace explicit v1 device rules" {
    const resources: Resources = .{ .cpu = .{ .shares = 512 } };
    const v1 = try v1Writes(std.testing.allocator, resources);
    defer freeV1Writes(std.testing.allocator, v1);
    try std.testing.expectEqual(@as(usize, 1), v1.len);
    try std.testing.expectEqualStrings("cpu.shares", v1[0].name);
    try std.testing.expectEqualStrings("512", v1[0].value);
    const v2 = try v2Writes(std.testing.allocator, resources);
    defer freeWrites(std.testing.allocator, v2);
    try std.testing.expectEqual(@as(usize, 1), v2.len);
    try std.testing.expectEqualStrings("cpu.weight", v2[0].name);
    try std.testing.expectEqualStrings("59", v2[0].value);
    const devices = try v1Writes(std.testing.allocator, .{
        .devices = &.{.{ .allow = true, .kind = .block, .major = 8, .minor = 0, .access = "rw" }},
    });
    defer freeV1Writes(std.testing.allocator, devices);
    try std.testing.expectEqual(@as(usize, 0), devices.len);
}

pub fn validateCgroupPath(path: []const u8) libcontainer.Error!void {
    if (path.len == 0 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or component.len > 255)
            return error.InvalidPath;
    }
}

/// Intermediate directories may exist; creation must own a new leaf.
pub fn createCgroupDirectory(parent: posix.fd_t, name: [:0]const u8, path: []const u8, leaf: bool) libcontainer.Error!bool {
    const result = linux.mkdirat(parent, name, 0o755);
    switch (linux.errno(result)) {
        .SUCCESS => return true,
        .EXIST => {
            if (leaf) {
                reportDiagnostic("cgroup '{s}' already exists", .{path});
                return error.CreateFailed;
            }
        },
        else => try checkResult(result),
    }
    return false;
}

fn cgroupMode(fs_type: usize) libcontainer.Error!CgroupMode {
    return switch (fs_type) {
        0x63677270 => .unified, // CGROUP2_SUPER_MAGIC
        0x01021994 => .legacy, // TMPFS_MAGIC
        else => error.Unsupported,
    };
}

pub fn openCgroupRoot() libcontainer.Error!CgroupRoot {
    const opened = linux.openat(linux.AT.FDCWD, "/sys/fs/cgroup", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return error.Unsupported,
        else => try checkResult(opened),
    }
    const root: posix.fd_t = @intCast(opened);
    errdefer closeFd(root);
    // Zig has no statfs wrapper; reserve enough storage for each kernel ABI.
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(root), @intFromPtr(&fs)));
    const fs_type = statfsType(&fs);
    const mode = cgroupMode(fs_type) catch {
        reportDiagnostic("unsupported cgroup filesystem at /sys/fs/cgroup", .{});
        return error.Unsupported;
    };
    // ponytail: hybrid hosts use v1 only, without systemd-unified membership,
    // like runc's fs driver without systemd.
    return .{ .fd = root, .fs_type = fs_type, .mode = mode };
}

pub fn readCgroupFile(allocator: std.mem.Allocator, dir: posix.fd_t, filename: [:0]const u8) libcontainer.Error![]u8 {
    const fd = try openPath(dir, filename, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.CgroupWriteFailed,
        }
        if (result == 0) return text.toOwnedSlice(allocator);
        try text.appendSlice(allocator, buffer[0..result]);
    }
}

pub fn collectCgroupPids(allocator: std.mem.Allocator, dir: posix.fd_t, result: *std.ArrayList(i32)) libcontainer.Error!void {
    const text = try readCgroupFile(allocator, dir, "cgroup.procs");
    defer allocator.free(text);
    var fields = std.mem.tokenizeAny(u8, text, " \t\n");
    while (fields.next()) |field| {
        const pid = std.fmt.parseInt(i32, field, 10) catch return error.InvalidProcess;
        if (pid <= 0) return error.InvalidProcess;
        if (std.mem.indexOfScalar(i32, result.items, pid) == null) try result.append(allocator, pid);
    }
    // Keep the caller's directory offset untouched for later cleanup or ps.
    const directory = try openPath(dir, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(directory);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.getdents64(directory, &buffer, buffer.len);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) return;
        var offset: usize = 0;
        while (offset < count) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            offset += entry.reclen;
            if (entry.type != linux.DT.DIR) continue;
            const name_ptr: [*]const u8 = &entry.name;
            const padded = name_ptr[0 .. entry.reclen - @offsetOf(linux.dirent64, "name")];
            const name = name_ptr[0..std.mem.indexOfScalar(u8, padded, 0).? :0];
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            const opened = linux.openat(dir, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
            if (linux.errno(opened) == .NOENT) continue; // A child can disappear during ps.
            try checkResult(opened);
            const child: posix.fd_t = @intCast(opened);
            defer closeFd(child);
            try collectCgroupPids(allocator, child, result);
        }
    }
}

test "backend cgroup paths must name a normalized child directory" {
    for ([_][]const u8{ "igvano/example", "custom", "a/b/c" }) |path| try validateCgroupPath(path);
    for ([_][]const u8{ "", "/", "/custom", "..", "a/../b", "a/./b", "a//b", "a/", "a\x00b" }) |path| {
        try std.testing.expectError(error.InvalidPath, validateCgroupPath(path));
    }
}

fn missingFileIsFine(filename: []const u8, value: []const u8) bool {
    // Like runc, a kernel without CFS burst ignores cpu.cfs_burst_us.
    if (std.mem.eql(u8, filename, "cpu.cfs_burst_us")) return true;
    return std.mem.eql(u8, filename, "memory.swap.max") and
        (std.mem.eql(u8, value, "max") or std.mem.eql(u8, value, "0"));
}

pub fn writeCgroupFile(dir: posix.fd_t, filename: []const u8, value: []const u8, path: []const u8) libcontainer.Error!void {
    if (filename.len == 0 or std.mem.indexOfAny(u8, filename, "/\x00") != null or
        std.mem.eql(u8, filename, ".") or std.mem.eql(u8, filename, "..")) return error.InvalidPath;
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{filename}) catch return error.InvalidPath;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            // Like runc, a host without swap ignores unlimiting or disabling
            // it, and one without CFS burst ignores the v1 burst.
            .NOENT => if (missingFileIsFine(filename, value)) return else {
                reportDiagnostic("cgroup '{s}' cannot open {s}: NOENT", .{ path, filename });
                return error.CgroupWriteFailed;
            },
            else => |err| {
                reportDiagnostic("cgroup '{s}' cannot open {s}: {s}", .{ path, filename, @tagName(err) });
                return error.CgroupWriteFailed;
            },
        }
    };
    defer closeFd(fd);
    var offset: usize = 0;
    while (offset < value.len) {
        const result = linux.write(fd, value[offset..].ptr, value.len - offset);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.CgroupWriteFailed;
                offset += result;
            },
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cgroup '{s}' cannot write {s} = '{s}': {s}", .{ path, filename, value, @tagName(err) });
                return error.CgroupWriteFailed;
            },
        }
    }
}

pub fn cgroupPopulated(dir: posix.fd_t) libcontainer.Error!bool {
    const fd = try openPath(dir, "cgroup.events", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fd);
    var buffer: [256]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) break;
                used += result;
            },
            .INTR => continue,
            else => return error.CgroupDeleteFailed,
        }
    }
    var fields = std.mem.tokenizeAny(u8, buffer[0..used], " \t\n");
    while (fields.next()) |key| {
        const value = fields.next() orelse return error.CgroupDeleteFailed;
        if (std.mem.eql(u8, key, "populated")) {
            if (std.mem.eql(u8, value, "0")) return false;
            if (std.mem.eql(u8, value, "1")) return true;
            return error.CgroupDeleteFailed;
        }
    }
    return error.CgroupDeleteFailed;
}

pub fn removeCreatedCgroup(root: posix.fd_t, path: []const u8, cgroup: posix.fd_t) libcontainer.Error!void {
    var owned: linux.Statx = undefined;
    try checkResult(linux.statx(cgroup, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &owned));
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return error.InvalidPath;
    var current: linux.Statx = undefined;
    const result = linux.statx(root, name, linux.AT.SYMLINK_NOFOLLOW, .{ .INO = true }, &current);
    switch (linux.errno(result)) {
        .NOENT, .NOTDIR => return,
        else => try checkResult(result),
    }
    if (!owned.mask.INO or !current.mask.INO) return error.CgroupDeleteFailed;
    // Forced deletion can let another container reuse this path before create unwinds.
    if (owned.dev_major != current.dev_major or owned.dev_minor != current.dev_minor or owned.ino != current.ino) return;
    try removeCgroup(root, path);
}

pub fn removeCgroup(root: posix.fd_t, path: []const u8) libcontainer.Error!void {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = @min(path.len, path_buffer.len);
    @memcpy(path_buffer[0..len], path[0..len]);
    return removeCgroupAt(root, path, &path_buffer, len);
}

fn removeCgroupAt(root: posix.fd_t, path: []const u8, path_buffer: []u8, path_len: usize) libcontainer.Error!void {
    const full_path = path_buffer[0..path_len];
    try validateCgroupPath(path);
    const parent = if (std.fs.path.dirname(path)) |parent_path|
        (try walkCgroup(root, parent_path, false, &.{})) orelse return
    else
        try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(parent);
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(path)}) catch return error.InvalidPath;
    const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
    for (0..50) |_| {
        const opened = linux.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .SUCCESS => {
                const cgroup: posix.fd_t = @intCast(opened);
                defer closeFd(cgroup);
                try removeCgroupChildrenAt(cgroup, path_buffer, path_len);
            },
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cannot open cgroup '{s}' for removal: {s}", .{ full_path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
        const result = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => return,
            .INTR => continue,
            .BUSY, .NOTEMPTY => _ = linux.nanosleep(&delay, null),
            else => |err| {
                reportDiagnostic("cannot remove cgroup '{s}': {s}", .{ full_path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
    }
    reportDiagnostic("cgroup '{s}' is still busy after waiting for members to exit", .{full_path});
    return error.CgroupDeleteFailed;
}

/// Remove descendants before their parent, without touching cgroup control files.
pub fn removeCgroupChildren(dir: posix.fd_t, path: []const u8) libcontainer.Error!void {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = @min(path.len, path_buffer.len);
    @memcpy(path_buffer[0..len], path[0..len]);
    return removeCgroupChildrenAt(dir, &path_buffer, len);
}

fn removeCgroupChildrenAt(dir: posix.fd_t, path_buffer: []u8, path_len: usize) libcontainer.Error!void {
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.getdents64(dir, &buffer, buffer.len);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                reportDiagnostic("cannot read child cgroups of '{s}': {s}", .{ path_buffer[0..path_len], @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
        if (result == 0) return;
        var offset: usize = 0;
        while (offset < result) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            offset += entry.reclen;
            if (entry.type != linux.DT.DIR) continue;
            const name_ptr: [*]const u8 = &entry.name;
            const padded_name = name_ptr[0 .. entry.reclen - @offsetOf(linux.dirent64, "name")];
            const name_len = std.mem.indexOfScalar(u8, padded_name, 0).?;
            const name = name_ptr[0..name_len :0];
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            if (name.len > 255) return error.CgroupDeleteFailed; // NAME_MAX
            var child_len = path_len + 1 + name.len;
            var restore_from = path_len;
            var saved_tail: [260]u8 = undefined;
            if (child_len <= path_buffer.len) {
                path_buffer[path_len] = '/';
                @memcpy(path_buffer[path_len + 1 .. child_len], name);
            } else {
                // Long fd-relative paths must not make deletion fail. Share
                // one path buffer and abbreviate only the diagnostic.
                restore_from = path_buffer.len - "/.../".len - name.len;
                // NAME_MAX bounds path_len - restore_from to 5..260.
                @memcpy(saved_tail[0 .. path_len - restore_from], path_buffer[restore_from..path_len]);
                @memcpy(path_buffer[restore_from..][0.."/.../".len], "/.../");
                @memcpy(path_buffer[restore_from + "/.../".len ..], name);
                child_len = path_buffer.len;
            }
            defer @memcpy(path_buffer[restore_from..path_len], saved_tail[0 .. path_len - restore_from]);
            try removeCgroupAt(dir, name, path_buffer, child_len);
        }
    }
}

pub fn procCgroupMatches(text: []const u8, mount_root: []const u8, path: []const u8, controller: ?[]const u8) bool {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const first = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const second = std.mem.indexOfScalarPos(u8, line, first + 1, ':') orelse continue;
        if (controller) |name|
            if (!procCgroupControllerMatches(line[0..first], line[first + 1 .. second], name)) continue;
        const relative = procCgroupRelativePath(line[second + 1 ..], mount_root) orelse continue;
        if (std.mem.startsWith(u8, relative, path) and
            (relative.len == path.len or relative[path.len] == '/')) return true;
    }
    return false;
}

fn procCgroupControllerMatches(id: []const u8, controllers: []const u8, name: []const u8) bool {
    if (name.len == 0) return std.mem.eql(u8, id, "0") and controllers.len == 0;
    var names = std.mem.tokenizeScalar(u8, controllers, ',');
    while (names.next()) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

fn procCgroupRelativePath(member: []const u8, mount_root: []const u8) ?[]const u8 {
    if (member.len == 0 or member[0] != '/') return null;
    if (std.mem.eql(u8, mount_root, "/")) return member[1..];
    if (std.mem.startsWith(u8, member, mount_root) and member.len > mount_root.len and member[mount_root.len] == '/')
        return member[mount_root.len + 1 ..];
    return null;
}

test "cgroup membership verifies hierarchy and subtree boundaries" {
    const text =
        \\4:cpu,cpuacct:/igvano/example/nested
        \\3:memory:/igvano/other
        \\0::/igvano/example/nested/grandchild
    ;
    try std.testing.expect(procCgroupMatches(text, "/", "igvano/example", "cpu"));
    try std.testing.expect(procCgroupMatches(text, "/", "igvano/example/nested", "cpuacct"));
    try std.testing.expect(procCgroupMatches(text, "/", "igvano/example", ""));
    try std.testing.expect(procCgroupMatches(text, "/", "igvano/example/nested/grandchild", ""));
    try std.testing.expect(!procCgroupMatches(text, "/", "igvano/example", "memory"));
    try std.testing.expect(!procCgroupMatches(text, "/", "igvano/exam", "cpu"));
    try std.testing.expect(!procCgroupMatches(text, "/", "igvano/example2", ""));
    try std.testing.expect(!procCgroupMatches("4:cpu,cpuacct:/igvano/example2\n", "/", "igvano/example", "cpu"));
    try std.testing.expect(!procCgroupMatches("0::/igvano/example2\n", "/", "igvano/example", ""));
    try std.testing.expect(!procCgroupMatches("1:name=systemd:/igvano/example\n", "/", "igvano/example", ""));
    try std.testing.expect(!procCgroupMatches("garbage\n0::relative\n", "/", "relative", ""));
    try std.testing.expect(procCgroupMatches("0::/igvano/example:colon\n", "/", "igvano/example:colon", ""));
    try std.testing.expect(!procCgroupMatches("0::/../..\n", "/", "igvano/example", ""));
    const mounted =
        \\4:cpu,cpuacct:/docker/cid/igvano/example/nested
        \\3:memory:/docker/cid/igvano/other
        \\1:name=systemd:/docker/cid/igvano/example
        \\0::/docker/cid/igvano/example/child/grandchild
    ;
    try std.testing.expect(procCgroupMatches(mounted, "/docker/cid", "igvano/example", "cpu"));
    try std.testing.expect(procCgroupMatches(mounted, "/docker/cid", "igvano/example/nested", "cpuacct"));
    try std.testing.expect(procCgroupMatches(mounted, "/docker/cid", "igvano/example", ""));
    try std.testing.expect(procCgroupMatches(mounted, "/docker/cid", "igvano/example/child", ""));
    try std.testing.expect(procCgroupMatches(mounted, "/docker/cid", "igvano/example/child/grandchild", ""));
    try std.testing.expect(!procCgroupMatches(mounted, "/docker/cid", "igvano/example", "memory"));
    try std.testing.expect(!procCgroupMatches(mounted, "/docker/cid", "igvano/example", "cpuset"));
    try std.testing.expect(!procCgroupMatches(mounted, "/docker/cid", "igvano/exam", "cpu"));
    try std.testing.expect(!procCgroupMatches(mounted, "/docker/cid", "igvano/example2", ""));
    try std.testing.expect(!procCgroupMatches("4:cpu,cpuacct:/igvano/example\n", "/docker/cid", "igvano/example", "cpu"));
    try std.testing.expect(!procCgroupMatches("4:cpu,cpuacct:/docker/cid2/igvano/example\n", "/docker/cid", "igvano/example", "cpu"));
    try std.testing.expect(!procCgroupMatches("4:cpu,cpuacct:/docker/cid/igvano/example2\n", "/docker/cid", "igvano/example", "cpu"));
    try std.testing.expect(!procCgroupMatches("0::/docker/cid/igvano/example2\n", "/docker/cid", "igvano/example", ""));
    try std.testing.expect(!procCgroupMatches("3:memory:/docker/cid/igvano/example\n", "/docker/cid", "igvano/example", "cpu"));
    try std.testing.expect(!procCgroupMatches("1:name=systemd:/docker/cid/igvano/example\n", "/docker/cid", "igvano/example", ""));
}

pub fn configureCgroup(allocator: std.mem.Allocator, root: posix.fd_t, mode: CgroupMode, cgroup: *?posix.fd_t, hierarchies: []V1Hierarchy, options: libcontainer.CreateOptions, writes: []const Write, v1_writes: []const V1Write) libcontainer.Error!void {
    if (mode == .unified) {
        cgroup.* = (try walkCgroup(root, options.cgroup_path, !options.systemd, writes)) orelse return error.CreateFailed;
        for (writes) |write| try writeCgroupFile(cgroup.*.?, write.name, write.value, options.cgroup_path);
        // BPF_CGROUP_DEVICE needs CAP_SYS_ADMIN in the initial user
        // namespace, so a non-root runtime cannot enforce device rules.
        const no_bpf = options.rootless_cgroups and linux.geteuid() != 0;
        if (!no_bpf and !devicefilter.isAllowAll(options.resources.devices)) {
            const rules = try v2DeviceRules(allocator, options.resources.devices, options.devices);
            defer allocator.free(rules);
            try applyV2DeviceFilter(allocator, cgroup.*.?, rules, options.cgroup_path, false);
        }
    } else {
        for (hierarchies) |*hierarchy| {
            hierarchy.leaf = if (options.systemd) try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, options.cgroup_path, false, false) else null;
            if (hierarchy.leaf == null)
                hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, options.cgroup_path, true, hierarchy.has("cpuset"))).?;
        }
        try applyV1Writes(allocator, hierarchies, v1_writes, options.resources, options.devices, options.cgroup_path, true);
    }
}

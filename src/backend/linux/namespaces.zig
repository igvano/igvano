const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const oci = @import("../../oci.zig");
const diagnostics = @import("diagnostic.zig");
const checkResult = @import("syscall.zig").checkResult;
const forkProcess = @import("syscall.zig").forkProcess;
const makePipe = @import("syscall.zig").makePipe;
const closeFd = @import("syscall.zig").closeFd;
const waitChild = @import("syscall.zig").waitChild;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const failCreate = @import("diagnostic.zig").failCreate;

pub fn namespaceFlag(kind: @FieldType(oci.Spec.Namespace, "type")) usize {
    return switch (kind) {
        .pid => linux.CLONE.NEWPID,
        .network => linux.CLONE.NEWNET,
        .mount => linux.CLONE.NEWNS,
        .ipc => linux.CLONE.NEWIPC,
        .uts => linux.CLONE.NEWUTS,
        .user => linux.CLONE.NEWUSER,
        .cgroup => linux.CLONE.NEWCGROUP,
        .time => linux.CLONE.NEWTIME,
    };
}

/// Only namespaces without paths are unshared. Constants work on macOS too.
pub fn namespaceFlags(config: ?oci.Spec.Linux) Backend.Error!usize {
    const settings = config orelse return 0;
    const namespaces = settings.namespaces orelse return 0;
    var flags: usize = 0;
    var seen: usize = 0;
    for (namespaces) |namespace| {
        const flag = namespaceFlag(namespace.type);
        if (seen & flag != 0) return error.InvalidConfig;
        seen |= flag;
        if (namespace.path) |path| {
            if (!std.mem.startsWith(u8, path, "/") or std.mem.indexOfScalar(u8, path, 0) != null)
                return error.InvalidPath;
        } else flags |= flag;
    }
    return flags;
}

pub const NamespaceJoin = struct {
    flag: usize,
    path: [:0]const u8,
};

pub fn validateNamespaceFd(fd: posix.fd_t, flag: usize) Backend.Error!void {
    const result = linux.ioctl(fd, linux.IOCTL.IO(0xb7, 3), 0); // NS_GET_NSTYPE
    switch (linux.errno(result)) {
        .SUCCESS => if (result != flag) return error.InvalidConfig,
        // Old kernels lack NS_GET_NSTYPE; trust the configured type. setns
        // still validates that the descriptor refers to a namespace.
        .NOTTY => {},
        else => try checkResult(result),
    }
}

/// Open every host path before entering a user or mount namespace.
pub fn joinNamespaces(joins: []const NamespaceJoin) Backend.Error!void {
    return joinNamespacesWithUser(joins, null);
}

pub fn joinNamespacesWithUser(joins: []const NamespaceJoin, user_fd: ?posix.fd_t) Backend.Error!void {
    var fds: [8]posix.fd_t = @splat(-1);
    if (joins.len > fds.len) return error.InvalidConfig;
    defer for (fds) |fd| {
        if (fd >= 0) closeFd(fd);
    };
    for (joins, 0..) |join, i| {
        fds[i] = if (join.flag == linux.CLONE.NEWUSER and user_fd != null)
            user_fd.?
        else
            try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        try validateNamespaceFd(fds[i], join.flag);
    }
    try joinNamespaceFds(joins, fds[0..joins.len]);
}

pub fn joinNamespaceFds(joins: []const NamespaceJoin, fds: []const posix.fd_t) Backend.Error!void {
    // User first grants capabilities in the target owner; mount last keeps
    // host paths reachable until all other namespace operations have finished.
    for ([_]usize{
        linux.CLONE.NEWUSER, linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC,
        linux.CLONE.NEWUTS,  linux.CLONE.NEWNET,    linux.CLONE.NEWPID,
        linux.CLONE.NEWTIME, linux.CLONE.NEWNS,
    }) |flag| {
        for (joins, 0..) |join, i| {
            if (join.flag == flag and fds[i] >= 0) {
                checkResult(linux.setns(fds[i], @intCast(flag))) catch |err| {
                    reportDiagnostic("cannot join namespace {s}: {s}", .{ join.path, @errorName(err) });
                    return err;
                };
            }
        }
    }
}

pub fn mappedRootID(mappings: []const Backend.IDMapping) Backend.Error!u32 {
    for (mappings) |mapping| {
        if (mapping.container_id == 0 and mapping.size > 0) return mapping.host_id;
    }
    reportDiagnostic("user namespace mappings must include container root", .{});
    return error.InvalidConfig;
}

/// Linux may return ranges in a different order; compare every range exactly.
fn equalIDMappings(allocator: std.mem.Allocator, a: []const Backend.IDMapping, b: []const Backend.IDMapping) Backend.Error!bool {
    if (a.len != b.len) return false;
    const left = try allocator.dupe(Backend.IDMapping, a);
    defer allocator.free(left);
    const right = try allocator.dupe(Backend.IDMapping, b);
    defer allocator.free(right);
    const Order = struct {
        fn lessThan(_: void, x: Backend.IDMapping, y: Backend.IDMapping) bool {
            if (x.container_id != y.container_id) return x.container_id < y.container_id;
            if (x.host_id != y.host_id) return x.host_id < y.host_id;
            return x.size < y.size;
        }
    };
    std.mem.sort(Backend.IDMapping, left, {}, Order.lessThan);
    std.mem.sort(Backend.IDMapping, right, {}, Order.lessThan);
    comptime std.debug.assert(std.meta.hasUniqueRepresentation(Backend.IDMapping));
    return std.mem.eql(u8, std.mem.sliceAsBytes(left), std.mem.sliceAsBytes(right));
}

pub fn validateJoinedMappings(allocator: std.mem.Allocator, actual: Backend.MountMappings, configured: Backend.MountMappings) Backend.Error!void {
    if ((configured.uid.len != 0 and !try equalIDMappings(allocator, actual.uid, configured.uid)) or
        (configured.gid.len != 0 and !try equalIDMappings(allocator, actual.gid, configured.gid)))
    {
        reportDiagnostic("user namespace mappings do not match the joined namespace", .{});
        return error.InvalidConfig;
    }
}

fn readIDMappings(allocator: std.mem.Allocator, pid: i32, name: []const u8) Backend.Error![]Backend.IDMapping {
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/{s}", .{ pid, name }) catch unreachable;
    const fd = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(fd);
    var buffer: [16384]u8 = undefined;
    var used: usize = 0;
    while (true) {
        if (used == buffer.len) return error.InvalidConfig;
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(result) == .INTR) continue;
        try checkResult(result);
        if (result == 0) break;
        used += result;
    }
    var mappings: std.ArrayList(Backend.IDMapping) = .empty;
    defer mappings.deinit(allocator);
    var lines = std.mem.tokenizeScalar(u8, buffer[0..used], '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        var numbers: [3]u32 = undefined;
        for (&numbers) |*number| {
            const field = fields.next() orelse return error.InvalidConfig;
            number.* = std.fmt.parseInt(u32, field, 10) catch return error.InvalidConfig;
        }
        if (fields.next() != null) return error.InvalidConfig;
        try mappings.append(allocator, .{ .container_id = numbers[0], .host_id = numbers[1], .size = numbers[2] });
    }
    return mappings.toOwnedSlice(allocator);
}

/// The parent reads /proc/<helper>/ maps so host IDs use the runtime's namespace.
/// Like createMountUserNamespace, keep the helper alive with a pipe and reap it.
pub fn joinedUserNamespaceMappings(allocator: std.mem.Allocator, fd: posix.fd_t) Backend.Error!Backend.MountMappings {
    const ready = try makePipe();
    defer closeFd(ready[0]);
    var ready_writer: ?posix.fd_t = ready[1];
    defer if (ready_writer) |pipe_fd| closeFd(pipe_fd);
    const go = try makePipe();
    defer closeFd(go[0]);
    const child = forkProcess() catch |err| {
        closeFd(go[1]);
        return err;
    };
    if (child == 0) {
        closeFd(ready[0]);
        closeFd(go[1]);
        // Hide inherited host descriptors from processes in the joined namespace.
        checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(ready[1], err);
        checkResult(linux.setns(fd, linux.CLONE.NEWUSER)) catch |err| failCreate(ready[1], err);
        const response: CreateResponse = .{};
        if (!writeAll(ready[1], std.mem.asBytes(&response))) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        _ = readAll(go[0], &byte);
        linux.exit_group(0);
    }
    defer {
        closeFd(go[1]);
        _ = waitChild(child) catch {};
    }
    closeFd(ready[1]);
    ready_writer = null;
    var response: CreateResponse = .{};
    if (!readAll(ready[0], std.mem.asBytes(&response))) return error.CreateFailed;
    if (response.failureError()) |err| return err;
    const uid = try readIDMappings(allocator, child, "uid_map");
    errdefer allocator.free(uid);
    const gid = try readIDMappings(allocator, child, "gid_map");
    return .{ .uid = uid, .gid = gid };
}

pub fn formatIDMappings(allocator: std.mem.Allocator, mappings: []const oci.Spec.IDMapping) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (mappings) |mapping| {
        try text.print(allocator, "{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
    }
    return text.toOwnedSlice(allocator);
}

fn formatMountIDMappings(allocator: std.mem.Allocator, mappings: []const Backend.IDMapping) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (mappings) |mapping|
        try text.print(allocator, "{d} {d} {d}\n", .{ mapping.container_id, mapping.host_id, mapping.size });
    return text.toOwnedSlice(allocator);
}

/// A separate namespace also works when the container has no user namespace.
/// As in runc's userns helpers, keep the child alive until maps are installed
/// and the namespace is pinned, then reap it. Only the parent allocates.
pub fn createMountUserNamespace(allocator: std.mem.Allocator, mappings: Backend.MountMappings) Backend.Error!posix.fd_t {
    const uid_map = try formatMountIDMappings(allocator, mappings.uid);
    defer allocator.free(uid_map);
    const gid_map = try formatMountIDMappings(allocator, mappings.gid);
    defer allocator.free(gid_map);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    var ready_writer: ?posix.fd_t = ready[1];
    defer if (ready_writer) |fd| closeFd(fd);
    const go = try makePipe();
    defer closeFd(go[0]);
    // Keeping a reader here avoids SIGPIPE if the helper has already died.
    const child = forkProcess() catch |err| {
        closeFd(go[1]);
        return err;
    };
    if (child == 0) {
        closeFd(ready[0]);
        closeFd(go[1]);
        checkResult(linux.unshare(linux.CLONE.NEWUSER)) catch |err| failCreate(ready[1], err);
        var response: CreateResponse = .{};
        if (!writeAll(ready[1], std.mem.asBytes(&response))) linux.exit_group(1);
        closeFd(ready[1]);
        var byte: [1]u8 = undefined;
        _ = readAll(go[0], &byte);
        linux.exit_group(0);
    }
    defer {
        // EOF releases the helper on both success and failure.
        closeFd(go[1]);
        _ = waitChild(child) catch {};
    }
    closeFd(ready[1]);
    ready_writer = null;
    var response: CreateResponse = .{};
    if (!readAll(ready[0], std.mem.asBytes(&response))) return error.CreateFailed;
    if (response.failureError()) |err| return err;
    try writeUserMappings(child, gid_map, uid_map);
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/user", .{child}) catch unreachable;
    return openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
}

/// The runtime parent writes maps from its original user namespace.
pub fn writeUserMappings(pid: i32, gid_map: []const u8, uid_map: []const u8) Backend.Error!void {
    var path_buffer: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}", .{pid}) catch unreachable;
    const dir = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    // setgroups defaults to "allow"; only rootless setup needs a "deny" write.
    try writeMappingFile(dir, "gid_map", gid_map);
    try writeMappingFile(dir, "uid_map", uid_map);
}

fn writeMappingFile(dir: posix.fd_t, name: [*:0]const u8, text: []const u8) Backend.Error!void {
    const fd = try openPath(dir, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
    defer closeFd(fd);
    // proc ID maps must be supplied in a single write.
    while (true) {
        const result = linux.write(fd, text.ptr, text.len);
        if (linux.errno(result) == .INTR) continue;
        if (linux.errno(result) == .INVAL) return error.InvalidConfig;
        try checkResult(result);
        if (result != text.len) return error.CreateFailed;
        return;
    }
}

test "namespace flags map each namespace and combine flags without system calls" {
    const cases = .{
        .{ .pid, linux.CLONE.NEWPID },
        .{ .network, linux.CLONE.NEWNET },
        .{ .mount, linux.CLONE.NEWNS },
        .{ .ipc, linux.CLONE.NEWIPC },
        .{ .uts, linux.CLONE.NEWUTS },
        .{ .user, linux.CLONE.NEWUSER },
        .{ .cgroup, linux.CLONE.NEWCGROUP },
        .{ .time, linux.CLONE.NEWTIME },
    };
    inline for (cases) |case| {
        try std.testing.expectEqual(@as(usize, case[1]), try namespaceFlags(.{ .namespaces = &.{.{ .type = case[0] }} }));
    }
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(null));
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(.{}));
    try std.testing.expectEqual(
        @as(usize, linux.CLONE.NEWPID | linux.CLONE.NEWUTS | linux.CLONE.NEWNS),
        try namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount } } }),
    );
}

test "namespace flags reject duplicate types" {
    try std.testing.expectError(
        error.InvalidConfig,
        namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount }, .{ .type = .pid } } }),
    );
}

test "namespace flags exclude joins including existing user namespaces" {
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(.{
        .namespaces = &.{.{ .type = .network, .path = "/proc/1234/ns/net" }},
    }));
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWNS), try namespaceFlags(.{
        .namespaces = &.{ .{ .type = .mount }, .{ .type = .user, .path = "/proc/1234/ns/user" } },
    }));
    const mappings: []const oci.Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }};
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWUSER | linux.CLONE.NEWNS), try namespaceFlags(.{
        .namespaces = &.{ .{ .type = .user }, .{ .type = .mount } },
        .uidMappings = mappings,
        .gidMappings = mappings,
    }));
}

test "namespace paths reject empty relative and NUL paths and duplicate joins" {
    for ([_][]const u8{ "", "relative", "/proc/1/ns/net\x00" }) |path| {
        try std.testing.expectError(error.InvalidPath, namespaceFlags(.{
            .namespaces = &.{.{ .type = .network, .path = path }},
        }));
    }
    try std.testing.expectError(error.InvalidConfig, namespaceFlags(.{
        .namespaces = &.{ .{ .type = .network, .path = "/proc/1/ns/net" }, .{ .type = .network } },
    }));
}

test "ID mapping lines preserve order and decimal IDs" {
    const text = try formatIDMappings(std.testing.allocator, &.{
        .{ .containerID = 0, .hostID = 100000, .size = 65536 },
        .{ .containerID = 100000, .hostID = 200000, .size = 1 },
    });
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("0 100000 65536\n100000 200000 1\n", text);
}

test "FIFO ownership uses namespace root's mapped host UID and GID" {
    try std.testing.expectEqual(@as(u32, 100000), try mappedRootID(&.{
        .{ .container_id = 10, .host_id = 300000, .size = 10 },
        .{ .container_id = 0, .host_id = 100000, .size = 10 },
    }));
    try std.testing.expectEqual(@as(u32, 200000), try mappedRootID(&.{.{ .container_id = 0, .host_id = 200000, .size = 10 }}));
    try std.testing.expectEqual(@as(u32, 0), try mappedRootID(&.{.{ .container_id = 0, .host_id = 0, .size = 1 }}));
    for ([_][]const Backend.IDMapping{
        &.{},
        &.{.{ .container_id = 1, .host_id = 100000, .size = 10 }},
        &.{.{ .container_id = 0, .host_id = 100000, .size = 0 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, mappedRootID(mappings));
    }
}

test "joined user namespace mappings compare ranges without regard to order" {
    defer diagnostics.last_diagnostic_len = 0;
    const mappings: []const Backend.IDMapping = &.{
        .{ .container_id = 0, .host_id = 1000, .size = 10 },
        .{ .container_id = 20, .host_id = 2000, .size = 2 },
    };
    const reversed: []const Backend.IDMapping = &.{ mappings[1], mappings[0] };
    const actual: Backend.MountMappings = .{ .uid = mappings, .gid = reversed };
    try validateJoinedMappings(std.testing.allocator, actual, .{ .uid = reversed, .gid = mappings });
    try validateJoinedMappings(std.testing.allocator, actual, .{});
    try validateJoinedMappings(std.testing.allocator, actual, .{ .uid = reversed });
    try validateJoinedMappings(std.testing.allocator, actual, .{ .gid = mappings });
    for ([_][]const Backend.IDMapping{
        mappings[0..1],
        &.{ mappings[0], mappings[0] },
        &.{ mappings[0], mappings[1], .{ .container_id = 30, .host_id = 3000, .size = 1 } },
        &.{ mappings[0], .{ .container_id = 21, .host_id = 2000, .size = 2 } },
        &.{ mappings[0], .{ .container_id = 20, .host_id = 2001, .size = 2 } },
        &.{ mappings[0], .{ .container_id = 20, .host_id = 2000, .size = 1 } },
    }) |wrong| {
        try std.testing.expectError(error.InvalidConfig, validateJoinedMappings(std.testing.allocator, actual, .{ .uid = wrong, .gid = mappings }));
        try std.testing.expectEqualStrings("user namespace mappings do not match the joined namespace", diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
        try std.testing.expectError(error.InvalidConfig, validateJoinedMappings(std.testing.allocator, actual, .{ .uid = mappings, .gid = wrong }));
    }
    // Equal lengths and membership do not account for duplicate multiplicities.
    try std.testing.expectError(error.InvalidConfig, validateJoinedMappings(
        std.testing.allocator,
        .{ .uid = &.{ mappings[0], mappings[0], mappings[1] } },
        .{ .uid = &.{ mappings[0], mappings[1], mappings[1] } },
    ));
}

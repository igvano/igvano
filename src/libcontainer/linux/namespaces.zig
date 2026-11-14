const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
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

pub fn namespaceFlag(kind: libcontainer.Namespace.Kind) usize {
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
pub fn namespaceFlags(namespaces: []const libcontainer.Namespace) libcontainer.Error!usize {
    var flags: usize = 0;
    var seen: usize = 0;
    for (namespaces) |namespace| {
        const flag = namespaceFlag(namespace.kind);
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

pub fn validateNamespaceFd(fd: posix.fd_t, flag: usize) libcontainer.Error!void {
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
pub fn joinNamespaces(joins: []const NamespaceJoin) libcontainer.Error!void {
    return joinNamespacesWithUser(joins, null);
}

pub fn joinNamespacesWithUser(joins: []const NamespaceJoin, user_fd: ?posix.fd_t) libcontainer.Error!void {
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

/// Like runc's join_namespaces: first the non-user namespaces we may
/// already join (EPERM skips one), then the user namespace, then the rest,
/// which the joined user namespace may now let us join. Mount goes last so
/// host paths stay reachable until the other joins are done.
pub fn joinNamespaceFds(joins: []const NamespaceJoin, fds: []const posix.fd_t) libcontainer.Error!void {
    var joined: [8]bool = @splat(false);
    try joinPass(joins, fds, &joined, false, true);
    try joinPass(joins, fds, &joined, true, false);
    try joinPass(joins, fds, &joined, false, false);
}

const join_order = [_]usize{
    linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC,  linux.CLONE.NEWUTS, linux.CLONE.NEWNET,
    linux.CLONE.NEWPID,    linux.CLONE.NEWTIME, linux.CLONE.NEWNS,
};

fn joinPass(joins: []const NamespaceJoin, fds: []const posix.fd_t, joined: *[8]bool, user: bool, skip_perm: bool) libcontainer.Error!void {
    const order: []const usize = if (user) &.{linux.CLONE.NEWUSER} else &join_order;
    for (order) |flag| {
        for (joins, 0..) |join, i| {
            if (join.flag != flag or fds[i] < 0 or joined[i]) continue;
            const result = linux.setns(fds[i], @intCast(flag));
            if (skip_perm and linux.errno(result) == .PERM) continue;
            checkResult(result) catch |err| {
                reportDiagnostic("cannot join namespace {s}: {s}", .{ join.path, @errorName(err) });
                return err;
            };
            // Like runc, become root in a joined user namespace.
            if (flag == linux.CLONE.NEWUSER) checkResult(linux.setresuid(0, 0, 0)) catch |err| {
                reportDiagnostic("failed to become root in user namespace", .{});
                return err;
            };
            joined[i] = true;
        }
    }
}

pub fn mappedRootID(mappings: []const libcontainer.IDMapping) libcontainer.Error!u32 {
    for (mappings) |mapping| {
        if (mapping.container_id == 0 and mapping.size > 0) return mapping.host_id;
    }
    reportDiagnostic("user namespace mappings must include container root", .{});
    return error.InvalidConfig;
}

/// Linux may return ranges in a different order; compare every range exactly.
fn equalIDMappings(allocator: std.mem.Allocator, a: []const libcontainer.IDMapping, b: []const libcontainer.IDMapping) libcontainer.Error!bool {
    if (a.len != b.len) return false;
    const left = try allocator.dupe(libcontainer.IDMapping, a);
    defer allocator.free(left);
    const right = try allocator.dupe(libcontainer.IDMapping, b);
    defer allocator.free(right);
    const Order = struct {
        fn lessThan(_: void, x: libcontainer.IDMapping, y: libcontainer.IDMapping) bool {
            if (x.container_id != y.container_id) return x.container_id < y.container_id;
            if (x.host_id != y.host_id) return x.host_id < y.host_id;
            return x.size < y.size;
        }
    };
    std.mem.sort(libcontainer.IDMapping, left, {}, Order.lessThan);
    std.mem.sort(libcontainer.IDMapping, right, {}, Order.lessThan);
    comptime std.debug.assert(std.meta.hasUniqueRepresentation(libcontainer.IDMapping));
    return std.mem.eql(u8, std.mem.sliceAsBytes(left), std.mem.sliceAsBytes(right));
}

pub fn validateJoinedMappings(allocator: std.mem.Allocator, actual: libcontainer.MountMappings, configured: libcontainer.MountMappings) libcontainer.Error!void {
    if ((configured.uid.len != 0 and !try equalIDMappings(allocator, actual.uid, configured.uid)) or
        (configured.gid.len != 0 and !try equalIDMappings(allocator, actual.gid, configured.gid)))
    {
        reportDiagnostic("user namespace mappings do not match the joined namespace", .{});
        return error.InvalidConfig;
    }
}

fn readIDMappings(allocator: std.mem.Allocator, pid: i32, name: []const u8) libcontainer.Error![]libcontainer.IDMapping {
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
    var mappings: std.ArrayList(libcontainer.IDMapping) = .empty;
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
pub fn joinedUserNamespaceMappings(allocator: std.mem.Allocator, fd: posix.fd_t) libcontainer.Error!libcontainer.MountMappings {
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

pub fn formatIDMappings(allocator: std.mem.Allocator, mappings: []const libcontainer.IDMapping) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (mappings) |mapping| {
        try text.print(allocator, "{d} {d} {d}\n", .{ mapping.container_id, mapping.host_id, mapping.size });
    }
    return text.toOwnedSlice(allocator);
}

/// A separate namespace also works when the container has no user namespace.
/// As in runc's userns helpers, keep the child alive until maps are installed
/// and the namespace is pinned, then reap it. Only the parent allocates.
pub fn createMountUserNamespace(allocator: std.mem.Allocator, mappings: libcontainer.MountMappings) libcontainer.Error!posix.fd_t {
    const uid_map = try formatIDMappings(allocator, mappings.uid);
    defer allocator.free(uid_map);
    const gid_map = try formatIDMappings(allocator, mappings.gid);
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
    try writeUserMappings(child, gid_map, uid_map, .{});
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/user", .{child}) catch unreachable;
    return openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
}

/// How a non-root runtime writes ID maps, as in runc's nsexec.
pub const MappingTools = struct {
    /// The runtime's effective UID is not 0.
    rootless: bool = false,
    /// newuidmap/newgidmap from shadow-utils, tried when a map write gets EPERM.
    newuidmap: ?[:0]const u8 = null,
    newgidmap: ?[:0]const u8 = null,
};

/// The runtime parent writes maps from its original user namespace.
pub fn writeUserMappings(pid: i32, gid_map: []const u8, uid_map: []const u8, tools: MappingTools) libcontainer.Error!void {
    var path_buffer: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}", .{pid}) catch unreachable;
    const dir = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    // setgroups defaults to "allow". The kernel only lets an unprivileged
    // user map its own GID after "deny"; other maps go through newgidmap.
    if (tools.rootless and onlySelfGidMap(gid_map)) try writeMappingFile(dir, "setgroups", "deny");
    try writeMapping(dir, pid, "gid_map", gid_map, tools.newgidmap);
    try writeMapping(dir, pid, "uid_map", uid_map, tools.newuidmap);
}

/// runc's requiresRootOrMappingTool, inverted: exactly "0 <egid> 1".
fn onlySelfGidMap(gid_map: []const u8) bool {
    var buffer: [32]u8 = undefined;
    const self = std.fmt.bufPrint(&buffer, "0 {d} 1\n", .{linux.getegid()}) catch return false;
    return std.mem.eql(u8, gid_map, self);
}

test "only a single map of the caller's own GID needs setgroups deny" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var buffer: [64]u8 = undefined;
    const gid = linux.getegid();
    try std.testing.expect(onlySelfGidMap(try std.fmt.bufPrint(&buffer, "0 {d} 1\n", .{gid})));
    try std.testing.expect(!onlySelfGidMap(try std.fmt.bufPrint(&buffer, "0 {d} 2\n", .{gid})));
    try std.testing.expect(!onlySelfGidMap(try std.fmt.bufPrint(&buffer, "0 {d} 1\n1 200000 65536\n", .{gid})));
    try std.testing.expect(!onlySelfGidMap(try std.fmt.bufPrint(&buffer, "0 {d} 1\n", .{gid +% 1})));
}

fn writeMapping(dir: posix.fd_t, pid: i32, name: [*:0]const u8, text: []const u8, tool: ?[:0]const u8) libcontainer.Error!void {
    if (text.len == 0) return;
    writeMappingFile(dir, name, text) catch |err| {
        const path = tool orelse return err;
        if (err != error.PermissionDenied) return err;
        return runMappingTool(path, pid, text);
    };
}

/// newuidmap <pid> <container> <host> <size>...; maps are already validated
/// to at most 340 ranges, so the argument array is bounded.
fn runMappingTool(tool: [:0]const u8, pid: i32, text: []const u8) libcontainer.Error!void {
    var args: [2 + 3 * 340 + 1]?[*:0]const u8 = @splat(null);
    var words: [3 * 340][16]u8 = undefined;
    var pid_buffer: [16]u8 = undefined;
    args[0] = tool.ptr;
    args[1] = (std.fmt.bufPrintZ(&pid_buffer, "{d}", .{pid}) catch unreachable).ptr;
    var count: usize = 0;
    var fields = std.mem.tokenizeAny(u8, text, " \n");
    while (fields.next()) |field| : (count += 1) {
        if (count == words.len) return error.InvalidConfig;
        args[2 + count] = (std.fmt.bufPrintZ(&words[count], "{s}", .{field}) catch return error.InvalidConfig).ptr;
    }
    const envp = [_:null]?[*:0]const u8{};
    const child = try forkProcess();
    if (child == 0) {
        _ = linux.execve(tool.ptr, @ptrCast(&args), &envp);
        linux.exit_group(127);
    }
    if (try waitChild(child) != 0) {
        reportDiagnostic("{s} {d} failed", .{ tool, pid });
        return error.PermissionDenied;
    }
}

fn writeMappingFile(dir: posix.fd_t, name: [*:0]const u8, text: []const u8) libcontainer.Error!void {
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
        try std.testing.expectEqual(@as(usize, case[1]), try namespaceFlags(&.{.{ .kind = case[0] }}));
    }
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(&.{}));
    try std.testing.expectEqual(
        @as(usize, linux.CLONE.NEWPID | linux.CLONE.NEWUTS | linux.CLONE.NEWNS),
        try namespaceFlags(&.{ .{ .kind = .pid }, .{ .kind = .uts }, .{ .kind = .mount } }),
    );
}

test "namespace flags reject duplicate types" {
    try std.testing.expectError(
        error.InvalidConfig,
        namespaceFlags(&.{ .{ .kind = .pid }, .{ .kind = .uts }, .{ .kind = .mount }, .{ .kind = .pid } }),
    );
}

test "namespace flags exclude joins including existing user namespaces" {
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(&.{.{ .kind = .network, .path = "/proc/1234/ns/net" }}));
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWNS), try namespaceFlags(&.{ .{ .kind = .mount }, .{ .kind = .user, .path = "/proc/1234/ns/user" } }));
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWUSER | linux.CLONE.NEWNS), try namespaceFlags(&.{ .{ .kind = .user }, .{ .kind = .mount } }));
}

test "namespace paths reject empty relative and NUL paths and duplicate joins" {
    for ([_][]const u8{ "", "relative", "/proc/1/ns/net\x00" }) |path| {
        try std.testing.expectError(error.InvalidPath, namespaceFlags(&.{.{ .kind = .network, .path = path }}));
    }
    try std.testing.expectError(error.InvalidConfig, namespaceFlags(&.{ .{ .kind = .network, .path = "/proc/1/ns/net" }, .{ .kind = .network } }));
}

test "ID mapping lines preserve order and decimal IDs" {
    const text = try formatIDMappings(std.testing.allocator, &.{
        .{ .container_id = 0, .host_id = 100000, .size = 65536 },
        .{ .container_id = 100000, .host_id = 200000, .size = 1 },
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
    for ([_][]const libcontainer.IDMapping{
        &.{},
        &.{.{ .container_id = 1, .host_id = 100000, .size = 10 }},
        &.{.{ .container_id = 0, .host_id = 100000, .size = 0 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, mappedRootID(mappings));
    }
}

test "joined user namespace mappings compare ranges without regard to order" {
    defer diagnostics.last_diagnostic_len = 0;
    const mappings: []const libcontainer.IDMapping = &.{
        .{ .container_id = 0, .host_id = 1000, .size = 10 },
        .{ .container_id = 20, .host_id = 2000, .size = 2 },
    };
    const reversed: []const libcontainer.IDMapping = &.{ mappings[1], mappings[0] };
    const actual: libcontainer.MountMappings = .{ .uid = mappings, .gid = reversed };
    try validateJoinedMappings(std.testing.allocator, actual, .{ .uid = reversed, .gid = mappings });
    try validateJoinedMappings(std.testing.allocator, actual, .{});
    try validateJoinedMappings(std.testing.allocator, actual, .{ .uid = reversed });
    try validateJoinedMappings(std.testing.allocator, actual, .{ .gid = mappings });
    for ([_][]const libcontainer.IDMapping{
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

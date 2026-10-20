const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../root.zig").Backend;
const OPEN_TREE_CLONE = @import("mount.zig").OPEN_TREE_CLONE;
const OPEN_TREE_CLOEXEC = @import("mount.zig").OPEN_TREE_CLOEXEC;
const MOUNT_ATTR_IDMAP = @import("mount.zig").MOUNT_ATTR_IDMAP;
const MountAttr = @import("mount.zig").MountAttr;
const PreparedMount = @import("mount.zig").PreparedMount;
const RESOLVE_NO_MAGICLINKS = @import("syscall.zig").RESOLVE_NO_MAGICLINKS;
const RESOLVE_NO_SYMLINKS = @import("syscall.zig").RESOLVE_NO_SYMLINKS;
const OpenHow = @import("syscall.zig").OpenHow;
const pathString = @import("syscall.zig").pathString;
const checkResult = @import("syscall.zig").checkResult;
const forkProcess = @import("syscall.zig").forkProcess;
const closeFd = @import("syscall.zig").closeFd;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const failCreate = @import("diagnostic.zig").failCreate;
const validateNamespaceFd = @import("namespaces.zig").validateNamespaceFd;
const createMountUserNamespace = @import("namespaces.zig").createMountUserNamespace;
const RootfsStep = @import("rootfs.zig").RootfsStep;
const console = @import("console.zig").console;

pub fn closeMountFds(mounts: []const PreparedMount) void {
    for (mounts) |mount| {
        if (mount.source_fd) |fd| closeFd(fd);
        if (mount.mount_fd) |fd| closeFd(fd);
        if (mount.userns_fd) |fd| closeFd(fd);
    }
}

/// Prepare mapping namespaces before fork; clones must come from init's mount
/// namespace so they inherit its MNT_LOCK_* protection.
pub fn prepareIDMappedMounts(allocator: std.mem.Allocator, mounts: []PreparedMount) Backend.Error!void {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    for (mounts) |*mount| {
        const mappings = mount.mappings orelse continue;
        var step: RootfsStep = .{ .operation = "prepare idmapping user namespace", .source = mount.source, .path = mount.destination };
        errdefer |err| if (step.operation.len != 0) step.report(err);
        const userns = if (mappings.userns_path) |path| existing: {
            const namespace_path = try pathString(allocator, path);
            defer allocator.free(namespace_path);
            break :existing try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
        } else try createMountUserNamespace(allocator, mappings);
        errdefer closeFd(userns);
        try validateNamespaceFd(userns, linux.CLONE.NEWUSER);
        mount.userns_fd = userns;
    }
}

/// Host credentials are needed for private sources and idmapping superblocks.
/// Join only init's mount namespace: opening sources there pins its locked
/// mounts, rather than unlocked host mounts. In particular, a mount namespace
/// joined by path resolves bind sources there, just as ordinary binds do.
/// Sources opened with host credentials in this mode must contain no symlinks.
/// Ordinary bind mounts opened in the runtime's own namespace still allow them.
pub fn startMountSourceHelper(mounts: []const PreparedMount) Backend.Error!struct { pid: i32, socket: posix.fd_t } {
    const sockets = try console.socketpair();
    errdefer for (sockets) |fd| closeFd(fd);
    const child = try forkProcess();
    if (child == 0) {
        closeFd(sockets[1]);
        checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(sockets[0], err);
        const namespace = console.receiveFd(sockets[0]) catch linux.exit_group(1);
        checkResult(linux.setns(namespace, linux.CLONE.NEWNS)) catch |err| failCreate(sockets[0], err);
        closeFd(namespace);
        sendMountSources(mounts, sockets[0]) catch |err| failCreate(sockets[0], err);
        linux.exit_group(0);
    }
    closeFd(sockets[0]);
    return .{ .pid = child, .socket = sockets[1] };
}

pub fn sendMountSources(mounts: []const PreparedMount, socket: posix.fd_t) Backend.Error!void {
    for (mounts) |mount| {
        if (mount.flags & linux.MS.BIND == 0) continue;
        var step: RootfsStep = .{ .operation = "open bind source", .source = mount.source, .path = mount.destination };
        errdefer |err| if (step.operation.len != 0) step.report(err);
        const source = mount.source orelse return error.InvalidConfig;
        const how: OpenHow = .{
            .flags = @as(u32, @bitCast(linux.O{ .PATH = true, .CLOEXEC = true })),
            .resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        const opened = linux.syscall4(.openat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(source.ptr), @intFromPtr(&how), @sizeOf(OpenHow));
        if (linux.errno(opened) == .LOOP) {
            step.operation = "";
            reportDiagnostic("bind source {s} contains a symlink; symlinks are not allowed when joining a mount namespace", .{source});
            return error.CreateFailed;
        }
        try checkResult(opened);
        const source_fd: posix.fd_t = @intCast(opened);
        defer closeFd(source_fd);
        var prepared = mount;
        prepared.source_fd = source_fd;
        step.operation = "";
        const tree = if (mount.userns_fd) |userns| try cloneIDMappedMount(prepared, userns) else null;
        defer if (tree) |fd| closeFd(fd);
        const response: CreateResponse = .{};
        if (!writeAll(socket, std.mem.asBytes(&response))) return error.CreateFailed;
        try console.sendFd(socket, tree orelse source_fd);
    }
}

pub fn receiveMountSources(mounts: []PreparedMount, socket: posix.fd_t, namespace: posix.fd_t) Backend.Error!void {
    try console.sendFd(socket, namespace);
    for (mounts) |*mount| {
        if (mount.flags & linux.MS.BIND == 0) continue;
        var response: CreateResponse = .{};
        if (!readAll(socket, std.mem.asBytes(&response))) return mountSourceHelperExited();
        if (response.failureError()) |err| return err;
        const fd = (try console.receiveFdOrEof(socket)) orelse return mountSourceHelperExited();
        if (mount.mappings != null) mount.mount_fd = fd else mount.source_fd = fd;
    }
}

fn mountSourceHelperExited() Backend.Error {
    reportDiagnostic("mount source helper exited unexpectedly", .{});
    return error.CreateFailed;
}

/// Called with host credentials inside the container's mount namespace.
/// open_tree copies the source's kernel locks, including for recursive binds.
pub fn cloneIDMappedMount(mount: PreparedMount, userns: posix.fd_t) Backend.Error!posix.fd_t {
    var step: RootfsStep = .{ .operation = "open_tree for idmapped mount", .source = mount.source, .path = mount.destination };
    errdefer |err| if (step.operation.len != 0) step.report(err);
    const source = mount.source orelse return error.InvalidConfig;
    const mappings = mount.mappings orelse return error.InvalidConfig;
    const source_fd = mount.source_fd orelse try openPath(linux.AT.FDCWD, source, .{ .PATH = true, .CLOEXEC = true });
    defer if (mount.source_fd == null) closeFd(source_fd);
    const clone_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | linux.AT.EMPTY_PATH |
        (if (mount.flags & linux.MS.REC != 0) @as(u32, linux.AT.RECURSIVE) else 0);
    const cloned = linux.syscall3(.open_tree, @intCast(source_fd), @intFromPtr(""), clone_flags);
    try checkResult(cloned);
    const fd: posix.fd_t = @intCast(cloned);
    errdefer closeFd(fd);
    const attr: MountAttr = .{ .attr_set = MOUNT_ATTR_IDMAP, .userns_fd = @intCast(userns) };
    const attr_flags = linux.AT.EMPTY_PATH | (if (mappings.recursive) @as(u32, linux.AT.RECURSIVE) else 0);
    const result = linux.syscall5(.mount_setattr, @intCast(fd), @intFromPtr(""), attr_flags, @intFromPtr(&attr), @sizeOf(MountAttr));
    if (linux.errno(result) != .SUCCESS) {
        step.operation = "";
        reportDiagnostic("cannot idmap mount '{s}' ({s}): mount_setattr(MOUNT_ATTR_IDMAP): {s}{s}", .{
            mount.destination, source, @tagName(linux.errno(result)),
            switch (linux.errno(result)) {
                .INVAL, .NOSYS, .OPNOTSUPP => "; kernel or filesystem does not support idmapped mounts",
                .PERM => "; kernel or filesystem does not support idmapped mounts, or permission was denied",
                else => "",
            },
        });
        try checkResult(result);
    }
    return fd;
}

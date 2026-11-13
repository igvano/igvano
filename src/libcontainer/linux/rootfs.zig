const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const hooks = @import("../hooks.zig");
const needsSetupDev = @import("mount.zig").needsSetupDev;
const PreparedMount = @import("mount.zig").PreparedMount;
const bindRemount = @import("mount.zig").bindRemount;
const applyMount = @import("mount.zig").applyMount;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const fdPath = @import("syscall.zig").fdPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const childError = @import("diagnostic.zig").childError;
const failCreate = @import("diagnostic.zig").failCreate;
const readMountinfo = @import("mountinfo.zig").readMountinfo;
const MountInfo = @import("mountinfo.zig").MountInfo;
const mountinfoPath = @import("mountinfo.zig").mountinfoPath;
const setupConsole = @import("console.zig").setupConsole;
const consolePath = @import("console.zig").consolePath;
const closeMountFds = @import("mount_sources.zig").closeMountFds;
const receiveMountSource = @import("mount_sources.zig").receiveMountSource;
const PreparedDevice = @import("device_nodes.zig").PreparedDevice;
const setupDevices = @import("device_nodes.zig").setupDevices;
const setupSymlinks = @import("device_nodes.zig").setupSymlinks;
const applySysctls = @import("procfs.zig").applySysctls;

/// A self-bind has the same filesystem root as its directory in the parent
/// mount. This checks its shape, not ownership; mountinfo IDs are reusable.
fn isRootfsSelfBind(text: []const u8, mount_id: u64, path: []const u8) libcontainer.Error!bool {
    var mount: ?MountInfo = null;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const entry = try MountInfo.parse(line);
        if (entry.id == mount_id) {
            mount = entry;
            break;
        }
    }
    const entry = mount orelse return false;
    var point_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (!std.mem.eql(u8, try mountinfoPath(&point_buffer, entry.mountpoint), path) or
        std.mem.eql(u8, path, "/")) return false;
    lines.reset();
    while (lines.next()) |line| {
        const parent = try MountInfo.parse(line);
        if (parent.id != entry.parent) continue;
        return selfBindRootMatches(entry, parent, path);
    }
    return false;
}

fn selfBindRootMatches(entry: MountInfo, parent: MountInfo, path: []const u8) libcontainer.Error!bool {
    if (!std.mem.eql(u8, entry.device, parent.device)) return false;
    var point_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const parent_point = try mountinfoPath(&point_buffer, parent.mountpoint);
    const relative = if (std.mem.eql(u8, parent_point, "/"))
        path[1..]
    else if (std.mem.eql(u8, parent_point, path))
        ""
    else if (std.mem.startsWith(u8, path, parent_point) and path.len > parent_point.len and path[parent_point.len] == '/')
        path[parent_point.len + 1 ..]
    else
        return false;
    var parent_root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const parent_root = try mountinfoPath(&parent_root_buffer, parent.root);
    var expected_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buffer, "{s}{s}{s}", .{
        parent_root,
        if (relative.len == 0 or std.mem.eql(u8, parent_root, "/")) "" else "/",
        relative,
    }) catch return error.InvalidPath;
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    return std.mem.eql(u8, try mountinfoPath(&root_buffer, entry.root), expected);
}

pub fn mountId(fd: posix.fd_t) libcontainer.Error!u64 {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .MNT_ID_UNIQUE = true }, &stat));
    if (!stat.mask.MNT_ID_UNIQUE) return error.Unsupported;
    return stat.mnt_id;
}

pub fn bootId() libcontainer.Error![36]u8 {
    const fd = try openPath(linux.AT.FDCWD, "/proc/sys/kernel/random/boot_id", .{ .CLOEXEC = true });
    defer closeFd(fd);
    var id: [36]u8 = undefined;
    if (!readAll(fd, &id)) return error.CreateFailed;
    return id;
}

// Linux 6.8 UAPI: STATMOUNT_MNT_BASIC supplies both unique and mountinfo IDs.
const StatMount = extern struct {
    size: u32,
    spare1: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_propagation_source: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    spare2: [50]u64,
};

pub fn statMount(id: u64) libcontainer.Error!?StatMount {
    const Request = extern struct {
        size: u32 = @sizeOf(@This()),
        spare: u32 = 0,
        mnt_id: u64,
        param: u64 = 2, // STATMOUNT_MNT_BASIC
    };
    const request: Request = .{ .mnt_id = id };
    var result: StatMount = undefined;
    switch (linux.errno(linux.syscall4(.statmount, @intFromPtr(&request), @intFromPtr(&result), @sizeOf(StatMount), 0))) {
        .SUCCESS => {},
        .NOENT => return null,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
    if (result.mask & 2 == 0 or result.mnt_id != id) return error.Unsupported;
    return result;
}

const RootfsMountIdentity = union(enum) {
    /// Used when init failed before reporting its newly created mount.
    before_create: u64,
    created: u64,
};

/// Configured mounts at "/" cover the self-bind, but remain its descendants.
fn rootfsSelfBindId(text: []const u8, current_id: u64, path: []const u8, identity: RootfsMountIdentity) libcontainer.Error!?u64 {
    var id = current_id;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    while (true) {
        const stat = (try statMount(id)) orelse return null;
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        const entry = find: {
            while (lines.next()) |line| {
                const mount = try MountInfo.parse(line);
                if (mount.id == stat.mnt_id_old) break :find mount;
            }
            return null;
        };
        if (!std.mem.eql(u8, try mountinfoPath(&buffer, entry.mountpoint), path)) return null;
        const owned = switch (identity) {
            .created => |created| id == created,
            .before_create => |before| id != before and stat.mnt_parent_id == before,
        };
        if (owned) return if (try isRootfsSelfBind(text, stat.mnt_id_old, path)) id else null;
        if (stat.mnt_parent_id == id) return null;
        id = stat.mnt_parent_id;
    }
}

pub fn detachRootfs(path: []const u8, identity: RootfsMountIdentity) libcontainer.Error!void {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.InvalidPath;
    while (true) {
        const opened = linux.openat(linux.AT.FDCWD, path_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
        switch (linux.errno(opened)) {
            .NOENT => return,
            else => try checkResult(opened),
        }
        const fd: posix.fd_t = @intCast(opened);
        defer closeFd(fd);
        const current_id = try mountId(fd);
        var fd_buffer: [64]u8 = undefined;
        var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const size = linux.readlink(fdPath(&fd_buffer, fd), &resolved_buffer, resolved_buffer.len);
        try checkResult(size);
        if (size == resolved_buffer.len) return error.InvalidPath;
        const text = try readMountinfo(std.heap.page_allocator);
        defer std.heap.page_allocator.free(text);
        const owned_id = (try rootfsSelfBindId(text, current_id, resolved_buffer[0..size], identity)) orelse return;
        // Recursive binds can retain host peers. As in the pivot_root path, cut
        // propagation on the owned tree before detach can unmount those peers.
        try checkResult(linux.mount(null, fdPath(&fd_buffer, fd), null, linux.MS.SLAVE | linux.MS.REC, 0));
        // Address the pinned mount, rather than a replacement at the original path.
        switch (linux.errno(linux.umount2(fdPath(&fd_buffer, fd), linux.MNT.DETACH))) {
            .SUCCESS => if (current_id == owned_id) return,
            .INVAL, .NOENT => return,
            else => return error.CreateFailed,
        }
    }
}

test "rootfs cleanup recognizes self-binds including escaped paths and bind-mounted parents" {
    const text =
        \\1 0 8:1 / / rw - ext4 /dev/root rw
        \\2 1 8:1 /containers /runtime rw - ext4 /dev/root rw
        \\3 2 8:1 /containers/rootfs\040space /runtime/rootfs\040space rw - ext4 /dev/root rw
        \\4 2 0:42 / /runtime/tmpfs rw - tmpfs tmpfs rw
        \\5 2 8:1 /elsewhere /runtime/other-bind rw - ext4 /dev/root rw
        \\6 1 8:1 /rootfs /rootfs rw - ext4 /dev/root rw
    ;
    try std.testing.expect(try isRootfsSelfBind(text, 3, "/runtime/rootfs space"));
    try std.testing.expect(try isRootfsSelfBind(text, 6, "/rootfs"));
    try std.testing.expect(!try isRootfsSelfBind(text, 4, "/runtime/tmpfs"));
    try std.testing.expect(!try isRootfsSelfBind(text, 5, "/runtime/other-bind"));
    try std.testing.expect(!try isRootfsSelfBind(text, 2, "/runtime"));
    try std.testing.expect(!try isRootfsSelfBind(text, 1, "/"));
    try std.testing.expect(!try isRootfsSelfBind(text, 3, "/runtime"));
    try std.testing.expect(!try isRootfsSelfBind(text, 99, "/missing"));
}

pub const RootfsStep = struct {
    operation: []const u8 = "",
    path: []const u8 = "",
    source: ?[]const u8 = null,
    fs_type: ?[]const u8 = null,

    pub fn report(self: RootfsStep, err: anyerror) void {
        reportDiagnostic("cannot prepare rootfs: {s}{s}{s}{s}{s}{s}{s}{s}{s}: {s}", .{
            self.operation,
            if (self.source != null) " " else "",
            self.source orelse "",
            if (self.source != null) " ->" else "",
            if (self.path.len != 0) " " else "",
            self.path,
            if (self.fs_type != null) " (" else "",
            self.fs_type orelse "",
            if (self.fs_type != null) ")" else "",
            @errorName(err),
        });
    }
};

pub const RootfsOptions = struct {
    private_mount_namespace: bool = true,
    console_fd: ?posix.fd_t = null,
    propagation: u32 = linux.MS.PRIVATE | linux.MS.REC,
    create_hooks: []const hooks.Prepared = &.{},
    create_hook_state: []const u8 = "",
    masked_paths: []const [:0]const u8 = &.{},
    readonly_paths: []const [:0]const u8 = &.{},
    sysctls: []const libcontainer.Sysctl = &.{},
    runtime_sync: ?struct { ready_fd: posix.fd_t, go_fd: posix.fd_t } = null,
    /// Mount source helper, already given init's mount namespace; bind sources
    /// are requested one by one, right before each mount.
    mount_source_socket: ?posix.fd_t = null,
    /// Read end of the runtime's "seccomp listener copied" pipe (init sync).
    seccomp_ack_fd: ?posix.fd_t = null,
};

/// Paths now resolve entirely inside the container rootfs. Missing targets are
/// ignored; other mount failures must not silently weaken isolation.
fn applyPathRestrictions(masked: []const [:0]const u8, readonly: []const [:0]const u8, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    for (masked) |path| {
        step.* = .{ .operation = "stat masked path", .path = path };
        var stat: linux.Statx = undefined;
        const result = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        if (!stat.mask.TYPE) return error.CreateFailed;
        step.operation = "masked path";
        if (stat.mode & linux.S.IFMT == linux.S.IFDIR) {
            try checkResult(linux.mount("tmpfs", path, "tmpfs", ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC, 0));
        } else {
            try checkResult(linux.mount("/dev/null", path, null, ms.BIND, 0));
        }
    }
    for (readonly) |path| {
        step.* = .{ .operation = "bind readonly path", .path = path };
        const result = linux.mount(path, path, null, ms.BIND | ms.REC, 0);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        step.operation = "open readonly path";
        const fd = try openPath(linux.AT.FDCWD, path, .{ .PATH = true, .CLOEXEC = true });
        defer closeFd(fd);
        step.operation = "remount readonly path";
        try bindRemount(fd, path, ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
}

/// Like runc, make the containing mount slave when requested, otherwise private.
/// Only that mount must stop being shared; submounts retain their peer groups.
fn makeRootfsParentUnshared(rootfs: [:0]const u8, propagation: u32, step: *RootfsStep) libcontainer.Error!void {
    const flags: u32 = if (propagation & linux.MS.SLAVE != 0) linux.MS.SLAVE else linux.MS.PRIVATE;
    const operation: []const u8 = if (flags == linux.MS.SLAVE) "mount parent slave propagation" else "mount parent private propagation";
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (rootfs.len >= buffer.len) return error.InvalidPath;
    @memcpy(buffer[0..rootfs.len], rootfs);
    var end = rootfs.len;
    while (true) {
        buffer[end] = 0;
        const result = linux.mount(null, buffer[0..end :0], null, flags, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INVAL => {
                if (end == 1) return error.CreateFailed;
                end = (std.fs.path.dirname(buffer[0..end]) orelse return error.InvalidPath).len;
            },
            else => {
                // Report before this stack-backed parent path goes out of scope.
                step.* = .{ .operation = operation, .path = "" };
                var message: [std.fs.max_path_bytes + 80]u8 = undefined;
                const text = std.fmt.bufPrint(&message, "cannot prepare rootfs: {s} {s}: ", .{ operation, buffer[0..end] }) catch unreachable;
                checkResult(result) catch |err| {
                    childError(text, err);
                    // The enclosing setupRootfs diagnostic was already emitted.
                    step.operation = "";
                    return err;
                };
            },
        }
    }
}

/// All paths, hook arguments and state buffers are prepared before fork.
/// Allocating in child2 risks inherited allocator locks (POSIX only permits
/// async-signal-safe work after fork). The raw hook runner needs no allocation.
pub fn setupRootfs(rootfs: [:0]const u8, mounts: []const PreparedMount, devices: []const PreparedDevice, symlinks: []const libcontainer.Symlink, readonly: bool, options: RootfsOptions) libcontainer.Error!void {
    var owns_mount_fds = true;
    defer if (owns_mount_fds) closeMountFds(mounts);
    const ms = linux.MS;
    var step: RootfsStep = .{ .operation = "mount propagation", .path = "/" };
    errdefer |err| if (step.operation.len != 0) step.report(err);
    try prepareRootfsBind(rootfs, options, &step);
    const restore_propagation = options.private_mount_namespace and options.propagation & (ms.SHARED | ms.UNBINDABLE) != 0;
    try applyRootfsMounts(rootfs, mounts, options, &step);
    closeMountFds(mounts);
    owns_mount_fds = false;
    try runCreateHooks(options, &step);
    // runc's fd trick stacks the old root on the new root without a put_old
    // directory. Detach it and close both handles before any container exec.
    // Keep them above stdio, which console setup replaces before they close.
    step = .{ .operation = "open old root", .path = "/" };
    const old_root = if (options.private_mount_namespace)
        try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        null;
    defer if (old_root) |fd| closeFd(fd);
    step = .{ .operation = "open rootfs", .path = rootfs };
    const new_root = try consolePath(rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(new_root);
    // Populate rootfs /dev even without tmpfs, but leave a bind-mounted /dev
    // untouched: device nodes and symlinks there would mutate the host source.
    if (needsSetupDev(mounts)) try setupDevices(new_root, devices, symlinks, options.private_mount_namespace, &step);
    try enterRootfs(rootfs, old_root, new_root, &step);
    if (options.console_fd) |socket| {
        defer closeFd(socket);
        setupConsole(socket, true) catch |err| {
            childError("cannot set up console (requires devpts mounted at /dev/pts): ", err);
            if (options.runtime_sync) |sync| failCreate(sync.ready_fd, err);
            linux.exit_group(1);
        };
    }
    // Sysctls must precede readonlyPaths (typically including /proc/sys).
    step.operation = "";
    try applySysctls(options.sysctls);
    try applyPathRestrictions(options.masked_paths, options.readonly_paths, &step);
    if (readonly) {
        step = .{ .operation = "remount readonly root", .path = "/" };
        try bindRemount(new_root, "/", ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
    step = .{ .operation = "restore mount propagation", .path = "/" };
    if (restore_propagation)
        try checkResult(linux.mount(null, "/", null, options.propagation, 0));
}

fn prepareRootfsBind(rootfs: [:0]const u8, options: RootfsOptions, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    if (options.private_mount_namespace)
        try checkResult(linux.mount(null, "/", null, options.propagation, 0));
    // Shared parents prevent pivot_root and leak the rootfs self-bind.
    // Making only the parent bindable also preserves runc's unbindable-submount pruning.
    if (options.private_mount_namespace) {
        step.* = .{ .operation = "mount parent propagation", .path = rootfs };
        try makeRootfsParentUnshared(rootfs, options.propagation, step);
    }
    step.* = .{ .operation = "bind", .source = rootfs, .path = rootfs };
    try checkResult(linux.mount(rootfs, rootfs, null, ms.BIND | ms.REC, 0));
    if (!options.private_mount_namespace) {
        // Report ownership before a configured mount at "/" can cover this bind.
        step.* = .{ .operation = "open rootfs", .path = rootfs };
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        step.operation = "stat rootfs mount";
        var response: CreateResponse = .{ .rootfs_mount_id = try mountId(root_fd) };
        step.* = .{ .operation = "report rootfs mount" };
        if (options.runtime_sync) |sync|
            if (!writeAll(sync.ready_fd, std.mem.asBytes(&response))) return error.CreateFailed;
    }
    // The new self-bind can inherit host peer groups. Isolate only this copy,
    // so configured submounts do not also appear beneath the covered directory.
    step.* = .{ .operation = "mount private propagation", .path = rootfs };
    if (!options.private_mount_namespace)
        try checkResult(linux.mount(null, rootfs, null, ms.PRIVATE | ms.REC, 0));
}

fn applyRootfsMounts(rootfs: [:0]const u8, mounts: []const PreparedMount, options: RootfsOptions, step: *RootfsStep) libcontainer.Error!void {
    for (mounts) |original| {
        var mount = original;
        const received = options.mount_source_socket != null and mount.flags & linux.MS.BIND != 0;
        if (options.mount_source_socket) |socket| {
            step.* = .{ .operation = "receive bind source", .source = mount.source, .path = mount.destination };
            try receiveMountSource(&mount, socket);
        }
        // The received fd belongs to this iteration; the slice's fds stay with closeMountFds.
        defer if (received) {
            if (if (mount.mappings != null) mount.mount_fd else mount.source_fd) |fd| closeFd(fd);
        };
        step.* = .{ .operation = "open rootfs", .path = rootfs };
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        try applyMount(rootfs, root_fd, mount, options.private_mount_namespace, options.propagation, step);
        try setupSymlinks(root_fd, mount.symlinks, step);
    }
}

fn runCreateHooks(options: RootfsOptions, step: *RootfsStep) libcontainer.Error!void {
    if (options.runtime_sync) |sync| {
        step.* = .{ .operation = "create synchronization" };
        var response: CreateResponse = .{};
        if (!writeAll(sync.ready_fd, std.mem.asBytes(&response))) return error.CreateFailed;
        var byte: [1]u8 = undefined;
        const released = readAll(sync.go_fd, &byte);
        closeFd(sync.go_fd);
        if (!released or byte[0] != 1) return error.CreateFailed;
    }
    // Runtime paths are still reachable; the hook already runs in the new
    // mount namespace and sees all configured mounts before pivot_root.
    step.* = .{ .operation = "create hooks" };
    hooks.run(options.create_hooks, options.create_hook_state) catch |err| {
        // The hook runner already recorded its captured output.
        step.operation = "";
        return @as(libcontainer.Error!void, err);
    };
}

fn enterRootfs(rootfs: [:0]const u8, old_root: ?posix.fd_t, new_root: posix.fd_t, step: *RootfsStep) libcontainer.Error!void {
    const ms = linux.MS;
    step.* = .{ .operation = "fchdir rootfs", .path = rootfs };
    try checkResult(linux.fchdir(new_root));
    if (old_root) |fd| {
        step.* = .{ .operation = "pivot_root" };
        try checkResult(linux.pivot_root(".", "."));
        step.* = .{ .operation = "fchdir old root" };
        try checkResult(linux.fchdir(fd));
        // Detaching inherited shared submounts must not unmount their host peers.
        step.* = .{ .operation = "mount old root slave propagation" };
        try checkResult(linux.mount(null, ".", null, ms.SLAVE | ms.REC, 0));
        step.* = .{ .operation = "umount old root" };
        try checkResult(linux.umount2(".", linux.MNT.DETACH));
    } else {
        step.* = .{ .operation = "chroot", .path = rootfs };
        try checkResult(linux.chroot("."));
    }
    step.* = .{ .operation = "chdir", .path = "/" };
    try checkResult(linux.chdir("/"));
}

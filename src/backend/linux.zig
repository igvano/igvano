const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../backend.zig").Backend;
const oci = @import("../oci.zig");

/// Pure filesystem selection; mount flags, including read-only, stay unchanged.
pub fn cgroupMountType(mount_type: []const u8, host_fs_type: usize) Backend.Error![]const u8 {
    if (!std.mem.eql(u8, mount_type, "cgroup") and !std.mem.eql(u8, mount_type, "cgroup2")) return mount_type;
    if (host_fs_type != 0x63677270) return error.Unsupported; // CGROUP2_SUPER_MAGIC
    return "cgroup2";
}

test "cgroup mounts map to cgroup2 only on unified hosts" {
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup", 0x63677270));
    for ([_]usize{ 0x01021994, 0x27e0eb, 0 }) |host_fs_type| {
        try std.testing.expectError(error.Unsupported, cgroupMountType("cgroup", host_fs_type));
    }
    try std.testing.expectEqualStrings("tmpfs", try cgroupMountType("tmpfs", 0x01021994));
    try std.testing.expectError(error.Unsupported, cgroupMountType("cgroup2", 0x01021994));
    try std.testing.expectEqualStrings("cgroup2", try cgroupMountType("cgroup2", 0x63677270));
}

/// Pure translation and validation; Linux flag constants are available on macOS too.
pub fn namespaceFlags(config: ?oci.Spec.Linux) Backend.Error!usize {
    const settings = config orelse return 0;
    const namespaces = settings.namespaces orelse return 0;
    var flags: usize = 0;
    var seen: usize = 0;
    for (namespaces) |namespace| {
        const flag: usize = switch (namespace.type) {
            .pid => linux.CLONE.NEWPID,
            .network => linux.CLONE.NEWNET,
            .mount => linux.CLONE.NEWNS,
            .ipc => linux.CLONE.NEWIPC,
            .uts => linux.CLONE.NEWUTS,
            .user => linux.CLONE.NEWUSER,
            .cgroup => linux.CLONE.NEWCGROUP,
            .time => linux.CLONE.NEWTIME,
        };
        if (seen & flag != 0) return error.InvalidConfig;
        seen |= flag;
        if (namespace.path != null) return error.Unsupported;
        flags |= flag;
    }
    return flags;
}

pub const LinuxBackend = struct {
    pub fn backend(self: *LinuxBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .create = create,
        .alive = alive,
        .kill = kill,
        .delete = delete,
    };

    fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
        if (comptime builtin.os.tag == .linux) {
            const flags = try namespaceFlags(options.spec.linux);
            if (options.spec.hostname != null and flags & linux.CLONE.NEWUTS == 0)
                return error.InvalidConfig;
            if (options.spec.process) |process| {
                if (process.terminal orelse false) return error.Unsupported;
                if (process.args.len == 0) return error.InvalidProcess;
            }
            if (options.capabilities) |caps| {
                if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
                    return error.AmbientCapabilitiesRequirePermittedAndInheritable;
            }
            const capabilities = if (options.capabilities) |caps| try kernelCapabilities(caps) else null;
            for (options.rlimits) |limit| {
                if (limit.soft > limit.hard) return error.InvalidConfig;
            }
            if (!std.fs.path.isAbsolute(options.exec_fifo) or
                std.mem.indexOfScalar(u8, options.exec_fifo, 0) != null)
                return error.InvalidPath;

            // Prepare the init's strings before either fork.
            var arena: std.heap.ArenaAllocator = .init(options.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            const user_namespace = flags & linux.CLONE.NEWUSER != 0;
            // Library callers bypass frontend validation, so mapping-presence checks are intentional.
            const uid_mappings = if (user_namespace) options.spec.linux.?.uidMappings orelse return error.InvalidConfig else &.{};
            const gid_mappings = if (user_namespace) options.spec.linux.?.gidMappings orelse return error.InvalidConfig else &.{};
            if (user_namespace and (uid_mappings.len == 0 or gid_mappings.len == 0)) return error.InvalidConfig;
            const fifo_uid = if (user_namespace) try mappedRootID(uid_mappings) else 0;
            const fifo_gid = if (user_namespace) try mappedRootID(gid_mappings) else 0;
            const uid_map = try formatIDMappings(allocator, uid_mappings);
            const gid_map = try formatIDMappings(allocator, gid_mappings);
            const fifo = try allocator.dupeZ(u8, options.exec_fifo);
            const rootfs = try processString(allocator, options.rootfs);
            const cwd = try processString(allocator, if (options.spec.process) |process| process.cwd else "/");
            if (!std.fs.path.isAbsolute(cwd)) return error.InvalidProcess;
            if (flags & linux.CLONE.NEWNS == 0) return error.MissingMountNamespace;
            if (!std.fs.path.isAbsolute(rootfs)) return error.InvalidPath;
            try validateCgroupPath(options.cgroup_path);
            const cgroup_root = try openCgroupRoot();
            defer closeFd(cgroup_root.fd);
            const mounts = try allocator.alloc(PreparedMount, options.mounts.len);
            for (options.mounts, mounts) |mount, *prepared| {
                if (!std.mem.startsWith(u8, mount.destination, "/")) return error.InvalidPath;
                var mount_type = mount.type;
                if (mount_type != null and mount.flags & linux.MS.BIND == 0) {
                    mount_type = try cgroupMountType(mount_type.?, cgroup_root.fs_type);
                }
                prepared.* = .{
                    .destination = try pathString(allocator, mount.destination),
                    .source = if (mount.source) |source| try pathString(allocator, source) else null,
                    .type = if (mount_type) |value| try pathString(allocator, value) else null,
                    .flags = mount.flags,
                    .propagation = mount.propagation,
                    .data = try pathString(allocator, mount.data),
                    .recursive_readonly = mount.recursive_readonly,
                };
            }
            const args: []const []const u8 = if (options.spec.process) |process| process.args else &.{};
            const env: []const []const u8 = if (options.spec.process) |process| process.env orelse &.{} else &.{};
            const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);
            for (args, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
            const envp = try allocator.allocSentinel(?[*:0]const u8, env.len, null);
            for (env, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;

            // pivot_root also changes child1's root while it waits in the same
            // mount namespace. Pin host /proc so it can still capture identity.
            const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
            defer closeFd(proc_dir);
            const cgroup = (try walkCgroup(cgroup_root.fd, options.cgroup_path, true, options.cgroup_writes)).?;
            defer closeFd(cgroup);
            errdefer {
                // Child1 can die before reporting child2's PID. Kill the entire
                // cgroup before removing it, including any blocked init.
                writeCgroupFile(cgroup, "cgroup.kill", "1", options.cgroup_path) catch {};
                removeCgroup(cgroup_root.fd, options.cgroup_path) catch {};
            }
            for (options.cgroup_writes) |write|
                try writeCgroupFile(cgroup, write.name, write.value, options.cgroup_path);
            const report = try makePipe();
            const ready = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                return err;
            };
            const map_pipe = if (user_namespace) makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                return err;
            } else null;
            const child1 = forkProcess() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                if (map_pipe) |fds| for (fds) |fd| closeFd(fd);
                return err;
            };
            if (child1 == 0) {
                if (map_pipe) |fds| closeFd(fds[1]);
                closeFd(cgroup_root.fd);
                closeFd(report[0]);
                // Join before NEWCGROUP snapshots the namespace root. Child2
                // inherits this membership; the runtime parent stays outside.
                writeCgroupFile(cgroup, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                closeFd(cgroup);
                // NEWUSER is unshared together with the others so it owns them.
                if (flags != 0) checkResult(linux.unshare(flags)) catch |err| failCreate(report[1], err);
                // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
                const child2 = forkProcess() catch |err| failCreate(report[1], err);
                if (child2 == 0) {
                    // Let the parent see report EOF if child1 dies during the map wait.
                    closeFd(report[1]);
                    closeFd(ready[0]);
                    closeFd(proc_dir);
                    // The outside parent must install our ID maps
                    // before any rootfs, mount, hostname, or process work.
                    if (map_pipe) |fds| {
                        var byte: [1]u8 = undefined;
                        if (!readAll(fds[0], &byte)) linux.exit_group(1);
                        closeFd(fds[0]);
                        // Like runc nsexec stage-2, become root in the user ns.
                        // Unmapped host-root fsuid/fsgid make may_create() fail
                        // with EOVERFLOW on filesystems mounted in this ns.
                        checkResult(linux.setgid(0)) catch linux.exit_group(1);
                        checkResult(linux.setuid(0)) catch linux.exit_group(1);
                    }
                    runInit(options.spec, capabilities, options.rlimits, flags, rootfs, mounts, cwd, fifo, argv.ptr, envp.ptr, ready[1]);
                }
                if (map_pipe) |fds| {
                    closeFd(fds[0]);
                    var mapping_response: CreateResponse = .{ .pid = child2 };
                    if (!writeAll(report[1], std.mem.asBytes(&mapping_response))) {
                        _ = linux.kill(child2, .KILL);
                        _ = waitChild(child2) catch {};
                        linux.exit_group(1);
                    }
                }
                closeFd(ready[1]);
                var byte: [1]u8 = undefined;
                const initialized = readAll(ready[0], &byte);
                closeFd(ready[0]);
                if (!initialized) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], error.CreateFailed);
                }
                // Capture identity while child2 is still our child, so its PID
                // cannot be recycled even if it has already exited.
                var stat_buffer: [4096]u8 = undefined;
                const stat = readProcStatAt(proc_dir, child2, &stat_buffer) catch |err| {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], err);
                };
                var response: CreateResponse = .{
                    .pid = child2,
                    .starttime = std.fmt.parseInt(u64, stat.starttime, 10) catch unreachable,
                };
                if (!writeAll(report[1], std.mem.asBytes(&response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
                // No shim: exiting child1 reparents the blocked init to host init.
                linux.exit_group(0);
            }

            closeFd(report[1]);
            for (ready) |fd| closeFd(fd);
            defer closeFd(report[0]);
            // Retain a reader so a dying init cannot SIGPIPE the runtime on go.
            defer if (map_pipe) |fds| closeFd(fds[0]);
            var map_writer: ?posix.fd_t = if (map_pipe) |fds| fds[1] else null;
            // On failure, close before waiting to unblock init; null prevents double close.
            defer if (map_writer) |fd| closeFd(fd);
            var child1_reaped = false;
            errdefer if (!child1_reaped) {
                if (map_writer) |fd| {
                    closeFd(fd);
                    map_writer = null;
                }
                _ = waitChild(child1) catch {};
            };
            if (map_writer) |fd| {
                var mapping_response: CreateResponse = .{};
                if (!readAll(report[0], std.mem.asBytes(&mapping_response))) return error.CreateFailed;
                if (mapping_response.failure != 0)
                    return @errorCast(@errorFromInt(@as(u16, @intCast(mapping_response.failure))));
                if (mapping_response.pid <= 0) return error.CreateFailed;
                try writeUserMappings(mapping_response.pid, gid_map, uid_map);
                // Init needs ownership as namespace root, even for a non-root process.
                try checkResult(linux.chown(fifo, fifo_uid, fifo_gid));
                if (!writeAll(fd, &.{1})) return error.CreateFailed;
                closeFd(fd);
                map_writer = null;
            }
            var response: CreateResponse = .{};
            const reported = readAll(report[0], std.mem.asBytes(&response));
            var starttime_buffer: [20]u8 = undefined;
            const starttime = std.fmt.bufPrint(&starttime_buffer, "{d}", .{response.starttime}) catch unreachable;
            const handle: Backend.Handle = .{
                .id = options.id,
                .pid = response.pid,
                .starttime = starttime,
                .cgroup_path = options.cgroup_path,
            };
            errdefer if (reported and response.pid > 0) {
                kill(ptr, handle, 9) catch {};
            };
            const status = try waitChild(child1);
            child1_reaped = true;
            if (!reported) return error.CreateFailed;
            if (response.failure != 0) return @errorCast(@errorFromInt(@as(u16, @intCast(response.failure))));
            if (status != 0 or response.pid <= 0) {
                return error.CreateFailed;
            }
            const owned_starttime = try options.allocator.dupe(u8, starttime);
            errdefer options.allocator.free(owned_starttime);
            return .{
                .id = options.id,
                .pid = response.pid,
                .starttime = owned_starttime,
                .cgroup_path = options.cgroup_path,
            };
        } else {
            return error.NotImplemented;
        }
    }

    fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            switch (linux.errno(linux.kill(handle.pid, @enumFromInt(0)))) {
                .SUCCESS, .PERM => {},
                .SRCH => return false,
                else => return error.LivenessFailed,
            }
            var buffer: [4096]u8 = undefined;
            // ponytail: /proc mounted with hidepid can conceal a live process.
            // Require a readable host /proc; kill(0) alone cannot verify identity.
            const stat = readProcStat(handle.pid, &buffer) catch |err| switch (err) {
                error.ProcessNotFound => return false,
                else => return err,
            };
            return stat.matches(handle.starttime);
        } else {
            return error.NotImplemented;
        }
    }

    fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
            // ponytail: PID reuse between alive() and kill() can signal the wrong
            // process. Fix with pidfd_open before checking identity, then use
            // pidfd_send_signal on that same descriptor.
            if (!try alive(ptr, handle)) return error.ProcessNotFound;
            switch (linux.errno(linux.kill(handle.pid, @enumFromInt(@as(u32, @intCast(signal)))))) {
                .SUCCESS => {},
                .SRCH => return error.ProcessNotFound,
                .PERM => return error.PermissionDenied,
                else => return error.KillFailed,
            }
        } else {
            return error.NotImplemented;
        }
    }

    fn delete(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        if (comptime builtin.os.tag == .linux) {
            const path = handle.cgroup_path orelse return;
            try validateCgroupPath(path);
            const root = try openCgroupRoot();
            defer closeFd(root.fd);
            const cgroup = (try walkCgroup(root.fd, path, false, &.{})) orelse return;
            defer closeFd(cgroup);
            // kill targets init only. delete terminates any remaining descendants.
            if (try cgroupPopulated(cgroup))
                try writeCgroupFile(cgroup, "cgroup.kill", "1", path);
            try removeCgroup(root.fd, path);
        } else {
            return error.NotImplemented;
        }
    }
};

fn validateCgroupPath(path: []const u8) Backend.Error!void {
    if (path.len == 0 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or component.len > 255)
            return error.InvalidPath;
    }
}

fn openCgroupRoot() Backend.Error!struct { fd: posix.fd_t, fs_type: usize } {
    const opened = linux.openat(linux.AT.FDCWD, "/sys/fs/cgroup", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return error.Unsupported,
        else => try checkResult(opened),
    }
    const root: posix.fd_t = @intCast(opened);
    errdefer closeFd(root);
    // Zig has no statfs wrapper. f_type is the first native word of Linux statfs.
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(root), @intFromPtr(&fs)));
    if (fs[0] != 0x63677270) {
        std.debug.print("igvano: cgroups require cgroup2 at /sys/fs/cgroup; legacy and hybrid hosts are unsupported\n", .{});
        return error.Unsupported;
    }
    return .{ .fd = root, .fs_type = fs[0] };
}

test "backend cgroup paths must name a normalized child directory" {
    for ([_][]const u8{ "igvano/example", "custom", "a/b/c" }) |path| try validateCgroupPath(path);
    for ([_][]const u8{ "", "/", "/custom", "..", "a/../b", "a/./b", "a//b", "a/", "a\x00b" }) |path| {
        try std.testing.expectError(error.InvalidPath, validateCgroupPath(path));
    }
}

test "linux cgroup creation reuses parents but rejects existing leaves" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign");
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_][]const u8{ "foreign", "parent/foreign" }) |path| {
        const result = walkCgroup(root, path, true, &.{});
        if (result) |fd| {
            if (fd) |opened| closeFd(opened);
        } else |_| {}
        try std.testing.expectError(error.CreateFailed, result);
        const existing = (try walkCgroup(root, path, false, &.{})).?;
        closeFd(existing);
    }
    const owned = (try walkCgroup(root, "parent/owned", true, &.{})).?;
    closeFd(owned);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "parent/owned", false, &.{}));
}

test "linux cgroup removal deletes nested children and preserves sibling cgroups" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/other");
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign/keep");
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "parent/foreign/keep", .{});
    try removeCgroup(root, "parent/owned");
    try removeCgroup(root, "missing/container");
}

test "linux child cgroup cleanup leaves control files and symlinks untouched" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "outside/keep");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "owned/cgroup.events", .data = "populated 0\n" });
    try tmp.dir.symLink(std.testing.io, "../outside", "owned/escape", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const owned = (try walkCgroup(root, "owned", false, &.{})).?;
    defer closeFd(owned);
    try removeCgroupChildren(owned, "owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned/child", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "owned/cgroup.events", .{});
    _ = try tmp.dir.statFile(std.testing.io, "owned/escape", .{});
    _ = try tmp.dir.statFile(std.testing.io, "outside/keep", .{});
}

/// Walk through pinned directory fds so symlinks cannot redirect cgroup writes.
/// Enable requested controllers in every parent before creating its child.
/// Creation requires a new leaf. Nested paths can still change controllers in
/// existing parents, including other containers' cgroups. Like runc, config is trusted.
fn walkCgroup(root: posix.fd_t, path: []const u8, create: bool, writes: []const Backend.CgroupWrite) Backend.Error!?posix.fd_t {
    try validateCgroupPath(path);
    var current = try openPath(root, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    errdefer closeFd(current);
    var controller_buffer: [32]u8 = undefined;
    var controller_len: usize = 0;
    const controllers = [_]struct { prefix: []const u8, enable: []const u8 }{
        .{ .prefix = "memory.", .enable = "+memory " },
        .{ .prefix = "cpu.", .enable = "+cpu " },
        .{ .prefix = "pids.", .enable = "+pids " },
    };
    for (controllers) |controller| {
        for (writes) |write| {
            if (std.mem.startsWith(u8, write.name, controller.prefix)) {
                @memcpy(controller_buffer[controller_len..][0..controller.enable.len], controller.enable);
                controller_len += controller.enable.len;
                break;
            }
        }
    }
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        var buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{s}", .{component}) catch return error.InvalidPath;
        if (create) {
            if (controller_len != 0)
                try writeCgroupFile(current, "cgroup.subtree_control", controller_buffer[0..controller_len], path);
            const result = linux.mkdirat(current, name, 0o755);
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .EXIST => {
                    if (components.peek() == null) {
                        std.debug.print("igvano: cgroup '{s}' already exists\n", .{path});
                        return error.CreateFailed;
                    }
                },
                else => try checkResult(result),
            }
        }
        const result = linux.openat(current, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => {
                closeFd(current);
                current = @intCast(result);
            },
            .NOENT => {
                if (create) return error.CreateFailed;
                closeFd(current);
                return null;
            },
            else => try checkResult(result),
        }
    }
    return current;
}

fn writeCgroupFile(dir: posix.fd_t, filename: []const u8, value: []const u8, path: []const u8) Backend.Error!void {
    if (filename.len == 0 or std.mem.indexOfAny(u8, filename, "/\x00") != null or
        std.mem.eql(u8, filename, ".") or std.mem.eql(u8, filename, "..")) return error.InvalidPath;
    var buffer: [256]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "{s}", .{filename}) catch return error.InvalidPath;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => |err| {
                std.debug.print("igvano: cgroup '{s}' cannot open {s}: {s}\n", .{ path, filename, @tagName(err) });
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
                std.debug.print("igvano: cgroup '{s}' cannot write {s} = '{s}': {s}\n", .{ path, filename, value, @tagName(err) });
                return error.CgroupWriteFailed;
            },
        }
    }
}

fn cgroupPopulated(dir: posix.fd_t) Backend.Error!bool {
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

fn removeCgroup(root: posix.fd_t, path: []const u8) Backend.Error!void {
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
                try removeCgroupChildren(cgroup, path);
            },
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                std.debug.print("igvano: cannot open cgroup '{s}' for removal: {s}\n", .{ path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
        const result = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => return,
            .INTR => continue,
            .BUSY, .NOTEMPTY => _ = linux.nanosleep(&delay, null),
            else => |err| {
                std.debug.print("igvano: cannot remove cgroup '{s}': {s}\n", .{ path, @tagName(err) });
                return error.CgroupDeleteFailed;
            },
        }
    }
    std.debug.print("igvano: cgroup '{s}' is still busy after waiting for members to exit\n", .{path});
    return error.CgroupDeleteFailed;
}

/// Remove descendants before their parent, without touching cgroup control files.
fn removeCgroupChildren(dir: posix.fd_t, path: []const u8) Backend.Error!void {
    var buffer: [4096]u8 = undefined;
    while (true) {
        const result = linux.getdents64(dir, &buffer, buffer.len);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .NOENT => return,
            .INTR => continue,
            else => |err| {
                std.debug.print("igvano: cannot read child cgroups of '{s}': {s}\n", .{ path, @tagName(err) });
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
            try removeCgroup(dir, name);
        }
    }
}

const CreateResponse = extern struct {
    pid: i32 = 0,
    failure: u32 = 0,
    starttime: u64 = 0,
};

const ProcStat = struct {
    state: u8,
    starttime: []const u8,

    fn matches(self: ProcStat, starttime: []const u8) bool {
        if (self.state == 'Z' or self.state == 'X') return false;
        return std.mem.eql(u8, starttime, self.starttime);
    }
};

fn parseProcStat(bytes: []const u8) Backend.Error!ProcStat {
    // comm can contain spaces and parentheses; only its final ')' delimits it.
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.LivenessFailed;
    var fields = std.mem.tokenizeAny(u8, bytes[end + 1 ..], " \t\n");
    const state = fields.next() orelse return error.LivenessFailed;
    if (state.len != 1) return error.LivenessFailed;
    // State is field 3; skip fields 4 through 21 to reach starttime.
    for (4..22) |_| _ = fields.next() orelse return error.LivenessFailed;
    const starttime = fields.next() orelse return error.LivenessFailed;
    _ = std.fmt.parseInt(u64, starttime, 10) catch return error.LivenessFailed;
    return .{ .state = state[0], .starttime = starttime };
}

fn readProcStat(pid: i32, buffer: []u8) Backend.Error!ProcStat {
    return readProcStatAt(linux.AT.FDCWD, pid, buffer);
}

fn readProcStatAt(proc_dir: posix.fd_t, pid: i32, buffer: []u8) Backend.Error!ProcStat {
    var path_buffer: [64]u8 = undefined;
    const path = if (proc_dir == linux.AT.FDCWD)
        std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/stat", .{pid}) catch unreachable
    else
        std.fmt.bufPrintZ(&path_buffer, "{d}/stat", .{pid}) catch unreachable;
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(proc_dir, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            .NOENT, .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    };
    defer closeFd(fd);
    var used: usize = 0;
    while (used < buffer.len) {
        const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return parseProcStat(buffer[0..used]);
                used += result;
            },
            .INTR => continue,
            .SRCH => return error.ProcessNotFound,
            else => return error.LivenessFailed,
        }
    }
    return error.LivenessFailed;
}

fn processString(allocator: std.mem.Allocator, value: []const u8) Backend.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidProcess;
    return allocator.dupeZ(u8, value);
}

fn pathString(allocator: std.mem.Allocator, value: []const u8) Backend.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidPath;
    return allocator.dupeZ(u8, value);
}

fn checkResult(result: usize) Backend.Error!void {
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .AGAIN, .MFILE, .NFILE => return error.SystemResources,
        .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

// Zig 0.16 exposes fork/pipe/waitpid through std.posix.system.
fn forkProcess() Backend.Error!i32 {
    const result = posix.system.fork();
    switch (posix.errno(result)) {
        .SUCCESS => return @intCast(result),
        .NOMEM, .AGAIN => return error.SystemResources,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

fn makePipe() Backend.Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    switch (posix.errno(posix.system.pipe2(&fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => return fds,
        .MFILE, .NFILE => return error.SystemResources,
        else => return error.CreateFailed,
    }
}

fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

fn mappedRootID(mappings: []const oci.Spec.IDMapping) Backend.Error!u32 {
    for (mappings) |mapping| {
        if (mapping.containerID == 0 and mapping.size > 0) return mapping.hostID;
    }
    return error.InvalidConfig;
}

fn formatIDMappings(allocator: std.mem.Allocator, mappings: []const oci.Spec.IDMapping) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (mappings) |mapping| {
        try text.print(allocator, "{d} {d} {d}\n", .{ mapping.containerID, mapping.hostID, mapping.size });
    }
    return text.toOwnedSlice(allocator);
}

/// The runtime parent writes maps from its original user namespace.
fn writeUserMappings(pid: i32, gid_map: []const u8, uid_map: []const u8) Backend.Error!void {
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
        try checkResult(result);
        if (result != text.len) return error.CreateFailed;
        return;
    }
}

/// Filter before fork so warnings and any stderr bookkeeping stay in the parent.
fn kernelCapabilities(configured: Backend.Capabilities) Backend.Error!Backend.Capabilities {
    var supported: u64 = 0;
    for (0..64) |cap| {
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        supported |= @as(u64, 1) << @intCast(cap);
    }
    var result = configured;
    var ignored: u64 = 0;
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
        ignored |= @field(result, field.name) & ~supported;
        @field(result, field.name) &= supported;
    }
    for (0..64) |cap| {
        if (ignored & (@as(u64, 1) << @intCast(cap)) != 0)
            std.debug.print("igvano: warning: ignoring capability {d}, unsupported by this kernel\n", .{cap});
    }
    return result;
}

fn waitChild(pid: i32) Backend.Error!u32 {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => return @bitCast(status),
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

fn readAll(fd: posix.fd_t, bytes: []u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn failCreate(fd: posix.fd_t, err: Backend.Error) noreturn {
    var response: CreateResponse = .{ .failure = @intFromError(err) };
    _ = writeAll(fd, std.mem.asBytes(&response));
    linux.exit_group(1);
}

const PreparedMount = struct {
    destination: [:0]const u8,
    source: ?[:0]const u8,
    type: ?[:0]const u8,
    flags: u32,
    propagation: u32,
    data: [:0]const u8,
    recursive_readonly: ?bool = null,
};

const CapabilityHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,
};

fn openPath(dir_fd: posix.fd_t, path: [*:0]const u8, flags: linux.O) Backend.Error!posix.fd_t {
    const result = linux.openat(dir_fd, path, flags, 0);
    try checkResult(result);
    return @intCast(result);
}

fn fileType(fd: posix.fd_t) Backend.Error!u16 {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    return stat.mode & linux.S.IFMT;
}

/// Walk beneath a pinned root, rejecting symlinks in every component. Mounting
/// through the returned fd also avoids a destination swap between lookup/mount.
fn mountDestination(root_fd: posix.fd_t, destination: []const u8, is_file: bool, create: bool) Backend.Error!posix.fd_t {
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

fn fdPath(buffer: []u8, fd: posix.fd_t) [:0]u8 {
    return std.fmt.bufPrintZ(buffer, "/proc/self/fd/{d}", .{fd}) catch unreachable;
}

fn applyMount(rootfs: [:0]const u8, root_fd: posix.fd_t, mount: PreparedMount) Backend.Error!void {
    const ms = linux.MS;
    const bind = mount.flags & ms.BIND != 0;
    const source_fd: ?posix.fd_t = if (bind)
        try openPath(linux.AT.FDCWD, (mount.source orelse return error.InvalidConfig).ptr, .{ .PATH = true, .CLOEXEC = true })
    else
        null;
    defer if (source_fd) |fd| closeFd(fd);
    const is_file = if (source_fd) |fd| try fileType(fd) != linux.S.IFDIR else false;
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
    try checkResult(linux.mount(
        source,
        fdPath(&target_buffer, target_fd),
        if (bind) null else if (mount.type) |value| value.ptr else null,
        if (bind) mount.flags & (ms.BIND | ms.REC) else mount.flags,
        if (bind or mount.data.len == 0) 0 else @intFromPtr(mount.data.ptr),
    ));
    // The original fd pins the covered mount. Reopen to address the new mount
    // for remount and propagation changes, still without following symlinks.
    const mounted_fd = if (std.mem.eql(u8, mount.destination, "/"))
        try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })
    else
        try mountDestination(root_fd, mount.destination, is_file, false);
    closeFd(target_fd);
    target_fd = mounted_fd;
    if (bind and mount.flags & ~@as(u32, ms.BIND | ms.REC) != 0) {
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, (mount.flags & ~@as(u32, ms.REC)) | ms.BIND | ms.REMOUNT, 0));
    }
    if (mount.recursive_readonly) |readonly| {
        const MountAttr = extern struct {
            attr_set: u64,
            attr_clr: u64,
            propagation: u64 = 0,
            userns_fd: u64 = 0,
        };
        const attr: MountAttr = .{
            .attr_set = if (readonly) 1 else 0, // MOUNT_ATTR_RDONLY
            .attr_clr = if (readonly) 0 else 1,
        };
        // Zig 0.16's wrapper omits the attr pointer and size; use the full ABI.
        try checkResult(linux.syscall5(.mount_setattr, @intCast(target_fd), @intFromPtr(""), linux.AT.EMPTY_PATH | linux.AT.RECURSIVE, @intFromPtr(&attr), @sizeOf(MountAttr)));
    }
    if (mount.propagation != 0) {
        try checkResult(linux.mount(null, fdPath(&target_buffer, target_fd), null, mount.propagation, 0));
    }
}

/// All paths/data are prepared before fork; child2 needs no allocator.
fn setupRootfs(rootfs: [:0]const u8, mounts: []const PreparedMount, readonly: bool) Backend.Error!void {
    const ms = linux.MS;
    try checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0));
    try checkResult(linux.mount(rootfs, rootfs, null, ms.BIND | ms.REC, 0));
    for (mounts) |mount| {
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        try applyMount(rootfs, root_fd, mount);
    }
    // runc's fd trick stacks the old root on the new root without a put_old
    // directory. Detach it and close both handles before any container exec.
    const old_root = try openPath(linux.AT.FDCWD, "/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(old_root);
    const new_root = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(new_root);
    try checkResult(linux.fchdir(new_root));
    try checkResult(linux.pivot_root(".", "."));
    try checkResult(linux.fchdir(old_root));
    try checkResult(linux.umount2(".", linux.MNT.DETACH));
    try checkResult(linux.chdir("/"));
    if (readonly) try checkResult(linux.mount(null, "/", null, ms.BIND | ms.REMOUNT | ms.RDONLY, 0));
}

fn runInit(
    spec: *const oci.Spec,
    capabilities: ?Backend.Capabilities,
    rlimits: []const Backend.Rlimit,
    flags: usize,
    rootfs: [:0]const u8,
    mounts: []const PreparedMount,
    cwd: [:0]const u8,
    fifo: [:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    ready_fd: posix.fd_t,
) noreturn {
    // Keep the host FIFO reachable without requiring /proc inside the rootfs.
    // These host descriptors are used only by init and closed before exec.
    const fifo_path = openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .CLOEXEC = true }) catch linux.exit_group(1);
    const fd_dir = openPath(linux.AT.FDCWD, "/proc/self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
    var fifo_buffer: [32]u8 = undefined;
    const fifo_name = std.fmt.bufPrintZ(&fifo_buffer, "{d}", .{fifo_path}) catch unreachable;
    setupRootfs(rootfs, mounts, spec.root.readonly) catch linux.exit_group(1);
    if (flags & linux.CLONE.NEWUTS != 0) {
        if (spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch linux.exit_group(1);
        }
    }
    checkResult(linux.chdir(cwd)) catch linux.exit_group(1);
    if (spec.process) |process| {
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.user.uid != 0)
            checkResult(linux.fchmodat(fd_dir, fifo_name, 0o622)) catch linux.exit_group(1);
        applyProcess(process, capabilities, rlimits) catch |err| {
            std.debug.print("igvano: cannot apply process settings: {s}\n", .{@errorName(err)});
            linux.exit_group(1);
        };
    }
    if (!writeAll(ready_fd, &.{1})) linux.exit_group(1);
    closeFd(ready_fd);

    // O_WRONLY blocks until start opens a reader; the byte acknowledges that start.
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(fd_dir, fifo_name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => linux.exit_group(1),
        }
    };
    closeFd(fd_dir);
    closeFd(fifo_path);
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    closeFd(fd);
    runProcess(spec, argv, envp);
}

fn runProcess(spec: *const oci.Spec, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) noreturn {
    // A process-less config can be created; it cannot be started.
    if (spec.process == null) linux.exit_group(1);
    // Linux CLOSE_RANGE_CLOEXEC is 1 << 2; Zig 0.16's packed flags use 1 << 1.
    checkResult(linux.syscall3(.close_range, 3, std.math.maxInt(u32), 1 << 2)) catch linux.exit_group(1);
    execProcess(argv, envp);
}

/// Runs before readiness, without allocating. Keep privileges until limits and
/// bounding drops finish, then retain permitted caps across the UID transition.
// For UID 0, exec recomputes permitted/effective as inheritable | bounding (as in runc).
fn applyProcess(process: oci.Spec.Process, capabilities: ?Backend.Capabilities, rlimits: []const Backend.Rlimit) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (rlimits) |limit| {
            const value: linux.rlimit = .{ .cur = limit.soft, .max = limit.hard };
            try checkResult(linux.setrlimit(limit.resource, &value));
        }
        if (process.noNewPrivileges)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
        if (capabilities) |caps| {
            for (0..64) |cap| {
                // EINVAL marks the running kernel's last supported capability.
                const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
                if (linux.errno(result) == .INVAL) break;
                try checkResult(result);
                if (result != 0 and caps.bounding & (@as(u64, 1) << @intCast(cap)) == 0)
                    try checkResult(linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0));
            }
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
        }
        // With a user namespace, additionalGids (like uid/gid) are namespace IDs.
        const groups = process.user.additionalGids orelse &.{};
        try checkResult(linux.setgroups(groups.len, groups.ptr));
        try checkResult(linux.setgid(process.user.gid));
        try checkResult(linux.setuid(process.user.uid));
        if (capabilities) |caps| {
            // Linux's header uses a 32-bit pid, unlike Zig 0.16's usize field.
            const header: CapabilityHeader = .{};
            const data = [2]linux.cap_user_data_t{
                .{ .effective = @truncate(caps.effective), .permitted = @truncate(caps.permitted), .inheritable = @truncate(caps.inheritable) },
                .{ .effective = @truncate(caps.effective >> 32), .permitted = @truncate(caps.permitted >> 32), .inheritable = @truncate(caps.inheritable >> 32) },
            };
            try checkResult(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 0, 0, 0, 0));
            // Discard inherited ambient caps even when the configured set is empty.
            try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
            for (0..64) |cap| {
                if (caps.ambient & (@as(u64, 1) << @intCast(cap)) != 0)
                    try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_RAISE, cap, 0, 0));
            }
        }
    } else {
        return error.NotImplemented;
    }
}

fn execProcess(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) noreturn {
    const executable = argv[0] orelse linux.exit_group(1);
    const name = std.mem.span(executable);
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        _ = linux.execve(executable, argv, envp);
        linux.exit_group(1);
    }
    var path: []const u8 = "/bin:/usr/bin";
    var index: usize = 0;
    while (envp[index]) |entry| : (index += 1) {
        const variable = std.mem.span(entry);
        if (std.mem.startsWith(u8, variable, "PATH=")) {
            path = variable["PATH=".len..];
            break;
        }
    }
    // Lookup happens inside the rootfs, without allocating after fork.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    var directories = std.mem.splitScalar(u8, path, ':');
    while (directories.next()) |directory| {
        const candidate = if (directory.len == 0) executable else (std.fmt.bufPrintZ(&buffer, "{s}/{s}", .{ directory, name }) catch continue).ptr;
        switch (linux.errno(linux.execve(candidate, argv, envp))) {
            .NOENT, .NOTDIR, .ACCES => continue,
            else => linux.exit_group(1),
        }
    }
    linux.exit_group(1);
}

test "proc stat parses field 22 after comm containing spaces and closing parentheses" {
    const stat = try parseProcStat(
        "1234 (init) name (x)) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 987654321 23 24\n",
    );
    try std.testing.expectEqual(@as(u8, 'S'), stat.state);
    try std.testing.expectEqualStrings("987654321", stat.starttime);
}

test "proc stat treats zombie and dead states as not alive" {
    for ([_]u8{ 'Z', 'X', 'S', 'R', 'T' }) |state| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "1234 (init) ) {c} 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345\n", .{state});
        defer std.testing.allocator.free(line);
        const stat = try parseProcStat(line);
        try std.testing.expectEqual(state != 'Z' and state != 'X', stat.matches("12345"));
        try std.testing.expect(!stat.matches("54321"));
    }
}

test "proc stat rejects missing fields and malformed starttime" {
    for ([_][]const u8{
        "1234 init S 4",
        "1234 (init)",
        "1234 (init) SS 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 12345",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21",
        "1234 (init) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 invalid",
    }) |line| {
        try std.testing.expectError(error.LivenessFailed, parseProcStat(line));
    }
}

test "linux backend is unavailable on other platforms" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234, .starttime = "12345" };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.NotImplemented, backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = "/tmp/bundle/rootfs",
            .exec_fifo = "/tmp/containers/example/exec.fifo",
            .spec = &spec,
        }));
    }
    try std.testing.expectError(error.NotImplemented, backend.alive(handle));
    try std.testing.expectError(error.NotImplemented, backend.kill(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.delete(handle));
}

test "linux liveness and signaling work with a handle loaded by a new backend" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    defer closeFd(pipe[1]);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(pipe[1]);
        var byte: [1]u8 = undefined;
        _ = readAll(pipe[0], &byte);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var stat_buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &stat_buffer);
    const handle: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(try backend.alive(handle));
    const reused: Backend.Handle = .{ .id = "persisted", .pid = pid, .starttime = "mismatched" };
    try std.testing.expect(!try backend.alive(reused));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(reused, 9));
    try std.testing.expect(try backend.alive(handle));
    try backend.kill(handle, 0);
    try std.testing.expectError(error.InvalidProcess, backend.kill(.{ .id = "invalid", .pid = 0, .starttime = "" }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.alive(.{ .id = "invalid", .pid = -1, .starttime = "" }));
    try std.testing.expectError(error.KillFailed, backend.kill(handle, 65));
    try backend.kill(handle, 9);
    _ = try waitChild(pid);
    reaped = true;
    try std.testing.expect(!try backend.alive(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
    try backend.delete(handle);
}

test "linux liveness rejects an unreaped zombie even though kill zero succeeds" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pid = try forkProcess();
    if (pid == 0) linux.exit_group(0);
    defer _ = waitChild(pid) catch {};
    var info: linux.siginfo_t = undefined;
    while (true) {
        switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT, null))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(pid, @enumFromInt(0))));
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var buffer: [4096]u8 = undefined;
    const stat = try readProcStat(pid, &buffer);
    const handle: Backend.Handle = .{ .id = "zombie", .pid = pid, .starttime = stat.starttime };
    try std.testing.expect(!try backend.alive(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
}

test "linux create rejects hostname without UTS isolation and unsupported terminals" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .hostname = "must-not-change-the-host",
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    spec.hostname = null;
    spec.process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .terminal = true, .user = .{ .uid = 0, .gid = 0 } };
    try std.testing.expectError(error.Unsupported, backend.create(options));
}

test "linux create requires mount isolation for library callers too" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "/" } };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.MissingMountNamespace, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
    }));
}

test "linux create rejects relative process cwd" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // These paths exist under rootfs, so existence alone cannot validate cwd.
    for ([_][]const u8{ "rootfs", ".", "" }) |cwd| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = rootfs },
            .process = .{ .args = &.{"/bin/sh"}, .cwd = cwd, .user = .{ .uid = 0, .gid = 0 } },
        };
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const result = backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            .spec = &spec,
        });
        if (result) |handle| {
            defer std.testing.allocator.free(handle.starttime);
            // Clean up if a regression incorrectly creates an init.
            backend.kill(handle, 9) catch {};
        } else |_| {}
        try std.testing.expectError(
            if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
            result,
        );
    }
}

test "linux create rejects empty process args" {
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
        result,
    );
}

test "linux create rejects a cwd missing from the resolved rootfs" {
    if (comptime builtin.os.tag == .linux) {
        try requireTestMountNamespace();
        const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
        closeFd(cgroup_root.fd);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // The resolved backend option is authoritative, even when root.path is "/".
    // /proc exists on the Linux host, but not inside this empty rootfs.
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/proc", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{
        if (comptime builtin.os.tag == .linux) linux.getpid() else 0,
    });
    defer std.testing.allocator.free(cgroup_path);
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = rootfs,
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .cgroup_path = cgroup_path,
    });
    if (result) |handle| {
        defer std.testing.allocator.free(handle.starttime);
        // Clean up if a regression incorrectly creates an init.
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.CreateFailed else error.NotImplemented,
        result,
    );
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

test "namespace flags reject joins including existing user namespaces" {
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .network, .path = "/proc/1234/ns/net" }},
    }));
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .user, .path = "/proc/1234/ns/user" }},
    }));
    const mappings: []const oci.Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }};
    try std.testing.expectEqual(@as(usize, linux.CLONE.NEWUSER | linux.CLONE.NEWNS), try namespaceFlags(.{
        .namespaces = &.{ .{ .type = .user }, .{ .type = .mount } },
        .uidMappings = mappings,
        .gidMappings = mappings,
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
        .{ .containerID = 10, .hostID = 300000, .size = 10 },
        .{ .containerID = 0, .hostID = 100000, .size = 10 },
    }));
    try std.testing.expectEqual(@as(u32, 200000), try mappedRootID(&.{.{ .containerID = 0, .hostID = 200000, .size = 10 }}));
    try std.testing.expectEqual(@as(u32, 0), try mappedRootID(&.{.{ .containerID = 0, .hostID = 0, .size = 1 }}));
    for ([_][]const oci.Spec.IDMapping{
        &.{},
        &.{.{ .containerID = 1, .hostID = 100000, .size = 10 }},
        &.{.{ .containerID = 0, .hostID = 100000, .size = 0 }},
    }) |mappings| {
        try std.testing.expectError(error.InvalidConfig, mappedRootID(mappings));
    }
}

test "linux create reports the frontend ambient capability validation error" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "/" } };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.AmbientCapabilitiesRequirePermittedAndInheritable, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        .capabilities = .{ .ambient = 1 },
    }));
}

test "linux capability preparation skips bits unsupported by the running kernel" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), 63, 0, 0, 0)) != .INVAL)
        return error.SkipZigTest;
    const future = @as(u64, 1) << 63;
    try std.testing.expectEqual(Backend.Capabilities{
        .bounding = 1,
        .effective = 1,
        .permitted = 1,
        .inheritable = 1,
        .ambient = 1,
    }, try kernelCapabilities(.{
        .bounding = future | 1,
        .effective = future | 1,
        .permitted = future | 1,
        .inheritable = future | 1,
        .ambient = future | 1,
    }));
}

test "linux exec searches the process PATH and preserves explicit paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct {
        executable: [*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        cwd: [:0]const u8 = "/",
        status: u32 = 0,
    }{
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:/bin:/usr/bin"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"}, .status = 1 << 8 },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{} },
        .{ .executable = "/bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH="}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=:/does-not-exist"}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:"}, .cwd = "/bin" },
    };
    for (cases) |case| {
        const argv = [_:null]?[*:0]const u8{ case.executable, "-c", "exit 0" };
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.chdir(case.cwd)) catch linux.exit_group(2);
            execProcess(&argv, case.envp);
        }
        try std.testing.expectEqual(case.status, try waitChild(pid));
    }
}

test "linux init applies uid gid and optional supplementary groups before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const cases = [_]struct { user_json: []const u8, expected: []const u8 }{
        .{ .user_json = "{\"uid\":1000,\"gid\":1000}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[]}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[1001,1002]}", .expected = "1000\n1000\n1000 1001 1002\n" },
    };
    for (cases) |case| {
        const user = try std.json.parseFromSlice(oci.Spec.User, std.testing.allocator, case.user_json, .{
            .ignore_unknown_fields = true,
        });
        defer user.deinit();
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "/" },
            .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .user = user.value },
        };
        const argv = [_:null]?[*:0]const u8{ "sh", "-c", "id -u; id -g; id -G" };
        const envp = [_:null]?[*:0]const u8{"PATH=/does-not-exist:/usr/bin:/bin"};
        const output = try makePipe();
        defer closeFd(output[0]);
        const ready = makePipe() catch |err| {
            closeFd(output[1]);
            return err;
        };
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(output[1]);
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(output[0]);
            closeFd(ready[0]);
            checkResult(linux.setgroups(1, &.{42})) catch linux.exit_group(1);
            checkResult(linux.dup2(output[1], posix.STDOUT_FILENO)) catch linux.exit_group(1);
            closeFd(output[1]);
            applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
            runProcess(&spec, &argv, &envp);
        }
        closeFd(output[1]);
        closeFd(ready[1]);
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        var bytes: [64]u8 = undefined;
        const result = bytes[0..case.expected.len];
        try std.testing.expect(readAll(output[0], result));
        try std.testing.expectEqualStrings(case.expected, result);
    }
}

test "linux init exits nonzero instead of exec when it cannot apply process user" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{ "/bin/sh", "-c", "exit 0" }, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        if (linux.geteuid() == 0) {
            checkResult(linux.setgid(1000)) catch linux.exit_group(2);
            checkResult(linux.setuid(1000)) catch linux.exit_group(2);
        }
        applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
        runProcess(&spec, &argv, &envp);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
}

test "linux init marks inherited descriptors CLOEXEC and sets noNewPrivileges" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const command = "test ! -e /proc/self/fd/200 && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status";
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{
            .args = &.{ "/bin/sh", "-c", command },
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0 },
            .noNewPrivileges = true,
        },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        checkResult(linux.dup2(ready[1], 200)) catch linux.exit_group(2);
        applyProcess(spec.process.?, null, &.{}) catch linux.exit_group(1);
        runProcess(&spec, &argv, &envp);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux process settings apply rlimits without changing inherited capabilities" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    var original: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.NOFILE, &original));
    const hard = @min(original.max, 1024);
    const soft = @min(hard, 512);
    const process: oci.Spec.Process = .{
        .args = &.{"/bin/true"},
        .cwd = "/",
        .user = .{ .uid = linux.geteuid(), .gid = linux.getegid(), .additionalGids = &.{} },
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, null, &.{.{ .resource = .NOFILE, .hard = hard, .soft = soft }}) catch linux.exit_group(1);
        var actual: linux.rlimit = undefined;
        checkResult(linux.getrlimit(.NOFILE, &actual)) catch linux.exit_group(2);
        if (actual.cur != soft or actual.max != hard) linux.exit_group(3);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(4);
        for (inherited, caps) |before, after| {
            if (before.effective != after.effective or before.permitted != after.permitted or
                before.inheritable != after.inheritable) linux.exit_group(5);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux process settings retain configured capabilities across nonzero uid and exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var inherited: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&inherited)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) | (@as(u32, 1) << linux.CAP.SETPCAP) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (inherited[0].effective & required != required) return error.SkipZigTest;
    if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.CHOWN, 0, 0, 0) != 1)
        return error.SkipZigTest;
    const command = "test \"$(id -u)\" = 1000 && grep -q '^CapAmb:[[:space:]]*0000000000000001$' /proc/self/status";
    const process: oci.Spec.Process = .{
        .args = &.{ "/bin/sh", "-c", command },
        .cwd = "/",
        .user = .{ .uid = 1000, .gid = 1000, .additionalGids = &.{} },
        .noNewPrivileges = true,
    };
    const pid = try forkProcess();
    if (pid == 0) {
        applyProcess(process, .{
            .bounding = 1,
            .permitted = 1,
            .effective = 1,
            .inheritable = 1,
            .ambient = 1,
        }, &.{}) catch linux.exit_group(1);
        var caps: [2]linux.cap_user_data_t = undefined;
        checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps))) catch linux.exit_group(2);
        if (caps[0].effective != 1 or caps[0].permitted != 1 or caps[0].inheritable != 1 or
            caps[1].effective != 0 or caps[1].permitted != 0 or caps[1].inheritable != 0) linux.exit_group(3);
        if (linux.prctl(@intFromEnum(linux.PR.GET_KEEPCAPS), 0, 0, 0, 0) != 0) linux.exit_group(4);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SETUID, 0, 0, 0) != 0) linux.exit_group(5);
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_IS_SET, linux.CAP.CHOWN, 0, 0) != 1)
            linux.exit_group(6);
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
        const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
        execProcess(&argv, &envp);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init reopens its root-owned pinned FIFO only for writing after dropping uid" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        const path_fd = openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .CLOEXEC = true }) catch linux.exit_group(1);
        const fd_dir = openPath(linux.AT.FDCWD, "/proc/self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
        var buffer: [32]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{d}", .{path_fd}) catch unreachable;
        checkResult(linux.fchmodat(fd_dir, name, 0o622)) catch linux.exit_group(2);
        applyProcess(.{
            .args = &.{"/bin/true"},
            .cwd = "/",
            .user = .{ .uid = 1000, .gid = 1000, .additionalGids = &.{} },
        }, null, &.{}) catch linux.exit_group(3);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(7);
        if (linux.errno(linux.openat(fd_dir, name, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0)) != .ACCES)
            linux.exit_group(8);
        if (!writeAll(ready[1], &.{1})) linux.exit_group(4);
        const fd = openPath(fd_dir, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch linux.exit_group(5);
        if (!writeAll(fd, &.{1})) linux.exit_group(6);
        linux.exit_group(0);
    }
    closeFd(ready[1]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(ready[0], &byte));
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    const status = try waitChild(pid);
    reaped = true;
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "linux create reports child setup failures without leaving an init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano/example-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const missing_cwd = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "missing" });
    defer std.testing.allocator.free(missing_cwd);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = missing_cwd, .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    var options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    spec.process.?.cwd = "/";
    // Linux rejects NOFILE above fs.nr_open even with CAP_SYS_RESOURCE.
    options.rlimits = &.{.{ .resource = .NOFILE, .hard = std.math.maxInt(u64), .soft = 0 }};
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
}

test "linux create accepts an empty rootfs and returns a live blocked init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    const specs = [_]oci.Spec{
        .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .linux = .{ .namespaces = &.{ .{ .type = .mount }, .{ .type = .cgroup } } },
            .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        },
        .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" }, .linux = .{ .namespaces = &.{.{ .type = .mount }} } },
    };
    for (specs) |spec| {
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const handle = try backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .spec = &spec,
            .cgroup_path = cgroup_path,
        });
        defer std.testing.allocator.free(handle.starttime);
        defer {
            backend.kill(handle, 9) catch {};
            backend.delete(handle) catch {};
        }
        try std.testing.expect(handle.pid > 0);
        try std.testing.expectEqualStrings("example", handle.id);
        try std.testing.expect(handle.starttime.len != 0);
        try std.testing.expect(try backend.alive(handle));
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(handle.pid, @enumFromInt(0))));
        const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
        try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode());
        if (spec.process != null) {
            var path_buffer: [64]u8 = undefined;
            const namespace_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/cgroup", .{handle.pid}) catch unreachable;
            const namespace = try openPath(linux.AT.FDCWD, namespace_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
            defer closeFd(namespace);
            const membership_path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/cgroup", .{handle.pid}) catch unreachable;
            // Read init's membership from its cgroup namespace without changing
            // the test runner's namespace or needing /proc in the empty rootfs.
            const checker = try forkProcess();
            if (checker == 0) {
                checkResult(linux.setns(namespace, linux.CLONE.NEWCGROUP)) catch linux.exit_group(1);
                const membership = openPath(linux.AT.FDCWD, membership_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch linux.exit_group(1);
                var bytes: [5]u8 = undefined;
                if (!readAll(membership, &bytes)) linux.exit_group(1);
                linux.exit_group(if (std.mem.eql(u8, &bytes, "0::/\n")) 0 else 1);
            }
            try std.testing.expectEqual(@as(u32, 0), try waitChild(checker));
        }
        try backend.kill(handle, 9);
        try backend.delete(handle);
        try backend.delete(handle);
    }
}

test "linux mapped create installs maps outside init and cleans up rejected maps" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var header: CapabilityHeader = .{};
    var caps: [2]linux.cap_user_data_t = undefined;
    try checkResult(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)));
    const required = (@as(u32, 1) << linux.CAP.CHOWN) |
        (@as(u32, 1) << linux.CAP.SETUID) | (@as(u32, 1) << linux.CAP.SETGID);
    if (caps[0].effective & required != required) return error.SkipZigTest;
    const namespace_probe = try forkProcess();
    if (namespace_probe == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(namespace_probe) != 0) return error.SkipZigTest;
    const cgroup_root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(cgroup_root.fd);
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-mapped-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "rootfs/dev", .default_dir);
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .user }, .{ .type = .mount }, .{ .type = .pid } },
            // Distinct container ranges with overlapping host ranges: the
            // kernel rejects uid_map after gid_map is written.
            .uidMappings = &.{
                .{ .containerID = 0, .hostID = 100000, .size = 2 },
                .{ .containerID = 2, .hostID = 100001, .size = 1 },
            },
            .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 10 }},
        },
        .process = .{
            .args = &.{"/bin/sh"},
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0, .additionalGids = &.{ 1, 2 } },
        },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "mapped",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        // Creating /dev/pts on the namespace-owned tmpfs needs mapped
        // fsuid/fsgid; unmapped host-root would fail mkdirat with EOVERFLOW.
        .mounts = &.{
            .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/pts", .source = "tmpfs", .type = "tmpfs", .flags = 0, .propagation = 0, .data = "mode=755" },
        },
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.Unsupported, backend.create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    spec.linux.?.uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 10 }};
    const handle = try backend.create(options);
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    try std.testing.expect(try backend.alive(handle));
    for ([_]struct { name: []const u8, tokens: []const []const u8 }{
        .{ .name = "uid_map", .tokens = &.{ "0", "100000", "10" } },
        .{ .name = "gid_map", .tokens = &.{ "0", "200000", "10" } },
        .{ .name = "setgroups", .tokens = &.{"allow"} },
    }) |expected| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/{s}", .{ handle.pid, expected.name });
        defer std.testing.allocator.free(path);
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(4096));
        defer std.testing.allocator.free(text);
        var tokens = std.mem.tokenizeAny(u8, text, " \t\n");
        for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
        try std.testing.expect(tokens.next() == null);
    }
    const status_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/status", .{handle.pid});
    defer std.testing.allocator.free(status_path);
    const status = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, status_path, std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(status);
    for ([_]struct { prefix: []const u8, tokens: []const []const u8 }{
        .{ .prefix = "Uid:", .tokens = &.{ "100000", "100000", "100000", "100000" } },
        .{ .prefix = "Gid:", .tokens = &.{ "200000", "200000", "200000", "200000" } },
        .{ .prefix = "Groups:", .tokens = &.{ "200001", "200002" } },
    }) |expected| {
        var lines = std.mem.tokenizeScalar(u8, status, '\n');
        var found = false;
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, expected.prefix)) continue;
            var tokens = std.mem.tokenizeAny(u8, line[expected.prefix.len..], " \t");
            for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
            try std.testing.expect(tokens.next() == null);
            found = true;
            break;
        }
        try std.testing.expect(found);
    }
    const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode());
    // Mapped root (host UID 100000) must still acknowledge start on the FIFO.
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll, 1, 2000));
    try std.testing.expect(poll[0].revents & linux.POLL.IN != 0);
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "linux mount destinations reject symlinks without creating host paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "outside", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const outside = try std.fs.path.join(std.testing.allocator, &.{ absolute, "outside" });
    defer std.testing.allocator.free(outside);
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/escape", .{});
    try tmp.dir.symLink(std.testing.io, outside, "rootfs/file", .{});
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const rootfs_z = try std.testing.allocator.dupeZ(u8, rootfs);
    defer std.testing.allocator.free(rootfs_z);
    const root_fd = try openPath(linux.AT.FDCWD, rootfs_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    if (mountDestination(root_fd, "/escape/new", false, true)) |fd| {
        closeFd(fd);
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.InvalidPath, mountDestination(root_fd, "/file", true, true));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/new", .{}));
}

test "linux rootfs setup applies ordered mounts detaches the host root and enforces readonly" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/item", .data = "bind contents" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source_dir = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source_dir);
    const source_file = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source/item", .{absolute}, 0);
    defer std.testing.allocator.free(source_file);
    const mounts = [_]PreparedMount{
        .{ .destination = "/work", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = linux.MS.PRIVATE, .data = "mode=755" },
        .{ .destination = "/work/from-bind", .source = source_dir, .type = null, .flags = linux.MS.BIND | linux.MS.REC, .propagation = 0, .data = "" },
        .{ .destination = "/etc/config", .source = source_file, .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY | linux.MS.NOSUID, .propagation = 0, .data = "" },
    };
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        setupRootfs(rootfs, &mounts, true) catch linux.exit_group(2);
        // The source's old absolute host path is unreachable after detaching.
        if (linux.errno(linux.access(source_file, linux.F_OK)) != .NOENT) linux.exit_group(3);
        if (linux.errno(linux.open("/new", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644)) != .ROFS) linux.exit_group(4);
        if (linux.errno(linux.open("/etc/config", .{ .ACCMODE = .WRONLY }, 0)) != .ROFS) linux.exit_group(5);
        const fd = openPath(linux.AT.FDCWD, "/etc/config", .{}) catch linux.exit_group(6);
        var contents: ["bind contents".len]u8 = undefined;
        if (!readAll(fd, &contents) or !std.mem.eql(u8, &contents, "bind contents")) linux.exit_group(7);
        closeFd(fd);
        if (linux.errno(linux.access("/work/from-bind/item", linux.F_OK)) != .SUCCESS) linux.exit_group(8);
        const writable = linux.open("/work/new", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
        if (linux.errno(writable) != .SUCCESS) linux.exit_group(9);
        closeFd(@intCast(writable));
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

fn requireTestMountNamespace() !void {
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    if (try waitChild(pid) != 0) return error.SkipZigTest;
}

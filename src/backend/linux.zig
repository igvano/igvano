const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../backend.zig").Backend;
const oci = @import("../oci.zig");
const hooks = @import("hooks.zig");

const ST_NOATIME: usize = 1024;
const ST_RELATIME: usize = 4096; // Unlike MS_RELATIME.
const OPEN_TREE_CLONE: u32 = 1;
const OPEN_TREE_CLOEXEC: u32 = 1 << @bitOffsetOf(linux.O, "CLOEXEC");

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

fn needsSetupDev(mounts: anytype) bool {
    var setup = true;
    for (mounts) |mount| {
        if (std.mem.eql(u8, mount.destination, "/dev"))
            setup = mount.flags & linux.MS.BIND == 0;
    }
    return setup;
}

fn validateDeviceMounts(mounts: []const Backend.Mount, devices: []const Backend.Device) Backend.Error!void {
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

fn namespaceFlag(kind: @FieldType(oci.Spec.Namespace, "type")) usize {
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

const NamespaceJoin = struct {
    flag: usize,
    path: [:0]const u8,
};

fn validateNamespaceFd(fd: posix.fd_t, flag: usize) Backend.Error!void {
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
fn joinNamespaces(joins: []const NamespaceJoin) Backend.Error!void {
    var fds: [8]posix.fd_t = @splat(-1);
    if (joins.len > fds.len) return error.InvalidConfig;
    defer for (fds) |fd| {
        if (fd >= 0) closeFd(fd);
    };
    for (joins, 0..) |join, i| {
        fds[i] = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        try validateNamespaceFd(fds[i], join.flag);
    }
    // runc's nsexec order: user first for capabilities in the target owner.
    for ([_]usize{
        linux.CLONE.NEWUSER, linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC,
        linux.CLONE.NEWUTS,  linux.CLONE.NEWNET,    linux.CLONE.NEWPID,
        linux.CLONE.NEWNS,   linux.CLONE.NEWTIME,
    }) |flag| {
        for (joins, 0..) |join, i| {
            if (join.flag == flag) try checkResult(linux.setns(fds[i], @intCast(flag)));
        }
    }
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
            var isolation_flags = flags;
            for (if (options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace|
                isolation_flags |= namespaceFlag(namespace.type);
            if (options.spec.hostname != null and isolation_flags & linux.CLONE.NEWUTS == 0)
                return error.InvalidConfig;
            if (options.spec.process) |process| {
                if (process.args.len == 0) return error.InvalidProcess;
            }
            const terminal = if (options.spec.process) |process| process.terminal orelse false else false;
            if (terminal != (options.console_fds != null)) return error.InvalidConfig;
            if (options.capabilities) |caps| {
                if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
                    return error.AmbientCapabilitiesRequirePermittedAndInheritable;
            }
            const capabilities = if (options.capabilities) |caps| try kernelCapabilities(caps) else null;
            for (options.rlimits) |limit| {
                if (limit.soft > limit.hard) return error.InvalidConfig;
            }
            try validateDeviceMounts(options.mounts, options.devices);
            if (!std.fs.path.isAbsolute(options.exec_fifo) or
                std.mem.indexOfScalar(u8, options.exec_fifo, 0) != null)
                return error.InvalidPath;

            // Prepare the init's strings before either fork.
            var arena: std.heap.ArenaAllocator = .init(options.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var joins: std.ArrayList(NamespaceJoin) = .empty;
            for (if (options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace| {
                if (namespace.path) |path| try joins.append(allocator, .{
                    .flag = namespaceFlag(namespace.type),
                    .path = try pathString(allocator, path),
                });
            }
            // Safety guard: rootfs setup in our mount namespace would mutate host mounts.
            for (joins.items) |join| {
                if (join.flag != linux.CLONE.NEWNS) continue;
                const own_fd = try openPath(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
                defer closeFd(own_fd);
                const target_fd = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
                defer closeFd(target_fd);
                try validateNamespaceFd(target_fd, join.flag);
                var own_stat: linux.Statx = undefined;
                var target_stat: linux.Statx = undefined;
                try checkResult(linux.statx(own_fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &own_stat));
                try checkResult(linux.statx(target_fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &target_stat));
                if (!own_stat.mask.INO or !target_stat.mask.INO) return error.CreateFailed;
                if (own_stat.dev_major == target_stat.dev_major and
                    own_stat.dev_minor == target_stat.dev_minor and own_stat.ino == target_stat.ino)
                {
                    std.debug.print("igvano: cannot join the runtime's own mount namespace\n", .{});
                    return error.InvalidConfig;
                }
            }
            const user_namespace = flags & linux.CLONE.NEWUSER != 0;
            const joined_user_namespace = !user_namespace and isolation_flags & linux.CLONE.NEWUSER != 0;
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
            if (isolation_flags & linux.CLONE.NEWNS == 0) return error.MissingMountNamespace;
            if (!std.fs.path.isAbsolute(rootfs)) return error.InvalidPath;
            try validateCgroupPath(options.cgroup_path);
            // Joined user namespaces may map root to a different host UID.
            // Only the outside parent can chmod this host-owned FIFO. Readers
            // remain root-only, as when init drops to a nonzero process UID.
            if (joined_user_namespace) try checkResult(linux.fchmodat(linux.AT.FDCWD, fifo, 0o622));
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
            const devices = try allocator.alloc(PreparedDevice, options.devices.len);
            for (options.devices, devices) |device, *prepared| {
                if (!std.mem.startsWith(u8, device.path, "/") or
                    device.major > 0xfff or device.minor > 0xfffff or
                    device.mode & ~@as(u32, 0o7777) != 0)
                    return error.InvalidConfig;
                prepared.* = .{
                    .path = try pathString(allocator, device.path),
                    .mode = device.mode | @as(u32, switch (device.kind) {
                        .character => linux.S.IFCHR,
                        .block => linux.S.IFBLK,
                        .fifo => linux.S.IFIFO,
                    }),
                    .dev = (device.major << 8) | (device.minor & 0xff) | ((device.minor & 0xfff00) << 12),
                    .uid = device.uid,
                    .gid = device.gid,
                };
            }
            const args: []const []const u8 = if (options.spec.process) |process| process.args else &.{};
            const env: []const []const u8 = if (options.spec.process) |process| process.env orelse &.{} else &.{};
            const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);
            for (args, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
            const envp = try allocator.allocSentinel(?[*:0]const u8, env.len, null);
            for (env, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;
            const create_hooks = try hooks.prepare(allocator, options.create_hooks);
            const start_hooks = try hooks.prepare(allocator, options.start_hooks);
            const create_state = try allocator.alloc(u8, options.create_hook_state.prefix.len + 20 + options.create_hook_state.suffix.len);
            const start_state = try allocator.alloc(u8, options.start_hook_state.prefix.len + 20 + options.start_hook_state.suffix.len);
            const masked_paths = try preparePaths(allocator, options.masked_paths);
            const readonly_paths = try preparePaths(allocator, options.readonly_paths);

            // pivot_root also changes child1's root while it waits in the same
            // mount namespace. Pin host /proc so it can still capture identity.
            const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
            defer closeFd(proc_dir);
            // Init must retain the host FIFO across namespace changes without
            // traversing the private state directory as a mapped user.
            const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
            defer closeFd(fifo_fd);
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
            // getpid() in child2 may be 1. Child1 supplies its host PID for
            // opaque hook input; buffers and JSON fragments were prepared above.
            const pid_pipe = try makePipe();
            var owns_pid_pipe = true;
            defer if (owns_pid_pipe) {
                for (pid_pipe) |fd| closeFd(fd);
            };
            const report = try makePipe();
            const ready = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                return err;
            };
            const create_go = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                return err;
            };
            var owns_create_go = true;
            defer if (owns_create_go) {
                for (create_go) |fd| closeFd(fd);
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
                if (options.console_fds) |fds| closeFd(fds[0]);
                closeFd(create_go[1]);
                if (map_pipe) |fds| closeFd(fds[1]);
                closeFd(cgroup_root.fd);
                closeFd(report[0]);
                // Join before NEWCGROUP snapshots the namespace root. Child2
                // inherits this membership; the runtime parent stays outside.
                writeCgroupFile(cgroup, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                closeFd(cgroup);
                // Set with host privileges before entering user namespaces.
                // Child2 inherits the adjustment across fork and exec.
                applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
                joinNamespaces(joins.items) catch |err| failCreate(report[1], err);
                // NEWUSER is unshared together with the others so it owns them.
                if (flags != 0) checkResult(linux.unshare(flags)) catch |err| failCreate(report[1], err);
                // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
                const child2 = forkProcess() catch |err| failCreate(report[1], err);
                if (child2 == 0) {
                    closeFd(pid_pipe[1]);
                    var host_pid: i32 = undefined;
                    if (!readAll(pid_pipe[0], std.mem.asBytes(&host_pid))) linux.exit_group(1);
                    closeFd(pid_pipe[0]);
                    // Let the parent see report EOF if child1 dies during the map wait.
                    closeFd(report[1]);
                    closeFd(ready[0]);
                    // Host procfs resolves "self" to child2's host PID, even
                    // when a joined mount namespace supplies a different /proc.
                    const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
                    closeFd(proc_dir);
                    // The outside parent must install our ID maps
                    // before any rootfs, mount, hostname, or process work.
                    if (map_pipe) |fds| {
                        var byte: [1]u8 = undefined;
                        if (!readAll(fds[0], &byte)) linux.exit_group(1);
                        closeFd(fds[0]);
                    }
                    if (isolation_flags & linux.CLONE.NEWUSER != 0) {
                        // Like runc nsexec stage-2, become root in the user ns.
                        // Unmapped host-root fsuid/fsgid make may_create() fail
                        // with EOVERFLOW on filesystems mounted in this ns.
                        checkResult(linux.setgid(0)) catch linux.exit_group(1);
                        checkResult(linux.setuid(0)) catch linux.exit_group(1);
                    }
                    const create_input = std.fmt.bufPrint(create_state, "{s}{d}{s}", .{
                        options.create_hook_state.prefix, host_pid, options.create_hook_state.suffix,
                    }) catch linux.exit_group(1);
                    const start_input = std.fmt.bufPrint(start_state, "{s}{d}{s}", .{
                        options.start_hook_state.prefix, host_pid, options.start_hook_state.suffix,
                    }) catch linux.exit_group(1);
                    runInit(options.spec, capabilities, options.rlimits, isolation_flags, rootfs, mounts, devices, options.device_symlinks, cwd, fifo_fd, fd_dir, argv.ptr, envp.ptr, ready[1], .{
                        .propagation = options.rootfs_propagation,
                        .create_hooks = create_hooks,
                        .create_hook_state = create_input,
                        .masked_paths = masked_paths,
                        .readonly_paths = readonly_paths,
                        .runtime_sync = .{ .ready_fd = ready[1], .go_fd = create_go[0] },
                        .console_fd = if (options.console_fds) |fds| fds[1] else null,
                        .fifo_writable = joined_user_namespace,
                    }, start_hooks, start_input);
                }
                closeFd(fifo_fd);
                if (options.console_fds) |fds| closeFd(fds[1]);
                closeFd(create_go[0]);
                closeFd(pid_pipe[0]);
                var host_pid = child2;
                if (!writeAll(pid_pipe[1], std.mem.asBytes(&host_pid))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], error.CreateFailed);
                }
                closeFd(pid_pipe[1]);
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
                // Child2 has applied mounts and waits before child hooks/pivot.
                if (!readAll(ready[0], &byte)) {
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
                const initialized = readAll(ready[0], &byte);
                closeFd(ready[0]);
                if (!initialized) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], error.CreateFailed);
                }
                if (!writeAll(report[1], std.mem.asBytes(&response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
                // No shim: exiting child1 reparents the blocked init to host init.
                linux.exit_group(0);
            }

            // Only child1 writes the PID. Keeping a writer in this parent
            // would strand child2 if child1 died before sending it, preventing
            // report EOF and hanging create.
            for (pid_pipe) |fd| closeFd(fd);
            owns_pid_pipe = false;
            closeFd(report[1]);
            for (ready) |fd| closeFd(fd);
            defer closeFd(report[0]);
            // Keep a reader to prevent SIGPIPE if init exits before release.
            defer closeFd(create_go[0]);
            var create_writer: ?posix.fd_t = create_go[1];
            defer if (create_writer) |fd| closeFd(fd);
            owns_create_go = false;
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
                if (create_writer) |fd| {
                    closeFd(fd);
                    create_writer = null;
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
            errdefer if (reported and handle.pid > 0) {
                kill(ptr, handle, 9) catch {};
            };
            if (!reported) return error.CreateFailed;
            if (response.failure != 0) return @errorCast(@errorFromInt(@as(u16, @intCast(response.failure))));
            if (response.pid <= 0) return error.CreateFailed;
            if (options.on_create) |callback| try callback.run(callback.ptr, handle);
            if (!writeAll(create_writer.?, &.{1})) return error.CreateFailed;
            closeFd(create_writer.?);
            create_writer = null;
            response = .{};
            const initialized = readAll(report[0], std.mem.asBytes(&response));
            child1_reaped = true;
            const status = try waitChild(child1);
            if (!initialized) return error.CreateFailed;
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

fn preparePaths(allocator: std.mem.Allocator, paths: []const []const u8) Backend.Error![]const [:0]const u8 {
    const prepared = try allocator.alloc([:0]const u8, paths.len);
    for (paths, prepared) |path, *value| {
        if (!std.mem.startsWith(u8, path, "/")) return error.InvalidPath;
        value.* = try pathString(allocator, path);
    }
    return prepared;
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

/// Linux descriptor passing, shared by init and the frontend. No allocation
/// or std.Io machinery: these helpers also run after fork.
pub const console = struct {
    const Rights = extern struct {
        header: linux.cmsghdr,
        fd: posix.fd_t,
    };
    const rights_len = @sizeOf(linux.cmsghdr) + @sizeOf(posix.fd_t);

    pub fn socketpair() Backend.Error![2]posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var fds: [2]posix.fd_t = undefined;
        try checkResult(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
        errdefer for (fds) |fd| closeFd(fd);
        for (&fds) |*fd| {
            if (fd.* <= 2) {
                const moved = linux.fcntl(fd.*, linux.F.DUPFD_CLOEXEC, 3);
                try checkResult(moved);
                closeFd(fd.*);
                fd.* = @intCast(moved);
            }
        }
        return fds;
    }

    pub fn sendFd(socket: posix.fd_t, fd: posix.fd_t) Backend.Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        rights.header = .{ .len = rights_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
        rights.fd = fd;
        const data = "ptmx";
        const iov = [_]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
        const message: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        while (true) {
            const result = linux.sendmsg(socket, &message, linux.MSG.NOSIGNAL);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.ConsoleFailed;
                    // Ancillary data is attached to the first byte, even when
                    // a stream write is short. Do not send the rights twice.
                    if (result < data.len and !writeAll(socket, data[result..])) return error.ConsoleFailed;
                    return;
                },
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        }
    }

    pub fn receiveFd(socket: posix.fd_t) Backend.Error!posix.fd_t {
        if (comptime builtin.os.tag != .linux) return error.NotImplemented;
        var rights: Rights = std.mem.zeroes(Rights);
        var data: [4]u8 = undefined;
        var iov = [_]posix.iovec{.{ .base = &data, .len = data.len }};
        var message: linux.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(Rights),
            .flags = 0,
        };
        const count = while (true) {
            const result = linux.recvmsg(socket, &message, linux.MSG.CMSG_CLOEXEC | linux.MSG.WAITALL);
            switch (linux.errno(result)) {
                .SUCCESS => break result,
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        };
        if (message.controllen < rights_len or rights.header.level != linux.SOL.SOCKET or
            rights.header.type != linux.SCM.RIGHTS or rights.header.len < rights_len)
            return error.ConsoleFailed;
        // The aligned control buffer can hold a second fd in its padding.
        // Close all delivered rights, including on truncated/malformed input.
        const bytes = std.mem.asBytes(&rights);
        const control_end = @min(message.controllen, @min(rights.header.len, bytes.len));
        var offset: usize = rights_len;
        while (offset + @sizeOf(posix.fd_t) <= control_end) : (offset += @sizeOf(posix.fd_t)) {
            const extra = std.mem.bytesToValue(posix.fd_t, bytes[offset..][0..@sizeOf(posix.fd_t)]);
            closeFd(extra);
        }
        errdefer closeFd(rights.fd);
        if (rights.header.len != rights_len or message.flags & linux.MSG.CTRUNC != 0 or count == 0)
            return error.ConsoleFailed;
        if (count < data.len and !readAll(socket, data[count..])) return error.ConsoleFailed;
        if (!std.mem.eql(u8, &data, "ptmx")) return error.ConsoleFailed;
        return rights.fd;
    }
};

test "linux SCM_RIGHTS roundtrip preserves a descriptor across forwarding" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer for (sockets) |fd| closeFd(fd);
    const forwarded = try console.socketpair();
    defer for (forwarded) |fd| closeFd(fd);
    const pipe = try makePipe();
    defer for (pipe) |fd| closeFd(fd);
    try console.sendFd(sockets[0], pipe[0]);
    const received = try console.receiveFd(sockets[1]);
    defer closeFd(received);
    try std.testing.expect(linux.fcntl(received, linux.F.GETFD, 0) & linux.FD_CLOEXEC != 0);
    try console.sendFd(forwarded[0], received);
    const final = try console.receiveFd(forwarded[1]);
    defer closeFd(final);
    try std.testing.expect(writeAll(pipe[1], "x"));
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(final, &byte));
    try std.testing.expectEqualStrings("x", &byte);
}

test "linux console receiver rejects a message without descriptor rights and EOF" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const sockets = try console.socketpair();
    defer closeFd(sockets[0]);
    try std.testing.expect(writeAll(sockets[1], "ptmx"));
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
    closeFd(sockets[1]);
    try std.testing.expectError(error.ConsoleFailed, console.receiveFd(sockets[0]));
}

test "linux namespace descriptors reject a mismatched configured type" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const fd = try openPath(linux.AT.FDCWD, "/proc/self/ns/net", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(fd);
    // Kernels without NS_GET_NSTYPE cannot exercise the type comparison.
    if (linux.errno(linux.ioctl(fd, linux.IOCTL.IO(0xb7, 3), 0)) == .NOTTY) return error.SkipZigTest;
    try validateNamespaceFd(fd, linux.CLONE.NEWNET);
    try std.testing.expectError(error.InvalidConfig, validateNamespaceFd(fd, linux.CLONE.NEWUTS));
}

test "linux console setup binds its slave to dev console and sends its master" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    const sockets = try console.socketpair();
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(sockets[0]);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        checkResult(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) catch linux.exit_group(1);
        checkResult(linux.mount("tmpfs", "/dev", "tmpfs", linux.MS.NOSUID, 0)) catch linux.exit_group(1);
        checkResult(linux.mkdir("/dev/pts", 0o755)) catch linux.exit_group(1);
        checkResult(linux.mount("devpts", "/dev/pts", "devpts", linux.MS.NOSUID | linux.MS.NOEXEC, @intFromPtr("newinstance,ptmxmode=666,mode=620"))) catch linux.exit_group(1);
        checkResult(linux.symlink("pts/ptmx", "/dev/ptmx")) catch linux.exit_group(1);
        setupConsole(sockets[1]) catch linux.exit_group(1);
        closeFd(sockets[1]);
        var console_stat: linux.Statx = undefined;
        var slave_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(1);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &slave_stat)) catch linux.exit_group(1);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != slave_stat.ino or
            console_stat.dev_major != slave_stat.dev_major or console_stat.dev_minor != slave_stat.dev_minor)
            linux.exit_group(1);
        var session: i32 = undefined;
        for (0..3) |fd| {
            checkResult(linux.ioctl(@intCast(fd), linux.T.IOCGSID, @intFromPtr(&session))) catch linux.exit_group(1);
            if (session != linux.getpid()) linux.exit_group(1);
            if (linux.fcntl(@intCast(fd), linux.F.GETFD, 0) != 0) linux.exit_group(1);
        }
        if (!writeAll(1, "console\n")) linux.exit_group(1);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(1);
        linux.exit_group(0);
    }
    closeFd(sockets[1]);
    defer closeFd(sockets[0]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    const master = try console.receiveFd(sockets[0]);
    defer closeFd(master);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(master, &output));
    try std.testing.expectEqualStrings("console\r\n", &output);
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
}

fn setupConsole(socket: posix.fd_t) Backend.Error!void {
    const pts = consolePath("/dev/pts", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch
        return error.MissingDevpts;
    defer closeFd(pts);
    var fs: [32]usize = undefined;
    try checkResult(linux.syscall2(.fstatfs, @intCast(pts), @intFromPtr(&fs)));
    if (fs[0] != 0x1cd1) return error.MissingDevpts; // DEVPTS_SUPER_MAGIC
    const master = try consolePath("/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    defer closeFd(master);
    var unlock: i32 = 0;
    try checkResult(linux.ioctl(master, linux.T.IOCSPTLCK, @intFromPtr(&unlock)));
    const slave_flags: linux.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
    var slave_path_buffer: [32]u8 = undefined;
    var slave_path: ?[:0]const u8 = null;
    const opened_slave: posix.fd_t = peer: {
        const result = linux.ioctl(master, linux.T.IOCGPTPEER, @as(u32, @bitCast(slave_flags)));
        switch (linux.errno(result)) {
            .SUCCESS => break :peer @intCast(result),
            .NOTTY, .INVAL, .NOSYS => {
                var number: u32 = undefined;
                try checkResult(linux.ioctl(master, linux.T.IOCGPTN, @intFromPtr(&number)));
                const path = std.fmt.bufPrintZ(&slave_path_buffer, "/dev/pts/{d}", .{number}) catch return error.ConsoleFailed;
                slave_path = path;
                break :peer try openPath(linux.AT.FDCWD, path, slave_flags);
            },
            else => return error.ConsoleFailed,
        }
    };
    const slave = try consoleAboveStdio(opened_slave);
    defer closeFd(slave);
    const root = try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const target = try consoleAboveStdio(try mountDestination(root, "/dev/console", true, true));
    defer closeFd(target);
    bind: {
        const cloned = linux.syscall3(.open_tree, @intCast(slave), @intFromPtr(""), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | linux.AT.EMPTY_PATH);
        if (linux.errno(cloned) != .NOSYS and linux.errno(cloned) != .PERM) {
            try checkResult(cloned);
            const tree: posix.fd_t = @intCast(cloned);
            defer closeFd(tree);
            var flags = std.mem.zeroes(linux.MOVE_MOUNT);
            flags.F_EMPTY_PATH = true;
            flags.T_EMPTY_PATH = true;
            const moved = linux.move_mount(tree, "", target, "", flags);
            if (linux.errno(moved) != .NOSYS) {
                try checkResult(moved);
                break :bind;
            }
        }
        // Older kernels and seccomp policies still need procfs for the descriptor paths.
        var source_buffer: [64]u8 = undefined;
        var target_buffer: [64]u8 = undefined;
        try checkResult(linux.mount(slave_path orelse fdPath(&source_buffer, slave), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
    }
    try checkResult(linux.setsid());
    try checkResult(linux.ioctl(slave, linux.T.IOCSCTTY, 0));
    for (0..3) |fd| {
        try checkResult(linux.dup2(slave, @intCast(fd)));
        // dup2(fd, fd) preserves CLOEXEC when stdio was initially closed.
        try checkResult(linux.fcntl(@intCast(fd), linux.F.SETFD, 0));
    }
    try console.sendFd(socket, master);
}

fn consoleAboveStdio(fd: posix.fd_t) Backend.Error!posix.fd_t {
    if (fd > 2) return fd;
    defer closeFd(fd);
    const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
    try checkResult(moved);
    return @intCast(moved);
}

fn consolePath(path: [*:0]const u8, flags: linux.O) Backend.Error!posix.fd_t {
    return consoleAboveStdio(try openPath(linux.AT.FDCWD, path, flags));
}

fn childError(message: []const u8, err: anyerror) void {
    _ = writeAll(2, message);
    _ = writeAll(2, @errorName(err));
    _ = writeAll(2, "\n");
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
        if (linux.errno(result) == .INVAL) return error.InvalidConfig;
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

const PreparedDevice = struct {
    path: [:0]const u8,
    mode: u32,
    dev: u32,
    uid: u32 = 0,
    gid: u32 = 0,
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

fn remountFlags(target_fd: posix.fd_t, requested: u32) Backend.Error!u32 {
    if (comptime builtin.os.tag == .linux) {
        // Linux statfs uses native words, except for the two-int fsid.
        const Statfs = extern struct {
            type: usize,
            bsize: usize,
            blocks: usize,
            bfree: usize,
            bavail: usize,
            files: usize,
            ffree: usize,
            fsid: [2]i32,
            namelen: usize,
            frsize: usize,
            flags: usize,
            spare: [4]usize,
        };
        var fs: Statfs = undefined;
        try checkResult(linux.syscall2(.fstatfs, @intCast(target_fd), @intFromPtr(&fs)));
        return lockedMountFlags(requested, fs.flags);
    } else {
        return error.NotImplemented;
    }
}

fn bindRemount(target_fd: posix.fd_t, target: [*:0]const u8, requested: u32) Backend.Error!void {
    const result = linux.mount(null, target, null, requested, 0);
    if (linux.errno(result) != .PERM) return checkResult(result);
    // Retry locked flags on EPERM, including in an inherited user namespace.
    // Privileged callers may change these flags, so first honor their request.
    const flags = try remountFlags(target_fd, requested);
    try checkResult(linux.mount(null, target, null, flags, 0));
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
        try bindRemount(target_fd, fdPath(&target_buffer, target_fd), (mount.flags & ~@as(u32, ms.REC)) | ms.BIND | ms.REMOUNT);
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

fn validateDeviceNode(fd: posix.fd_t, device: PreparedDevice) Backend.Error!void {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    const kind = device.mode & linux.S.IFMT;
    if (stat.mode & linux.S.IFMT != kind) return error.InvalidPath;
    if (kind == linux.S.IFCHR or kind == linux.S.IFBLK) {
        // Decode the Linux device number passed to mknodat.
        const major = (device.dev >> 8) & 0xfff;
        const minor = (device.dev & 0xff) | ((device.dev >> 12) & 0xfff00);
        if (stat.rdev_major != major or stat.rdev_minor != minor) return error.InvalidPath;
    }
}

fn createDevice(root_fd: posix.fd_t, device: PreparedDevice) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        const parent = std.fs.path.dirname(device.path) orelse return error.InvalidPath;
        const dir = try mountDestination(root_fd, parent, false, true);
        defer closeFd(dir);
        var name_buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&name_buffer, "{s}", .{std.fs.path.basename(device.path)}) catch return error.InvalidPath;
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
        const created = linux.mknodat(dir, name, device.mode, device.dev);
        switch (linux.errno(created)) {
            .SUCCESS => {
                // Pin the new node for metadata updates, even if the name changes.
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                try validateDeviceNode(node, device);
                try checkResult(linux.fchownat(node, "", device.uid, device.gid, linux.AT.EMPTY_PATH));
                var buffer: [64]u8 = undefined;
                try checkResult(linux.fchmodat(linux.AT.FDCWD, fdPath(&buffer, node), device.mode & 0o7777));
            },
            // A configured mount may already supply this device. Preserve it
            // only when its type and device number match the requested node.
            .EXIST => {
                // Deliberately keep existing metadata: this node may come
                // from a bind mount, and rewriting it would change the host.
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                try validateDeviceNode(node, device);
            },
            .PERM => {
                // mknod is forbidden in user namespaces. Like runc, retry an
                // EPERM as a bind, including when the runtime inherited a user ns.
                const source = try openPath(linux.AT.FDCWD, device.path, .{ .PATH = true, .CLOEXEC = true });
                defer closeFd(source);
                try validateDeviceNode(source, device);
                const target = try mountDestination(root_fd, device.path, true, true);
                defer closeFd(target);
                var source_buffer: [64]u8 = undefined;
                var target_buffer: [64]u8 = undefined;
                try checkResult(linux.mount(fdPath(&source_buffer, source), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
                // Like runc, bind fallback inherits host metadata; changing it
                // here would chmod/chown the host device as well.
            },
            else => try checkResult(created),
        }
    } else {
        return error.NotImplemented;
    }
}

fn setupDevices(root_fd: posix.fd_t, devices: []const PreparedDevice, symlinks: []const Backend.Symlink) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (devices) |device| try createDevice(root_fd, device);
        for (symlinks) |link| {
            if (!std.mem.startsWith(u8, link.path, "/")) return error.InvalidPath;
            const parent = std.fs.path.dirname(link.path) orelse return error.InvalidPath;
            const dir = try mountDestination(root_fd, parent, false, true);
            defer closeFd(dir);
            var buffer: [256]u8 = undefined;
            const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(link.path)}) catch return error.InvalidPath;
            const result = linux.symlinkat(link.target, dir, name);
            switch (linux.errno(result)) {
                .SUCCESS, .EXIST => {},
                else => try checkResult(result),
            }
        }
    } else {
        return error.NotImplemented;
    }
}

const RootfsOptions = struct {
    console_fd: ?posix.fd_t = null,
    fifo_writable: bool = false,
    propagation: u32 = linux.MS.PRIVATE | linux.MS.REC,
    create_hooks: []const hooks.Prepared = &.{},
    create_hook_state: []const u8 = "",
    masked_paths: []const [:0]const u8 = &.{},
    readonly_paths: []const [:0]const u8 = &.{},
    runtime_sync: ?struct { ready_fd: posix.fd_t, go_fd: posix.fd_t } = null,
};

/// Paths now resolve entirely inside the pivoted rootfs. Missing targets are
/// ignored; other mount failures must not silently weaken isolation.
fn applyPathRestrictions(masked: []const [:0]const u8, readonly: []const [:0]const u8) Backend.Error!void {
    const ms = linux.MS;
    for (masked) |path| {
        var stat: linux.Statx = undefined;
        const result = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        if (!stat.mask.TYPE) return error.CreateFailed;
        if (stat.mode & linux.S.IFMT == linux.S.IFDIR) {
            try checkResult(linux.mount("tmpfs", path, "tmpfs", ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC, 0));
        } else {
            try checkResult(linux.mount("/dev/null", path, null, ms.BIND, 0));
        }
    }
    for (readonly) |path| {
        const result = linux.mount(path, path, null, ms.BIND | ms.REC, 0);
        switch (linux.errno(result)) {
            .NOENT => continue,
            .SUCCESS => {},
            else => try checkResult(result),
        }
        const fd = try openPath(linux.AT.FDCWD, path, .{ .PATH = true, .CLOEXEC = true });
        defer closeFd(fd);
        try bindRemount(fd, path, ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
}

/// Like runc, walk up to the containing mount. Only that mount must be
/// private for pivot_root; inherited submounts retain their peer groups.
fn makeRootfsParentPrivate(rootfs: [:0]const u8) Backend.Error!void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (rootfs.len >= buffer.len) return error.InvalidPath;
    @memcpy(buffer[0..rootfs.len], rootfs);
    var end = rootfs.len;
    while (true) {
        buffer[end] = 0;
        const result = linux.mount(null, buffer[0..end :0], null, linux.MS.PRIVATE, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INVAL => {
                if (end == 1) return error.CreateFailed;
                end = (std.fs.path.dirname(buffer[0..end]) orelse return error.InvalidPath).len;
            },
            else => try checkResult(result),
        }
    }
}

/// All paths, hook arguments and state buffers are prepared before fork.
/// Allocating in child2 risks inherited allocator locks (POSIX only permits
/// async-signal-safe work after fork). The raw hook runner needs no allocation.
fn setupRootfs(rootfs: [:0]const u8, mounts: []const PreparedMount, devices: []const PreparedDevice, symlinks: []const Backend.Symlink, readonly: bool, options: RootfsOptions) Backend.Error!void {
    const ms = linux.MS;
    try checkResult(linux.mount(null, "/", null, options.propagation, 0));
    // Shared parents prevent pivot_root; make only the containing mount private.
    // Unbindable sources require temporary recursive private propagation.
    const restore_propagation = options.propagation & (ms.SHARED | ms.UNBINDABLE) != 0;
    if (options.propagation & ms.UNBINDABLE != 0) {
        try checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0));
    } else if (options.propagation & ms.SHARED != 0) {
        try makeRootfsParentPrivate(rootfs);
    }
    try checkResult(linux.mount(rootfs, rootfs, null, ms.BIND | ms.REC, 0));
    for (mounts) |mount| {
        const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        try applyMount(rootfs, root_fd, mount);
    }
    if (options.runtime_sync) |sync| {
        if (!writeAll(sync.ready_fd, &.{1})) return error.CreateFailed;
        var byte: [1]u8 = undefined;
        const released = readAll(sync.go_fd, &byte);
        closeFd(sync.go_fd);
        if (!released or byte[0] != 1) return error.CreateFailed;
    }
    // Runtime paths are still reachable; the hook already runs in the new
    // mount namespace and sees all configured mounts before pivot_root.
    try hooks.run(options.create_hooks, options.create_hook_state);
    // runc's fd trick stacks the old root on the new root without a put_old
    // directory. Detach it and close both handles before any container exec.
    // Keep them above stdio, which console setup replaces before they close.
    const old_root = try consolePath("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(old_root);
    const new_root = try consolePath(rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(new_root);
    // Populate rootfs /dev even without tmpfs, but leave a bind-mounted /dev
    // untouched: device nodes and symlinks there would mutate the host source.
    if (needsSetupDev(mounts)) try setupDevices(new_root, devices, symlinks);
    try checkResult(linux.fchdir(new_root));
    try checkResult(linux.pivot_root(".", "."));
    try checkResult(linux.fchdir(old_root));
    // Detaching inherited shared submounts must not unmount their host peers.
    try checkResult(linux.mount(null, ".", null, ms.SLAVE | ms.REC, 0));
    try checkResult(linux.umount2(".", linux.MNT.DETACH));
    try checkResult(linux.chdir("/"));
    if (options.console_fd) |socket| {
        defer closeFd(socket);
        setupConsole(socket) catch |err| {
            childError("igvano: cannot set up console (requires devpts mounted at /dev/pts): ", err);
            linux.exit_group(1);
        };
    }
    try applyPathRestrictions(options.masked_paths, options.readonly_paths);
    if (readonly) {
        try bindRemount(new_root, "/", ms.BIND | ms.REMOUNT | ms.RDONLY);
    }
    if (restore_propagation)
        try checkResult(linux.mount(null, "/", null, options.propagation, 0));
}

fn runInit(
    spec: *const oci.Spec,
    capabilities: ?Backend.Capabilities,
    rlimits: []const Backend.Rlimit,
    flags: usize,
    rootfs: [:0]const u8,
    mounts: []const PreparedMount,
    devices: []const PreparedDevice,
    symlinks: []const Backend.Symlink,
    cwd: [:0]const u8,
    fifo_fd: posix.fd_t,
    fd_dir: posix.fd_t,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    ready_fd: posix.fd_t,
    rootfs_options: RootfsOptions,
    start_hooks: []const hooks.Prepared,
    start_hook_state: []const u8,
) noreturn {
    // The inherited host descriptors avoid path access to the state directory
    // or /proc inside the container and are closed before exec.
    var fifo_buffer: [32]u8 = undefined;
    const fifo_name = std.fmt.bufPrintZ(&fifo_buffer, "{d}", .{fifo_fd}) catch unreachable;
    setupRootfs(rootfs, mounts, devices, symlinks, spec.root.readonly, rootfs_options) catch |err| {
        childError("igvano: cannot prepare rootfs: ", err);
        linux.exit_group(1);
    };
    if (flags & linux.CLONE.NEWUTS != 0) {
        if (spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch linux.exit_group(1);
        }
    }
    checkResult(linux.chdir(cwd)) catch linux.exit_group(1);
    if (spec.process) |process| {
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.user.uid != 0 and !rootfs_options.fifo_writable)
            checkResult(linux.fchmodat(fd_dir, fifo_name, 0o622)) catch linux.exit_group(1);
        applyProcess(process, capabilities, rlimits) catch |err| {
            childError("igvano: cannot apply process settings: ", err);
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
    closeFd(fifo_fd);
    // Opening the writer unblocks start. Report success only after hooks pass,
    // so a timeout or nonzero exit fails start without publishing "running".
    hooks.run(start_hooks, start_hook_state) catch |err| {
        childError("igvano: start hook failed: ", err);
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
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

fn applyOomScoreAdj(proc_dir: posix.fd_t, oom_score_adj: ?i32) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        const value = oom_score_adj orelse return;
        var buffer: [12]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable;
        const fd = try openPath(proc_dir, "self/oom_score_adj", .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
        defer closeFd(fd);
        if (!writeAll(fd, text)) return error.CreateFailed;
    } else {
        return error.NotImplemented;
    }
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

test "linux create rejects hostname without UTS isolation and terminals without a console" {
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
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
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

test "linux create rejects joining the runtime's own mount namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .linux = .{ .namespaces = &.{.{ .type = .mount, .path = "/proc/self/ns/mnt" }} },
    };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
        // An invalid cgroup path prevents mount setup if the guard regresses.
        .cgroup_path = "",
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

test "linux init applies oomScoreAdj before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(1);
        execProcess(&argv, &envp);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init preserves inherited oomScoreAdj when unset" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "test \"$(cat /proc/self/oom_score_adj)\" = 500" };
    const envp = [_:null]?[*:0]const u8{"PATH=/usr/bin:/bin"};
    const pid = try forkProcess();
    if (pid == 0) {
        applyOomScoreAdj(proc_dir, 500) catch linux.exit_group(2);
        const child = forkProcess() catch linux.exit_group(2);
        if (child == 0) {
            applyOomScoreAdj(proc_dir, null) catch linux.exit_group(1);
            execProcess(&argv, &envp);
        }
        const status = waitChild(child) catch linux.exit_group(2);
        linux.exit_group(if (status == 0) 0 else 1);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux init exits nonzero instead of exec for out of range oomScoreAdj" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    for ([_]i32{ 1001, -1001 }) |value| {
        const pid = try forkProcess();
        if (pid == 0) {
            applyOomScoreAdj(proc_dir, value) catch linux.exit_group(1);
            execProcess(&argv, &envp);
        }
        try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
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
    const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(fifo_fd);
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
        closeFd(proc_dir);
        var buffer: [32]u8 = undefined;
        const name = std.fmt.bufPrintZ(&buffer, "{d}", .{fifo_fd}) catch unreachable;
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
    options.rlimits = &.{};
    for ([_]i32{ 1001, -1001 }) |value| {
        options.oom_score_adj = value;
        try std.testing.expectError(error.CreateFailed, implementation.backend().create(options));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    }
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
    const parent_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/parent-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(parent_marker);
    const child_marker = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/child-hook", .{absolute_base}, 0);
    defer std.testing.allocator.free(child_marker);
    const Callback = struct {
        parent_marker: [:0]const u8,
        child_marker: [:0]const u8,
        pid: i32 = 0,
        fail: bool = false,

        fn run(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.pid = handle.pid;
            if (linux.errno(linux.access(self.child_marker, linux.F_OK)) != .NOENT)
                return error.InvalidConfig;
            if (self.fail) return error.HookFailed;
            const fd = try openPath(linux.AT.FDCWD, self.parent_marker, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true });
            defer closeFd(fd);
        }
    };
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
        var callback: Callback = .{ .parent_marker = parent_marker, .child_marker = child_marker, .fail = true };
        const options: Backend.CreateOptions = .{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .spec = &spec,
            .cgroup_path = cgroup_path,
            .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
            .device_symlinks = oci.deviceSymlinks(&.{}),
            .on_create = .{ .ptr = &callback, .run = Callback.run },
            .create_hooks = &.{.{
                .path = "/bin/sh",
                // The host shell must remain reachable until this hook finishes.
                .args = &.{ "sh", "-c", "test -e \"$1\" && printf child > \"$2\"", "sh", parent_marker, child_marker },
                .timeout_seconds = 2,
            }},
        };
        try std.testing.expectError(error.HookFailed, backend.create(options));
        try std.testing.expectEqual(linux.E.SRCH, linux.errno(linux.kill(callback.pid, @enumFromInt(0))));
        try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "child-hook", .{}));
        callback.fail = false;
        const handle = try backend.create(options);
        defer std.testing.allocator.free(handle.starttime);
        defer {
            backend.kill(handle, 9) catch {};
            backend.delete(handle) catch {};
        }
        try std.testing.expect(handle.pid > 0);
        try std.testing.expectEqual(handle.pid, callback.pid);
        const child_output = try tmp.dir.readFileAlloc(std.testing.io, "child-hook", std.testing.allocator, .limited(16));
        defer std.testing.allocator.free(child_output);
        try std.testing.expectEqualStrings("child", child_output);
        try tmp.dir.deleteFile(std.testing.io, "parent-hook");
        try tmp.dir.deleteFile(std.testing.io, "child-hook");
        try std.testing.expectEqualStrings("example", handle.id);
        try std.testing.expect(handle.starttime.len != 0);
        try std.testing.expect(try backend.alive(handle));
        const null_device = try tmp.dir.statFile(std.testing.io, "rootfs/dev/null", .{});
        try std.testing.expectEqual(std.Io.File.Kind.character_device, null_device.kind);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(handle.pid, @enumFromInt(0))));
        const fifo_stat = try tmp.dir.statFile(std.testing.io, "exec.fifo", .{});
        try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
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

test "linux mapped init acknowledges start without path access to its private state directory" {
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
    const cgroup_path = try std.fmt.allocPrint(std.testing.allocator, "igvano-private-fifo-test-{d}", .{linux.getpid()});
    defer std.testing.allocator.free(cgroup_path);
    const cgroup_probe = (walkCgroup(cgroup_root.fd, cgroup_path, true, &.{}) catch return error.SkipZigTest).?;
    closeFd(cgroup_probe);
    try removeCgroup(cgroup_root.fd, cgroup_path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "state", .fromMode(0o700));
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/state/exec.fifo", .{absolute}, 0);
    defer std.testing.allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{
            .namespaces = &.{ .{ .type = .user }, .{ .type = .mount }, .{ .type = .pid } },
            .uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 2 }},
            .gidMappings = &.{.{ .containerID = 0, .hostID = 200000, .size = 2 }},
        },
        .process = .{
            .args = &.{"/bin/true"},
            .cwd = "/",
            .user = .{ .uid = 1, .gid = 1 },
        },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = std.testing.allocator,
        .id = "private",
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
    const stat = try tmp.dir.statFile(std.testing.io, "state", .{});
    try std.testing.expectEqual(@as(posix.mode_t, 0o700), stat.permissions.toMode() & 0o7777);
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    defer closeFd(reader);
    var poll_fds = [_]linux.pollfd{.{ .fd = reader, .events = linux.POLL.IN, .revents = 0 }};
    try checkResult(linux.poll(&poll_fds, 1, 2000));
    try std.testing.expect(poll_fds[0].revents & linux.POLL.IN != 0);
    var acknowledgement: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &acknowledgement));
    try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
}

test "linux mapped create installs maps outside init and cleans up rejected maps" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const ProcFile = struct {
        fn read(path: []const u8, limit: std.Io.Limit) ![]u8 {
            const file = try std.Io.Dir.cwd().openFile(std.testing.io, path, .{});
            defer file.close(std.testing.io);
            // Proc files report size zero; force reads through EOF.
            var reader = file.readerStreaming(std.testing.io, &.{});
            return reader.interface.allocRemaining(std.testing.allocator, limit);
        }
    };
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
        .root = .{ .path = "rootfs", .readonly = true },
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
            .{ .destination = "/dev/host-null", .source = "/dev/null", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
        },
        .devices = &.{
            .{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 },
            .{ .path = "/dev/zero", .kind = .character, .major = 1, .minor = 5 },
            .{ .path = "/dev/pipe", .kind = .fifo, .mode = 0o620, .uid = 1, .gid = 2 },
        },
        .oom_score_adj = 500,
        .device_symlinks = oci.deviceSymlinks(&.{}),
        .cgroup_path = cgroup_path,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(cgroup_root.fd, cgroup_path, false, &.{}));
    spec.linux.?.uidMappings = &.{.{ .containerID = 0, .hostID = 100000, .size = 10 }};
    const handle = try backend.create(options);
    defer std.testing.allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    try std.testing.expect(try backend.alive(handle));
    const oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{handle.pid});
    defer std.testing.allocator.free(oom_path);
    const oom_score_adj = try ProcFile.read(oom_path, .limited(32));
    defer std.testing.allocator.free(oom_score_adj);
    try std.testing.expectEqualStrings("500\n", oom_score_adj);
    for ([_]struct { name: []const u8, tokens: []const []const u8 }{
        .{ .name = "uid_map", .tokens = &.{ "0", "100000", "10" } },
        .{ .name = "gid_map", .tokens = &.{ "0", "200000", "10" } },
        .{ .name = "setgroups", .tokens = &.{"allow"} },
    }) |expected| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/{s}", .{ handle.pid, expected.name });
        defer std.testing.allocator.free(path);
        const text = try ProcFile.read(path, .limited(4096));
        defer std.testing.allocator.free(text);
        var tokens = std.mem.tokenizeAny(u8, text, " \t\n");
        for (expected.tokens) |token| try std.testing.expectEqualStrings(token, tokens.next().?);
        try std.testing.expect(tokens.next() == null);
    }
    const status_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/status", .{handle.pid});
    defer std.testing.allocator.free(status_path);
    const status = try ProcFile.read(status_path, .limited(16384));
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
    try std.testing.expectEqual(@as(posix.mode_t, 0o600), fifo_stat.permissions.toMode() & 0o7777);
    {
        // Reuse this mapped user namespace while creating fresh mount/PID
        // namespaces. Root's host UID differs from the runtime's UID.
        const user_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/ns/user", .{handle.pid});
        defer std.testing.allocator.free(user_path);
        const joined_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/joined.fifo", .{absolute}, 0);
        defer std.testing.allocator.free(joined_fifo);
        try checkResult(linux.mknod(joined_fifo, linux.S.IFIFO | 0o600, 0));
        const joined_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-joined", .{cgroup_path});
        defer std.testing.allocator.free(joined_cgroup);
        var joined_spec = spec;
        joined_spec.linux.?.namespaces = &.{ .{ .type = .mount }, .{ .type = .user, .path = user_path }, .{ .type = .pid } };
        joined_spec.linux.?.uidMappings = null;
        joined_spec.linux.?.gidMappings = null;
        var joined_options = options;
        joined_options.id = "joined";
        joined_options.spec = &joined_spec;
        joined_options.exec_fifo = joined_fifo;
        joined_options.cgroup_path = joined_cgroup;
        // Lowering requires host CAP_SYS_RESOURCE even when joining a user
        // namespace whose root maps to a different host UID.
        if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0)
            joined_options.oom_score_adj = -500;
        const joined = try backend.create(joined_options);
        defer std.testing.allocator.free(joined.starttime);
        defer {
            backend.kill(joined, 9) catch {};
            backend.delete(joined) catch {};
        }
        try std.testing.expect(try backend.alive(joined));
        const joined_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{joined.pid});
        defer std.testing.allocator.free(joined_oom_path);
        const joined_oom_score_adj = try ProcFile.read(joined_oom_path, .limited(32));
        defer std.testing.allocator.free(joined_oom_score_adj);
        try std.testing.expectEqualStrings(if (joined_options.oom_score_adj == -500) "-500\n" else "500\n", joined_oom_score_adj);
        const joined_reader = try openPath(linux.AT.FDCWD, joined_fifo, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        defer closeFd(joined_reader);
        var joined_poll = [_]linux.pollfd{.{ .fd = joined_reader, .events = linux.POLL.IN, .revents = 0 }};
        try checkResult(linux.poll(&joined_poll, 1, 2000));
        try std.testing.expect(joined_poll[0].revents & linux.POLL.IN != 0);
        var acknowledgement: [1]u8 = undefined;
        try std.testing.expect(readAll(joined_reader, &acknowledgement));
        try std.testing.expectEqual(@as(u8, 1), acknowledgement[0]);
    }
    if (caps[0].effective & (@as(u32, 1) << linux.CAP.SYS_RESOURCE) != 0) {
        // Identity maps isolate loss of host CAP_SYS_RESOURCE from the proc
        // ownership failure exercised by the nonidentity maps above.
        var lowered_spec = spec;
        lowered_spec.linux.?.uidMappings = &.{.{ .containerID = 0, .hostID = 0, .size = 10 }};
        lowered_spec.linux.?.gidMappings = &.{.{ .containerID = 0, .hostID = 0, .size = 10 }};
        const lowered_fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/lowered.fifo", .{absolute}, 0);
        defer std.testing.allocator.free(lowered_fifo);
        try checkResult(linux.mknod(lowered_fifo, linux.S.IFIFO | 0o600, 0));
        const lowered_cgroup = try std.fmt.allocPrint(std.testing.allocator, "{s}-lowered", .{cgroup_path});
        defer std.testing.allocator.free(lowered_cgroup);
        var lowered_options = options;
        lowered_options.spec = &lowered_spec;
        lowered_options.exec_fifo = lowered_fifo;
        lowered_options.cgroup_path = lowered_cgroup;
        lowered_options.oom_score_adj = -500;
        const lowered = try backend.create(lowered_options);
        defer std.testing.allocator.free(lowered.starttime);
        defer {
            backend.kill(lowered, 9) catch {};
            backend.delete(lowered) catch {};
        }
        const lowered_oom_path = try std.fmt.allocPrint(std.testing.allocator, "/proc/{d}/oom_score_adj", .{lowered.pid});
        defer std.testing.allocator.free(lowered_oom_path);
        const lowered_oom_score_adj = try ProcFile.read(lowered_oom_path, .limited(32));
        defer std.testing.allocator.free(lowered_oom_score_adj);
        try std.testing.expectEqualStrings("-500\n", lowered_oom_score_adj);
    }
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
    if (createDevice(root_fd, .{ .path = "/escape/new", .mode = linux.S.IFIFO | 0o600, .dev = 0 })) {
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "outside/new", .{}));
}

test "linux device creation rejects mismatched existing nodes and preserves matching FIFOs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "file", .data = "" });
    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    try tmp.dir.symLink(std.testing.io, "pipe", "link", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try checkResult(linux.mknodat(root, "pipe", linux.S.IFIFO | 0o600, 0));
    const before = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    for ([_][:0]const u8{ "/file", "/directory", "/link" }) |path| {
        try std.testing.expectError(error.InvalidPath, createDevice(root, .{
            .path = path,
            .mode = linux.S.IFIFO | 0o666,
            .dev = 0,
        }));
    }
    try createDevice(root, .{ .path = "/pipe", .mode = linux.S.IFIFO | 0o666, .dev = 0 });
    const stat = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    try std.testing.expectEqual(before.permissions.toMode(), stat.permissions.toMode());
}

test "linux device validation rejects mismatched types and device numbers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const source = try openPath(linux.AT.FDCWD, "/dev/null", .{ .PATH = true, .CLOEXEC = true });
    defer closeFd(source);
    try validateDeviceNode(source, .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 });
    for ([_]PreparedDevice{
        .{ .path = "/dev/null", .mode = linux.S.IFBLK | 0o666, .dev = 0x103 },
        .{ .path = "/dev/null", .mode = linux.S.IFIFO | 0o666, .dev = 0 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x203 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x105 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x100103 },
    }) |device| {
        try std.testing.expectError(error.InvalidPath, validateDeviceNode(source, device));
    }
}

test "linux privileged bind remount honors atime changes and clears unrequested flags" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const source = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/source", .{absolute}, 0);
    defer std.testing.allocator.free(source);
    const ms = linux.MS;
    const cases = [_]struct { source_atime: u32, requested: u32 }{
        .{ .source_atime = ms.RELATIME, .requested = ms.STRICTATIME },
        .{ .source_atime = ms.STRICTATIME, .requested = ms.NOATIME },
        .{ .source_atime = ms.NOATIME, .requested = ms.RELATIME },
    };
    for (cases) |case| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            checkResult(linux.mount(null, "/", null, ms.PRIVATE | ms.REC, 0)) catch linux.exit_group(2);
            checkResult(linux.mount("tmpfs", source, "tmpfs", 0, 0)) catch linux.exit_group(3);
            // Set per-mount readonly without making the superblock readonly.
            checkResult(linux.mount(null, source, null, ms.BIND | ms.REMOUNT | ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC | case.source_atime, 0)) catch linux.exit_group(4);
            const root_fd = openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(5);
            applyMount(rootfs, root_fd, .{
                .destination = "/bound",
                .source = source,
                .type = null,
                .flags = ms.BIND | case.requested,
                .propagation = 0,
                .data = "",
            }) catch linux.exit_group(6);
            const target = mountDestination(root_fd, "/bound", false, false) catch linux.exit_group(7);
            const actual = remountFlags(target, 0) catch linux.exit_group(8);
            if (actual != case.requested) linux.exit_group(9);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
}

test "linux rootfs console setup precedes restrictions and readonly without a dev tmpfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try testRootfsConsole(true, true);
}

test "linux rootfs console setup uses move mount without procfs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try testRootfsConsole(false, false);
}

fn testRootfsConsole(readonly: bool, mount_proc: bool) !void {
    try requireTestMountNamespace();
    if (!mount_proc) {
        // Invalid descriptors probe syscall availability without changing mounts.
        const invalid_fd = std.math.maxInt(usize);
        if (linux.errno(linux.syscall3(.open_tree, invalid_fd, @intFromPtr(""), linux.AT.EMPTY_PATH)) == .NOSYS or
            linux.errno(linux.move_mount(-1, "", -1, "", std.mem.zeroes(linux.MOVE_MOUNT))) == .NOSYS)
            return error.SkipZigTest;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = linux.MS.NOSUID | linux.MS.NOEXEC, .propagation = 0, .data = "newinstance,ptmxmode=666,mode=620" },
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
    };
    const symlinks = [_]Backend.Symlink{.{ .path = "/dev/ptmx", .target = "pts/ptmx" }};
    const sockets = try console.socketpair();
    const go = try makePipe();
    defer for (go) |fd| closeFd(fd);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(sockets[0]);
        closeFd(go[1]);
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        // Exercise retained root descriptors when console replaces closed stdio.
        for (0..3) |fd| closeFd(@intCast(fd));
        setupRootfs(rootfs, mounts[0..if (mount_proc) 2 else 1], &.{}, &symlinks, readonly, .{
            .console_fd = sockets[1],
            .masked_paths = if (readonly) &.{"/dev/pts"} else &.{},
            .readonly_paths = if (readonly) &.{"/dev"} else &.{},
        }) catch linux.exit_group(2);
        if (linux.errno(linux.fcntl(sockets[1], linux.F.GETFD, 0)) != .BADF) linux.exit_group(3);
        if (!mount_proc and linux.errno(linux.access("/proc/self/fd", linux.F_OK)) != .NOENT) linux.exit_group(4);
        if (readonly) {
            for ([_][*:0]const u8{ "/new", "/dev/new" }) |path| {
                if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600)) != .ROFS)
                    linux.exit_group(5);
            }
            if (linux.errno(linux.access("/dev/pts/ptmx", linux.F_OK)) != .NOENT) linux.exit_group(6);
        }
        var root_stat: linux.Statx = undefined;
        var dev_stat: linux.Statx = undefined;
        var console_stat: linux.Statx = undefined;
        var slave_stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/", 0, .BASIC_STATS, &root_stat)) catch linux.exit_group(7);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev", 0, .BASIC_STATS, &dev_stat)) catch linux.exit_group(7);
        if (root_stat.dev_major != dev_stat.dev_major or root_stat.dev_minor != dev_stat.dev_minor)
            linux.exit_group(8);
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/console", linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &console_stat)) catch linux.exit_group(9);
        checkResult(linux.statx(1, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &slave_stat)) catch linux.exit_group(9);
        if (console_stat.mode & linux.S.IFMT != linux.S.IFCHR or
            console_stat.ino != slave_stat.ino or
            console_stat.dev_major != slave_stat.dev_major or console_stat.dev_minor != slave_stat.dev_minor)
            linux.exit_group(10);
        if (!writeAll(1, "console\n")) linux.exit_group(11);
        var byte: [1]u8 = undefined;
        if (!readAll(go[0], &byte)) linux.exit_group(12);
        linux.exit_group(0);
    }
    closeFd(sockets[1]);
    defer closeFd(sockets[0]);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    const master = try console.receiveFd(sockets[0]);
    defer closeFd(master);
    var output: [9]u8 = undefined;
    try std.testing.expect(readAll(master, &output));
    try std.testing.expectEqualStrings("console\r\n", &output);
    try std.testing.expect(writeAll(go[1], &.{1}));
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    reaped = true;
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
        .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = 0, .data = "mode=755" },
        .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = linux.MS.NOSUID | linux.MS.NOEXEC, .propagation = 0, .data = "newinstance,ptmxmode=666,mode=620" },
    };
    const devices = [_]PreparedDevice{
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 },
        .{ .path = "/run/pipe", .mode = linux.S.IFIFO | 0o640, .dev = 0 },
    };
    const symlinks = oci.deviceSymlinks(&.{.{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = 0, .propagation = 0, .data = "" }});
    const pid = try forkProcess();
    if (pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        _ = linux.syscall1(.umask, 0o777);
        setupRootfs(rootfs, &mounts, &devices, symlinks, true, .{}) catch linux.exit_group(2);
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
        var stat: linux.Statx = undefined;
        checkResult(linux.statx(linux.AT.FDCWD, "/dev/null", 0, .BASIC_STATS, &stat)) catch linux.exit_group(10);
        if (stat.mode != linux.S.IFCHR | 0o666 or stat.rdev_major != 1 or stat.rdev_minor != 3 or stat.uid != 0 or stat.gid != 0)
            linux.exit_group(11);
        checkResult(linux.statx(linux.AT.FDCWD, "/run/pipe", 0, .BASIC_STATS, &stat)) catch linux.exit_group(12);
        if (stat.mode != linux.S.IFIFO | 0o640) linux.exit_group(13);
        for (symlinks) |link| {
            var link_buffer: [64]u8 = undefined;
            const result = linux.readlink(link.path, &link_buffer, link_buffer.len);
            checkResult(result) catch linux.exit_group(14);
            if (!std.mem.eql(u8, link_buffer[0..result], link.target)) linux.exit_group(15);
        }
        const null_fd = openPath(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch linux.exit_group(16);
        if (!writeAll(null_fd, "device works")) linux.exit_group(17);
        closeFd(null_fd);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));

    // A later /dev bind covers the tmpfs. Leave its host source untouched.
    var bind_mounts: [mounts.len + 1]PreparedMount = undefined;
    @memcpy(bind_mounts[0..mounts.len], &mounts);
    bind_mounts[mounts.len] = .{
        .destination = "/dev",
        .source = source_dir,
        .type = null,
        .flags = linux.MS.BIND,
        .propagation = 0,
        .data = "",
    };
    const bind_pid = try forkProcess();
    if (bind_pid == 0) {
        checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
        setupRootfs(rootfs, &bind_mounts, &devices, symlinks, true, .{}) catch linux.exit_group(2);
        if (linux.errno(linux.access("/dev/item", linux.F_OK)) != .SUCCESS) linux.exit_group(3);
        if (linux.errno(linux.access("/dev/null", linux.F_OK)) != .NOENT) linux.exit_group(4);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(bind_pid));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "source/null", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "source/fd", .{ .follow_symlinks = false }));
}

test "linux rootfs restrictions hide files and directories and preserve propagation modes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try requireTestMountNamespace();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/masked-dir");
    try tmp.dir.createDirPath(std.testing.io, "rootfs/readonly-dir");
    for ([_][]const u8{ "masked-file", "masked-dir/secret", "readonly-file", "readonly-dir/item" }) |path| {
        const name = try std.fmt.allocPrint(std.testing.allocator, "rootfs/{s}", .{path});
        defer std.testing.allocator.free(name);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = "secret" });
    }
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const rootfs = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/rootfs", .{absolute}, 0);
    defer std.testing.allocator.free(rootfs);
    const mounts = [_]PreparedMount{
        .{ .destination = "/proc", .source = "proc", .type = "proc", .flags = 0, .propagation = 0, .data = "" },
    };
    const devices = [_]PreparedDevice{.{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 }};
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const hook_env = try std.fmt.allocPrint(arena.allocator(), "ROOTFS={s}", .{rootfs});
    const create_hooks = try hooks.prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "test -f \"$ROOTFS/masked-dir/secret\" && IFS= read -r state && test \"$state\" = creating && printf hook > \"$ROOTFS/hook-observed\"" },
        .env = &.{hook_env},
        .timeout_seconds = 2,
    }});
    for ([_]u32{ linux.MS.PRIVATE, linux.MS.SLAVE, linux.MS.SHARED, linux.MS.UNBINDABLE }) |propagation| {
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.unshare(linux.CLONE.NEWNS)) catch linux.exit_group(1);
            setupRootfs(rootfs, &mounts, &devices, &.{}, false, .{
                .propagation = propagation | linux.MS.REC,
                .create_hooks = create_hooks,
                .create_hook_state = "creating\n",
                .masked_paths = &.{ "/masked-file", "/masked-dir", "/missing-mask" },
                .readonly_paths = &.{ "/readonly-file", "/readonly-dir", "/missing-readonly" },
            }) catch |err| {
                std.debug.print("rootfs restriction setup: {s}\n", .{@errorName(err)});
                linux.exit_group(2);
            };
            if (linux.errno(linux.access("/hook-observed", linux.F_OK)) != .SUCCESS) linux.exit_group(3);
            const masked = openPath(linux.AT.FDCWD, "/masked-file", .{}) catch linux.exit_group(4);
            var byte: [1]u8 = undefined;
            if (linux.read(masked, &byte, 1) != 0) linux.exit_group(5);
            closeFd(masked);
            if (linux.errno(linux.access("/masked-dir/secret", linux.F_OK)) != .NOENT) linux.exit_group(6);
            for ([_][*:0]const u8{ "/masked-dir/new", "/readonly-file", "/readonly-dir/item", "/readonly-dir/new" }) |path| {
                if (linux.errno(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600)) != .ROFS)
                    linux.exit_group(7);
            }
            if (linux.errno(linux.access("/missing-mask", linux.F_OK)) != .NOENT or
                linux.errno(linux.access("/missing-readonly", linux.F_OK)) != .NOENT) linux.exit_group(8);
            const mountinfo = openPath(linux.AT.FDCWD, "/proc/self/mountinfo", .{}) catch linux.exit_group(9);
            var buffer: [65536]u8 = undefined;
            const size = linux.read(mountinfo, &buffer, buffer.len);
            checkResult(size) catch linux.exit_group(10);
            var lines = std.mem.splitScalar(u8, buffer[0..size], '\n');
            var root_seen = false;
            while (lines.next()) |line| {
                var fields = std.mem.tokenizeScalar(u8, line, ' ');
                for (0..4) |_| _ = fields.next();
                const mountpoint = fields.next() orelse continue;
                if (std.mem.eql(u8, mountpoint, "/")) root_seen = true;
                const shared = std.mem.indexOf(u8, line, " shared:") != null;
                const unbindable = std.mem.indexOf(u8, line, " unbindable ") != null;
                if (shared != (propagation == linux.MS.SHARED) or
                    unbindable != (propagation == linux.MS.UNBINDABLE)) linux.exit_group(11);
            }
            if (!root_seen) linux.exit_group(12);
            linux.exit_group(0);
        }
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
    }
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

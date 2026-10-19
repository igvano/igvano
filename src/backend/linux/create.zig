const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const oci = @import("../../oci.zig");
const hooks = @import("../hooks.zig");
const seccomp = @import("../seccomp.zig");
const dbus = @import("../dbus.zig");
const diagnostics = @import("diagnostic.zig");
const v2DeviceRules = @import("devices.zig").v2DeviceRules;
const prepareMounts = @import("mount.zig").prepareMounts;
const validateDeviceMounts = @import("mount.zig").validateDeviceMounts;
const PreparedMount = @import("mount.zig").PreparedMount;
const processString = @import("syscall.zig").processString;
const pathString = @import("syscall.zig").pathString;
const preparePaths = @import("syscall.zig").preparePaths;
const checkResult = @import("syscall.zig").checkResult;
const forkProcess = @import("syscall.zig").forkProcess;
const makePipe = @import("syscall.zig").makePipe;
const closeFd = @import("syscall.zig").closeFd;
const waitChild = @import("syscall.zig").waitChild;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const fdPath = @import("syscall.zig").fdPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const childError = @import("diagnostic.zig").childError;
const failCreate = @import("diagnostic.zig").failCreate;
const Write = @import("cgroup_v2.zig").Write;
const v2Writes = @import("cgroup_v2.zig").v2Writes;
const freeWrites = @import("cgroup_v2.zig").freeWrites;
const v2IgnoredFields = @import("cgroup_v2.zig").v2IgnoredFields;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const removeCreatedCgroup = @import("cgroup.zig").removeCreatedCgroup;
const configureCgroup = @import("cgroup.zig").configureCgroup;
const V1Write = @import("cgroup_v1.zig").V1Write;
const freeV1Writes = @import("cgroup_v1.zig").freeV1Writes;
const v1Writes = @import("cgroup_v1.zig").v1Writes;
const V1Hierarchy = @import("cgroup_v1.zig").V1Hierarchy;
const freeV1Hierarchies = @import("cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("cgroup_v1.zig").openV1Hierarchies;
const removeV1Cgroups = @import("cgroup_v1.zig").removeV1Cgroups;
const namespaceFlag = @import("namespaces.zig").namespaceFlag;
const namespaceFlags = @import("namespaces.zig").namespaceFlags;
const NamespaceJoin = @import("namespaces.zig").NamespaceJoin;
const validateNamespaceFd = @import("namespaces.zig").validateNamespaceFd;
const joinNamespacesWithUser = @import("namespaces.zig").joinNamespacesWithUser;
const mappedRootID = @import("namespaces.zig").mappedRootID;
const validateJoinedMappings = @import("namespaces.zig").validateJoinedMappings;
const joinedUserNamespaceMappings = @import("namespaces.zig").joinedUserNamespaceMappings;
const formatIDMappings = @import("namespaces.zig").formatIDMappings;
const writeUserMappings = @import("namespaces.zig").writeUserMappings;
const mountId = @import("rootfs.zig").mountId;
const bootId = @import("rootfs.zig").bootId;
const statMount = @import("rootfs.zig").statMount;
const detachRootfs = @import("rootfs.zig").detachRootfs;
const RootfsOptions = @import("rootfs.zig").RootfsOptions;
const setupRootfs = @import("rootfs.zig").setupRootfs;
const kill = @import("proc.zig").kill;
const readProcStatAt = @import("proc.zig").readProcStatAt;
const closeExecFrom = @import("process.zig").closeExecFrom;
const kernelCapabilities = @import("process.zig").kernelCapabilities;
const runProcess = @import("process.zig").runProcess;
const installSeccomp = @import("process.zig").installSeccomp;
const applyOomScoreAdj = @import("process.zig").applyOomScoreAdj;
const applyProcess = @import("process.zig").applyProcess;
const applyRlimits = @import("process.zig").applyRlimits;
const resolveExecutable = @import("process.zig").resolveExecutable;
const closeMountFds = @import("mount_sources.zig").closeMountFds;
const prepareIDMappedMounts = @import("mount_sources.zig").prepareIDMappedMounts;
const startMountSourceHelper = @import("mount_sources.zig").startMountSourceHelper;
const receiveMountSources = @import("mount_sources.zig").receiveMountSources;
const PreparedDevice = @import("device_nodes.zig").PreparedDevice;
const prepareAppArmor = @import("procfs.zig").prepareAppArmor;
const applyAppArmor = @import("procfs.zig").applyAppArmor;
const systemdFailure = @import("systemd.zig").systemdFailure;
const freeSystemdProperties = @import("systemd.zig").freeSystemdProperties;
const systemdProperties = @import("systemd.zig").systemdProperties;
const stopSystemdScope = @import("systemd.zig").stopSystemdScope;

pub fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        const flags = try namespaceFlags(options.spec.linux);
        var isolation_flags = flags;
        for (if (options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace|
            isolation_flags |= namespaceFlag(namespace.type);
        const private_mount_namespace = isolation_flags & linux.CLONE.NEWNS != 0;
        if (!private_mount_namespace and options.rootfs_propagation != null) {
            reportDiagnostic("cannot change propagation without a private mount namespace", .{});
            return error.InvalidConfig;
        }
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
        const apparmor_command = try prepareAppArmor(allocator, options.apparmor_profile);
        const seccomp_program = if (options.seccomp) |config|
            seccomp.compile(allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
                return error.InvalidConfig;
            }
        else
            null;
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
                reportDiagnostic("cannot join the runtime's own mount namespace", .{});
                return error.InvalidConfig;
            }
        }
        const user_namespace = flags & linux.CLONE.NEWUSER != 0;
        const joined_user_namespace = !user_namespace and isolation_flags & linux.CLONE.NEWUSER != 0;
        // Library callers bypass frontend validation, so mapping-presence checks are intentional.
        const uid_mappings: []const oci.Spec.IDMapping = if (options.spec.linux) |settings| settings.uidMappings orelse &.{} else &.{};
        const gid_mappings: []const oci.Spec.IDMapping = if (options.spec.linux) |settings| settings.gidMappings orelse &.{} else &.{};
        if (user_namespace and (uid_mappings.len == 0 or gid_mappings.len == 0)) return error.InvalidConfig;
        var container_mappings: Backend.MountMappings = .{};
        const uid_ranges = try allocator.alloc(Backend.IDMapping, uid_mappings.len);
        for (uid_mappings, uid_ranges) |mapping, *range| range.* = .{
            .container_id = mapping.containerID,
            .host_id = mapping.hostID,
            .size = mapping.size,
        };
        const gid_ranges = try allocator.alloc(Backend.IDMapping, gid_mappings.len);
        for (gid_mappings, gid_ranges) |mapping, *range| range.* = .{
            .container_id = mapping.containerID,
            .host_id = mapping.hostID,
            .size = mapping.size,
        };
        container_mappings = .{ .uid = uid_ranges, .gid = gid_ranges };
        // Pin the validated namespace and use that same descriptor in init.
        var joined_user_fd: ?posix.fd_t = null;
        var joined_user_path: ?[]const u8 = null;
        defer if (joined_user_fd) |fd| closeFd(fd);
        if (joined_user_namespace) {
            for (joins.items) |join| {
                if (join.flag != linux.CLONE.NEWUSER) continue;
                const fd = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
                joined_user_fd = fd;
                joined_user_path = join.path;
                try validateNamespaceFd(fd, linux.CLONE.NEWUSER);
                container_mappings = try joinedUserNamespaceMappings(allocator, fd);
                try validateJoinedMappings(allocator, container_mappings, .{ .uid = uid_ranges, .gid = gid_ranges });
                break;
            }
        }
        const fifo_uid = if (user_namespace or joined_user_namespace) try mappedRootID(container_mappings.uid) else 0;
        const fifo_gid = if (user_namespace or joined_user_namespace) try mappedRootID(container_mappings.gid) else 0;
        const uid_map = try formatIDMappings(allocator, uid_mappings);
        const gid_map = try formatIDMappings(allocator, gid_mappings);
        const fifo = try allocator.dupeZ(u8, options.exec_fifo);
        const rootfs = try processString(allocator, options.rootfs);
        const cwd = try processString(allocator, if (options.spec.process) |process| process.cwd else "/");
        if (!std.fs.path.isAbsolute(cwd)) return error.InvalidProcess;
        if (!std.fs.path.isAbsolute(rootfs)) return error.InvalidPath;
        var rootfs_mount_before: ?u64 = null;
        var rootfs_mount_boot_id: ?[36]u8 = null;
        if (!private_mount_namespace) {
            const root_fd = try openPath(linux.AT.FDCWD, rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
            defer closeFd(root_fd);
            var fd_buffer: [64]u8 = undefined;
            var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const size = linux.readlink(fdPath(&fd_buffer, root_fd), &resolved_buffer, resolved_buffer.len);
            try checkResult(size);
            if (size == 1 and resolved_buffer[0] == '/') {
                reportDiagnostic("cannot use / as rootfs without a private mount namespace", .{});
                return error.InvalidConfig;
            }
            rootfs_mount_before = mountId(root_fd) catch |err| {
                if (err == error.Unsupported)
                    reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
                return err;
            };
            // Probe both APIs before creating any mounts.
            _ = (statMount(rootfs_mount_before.?) catch |err| {
                if (err == error.Unsupported)
                    reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
                return err;
            }) orelse return error.CreateFailed;
            rootfs_mount_boot_id = try bootId();
        }
        try validateCgroupPath(options.cgroup_path);
        var systemd_client = dbus.Client.init(allocator);
        defer systemd_client.deinit();
        if (options.systemd) {
            if (!std.mem.eql(u8, options.systemd_unit, std.fs.path.basename(options.cgroup_path)) or
                !std.mem.endsWith(u8, options.systemd_unit, ".scope") or
                !std.mem.endsWith(u8, options.systemd_slice, ".slice") or
                std.mem.indexOfAny(u8, options.systemd_slice, "/\x00") != null)
                return error.InvalidConfig;
            systemd_client.connect() catch |err| return systemdFailure(&systemd_client, "create systemd scope", err);
        }
        if (joined_user_namespace) try checkResult(linux.chown(fifo, fifo_uid, fifo_gid));
        const cgroup_root = try openCgroupRoot();
        defer closeFd(cgroup_root.fd);
        const hierarchies: []V1Hierarchy = if (cgroup_root.mode == .legacy) try openV1Hierarchies(allocator, options.systemd) else &.{};
        defer if (cgroup_root.mode == .legacy) freeV1Hierarchies(allocator, hierarchies);
        const mounts = try prepareMounts(allocator, options.mounts, cgroup_root.fs_type, hierarchies, options.cgroup_path);
        defer closeMountFds(mounts);
        if (joined_user_fd) |fd| {
            for (mounts) |*mount| {
                if (mount.mappings) |*mappings| {
                    const path = mappings.userns_path orelse continue;
                    if (std.mem.eql(u8, path, joined_user_path.?))
                        mappings.userns_path = try std.fmt.allocPrint(allocator, "/proc/self/fd/{d}", .{fd});
                }
            }
        }
        try prepareIDMappedMounts(allocator, mounts);
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
        const cgroup_writes: []const Write = if (cgroup_root.mode == .unified) try v2Writes(allocator, options.resources) else &.{};
        defer if (cgroup_root.mode == .unified) freeWrites(allocator, cgroup_writes);
        if (cgroup_root.mode == .legacy and options.resources.unified.len != 0) {
            reportDiagnostic("unified resources require cgroup v2", .{});
            return error.InvalidConfig;
        }
        const v1_writes: []const V1Write = if (cgroup_root.mode == .legacy) try v1Writes(allocator, options.resources) else &.{};
        defer if (cgroup_root.mode == .legacy) freeV1Writes(allocator, v1_writes);
        const ignored_fields = if (cgroup_root.mode == .unified) try v2IgnoredFields(allocator, options.resources) else try allocator.dupe(u8, "");
        defer allocator.free(ignored_fields);
        if (ignored_fields.len != 0)
            std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ignored_fields});

        // pivot_root also changes child1's root while it waits in the same
        // mount namespace. Pin host /proc so it can still capture identity.
        const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(proc_dir);
        // Init must retain the host FIFO across namespace changes without
        // traversing the private state directory as a mapped user.
        const fifo_fd = try openPath(linux.AT.FDCWD, fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
        defer closeFd(fifo_fd);
        var cgroup: ?posix.fd_t = null;
        defer if (cgroup) |fd| closeFd(fd);
        var rootfs_mount_id: ?u64 = null;
        errdefer {
            const saved_diagnostic = diagnostics.last_diagnostic;
            const saved_len = diagnostics.last_diagnostic_len;
            defer {
                diagnostics.last_diagnostic = saved_diagnostic;
                diagnostics.last_diagnostic_len = saved_len;
            }
            if (systemd_client.unit_started)
                stopSystemdScope(allocator, options.systemd_unit) catch {};
            // Child1 can die before reporting child2's PID. Kill the entire
            // cgroup before removing it, including any blocked init.
            if (cgroup) |fd| {
                writeCgroupFile(fd, "cgroup.kill", "1", options.cgroup_path) catch {};
                removeCreatedCgroup(cgroup_root.fd, options.cgroup_path, fd) catch {};
            } else {
                removeV1Cgroups(hierarchies, options.cgroup_path) catch {};
            }
            if (rootfs_mount_before) |before| detachRootfs(rootfs, if (rootfs_mount_id) |id|
                .{ .created = id }
            else
                .{ .before_create = before }) catch {};
        }
        // fs cgroups are ready before fork; systemd adopts init at the
        // early mapping exchange, while init is blocked before rootfs work.
        if (!options.systemd)
            try configureCgroup(allocator, cgroup_root.fd, cgroup_root.mode, &cgroup, hierarchies, options, cgroup_writes, v1_writes);
        var needs_mount_sources = false;
        for (mounts) |mount| {
            if (mount.flags & linux.MS.BIND != 0 and
                (isolation_flags & linux.CLONE.NEWUSER != 0 or mount.mappings != null))
            {
                needs_mount_sources = true;
                break;
            }
        }
        const mount_source_helper = if (needs_mount_sources) try startMountSourceHelper(mounts) else null;
        var mount_source_socket: ?posix.fd_t = if (mount_source_helper) |helper| helper.socket else null;
        defer if (mount_source_helper) |helper| {
            if (mount_source_socket) |fd| closeFd(fd);
            _ = waitChild(helper.pid) catch {};
        };
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
        const map_pipe = if (user_namespace or options.systemd) makePipe() catch |err| {
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
            checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(report[1], err);
            if (options.console_fds) |fds| closeFd(fds[0]);
            if (options.systemd) closeFd(systemd_client.fd);
            closeFd(create_go[1]);
            if (map_pipe) |fds| closeFd(fds[1]);
            closeFd(cgroup_root.fd);
            closeFd(report[0]);
            // Join before NEWCGROUP snapshots the namespace root. Child2
            // inherits this membership; the runtime parent stays outside.
            if (cgroup) |fd| {
                writeCgroupFile(fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                closeFd(fd);
            } else for (hierarchies) |hierarchy| {
                if (hierarchy.leaf) |fd| {
                    writeCgroupFile(fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
                    closeFd(fd);
                }
                closeFd(hierarchy.root.?);
            }
            // Set with host privileges before entering user namespaces.
            // Child2 inherits the adjustment across fork and exec.
            applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
            joinNamespacesWithUser(joins.items, joined_user_fd) catch |err| failCreate(report[1], err);
            // NEWUSER is unshared together with the others so it owns them.
            const early_flags = if (options.systemd) flags & ~@as(usize, linux.CLONE.NEWCGROUP) else flags;
            if (early_flags != 0) checkResult(linux.unshare(early_flags)) catch |err| failCreate(report[1], err);
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
                // systemd has adopted init before NEWCGROUP captures its
                // namespace root. Explicitly joined cgroup namespaces stay joined.
                if (options.systemd and flags & linux.CLONE.NEWCGROUP != 0)
                    checkResult(linux.unshare(linux.CLONE.NEWCGROUP)) catch linux.exit_group(1);
                if (mount_source_socket) |socket| {
                    const namespace = openPath(proc_dir, "self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch |err| failCreate(ready[1], err);
                    receiveMountSources(mounts, socket, namespace) catch |err| failCreate(ready[1], err);
                    closeFd(namespace);
                    closeFd(socket);
                }
                closeFd(proc_dir);
                const create_input = std.fmt.bufPrint(create_state, "{s}{d}{s}", .{
                    options.create_hook_state.prefix, host_pid, options.create_hook_state.suffix,
                }) catch linux.exit_group(1);
                const start_input = std.fmt.bufPrint(start_state, "{s}{d}{s}", .{
                    options.start_hook_state.prefix, host_pid, options.start_hook_state.suffix,
                }) catch linux.exit_group(1);
                runInit(options.spec, capabilities, options.rlimits, isolation_flags, rootfs, mounts, devices, options.device_symlinks, cwd, fifo_fd, fd_dir, argv.ptr, envp.ptr, ready[1], .{
                    .private_mount_namespace = private_mount_namespace,
                    .propagation = options.rootfs_propagation orelse (linux.MS.PRIVATE | linux.MS.REC),
                    .create_hooks = create_hooks,
                    .create_hook_state = create_input,
                    .masked_paths = masked_paths,
                    .readonly_paths = readonly_paths,
                    .sysctls = options.sysctls,
                    .runtime_sync = .{ .ready_fd = ready[1], .go_fd = create_go[0] },
                    .console_fd = if (options.console_fds) |fds| fds[1] else null,
                }, start_hooks, start_input, apparmor_command, seccomp_program);
            }
            if (mount_source_socket) |fd| closeFd(fd);
            closeMountFds(mounts);
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
            if (!private_mount_namespace) {
                var mount_response: CreateResponse = .{};
                if (!readAll(ready[0], std.mem.asBytes(&mount_response)) or mount_response.failure != 0) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], mount_response.failureError() orelse error.CreateFailed);
                }
                if (!writeAll(report[1], std.mem.asBytes(&mount_response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
            }
            var init_response: CreateResponse = .{};
            // Child2 has applied mounts and waits before child hooks/pivot.
            if (!readAll(ready[0], std.mem.asBytes(&init_response)) or init_response.failure != 0) {
                _ = waitChild(child2) catch {};
                failCreate(report[1], init_response.failureError() orelse error.CreateFailed);
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
            init_response = .{};
            const initialized = readAll(ready[0], std.mem.asBytes(&init_response));
            closeFd(ready[0]);
            if (!initialized or init_response.failure != 0) {
                _ = waitChild(child2) catch {};
                failCreate(report[1], init_response.failureError() orelse error.CreateFailed);
            }
            if (!writeAll(report[1], std.mem.asBytes(&response))) {
                _ = linux.kill(child2, .KILL);
                _ = waitChild(child2) catch {};
                linux.exit_group(1);
            }
            // No shim: exiting child1 reparents the blocked init to host init.
            linux.exit_group(0);
        }

        if (mount_source_socket) |fd| closeFd(fd);
        mount_source_socket = null;
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
            if (mapping_response.failureError()) |err| return err;
            if (mapping_response.pid <= 0) return error.CreateFailed;
            // Child2 cannot exit/reuse its PID while child1 owns it. On
            // any early failure kill it before closing the release pipe.
            errdefer _ = linux.kill(mapping_response.pid, .KILL);
            if (options.systemd) {
                const device_rules = if (cgroup_root.mode == .legacy)
                    try v2DeviceRules(allocator, options.resources.devices, options.devices)
                else
                    &.{};
                defer allocator.free(device_rules);
                const resource_properties = try systemdProperties(allocator, options.resources, cgroup_root.mode, device_rules);
                defer freeSystemdProperties(allocator, resource_properties);
                var properties: std.ArrayList(dbus.Property) = .empty;
                defer properties.deinit(allocator);
                const init_pids = [_]u32{@intCast(mapping_response.pid)};
                try properties.appendSlice(allocator, &.{
                    .{ .name = "Description", .value = .{ .string = try std.fmt.allocPrint(allocator, "igvano container {s}", .{options.id}) } },
                    .{ .name = "Slice", .value = .{ .string = options.systemd_slice } },
                    .{ .name = "Delegate", .value = .{ .boolean = true } },
                    .{ .name = "PIDs", .value = .{ .uint32s = &init_pids } },
                    .{ .name = "DefaultDependencies", .value = .{ .boolean = false } },
                    .{ .name = "MemoryAccounting", .value = .{ .boolean = true } },
                    .{ .name = "CPUAccounting", .value = .{ .boolean = true } },
                    .{ .name = "IOAccounting", .value = .{ .boolean = true } },
                    .{ .name = "TasksAccounting", .value = .{ .boolean = true } },
                });
                if (cgroup_root.mode == .legacy)
                    try properties.append(allocator, .{ .name = "BlockIOAccounting", .value = .{ .boolean = true } });
                try properties.appendSlice(allocator, resource_properties);
                systemd_client.start(options.systemd_unit, properties.items) catch |err| return systemdFailure(&systemd_client, "create systemd scope", err);
                try configureCgroup(allocator, cgroup_root.fd, cgroup_root.mode, &cgroup, hierarchies, options, cgroup_writes, v1_writes);
                if (cgroup_root.mode == .legacy) {
                    const pid_text = try std.fmt.allocPrint(allocator, "{d}", .{mapping_response.pid});
                    for (hierarchies) |hierarchy|
                        try writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", pid_text, options.cgroup_path);
                }
            }
            if (user_namespace) {
                try writeUserMappings(mapping_response.pid, gid_map, uid_map);
                // Init needs ownership as namespace root, even for a non-root process.
                try checkResult(linux.chown(fifo, fifo_uid, fifo_gid));
            }
            if (!writeAll(fd, &.{1})) return error.CreateFailed;
            closeFd(fd);
            map_writer = null;
        }
        if (rootfs_mount_before) |before| {
            var mount_response: CreateResponse = .{};
            if (!readAll(report[0], std.mem.asBytes(&mount_response))) return error.CreateFailed;
            if (mount_response.failureError()) |err| return err;
            if (mount_response.rootfs_mount_id == 0 or mount_response.rootfs_mount_id == before)
                return error.CreateFailed;
            rootfs_mount_id = mount_response.rootfs_mount_id;
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
            .systemd = options.systemd,
            .device_nodes = options.devices,
            .rootfs_mount = if (private_mount_namespace) null else options.rootfs,
            .rootfs_mount_id = rootfs_mount_id,
            .rootfs_mount_boot_id = rootfs_mount_boot_id,
        };
        errdefer if (reported and handle.pid > 0) {
            const saved_diagnostic = diagnostics.last_diagnostic;
            const saved_len = diagnostics.last_diagnostic_len;
            kill(ptr, handle, 9) catch {};
            diagnostics.last_diagnostic = saved_diagnostic;
            diagnostics.last_diagnostic_len = saved_len;
        };
        if (!reported) return error.CreateFailed;
        if (response.failureError()) |err| return err;
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
        if (response.failureError()) |err| return err;
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
            .systemd = options.systemd,
            .device_nodes = options.devices,
            .rootfs_mount = if (private_mount_namespace) null else options.rootfs,
            .rootfs_mount_id = rootfs_mount_id,
            .rootfs_mount_boot_id = rootfs_mount_boot_id,
        };
    } else {
        return error.NotImplemented;
    }
}

pub fn runInit(
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
    apparmor_command: ?[]const u8,
    seccomp_program: ?seccomp.Program,
) noreturn {
    // The inherited host descriptors avoid path access to the state directory
    // or /proc inside the container and are closed before or at exec.
    var fifo_buffer: [32]u8 = undefined;
    const fifo_name = std.fmt.bufPrintZ(&fifo_buffer, "{d}", .{fifo_fd}) catch unreachable;
    // Sysctls in setupRootfs may override the configured hostname.
    if (flags & linux.CLONE.NEWUTS != 0) {
        if (spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch |err| failCreate(ready_fd, err);
        }
    }
    setupRootfs(rootfs, mounts, devices, symlinks, spec.root.readonly, rootfs_options) catch |err| failCreate(ready_fd, err);
    checkResult(linux.chdir(cwd)) catch |err| failCreate(ready_fd, err);
    applyAppArmor(apparmor_command) catch |err| failCreate(ready_fd, err);
    closeExecFrom(3, fd_dir) catch |err| failCreate(ready_fd, err);
    if (spec.process) |process| {
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.user.uid != 0)
            checkResult(linux.fchmodat(fd_dir, fifo_name, 0o622)) catch |err| failCreate(ready_fd, err);
        applyRlimits(rlimits) catch |err| failCreate(ready_fd, err);
        // Without NNP the kernel requires CAP_SYS_ADMIN, which applyProcess
        // may drop. Do not change the OCI noNewPrivileges setting.
        // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
        if (!process.noNewPrivileges) {
            if (seccomp_program) |program|
                installSeccomp(program) catch |err| failCreate(ready_fd, err);
        }
        applyProcess(process, capabilities, &.{}) catch |err| {
            childError("cannot apply process settings: ", err);
            failCreate(ready_fd, err);
        };
    }
    var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = if (spec.process != null)
        resolveExecutable(argv, envp, &executable_buffer) catch |err| failCreate(ready_fd, err)
    else
        null;
    var response: CreateResponse = .{};
    if (!writeAll(ready_fd, std.mem.asBytes(&response))) linux.exit_group(1);
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
    // Opening the writer unblocks start. Acknowledge after hooks pass, then
    // retain the CLOEXEC writer so EOF confirms exec before start succeeds.
    hooks.runWithCloexecFds(start_hooks, start_hook_state) catch {
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    runProcess(spec, executable, argv, envp, seccomp_program) catch |err| {
        if (err != error.ExecFailed) childError("cannot execute process: ", err);
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
}

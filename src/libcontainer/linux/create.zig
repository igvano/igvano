const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const hooks = @import("../hooks.zig");
const seccomp = @import("../seccomp.zig");
const selinux = @import("selinux.zig");
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
const netdev = @import("netdev.zig");
const debugLog = @import("diagnostic.zig").debugLog;
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
const readProcStat = @import("proc.zig").readProcStat;
const criu = @import("criu.zig");
const closeExecFrom = @import("process.zig").closeExecFrom;
const kernelCapabilities = @import("process.zig").kernelCapabilities;
const runProcess = @import("process.zig").runProcess;
const installSeccomp = @import("process.zig").installSeccomp;
const installSeccompFor = @import("process.zig").installSeccompFor;
const installSeccompListener = @import("process.zig").installSeccompListener;
const deliverSeccompListener = @import("process.zig").deliverSeccompListener;
const applyOomScoreAdj = @import("process.zig").applyOomScoreAdj;
const resetCpuAffinity = @import("process.zig").resetCpuAffinity;
const applyProcess = @import("process.zig").applyProcess;
const applyMemoryPolicy = @import("process.zig").applyMemoryPolicy;
const applySchedulerAndIOPriority = @import("process.zig").applySchedulerAndIOPriority;
const applyRlimits = @import("process.zig").applyRlimits;
const resolveExecutable = @import("process.zig").resolveExecutable;
const closeMountFds = @import("mount_sources.zig").closeMountFds;
const prepareIDMappedMounts = @import("mount_sources.zig").prepareIDMappedMounts;
const startMountSourceHelper = @import("mount_sources.zig").startMountSourceHelper;
const console = @import("console.zig").console;
const PreparedDevice = @import("device_nodes.zig").PreparedDevice;
const prepareAppArmor = @import("procfs.zig").prepareAppArmor;
const applyAppArmor = @import("procfs.zig").applyAppArmor;
const systemdFailure = @import("systemd.zig").systemdFailure;
const freeSystemdProperties = @import("systemd.zig").freeSystemdProperties;
const systemdProperties = @import("systemd.zig").systemdProperties;
const stopSystemdScope = @import("systemd.zig").stopSystemdScope;

const CgroupRoot = @import("cgroup.zig").CgroupRoot;

const CreateNamespaces = struct {
    flags: usize = undefined,
    isolation_flags: usize = undefined,
    private_mount_namespace: bool = undefined,
    user_namespace: bool = undefined,
    joined_user_namespace: bool = undefined,
    joins: std.ArrayList(NamespaceJoin) = .empty,
    container_mappings: libcontainer.MountMappings = .{},
    joined_user_fd: ?posix.fd_t = null,
    joined_user_path: ?[]const u8 = null,
    fifo_uid: u32 = undefined,
    fifo_gid: u32 = undefined,
    uid_map: []const u8 = undefined,
    gid_map: []const u8 = undefined,
    /// A non-root runtime with a created or joined user namespace.
    rootless_userns: bool = false,
    /// rootless_userns with a new user namespace and no namespace joins: init
    /// stays dumpable like runc's; joined namespaces keep it non-dumpable.
    rootless_dumpable: bool = false,
};

const CreateInit = struct {
    capabilities: ?libcontainer.Capabilities = undefined,
    apparmor_command: ?[]const u8 = undefined,
    seccomp_program: ?seccomp.Program = undefined,
    fifo: [:0]const u8 = undefined,
    rootfs: [:0]const u8 = undefined,
    cwd: [:0]const u8 = undefined,
    mounts: []PreparedMount = undefined,
    devices: []PreparedDevice = undefined,
    argv: [:null]?[*:0]const u8 = undefined,
    envp: [:null]?[*:0]const u8 = undefined,
    create_hooks: []const hooks.Prepared = undefined,
    start_hooks: []const hooks.Prepared = undefined,
    create_state: []u8 = undefined,
    start_state: []u8 = undefined,
    masked_paths: []const [:0]const u8 = undefined,
    readonly_paths: []const [:0]const u8 = undefined,
    /// /proc/self/timens_offsets text, written by child1 after unshare.
    time_offsets: []const u8 = "",
};

const CreateCgroups = struct {
    cgroup_root: CgroupRoot = undefined,
    systemd_client: dbus.Client = undefined,
    hierarchies: []V1Hierarchy = undefined,
    cgroup_writes: []const Write = undefined,
    v1_writes: []const V1Write = undefined,
    cgroup: ?posix.fd_t = null,
    /// Rootless without cgroup permission: init joins no cgroup.
    skipped: bool = false,
};

const CreateSync = struct {
    pid_pipe: [2]posix.fd_t = undefined,
    report: [2]posix.fd_t = undefined,
    ready: [2]posix.fd_t = undefined,
    create_go: [2]posix.fd_t = undefined,
    map_pipe: ?[2]posix.fd_t = undefined,
    child1: i32 = undefined,
    owns_pid_pipe: bool = true,
    owns_create_go: bool = true,
    create_writer: ?posix.fd_t = null,
    /// Runtime -> init: "seccomp listener copied"; only with notify rules.
    seccomp_ack: ?[2]posix.fd_t = null,
    map_writer: ?posix.fd_t = null,
    child1_reaped: bool = false,
};

const CreateContext = struct {
    options: libcontainer.CreateOptions,
    allocator: std.mem.Allocator,
    namespaces: CreateNamespaces = .{},
    init: CreateInit = .{},
    cgroups: CreateCgroups = .{},
    sync: CreateSync = .{},
    proc_dir: posix.fd_t = undefined,
    fifo_fd: posix.fd_t = undefined,
    rootfs_mount_before: ?u64 = null,
    rootfs_mount_boot_id: ?[36]u8 = null,
    rootfs_mount_id: ?u64 = null,
    mount_source_socket: ?posix.fd_t = null,
};

// Step chain: validate → prepare → joined user namespace → cgroups → mounts
// → resources → host descriptors → mount sources → fork → await parent.
// Each step owns a defer scope that stays active through the following steps.
pub fn create(options: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        var context: CreateContext = .{ .options = options, .allocator = options.allocator };
        try validateCreate(&context);
        // Prepare the init's strings before either fork.
        var arena: std.heap.ArenaAllocator = .init(options.allocator);
        defer arena.deinit();
        context.allocator = arena.allocator();
        return prepareCreate(&context);
    } else {
        return error.NotImplemented;
    }
}

fn validateCreate(ctx: *CreateContext) libcontainer.Error!void {
    ctx.namespaces.flags = try namespaceFlags(ctx.options.namespaces);
    ctx.namespaces.isolation_flags = ctx.namespaces.flags;
    for (ctx.options.namespaces) |namespace|
        ctx.namespaces.isolation_flags |= namespaceFlag(namespace.kind);
    ctx.namespaces.private_mount_namespace = ctx.namespaces.isolation_flags & linux.CLONE.NEWNS != 0;
    if (!ctx.namespaces.private_mount_namespace and ctx.options.rootfs_propagation != null) {
        reportDiagnostic("cannot change propagation without a private mount namespace", .{});
        return error.InvalidConfig;
    }
    // Offsets can only be set on a time namespace igvano creates, like runc.
    if (ctx.options.time_offsets != null and ctx.namespaces.flags & linux.CLONE.NEWTIME == 0) {
        reportDiagnostic("time offsets require a new time namespace", .{});
        return error.InvalidConfig;
    }
    if ((ctx.options.hostname != null or ctx.options.domainname != null) and ctx.namespaces.isolation_flags & linux.CLONE.NEWUTS == 0)
        return error.InvalidConfig;
    try validateCreateProcess(ctx);
    try validateDeviceMounts(ctx.options.mounts, ctx.options.devices);
    if (!std.fs.path.isAbsolute(ctx.options.exec_fifo) or
        std.mem.indexOfScalar(u8, ctx.options.exec_fifo, 0) != null)
        return error.InvalidPath;
}

fn validateCreateProcess(ctx: *CreateContext) libcontainer.Error!void {
    if (ctx.options.process) |process| {
        if (process.args.len == 0) return error.InvalidProcess;
    }
    const terminal = if (ctx.options.process) |process| process.terminal else false;
    // CRIU recreates a restored terminal itself.
    if (ctx.options.restore == null and terminal != (ctx.options.console_fds != null)) return error.InvalidConfig;
    ctx.init.capabilities = if (ctx.options.capabilities) |caps| try kernelCapabilities(caps) else null;
    for (ctx.options.rlimits) |limit| {
        if (limit.soft > limit.hard) return error.InvalidConfig;
    }
}

fn prepareCreate(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    ctx.init.apparmor_command = try prepareAppArmor(ctx.allocator, ctx.options.apparmor_profile);
    try selinux.requireLabelSupport(ctx.options.selinux_label);
    ctx.init.seccomp_program = if (ctx.options.seccomp) |config|
        seccomp.compile(ctx.allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
            return error.InvalidConfig;
        }
    else
        null;
    // runc's debug line; its tests read the flags from it.
    if (ctx.init.seccomp_program) |program| debugLog(ctx.options.debug, "seccomp filter flags: {d}", .{program.flags});
    for (ctx.options.namespaces) |namespace| {
        if (namespace.path) |path| try ctx.namespaces.joins.append(ctx.allocator, .{
            .flag = namespaceFlag(namespace.kind),
            .path = try pathString(ctx.allocator, path),
        });
    }
    try validateMountNamespaceJoins(ctx);
    if (ctx.options.time_offsets) |offsets| ctx.init.time_offsets = try timeOffsetsText(ctx.allocator, offsets);
    try prepareCreateMappings(ctx);
    return prepareJoinedUserNamespace(ctx);
}

fn validateMountNamespaceJoins(ctx: *const CreateContext) libcontainer.Error!void {
    // Safety guard: rootfs setup in our mount namespace would mutate host mounts.
    for (ctx.namespaces.joins.items) |join| {
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
}

fn prepareCreateMappings(ctx: *CreateContext) libcontainer.Error!void {
    ctx.namespaces.user_namespace = ctx.namespaces.flags & linux.CLONE.NEWUSER != 0;
    ctx.namespaces.joined_user_namespace = !ctx.namespaces.user_namespace and ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0;
    // Library callers bypass frontend validation, so mapping-presence checks are intentional.
    if (ctx.namespaces.user_namespace and (ctx.options.uid_mappings.len == 0 or ctx.options.gid_mappings.len == 0)) return error.InvalidConfig;
    ctx.namespaces.container_mappings = .{ .uid = ctx.options.uid_mappings, .gid = ctx.options.gid_mappings };
}

fn prepareJoinedUserNamespace(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    // Pin the validated namespace and use that same descriptor in init.
    defer if (ctx.namespaces.joined_user_fd) |fd| closeFd(fd);
    if (ctx.namespaces.joined_user_namespace) {
        for (ctx.namespaces.joins.items) |join| {
            if (join.flag != linux.CLONE.NEWUSER) continue;
            const fd = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
            ctx.namespaces.joined_user_fd = fd;
            ctx.namespaces.joined_user_path = join.path;
            try validateNamespaceFd(fd, linux.CLONE.NEWUSER);
            ctx.namespaces.container_mappings = try joinedUserNamespaceMappings(ctx.allocator, fd);
            try validateJoinedMappings(ctx.allocator, ctx.namespaces.container_mappings, .{ .uid = ctx.options.uid_mappings, .gid = ctx.options.gid_mappings });
            break;
        }
    }
    try prepareCreatePaths(ctx);
    return prepareCreateCgroups(ctx);
}

fn prepareCreatePaths(ctx: *CreateContext) libcontainer.Error!void {
    ctx.namespaces.fifo_uid = if (ctx.namespaces.user_namespace or ctx.namespaces.joined_user_namespace) try mappedRootID(ctx.namespaces.container_mappings.uid) else 0;
    ctx.namespaces.fifo_gid = if (ctx.namespaces.user_namespace or ctx.namespaces.joined_user_namespace) try mappedRootID(ctx.namespaces.container_mappings.gid) else 0;
    ctx.namespaces.uid_map = try formatIDMappings(ctx.allocator, ctx.options.uid_mappings);
    ctx.namespaces.rootless_userns = ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0 and linux.geteuid() != 0;
    ctx.namespaces.rootless_dumpable = ctx.namespaces.rootless_userns and ctx.namespaces.user_namespace and ctx.namespaces.joins.items.len == 0;
    ctx.namespaces.gid_map = try formatIDMappings(ctx.allocator, ctx.options.gid_mappings);
    ctx.init.fifo = try ctx.allocator.dupeZ(u8, ctx.options.exec_fifo);
    ctx.init.rootfs = try processString(ctx.allocator, ctx.options.rootfs);
    ctx.init.cwd = try processString(ctx.allocator, if (ctx.options.process) |process| process.cwd else "/");
    if (!std.fs.path.isAbsolute(ctx.init.cwd)) return error.InvalidProcess;
    if (!std.fs.path.isAbsolute(ctx.init.rootfs)) return error.InvalidPath;
    try netdev.validate(ctx.options.net_devices, ctx.options.namespaces);
    try probeInheritedRootfs(ctx);
}

fn probeInheritedRootfs(ctx: *CreateContext) libcontainer.Error!void {
    if (!ctx.namespaces.private_mount_namespace) {
        const root_fd = try openPath(linux.AT.FDCWD, ctx.init.rootfs, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
        defer closeFd(root_fd);
        var fd_buffer: [64]u8 = undefined;
        var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const size = linux.readlink(fdPath(&fd_buffer, root_fd), &resolved_buffer, resolved_buffer.len);
        try checkResult(size);
        if (size == 1 and resolved_buffer[0] == '/') {
            reportDiagnostic("cannot use / as rootfs without a private mount namespace", .{});
            return error.InvalidConfig;
        }
        ctx.rootfs_mount_before = mountId(root_fd) catch |err| {
            if (err == error.Unsupported)
                reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
            return err;
        };
        // Probe both APIs before creating any mounts.
        _ = (statMount(ctx.rootfs_mount_before.?) catch |err| {
            if (err == error.Unsupported)
                reportDiagnostic("inheriting the mount namespace requires Linux 6.8+ (unique mount IDs); add a mount namespace to the config", .{});
            return err;
        }) orelse return error.CreateFailed;
        ctx.rootfs_mount_boot_id = try bootId();
    }
}

fn prepareCreateCgroups(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    try validateCgroupPath(ctx.options.cgroup_path);
    ctx.cgroups.systemd_client = dbus.Client.init(ctx.allocator);
    defer ctx.cgroups.systemd_client.deinit();
    try connectCreateSystemd(ctx);
    if (ctx.namespaces.joined_user_namespace) try checkResult(linux.chown(ctx.init.fifo, ctx.namespaces.fifo_uid, ctx.namespaces.fifo_gid));
    ctx.cgroups.cgroup_root = try openCgroupRoot();
    defer closeFd(ctx.cgroups.cgroup_root.fd);
    ctx.cgroups.hierarchies = if (ctx.cgroups.cgroup_root.mode == .legacy) try openV1Hierarchies(ctx.allocator, ctx.options.systemd) else &.{};
    defer if (ctx.cgroups.cgroup_root.mode == .legacy) freeV1Hierarchies(ctx.allocator, ctx.cgroups.hierarchies);
    return prepareCreateMounts(ctx);
}

fn connectCreateSystemd(ctx: *CreateContext) libcontainer.Error!void {
    if (ctx.options.systemd) {
        if (!std.mem.eql(u8, ctx.options.systemd_unit, std.fs.path.basename(ctx.options.cgroup_path)) or
            !std.mem.endsWith(u8, ctx.options.systemd_unit, ".scope") or
            !std.mem.endsWith(u8, ctx.options.systemd_slice, ".slice") or
            std.mem.indexOfAny(u8, ctx.options.systemd_slice, "/\x00") != null)
            return error.InvalidConfig;
        ctx.cgroups.systemd_client.connect() catch |err| return systemdFailure(&ctx.cgroups.systemd_client, "create systemd scope", err);
    }
}

fn prepareCreateMounts(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    ctx.init.mounts = try prepareMounts(ctx.allocator, ctx.options.mounts, ctx.cgroups.cgroup_root.fs_type, ctx.cgroups.hierarchies, ctx.options.cgroup_path);
    defer closeMountFds(ctx.init.mounts);
    if (ctx.namespaces.joined_user_fd) |fd| {
        for (ctx.init.mounts) |*mount| {
            if (mount.mappings) |*mappings| {
                const path = mappings.userns_path orelse continue;
                if (std.mem.eql(u8, path, ctx.namespaces.joined_user_path.?))
                    mappings.userns_path = try std.fmt.allocPrint(ctx.allocator, "/proc/self/fd/{d}", .{fd});
            }
        }
    }
    try prepareIDMappedMounts(ctx.allocator, ctx.init.mounts);
    try prepareCreateDevices(ctx);
    try prepareCreateProcess(ctx);
    return prepareCreateResources(ctx);
}

fn prepareCreateDevices(ctx: *CreateContext) libcontainer.Error!void {
    ctx.init.devices = try ctx.allocator.alloc(PreparedDevice, ctx.options.devices.len);
    for (ctx.options.devices, ctx.init.devices) |device, *prepared| {
        if (!std.mem.startsWith(u8, device.path, "/") or
            device.major > 0xfff or device.minor > 0xfffff or
            device.mode & ~@as(u32, 0o7777) != 0)
            return error.InvalidConfig;
        prepared.* = .{
            .path = try pathString(ctx.allocator, device.path),
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
}

fn prepareCreateProcess(ctx: *CreateContext) libcontainer.Error!void {
    const args: []const []const u8 = if (ctx.options.process) |process| process.args else &.{};
    const env: []const []const u8 = if (ctx.options.process) |process| process.env else &.{};
    ctx.init.argv = try ctx.allocator.allocSentinel(?[*:0]const u8, args.len, null);
    for (args, 0..) |arg, i| ctx.init.argv[i] = (try processString(ctx.allocator, arg)).ptr;
    ctx.init.envp = try ctx.allocator.allocSentinel(?[*:0]const u8, env.len, null);
    for (env, 0..) |entry, i| ctx.init.envp[i] = (try processString(ctx.allocator, entry)).ptr;
    ctx.init.create_hooks = try hooks.prepare(ctx.allocator, ctx.options.create_hooks);
    ctx.init.start_hooks = try hooks.prepare(ctx.allocator, ctx.options.start_hooks);
    ctx.init.create_state = try ctx.allocator.alloc(u8, ctx.options.create_hook_state.prefix.len + 20 + ctx.options.create_hook_state.suffix.len);
    ctx.init.start_state = try ctx.allocator.alloc(u8, ctx.options.start_hook_state.prefix.len + 20 + ctx.options.start_hook_state.suffix.len);
    ctx.init.masked_paths = try preparePaths(ctx.allocator, ctx.options.masked_paths);
    ctx.init.readonly_paths = try preparePaths(ctx.allocator, ctx.options.readonly_paths);
}

fn prepareCreateResources(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    ctx.cgroups.cgroup_writes = if (ctx.cgroups.cgroup_root.mode == .unified) try v2Writes(ctx.allocator, ctx.options.resources) else &.{};
    defer if (ctx.cgroups.cgroup_root.mode == .unified) freeWrites(ctx.allocator, ctx.cgroups.cgroup_writes);
    if (ctx.cgroups.cgroup_root.mode == .legacy and ctx.options.resources.unified.len != 0) {
        reportDiagnostic("unified resources require cgroup v2", .{});
        return error.InvalidConfig;
    }
    ctx.cgroups.v1_writes = if (ctx.cgroups.cgroup_root.mode == .legacy) try v1Writes(ctx.allocator, ctx.options.resources) else &.{};
    defer if (ctx.cgroups.cgroup_root.mode == .legacy) freeV1Writes(ctx.allocator, ctx.cgroups.v1_writes);
    const ignored_fields = if (ctx.cgroups.cgroup_root.mode == .unified) try v2IgnoredFields(ctx.allocator, ctx.options.resources) else try ctx.allocator.dupe(u8, "");
    defer ctx.allocator.free(ignored_fields);
    if (ignored_fields.len != 0)
        std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ignored_fields});
    return createWithHostDescriptors(ctx);
}

fn createWithHostDescriptors(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    // pivot_root also changes child1's root while it waits in the same
    // mount namespace. Pin host /proc so it can still capture identity.
    ctx.proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(ctx.proc_dir);
    // Init must retain the host FIFO across namespace changes without
    // traversing the private state directory as a mapped user.
    ctx.fifo_fd = try openPath(linux.AT.FDCWD, ctx.init.fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(ctx.fifo_fd);
    defer if (ctx.cgroups.cgroup) |fd| closeFd(fd);
    errdefer cleanupFailedCreate(ctx);
    // fs cgroups are ready before fork; systemd adopts init at the
    // early mapping exchange, while init is blocked before rootfs work.
    if (!ctx.options.systemd)
        configureCgroup(ctx.allocator, ctx.cgroups.cgroup_root.fd, ctx.cgroups.cgroup_root.mode, &ctx.cgroups.cgroup, ctx.cgroups.hierarchies, ctx.options, ctx.cgroups.cgroup_writes, ctx.cgroups.v1_writes) catch |err| {
            if (!skipRootlessCgroup(ctx, err)) return err;
        };
    return createWithMountSources(ctx);
}

/// runc's fs2 Apply: rootless, no permission, the default path and no
/// limits means running without a cgroup instead of failing.
fn skipRootlessCgroup(ctx: *CreateContext, err: libcontainer.Error) bool {
    if (err != error.PermissionDenied or !ctx.options.rootless_cgroups) return false;
    if (!ctx.options.cgroup_path_default) {
        reportDiagnostic("rootless needs no limits + no cgrouppath when no permission is granted for cgroups", .{});
        return false;
    }
    if (ctx.cgroups.cgroup_writes.len != 0 or ctx.cgroups.v1_writes.len != 0) {
        reportDiagnostic("rootless needs no limits + no cgrouppath when no permission is granted for cgroups", .{});
        return false;
    }
    if (ctx.cgroups.cgroup) |fd| closeFd(fd);
    ctx.cgroups.cgroup = null;
    removeV1Cgroups(ctx.cgroups.hierarchies, ctx.options.cgroup_path) catch {};
    for (ctx.cgroups.hierarchies) |*hierarchy| {
        if (hierarchy.leaf) |fd| closeFd(fd);
        hierarchy.leaf = null;
    }
    ctx.cgroups.skipped = true;
    diagnostics.last_diagnostic_len = 0;
    return true;
}

fn cleanupFailedCreate(ctx: *CreateContext) void {
    const saved_diagnostic = diagnostics.last_diagnostic;
    const saved_len = diagnostics.last_diagnostic_len;
    defer {
        diagnostics.last_diagnostic = saved_diagnostic;
        diagnostics.last_diagnostic_len = saved_len;
    }
    if (ctx.cgroups.systemd_client.unit_started)
        stopSystemdScope(ctx.allocator, ctx.options.systemd_unit) catch {};
    // Child1 can die before reporting child2's PID. Kill the entire
    // cgroup before removing it, including any blocked init.
    if (ctx.cgroups.cgroup) |fd| {
        writeCgroupFile(fd, "cgroup.kill", "1", ctx.options.cgroup_path) catch {};
        removeCreatedCgroup(ctx.cgroups.cgroup_root.fd, ctx.options.cgroup_path, fd) catch {};
    } else {
        removeV1Cgroups(ctx.cgroups.hierarchies, ctx.options.cgroup_path) catch {};
    }
    if (ctx.rootfs_mount_before) |before| detachRootfs(ctx.init.rootfs, if (ctx.rootfs_mount_id) |id|
        .{ .created = id }
    else
        .{ .before_create = before }) catch {};
}

fn createWithMountSources(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    var needs_mount_sources = false;
    for (ctx.init.mounts) |mount| {
        if (mount.flags & linux.MS.BIND != 0 and
            (ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0 or mount.mappings != null))
        {
            needs_mount_sources = true;
            break;
        }
    }
    if (ctx.options.restore) |restore| return restoreCreate(ctx, restore);
    const mount_source_helper = if (needs_mount_sources) try startMountSourceHelper(
        ctx.init.mounts,
        // Only a mount namespace igvano unshares itself; one joined by path keeps NO_SYMLINKS.
        ctx.namespaces.flags & linux.CLONE.NEWNS != 0,
        ctx.namespaces.rootless_userns,
    ) else null;
    ctx.mount_source_socket = if (mount_source_helper) |helper| helper.socket else null;
    defer if (mount_source_helper) |helper| {
        if (ctx.mount_source_socket) |fd| closeFd(fd);
        _ = waitChild(helper.pid) catch {};
    };
    return forkCreate(ctx);
}

/// Restore replaces the init fork: criu takes the place of child1 in the
/// container's cgroup and recreates the checkpointed processes.
fn restoreCreate(ctx: *CreateContext, restore: *const libcontainer.Restore) libcontainer.Error!libcontainer.State {
    var callback: RestoreCallback = .{ .ctx = ctx };
    const pid = try criu.restore(ctx.allocator, restore, .{
        .rootfs = ctx.init.rootfs,
        .mounts = ctx.options.mounts,
        .masked_paths = ctx.options.masked_paths,
        .devices = ctx.options.devices,
        .namespaces = ctx.options.namespaces,
    }, .{ .ptr = &callback, .started = RestoreCallback.started, .restored = RestoreCallback.restored });
    errdefer _ = linux.kill(pid, linux.SIG.KILL);
    const owned_starttime = try ctx.options.allocator.dupe(u8, callback.starttime[0..callback.starttime_len]);
    return createHandle(ctx, pid, owned_starttime);
}

const RestoreCallback = struct {
    ctx: *CreateContext,
    starttime: [20]u8 = undefined,
    starttime_len: usize = 0,

    fn started(ptr: *anyopaque, criu_pid: i32) libcontainer.Error!void {
        const self: *RestoreCallback = @ptrCast(@alignCast(ptr));
        const ctx = self.ctx;
        if (ctx.options.systemd) return adoptInitSystemd(ctx, criu_pid);
        var buffer: [20]u8 = undefined;
        const pid_text = std.fmt.bufPrint(&buffer, "{d}", .{criu_pid}) catch unreachable;
        if (ctx.cgroups.cgroup) |fd| return writeCgroupFile(fd, "cgroup.procs", pid_text, ctx.options.cgroup_path);
        for (ctx.cgroups.hierarchies) |hierarchy| if (hierarchy.leaf) |fd|
            try writeCgroupFile(fd, "cgroup.procs", pid_text, ctx.options.cgroup_path);
    }

    /// Like runc's setup-namespaces notification: state and createRuntime hooks.
    fn restored(ptr: *anyopaque, pid: i32) libcontainer.Error!void {
        const self: *RestoreCallback = @ptrCast(@alignCast(ptr));
        var buffer: [512]u8 = undefined;
        const stat = try readProcStat(pid, &buffer);
        @memcpy(self.starttime[0..stat.starttime.len], stat.starttime);
        self.starttime_len = stat.starttime.len;
        const ctx = self.ctx;
        if (ctx.options.on_create) |callback| try callback.run(callback.ptr, createHandle(ctx, pid, stat.starttime));
    }
};

fn forkCreate(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    // getpid() in child2 may be 1. Child1 supplies its host PID for
    // opaque hook input; buffers and JSON fragments were prepared above.
    ctx.sync.pid_pipe = try makePipe();
    defer if (ctx.sync.owns_pid_pipe) {
        for (ctx.sync.pid_pipe) |fd| closeFd(fd);
    };
    const listens = listenerProgram(ctx.init.seccomp_program) != null;
    // Checked before fork: without a callback the listener fd has nowhere to go.
    if (listens and ctx.options.on_seccomp_listener == null) {
        reportDiagnostic("seccomp notify rules need a listener callback", .{});
        return error.InvalidConfig;
    }
    ctx.sync.seccomp_ack = if (listens) try makePipe() else null;
    defer closeSeccompAck(ctx);
    try prepareCreatePipes(ctx);
    defer if (ctx.sync.owns_create_go) {
        for (ctx.sync.create_go) |fd| closeFd(fd);
    };
    ctx.sync.child1 = forkProcess() catch |err| {
        for (ctx.sync.report) |fd| closeFd(fd);
        for (ctx.sync.ready) |fd| closeFd(fd);
        if (ctx.sync.map_pipe) |fds| for (fds) |fd| closeFd(fd);
        return err;
    };
    if (ctx.sync.child1 == 0) runCreateChild(ctx);
    debugLog(ctx.options.debug, "nsexec[{d}]: nsexec container setup", .{ctx.sync.child1});
    return awaitCreateParent(ctx);
}

fn prepareCreatePipes(ctx: *CreateContext) libcontainer.Error!void {
    ctx.sync.report = try makePipe();
    ctx.sync.ready = makePipe() catch |err| {
        for (ctx.sync.report) |fd| closeFd(fd);
        return err;
    };
    ctx.sync.create_go = makePipe() catch |err| {
        for (ctx.sync.report) |fd| closeFd(fd);
        for (ctx.sync.ready) |fd| closeFd(fd);
        return err;
    };
    errdefer {
        for (ctx.sync.create_go) |fd| closeFd(fd);
    }
    ctx.sync.map_pipe = if (ctx.namespaces.user_namespace or ctx.options.systemd) makePipe() catch |err| {
        for (ctx.sync.report) |fd| closeFd(fd);
        for (ctx.sync.ready) |fd| closeFd(fd);
        return err;
    } else null;
}

fn closeSeccompAck(ctx: *const CreateContext) void {
    const fds = ctx.sync.seccomp_ack orelse return;
    for (fds) |fd| if (fd >= 0) closeFd(fd);
}

/// Opened with the runtime's credentials before any namespace change: the
/// kernel checks CAP_SYS_TIME of the opener against the new time namespace's
/// owner, which the runtime's user (root, or the rootless user) owns.
fn openTimeOffsets(ctx: *const CreateContext) ?posix.fd_t {
    if (ctx.init.time_offsets.len == 0) return null;
    return openPath(ctx.proc_dir, "self/timens_offsets", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch |err| failCreate(ctx.sync.report[1], err);
}

/// Offsets apply to the time namespace for children, before any child enters it.
fn writeTimeOffsets(ctx: *const CreateContext, fd: ?posix.fd_t) void {
    const opened = fd orelse return;
    if (!writeAll(opened, ctx.init.time_offsets)) {
        reportDiagnostic("cannot write time namespace offsets", .{});
        failCreate(ctx.sync.report[1], error.CreateFailed);
    }
    closeFd(opened);
}

fn setDumpable(ctx: *const CreateContext, dumpable: bool) void {
    checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), @intFromBool(dumpable), 0, 0, 0)) catch |err| failCreate(ctx.sync.report[1], err);
}

fn runCreateChild(ctx: *const CreateContext) noreturn {
    // Open before dropping dumpable: a non-dumpable task's /proc files
    // belong to root, which a non-root runtime cannot open.
    const time_offsets = openTimeOffsets(ctx);
    checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(ctx.sync.report[1], err);
    if (ctx.options.console_fds) |fds| closeFd(fds[0]);
    if (ctx.sync.seccomp_ack) |fds| closeFd(fds[1]);
    if (ctx.options.systemd) closeFd(ctx.cgroups.systemd_client.fd);
    closeFd(ctx.sync.create_go[1]);
    if (ctx.sync.map_pipe) |fds| closeFd(fds[1]);
    closeFd(ctx.cgroups.cgroup_root.fd);
    closeFd(ctx.sync.report[0]);
    joinCreateCgroups(ctx);
    // Match the container cpuset, not the caller's affinity, like runc.
    resetCpuAffinity();
    // Set with host privileges before entering user namespaces.
    // Child2 inherits the adjustment across fork and exec.
    applyOomScoreAdj(ctx.proc_dir, ctx.options.oom_score_adj) catch |err| failCreate(ctx.sync.report[1], err);
    const time_fd = joinCreateNamespaces(ctx);
    // NEWUSER is unshared together with the others so it owns them.
    const early_flags = if (ctx.options.systemd) ctx.namespaces.flags & ~@as(usize, linux.CLONE.NEWCGROUP) else ctx.namespaces.flags;
    if (early_flags != 0) checkResult(linux.unshare(early_flags)) catch |err| failCreate(ctx.sync.report[1], err);
    writeTimeOffsets(ctx, time_offsets);
    // Like runc, a non-root runtime keeps init dumpable: a non-dumpable
    // task's /proc files belong to root, so the runtime could neither write
    // its ID maps nor open its namespaces for exec. Every process involved
    // already runs as the same host user.
    if (ctx.namespaces.rootless_dumpable) setDumpable(ctx, true);
    // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
    const child2 = forkProcess() catch |err| failCreate(ctx.sync.report[1], err);
    if (child2 == 0) runInitChild(ctx, time_fd);
    if (time_fd) |fd| closeFd(fd);
    if (ctx.namespaces.rootless_dumpable) setDumpable(ctx, false);
    reportCreatedInit(ctx, child2);
}

/// One "<clock> <secs> <nanosecs>" line per clock, as /proc/PID/timens_offsets takes.
fn timeOffsetsText(allocator: std.mem.Allocator, offsets: libcontainer.TimeOffsets) libcontainer.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    inline for (.{ "monotonic", "boottime" }) |clock| {
        if (@field(offsets, clock)) |offset| {
            if (offset.nanosecs >= std.time.ns_per_s) {
                reportDiagnostic("time offset {s}: nanosecs must be below 1000000000", .{clock});
                return error.InvalidConfig;
            }
            try text.print(allocator, clock ++ " {d} {d}\n", .{ offset.secs, offset.nanosecs });
        }
    }
    return text.toOwnedSlice(allocator);
}

test "time offsets format one line per clock and reject bad nanoseconds" {
    const text = try timeOffsetsText(std.testing.allocator, .{ .monotonic = .{ .secs = 7881, .nanosecs = 2718281 }, .boottime = .{ .secs = -1337, .nanosecs = 0 } });
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("monotonic 7881 2718281\nboottime -1337 0\n", text);
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectError(error.InvalidConfig, timeOffsetsText(std.testing.allocator, .{ .boottime = .{ .secs = 0, .nanosecs = std.time.ns_per_s } }));
}

fn joinCreateCgroups(ctx: *const CreateContext) void {
    // Join before NEWCGROUP snapshots the namespace root. Child2
    // inherits this membership; the runtime parent stays outside.
    if (ctx.cgroups.cgroup) |fd| {
        writeCgroupFile(fd, "cgroup.procs", "0", ctx.options.cgroup_path) catch |err| failCreate(ctx.sync.report[1], err);
        closeFd(fd);
    } else for (ctx.cgroups.hierarchies) |hierarchy| {
        if (hierarchy.leaf) |fd| {
            writeCgroupFile(fd, "cgroup.procs", "0", ctx.options.cgroup_path) catch |err| failCreate(ctx.sync.report[1], err);
            closeFd(fd);
        }
        closeFd(hierarchy.root.?);
    }
}

/// setns(CLONE_NEWTIME) also moves the caller, and /proc/<pid>/stat shows
/// start times in the reader's time namespace. So child1 stays in the host
/// time namespace to read init's start time, and init joins it itself.
/// Returns the opened time namespace; `joins` gets the other joins.
fn joinCreateNamespaces(ctx: *const CreateContext) ?posix.fd_t {
    var joins: [8]NamespaceJoin = undefined;
    const time_fd = splitTimeJoin(ctx, &joins);
    const count = ctx.namespaces.joins.items.len - @intFromBool(time_fd != null);
    joinNamespacesWithUser(joins[0..count], ctx.namespaces.joined_user_fd) catch |err| failCreate(ctx.sync.report[1], err);
    return time_fd;
}

/// With a new user namespace, init could no longer join a time namespace
/// owned elsewhere, so child1 joins it before the unshare.
// ponytail: that case still reads init's start time inside the joined time
// namespace; pass the start time through a host-side helper if it matters.
fn splitTimeJoin(ctx: *const CreateContext, joins: *[8]NamespaceJoin) ?posix.fd_t {
    var time_fd: ?posix.fd_t = null;
    var count: usize = 0;
    const defer_time = ctx.namespaces.flags & linux.CLONE.NEWUSER == 0;
    for (ctx.namespaces.joins.items) |join| {
        if (join.flag != linux.CLONE.NEWTIME or !defer_time) {
            if (count == joins.len) failCreate(ctx.sync.report[1], error.InvalidConfig);
            joins[count] = join;
            count += 1;
            continue;
        }
        const fd = openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }) catch |err| failCreate(ctx.sync.report[1], err);
        validateNamespaceFd(fd, linux.CLONE.NEWTIME) catch |err| failCreate(ctx.sync.report[1], err);
        time_fd = fd;
    }
    return time_fd;
}

fn joinInitTime(time_fd: ?posix.fd_t) void {
    const fd = time_fd orelse return;
    checkResult(linux.setns(fd, linux.CLONE.NEWTIME)) catch linux.exit_group(1);
    closeFd(fd);
}

fn runInitChild(ctx: *const CreateContext, time_fd: ?posix.fd_t) noreturn {
    // Like runc's nsexec stage-2, init leads its own session; CRIU refuses
    // to dump a session led from outside the PID namespace.
    _ = linux.setsid();
    joinInitTime(time_fd);
    closeFd(ctx.sync.pid_pipe[1]);
    var host_pid: i32 = undefined;
    if (!readAll(ctx.sync.pid_pipe[0], std.mem.asBytes(&host_pid))) linux.exit_group(1);
    closeFd(ctx.sync.pid_pipe[0]);
    // Let the parent see report EOF if child1 dies during the map wait.
    closeFd(ctx.sync.report[1]);
    closeFd(ctx.sync.ready[0]);
    // Host procfs resolves "self" to child2's host PID, even
    // when a joined mount namespace supplies a different /proc.
    const fd_dir = openPath(ctx.proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch linux.exit_group(1);
    enterInitNamespaces(ctx);
    if (ctx.mount_source_socket) |socket| {
        if (ctx.namespaces.rootless_userns) sendInitNamespace(ctx, socket, "self/ns/user");
        // Sources are requested during rootfs setup, one per bind mount.
        sendInitNamespace(ctx, socket, "self/ns/mnt");
    }
    closeFd(ctx.proc_dir);
    const create_input = std.fmt.bufPrint(ctx.init.create_state, "{s}{d}{s}", .{
        ctx.options.create_hook_state.prefix, host_pid, ctx.options.create_hook_state.suffix,
    }) catch linux.exit_group(1);
    const start_input = std.fmt.bufPrint(ctx.init.start_state, "{s}{d}{s}", .{
        ctx.options.start_hook_state.prefix, host_pid, ctx.options.start_hook_state.suffix,
    }) catch linux.exit_group(1);
    runInit(ctx.options.process, .{ .hostname = ctx.options.hostname, .domainname = ctx.options.domainname }, ctx.options.readonly_rootfs, ctx.init.capabilities, ctx.options.rlimits, ctx.namespaces.isolation_flags, ctx.init.rootfs, ctx.init.mounts, ctx.init.devices, ctx.options.device_symlinks, ctx.init.cwd, ctx.fifo_fd, fd_dir, ctx.init.argv.ptr, ctx.init.envp.ptr, ctx.sync.ready[1], initRootfsOptions(ctx, create_input), ctx.init.start_hooks, start_input, ctx.init.apparmor_command, ctx.init.seccomp_program);
}

fn initRootfsOptions(ctx: *const CreateContext, create_input: []const u8) RootfsOptions {
    return .{
        .private_mount_namespace = ctx.namespaces.private_mount_namespace,
        .propagation = ctx.options.rootfs_propagation orelse (linux.MS.SLAVE | linux.MS.REC),
        .create_hooks = ctx.init.create_hooks,
        .create_hook_state = create_input,
        .masked_paths = ctx.init.masked_paths,
        .readonly_paths = ctx.init.readonly_paths,
        .sysctls = ctx.options.sysctls,
        .runtime_sync = .{ .ready_fd = ctx.sync.ready[1], .go_fd = ctx.sync.create_go[0] },
        .console_fd = if (ctx.options.console_fds) |fds| fds[1] else null,
        .mount_source_socket = ctx.mount_source_socket,
        .seccomp_ack_fd = if (ctx.sync.seccomp_ack) |fds| fds[0] else null,
        .rootless = ctx.namespaces.rootless_dumpable,
        .cpuset = if (ctx.options.resources.cpu) |cpu| cpu.cpus != null else false,
        .no_pivot = ctx.options.no_pivot,
        .preserve_fds = ctx.options.preserve_fds,
        .mount_label = ctx.options.mount_label,
        .selinux_label = ctx.options.selinux_label,
        .console_size = if (ctx.options.process) |process| process.console_size else null,
    };
}

fn sendInitNamespace(ctx: *const CreateContext, socket: posix.fd_t, path: [*:0]const u8) void {
    const namespace = openPath(ctx.proc_dir, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch |err| failCreate(ctx.sync.ready[1], err);
    console.sendFd(socket, namespace) catch |err| failCreate(ctx.sync.ready[1], err);
    closeFd(namespace);
}

fn enterInitNamespaces(ctx: *const CreateContext) void {
    // The outside parent must install our ID maps
    // before any rootfs, mount, hostname, or process work.
    if (ctx.sync.map_pipe) |fds| {
        var byte: [1]u8 = undefined;
        if (!readAll(fds[0], &byte)) linux.exit_group(1);
        closeFd(fds[0]);
    }
    if (ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0) {
        // Like runc nsexec stage-2, become root in the user ns.
        // Unmapped host-root fsuid/fsgid make may_create() fail
        // with EOVERFLOW on filesystems mounted in this ns.
        checkResult(linux.setgid(0)) catch linux.exit_group(1);
        checkResult(linux.setuid(0)) catch linux.exit_group(1);
    }

    // systemd has adopted init before NEWCGROUP captures its
    // namespace root. Explicitly joined cgroup namespaces stay joined.
    if (ctx.options.systemd and ctx.namespaces.flags & linux.CLONE.NEWCGROUP != 0)
        checkResult(linux.unshare(linux.CLONE.NEWCGROUP)) catch linux.exit_group(1);
}

fn closeCreateChildFds(ctx: *const CreateContext) void {
    if (ctx.mount_source_socket) |fd| closeFd(fd);
    closeMountFds(ctx.init.mounts);
    closeFd(ctx.fifo_fd);
    if (ctx.options.console_fds) |fds| closeFd(fds[1]);
    closeFd(ctx.sync.create_go[0]);
    closeFd(ctx.sync.pid_pipe[0]);
    if (ctx.sync.seccomp_ack) |fds| closeFd(fds[0]);
}

fn sendInitHostPid(ctx: *const CreateContext, child2: i32) void {
    var host_pid = child2;
    if (!writeAll(ctx.sync.pid_pipe[1], std.mem.asBytes(&host_pid))) {
        _ = linux.kill(child2, .KILL);
        _ = waitChild(child2) catch {};
        failCreate(ctx.sync.report[1], error.CreateFailed);
    }
    closeFd(ctx.sync.pid_pipe[1]);
}

fn reportInitMappingPid(ctx: *const CreateContext, child2: i32) void {
    if (ctx.sync.map_pipe) |fds| {
        closeFd(fds[0]);
        var mapping_response: CreateResponse = .{ .pid = child2 };
        if (!writeAll(ctx.sync.report[1], std.mem.asBytes(&mapping_response))) {
            _ = linux.kill(child2, .KILL);
            _ = waitChild(child2) catch {};
            linux.exit_group(1);
        }
    }
}

fn forwardInitMount(ctx: *const CreateContext, child2: i32) void {
    if (!ctx.namespaces.private_mount_namespace) {
        var mount_response: CreateResponse = .{};
        if (!readAll(ctx.sync.ready[0], std.mem.asBytes(&mount_response)) or mount_response.failure != 0) {
            _ = waitChild(child2) catch {};
            failCreate(ctx.sync.report[1], mount_response.failureError() orelse error.CreateFailed);
        }
        if (!writeAll(ctx.sync.report[1], std.mem.asBytes(&mount_response))) {
            _ = linux.kill(child2, .KILL);
            _ = waitChild(child2) catch {};
            linux.exit_group(1);
        }
    }
}

fn waitInitMounts(ctx: *const CreateContext, child2: i32) void {
    var init_response: CreateResponse = .{};
    // Child2 has applied mounts and waits before child hooks/pivot.
    if (!readAll(ctx.sync.ready[0], std.mem.asBytes(&init_response)) or init_response.failure != 0) {
        _ = waitChild(child2) catch {};
        failCreate(ctx.sync.report[1], init_response.failureError() orelse error.CreateFailed);
    }
}

fn captureInitIdentity(ctx: *const CreateContext, child2: i32) CreateResponse {
    // Capture identity while child2 is still our child, so its PID
    // cannot be recycled even if it has already exited.
    var stat_buffer: [4096]u8 = undefined;
    const stat = readProcStatAt(ctx.proc_dir, child2, &stat_buffer) catch |err| {
        _ = linux.kill(child2, .KILL);
        _ = waitChild(child2) catch {};
        failCreate(ctx.sync.report[1], err);
    };
    const response: CreateResponse = .{
        .pid = child2,
        .starttime = std.fmt.parseInt(u64, stat.starttime, 10) catch unreachable,
    };
    return response;
}

fn reportInitIdentity(ctx: *const CreateContext, child2: i32, response: *CreateResponse) void {
    if (!writeAll(ctx.sync.report[1], std.mem.asBytes(response))) {
        _ = linux.kill(child2, .KILL);
        _ = waitChild(child2) catch {};
        linux.exit_group(1);
    }
}

fn waitInitInitialized(ctx: *const CreateContext, child2: i32) void {
    var init_response: CreateResponse = .{};
    var initialized = readAll(ctx.sync.ready[0], std.mem.asBytes(&init_response));
    // Forward a seccomp listener report with init's host PID, then keep waiting.
    while (initialized and init_response.failure == 0 and init_response.seccomp_fd >= 0) {
        init_response.pid = child2;
        reportInitIdentity(ctx, child2, &init_response);
        init_response = .{};
        initialized = readAll(ctx.sync.ready[0], std.mem.asBytes(&init_response));
    }
    closeFd(ctx.sync.ready[0]);
    if (!initialized or init_response.failure != 0) {
        _ = waitChild(child2) catch {};
        failCreate(ctx.sync.report[1], init_response.failureError() orelse error.CreateFailed);
    }
}

fn reportCreatedInit(ctx: *const CreateContext, child2: i32) noreturn {
    closeCreateChildFds(ctx);
    sendInitHostPid(ctx, child2);
    reportInitMappingPid(ctx, child2);
    closeFd(ctx.sync.ready[1]);
    forwardInitMount(ctx, child2);
    waitInitMounts(ctx, child2);
    var response = captureInitIdentity(ctx, child2);
    reportInitIdentity(ctx, child2, &response);
    waitInitInitialized(ctx, child2);
    reportInitIdentity(ctx, child2, &response);
    // No shim: exiting child1 reparents the blocked init to host init.
    linux.exit_group(0);
}

fn awaitCreateParent(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    if (ctx.mount_source_socket) |fd| closeFd(fd);
    ctx.mount_source_socket = null;
    // Only child1 writes the PID. Keeping a writer in this parent
    // would strand child2 if child1 died before sending it, preventing
    // report EOF and hanging create.
    for (ctx.sync.pid_pipe) |fd| closeFd(fd);
    ctx.sync.owns_pid_pipe = false;
    closeFd(ctx.sync.report[1]);
    for (ctx.sync.ready) |fd| closeFd(fd);
    if (ctx.sync.seccomp_ack) |*fds| {
        closeFd(fds[0]);
        fds[0] = -1;
    }
    defer closeFd(ctx.sync.report[0]);
    // Keep a reader to prevent SIGPIPE if init exits before release.
    defer closeFd(ctx.sync.create_go[0]);
    ctx.sync.create_writer = ctx.sync.create_go[1];
    defer if (ctx.sync.create_writer) |fd| closeFd(fd);
    ctx.sync.owns_create_go = false;
    // Retain a reader so a dying init cannot SIGPIPE the runtime on go.
    defer if (ctx.sync.map_pipe) |fds| closeFd(fds[0]);
    ctx.sync.map_writer = if (ctx.sync.map_pipe) |fds| fds[1] else null;
    // On failure, close before waiting to unblock init; null prevents double close.
    defer if (ctx.sync.map_writer) |fd| closeFd(fd);
    errdefer if (!ctx.sync.child1_reaped) reapFailedCreateChild(ctx);
    try releaseInitMappings(ctx);
    try receiveRootfsMount(ctx);
    const state = try finishCreateParent(ctx);
    debugLog(ctx.options.debug, "child process in init()", .{});
    debugLog(ctx.options.debug, "init: closing the pipe to signal completion", .{});
    return state;
}

fn reapFailedCreateChild(ctx: *CreateContext) void {
    if (ctx.sync.map_writer) |fd| {
        closeFd(fd);
        ctx.sync.map_writer = null;
    }
    if (ctx.sync.create_writer) |fd| {
        closeFd(fd);
        ctx.sync.create_writer = null;
    }
    _ = waitChild(ctx.sync.child1) catch {};
}

fn releaseInitMappings(ctx: *CreateContext) libcontainer.Error!void {
    if (ctx.sync.map_writer) |fd| {
        var mapping_response: CreateResponse = .{};
        if (!readAll(ctx.sync.report[0], std.mem.asBytes(&mapping_response))) return error.CreateFailed;
        if (mapping_response.failureError()) |err| return err;
        if (mapping_response.pid <= 0) return error.CreateFailed;
        // Child2 cannot exit/reuse its PID while child1 owns it. On
        // any early failure kill it before closing the release pipe.
        errdefer _ = linux.kill(mapping_response.pid, .KILL);
        if (ctx.options.systemd) try adoptInitSystemd(ctx, mapping_response.pid);
        if (ctx.namespaces.user_namespace) try writeInitMappings(ctx, mapping_response.pid);
        if (!writeAll(fd, &.{1})) return error.CreateFailed;
        closeFd(fd);
        ctx.sync.map_writer = null;
    }
}

fn writeInitMappings(ctx: *CreateContext, pid: i32) libcontainer.Error!void {
    try writeUserMappings(pid, ctx.namespaces.gid_map, ctx.namespaces.uid_map, .{
        .rootless = linux.geteuid() != 0,
        .newuidmap = if (ctx.options.newuidmap) |path| try pathString(ctx.allocator, path) else null,
        .newgidmap = if (ctx.options.newgidmap) |path| try pathString(ctx.allocator, path) else null,
    });
    // Init needs ownership as namespace root, even for a non-root process.
    try checkResult(linux.chown(ctx.init.fifo, ctx.namespaces.fifo_uid, ctx.namespaces.fifo_gid));
}

fn adoptInitSystemd(ctx: *CreateContext, init_pid: i32) libcontainer.Error!void {
    const device_rules = if (ctx.cgroups.cgroup_root.mode == .legacy)
        try v2DeviceRules(ctx.allocator, ctx.options.resources.devices)
    else
        &.{};
    defer ctx.allocator.free(device_rules);
    const resource_properties = try systemdProperties(ctx.allocator, ctx.options.resources, ctx.cgroups.cgroup_root.mode, device_rules);
    defer freeSystemdProperties(ctx.allocator, resource_properties);
    var properties: std.ArrayList(dbus.Property) = .empty;
    defer properties.deinit(ctx.allocator);
    const init_pids = [_]u32{@intCast(init_pid)};
    try properties.appendSlice(ctx.allocator, &.{
        .{ .name = "Description", .value = .{ .string = try std.fmt.allocPrint(ctx.allocator, "igvano container {s}", .{ctx.options.id}) } },
        .{ .name = "Slice", .value = .{ .string = ctx.options.systemd_slice } },
        .{ .name = "Delegate", .value = .{ .boolean = true } },
        .{ .name = "PIDs", .value = .{ .uint32s = &init_pids } },
        .{ .name = "DefaultDependencies", .value = .{ .boolean = false } },
        .{ .name = "MemoryAccounting", .value = .{ .boolean = true } },
        .{ .name = "CPUAccounting", .value = .{ .boolean = true } },
        .{ .name = "IOAccounting", .value = .{ .boolean = true } },
        .{ .name = "TasksAccounting", .value = .{ .boolean = true } },
    });
    if (ctx.cgroups.cgroup_root.mode == .legacy)
        try properties.append(ctx.allocator, .{ .name = "BlockIOAccounting", .value = .{ .boolean = true } });
    try properties.appendSlice(ctx.allocator, resource_properties);
    ctx.cgroups.systemd_client.start(ctx.options.systemd_unit, properties.items) catch |err| return systemdFailure(&ctx.cgroups.systemd_client, "create systemd scope", err);
    try configureCgroup(ctx.allocator, ctx.cgroups.cgroup_root.fd, ctx.cgroups.cgroup_root.mode, &ctx.cgroups.cgroup, ctx.cgroups.hierarchies, ctx.options, ctx.cgroups.cgroup_writes, ctx.cgroups.v1_writes);
    if (ctx.cgroups.cgroup_root.mode == .legacy) {
        const pid_text = try std.fmt.allocPrint(ctx.allocator, "{d}", .{init_pid});
        for (ctx.cgroups.hierarchies) |hierarchy|
            try writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", pid_text, ctx.options.cgroup_path);
    }
}

fn receiveRootfsMount(ctx: *CreateContext) libcontainer.Error!void {
    if (ctx.rootfs_mount_before) |before| {
        var mount_response: CreateResponse = .{};
        if (!readAll(ctx.sync.report[0], std.mem.asBytes(&mount_response))) return error.CreateFailed;
        if (mount_response.failureError()) |err| return err;
        if (mount_response.rootfs_mount_id == 0 or mount_response.rootfs_mount_id == before)
            return error.CreateFailed;
        ctx.rootfs_mount_id = mount_response.rootfs_mount_id;
    }
}

fn finishCreateParent(ctx: *CreateContext) libcontainer.Error!libcontainer.State {
    var response: CreateResponse = .{};
    const reported = readAll(ctx.sync.report[0], std.mem.asBytes(&response));
    var starttime_buffer: [20]u8 = undefined;
    const starttime = std.fmt.bufPrint(&starttime_buffer, "{d}", .{response.starttime}) catch unreachable;
    const handle = createHandle(ctx, response.pid, starttime);
    errdefer killReportedInit(reported, handle);
    if (!reported) return error.CreateFailed;
    try validateInitResponse(response);
    try netdev.moveNetDevices(ctx.options.net_devices, response.pid);
    if (ctx.options.on_create) |callback| try callback.run(callback.ptr, handle);
    if (!writeAll(ctx.sync.create_writer.?, &.{1})) return error.CreateFailed;
    closeFd(ctx.sync.create_writer.?);
    ctx.sync.create_writer = null;
    const initialized_response = try awaitInitializedInit(ctx);
    const owned_starttime = try ctx.options.allocator.dupe(u8, starttime);
    errdefer ctx.options.allocator.free(owned_starttime);
    return createHandle(ctx, initialized_response.pid, owned_starttime);
}

fn createHandle(ctx: *const CreateContext, pid: i32, starttime: []const u8) libcontainer.State {
    return .{
        .id = ctx.options.id,
        .pid = pid,
        .starttime = starttime,
        .cgroup_path = if (ctx.cgroups.skipped) null else ctx.options.cgroup_path,
        .systemd = ctx.options.systemd,
        .device_nodes = ctx.options.devices,
        .rootfs_mount = if (ctx.namespaces.private_mount_namespace) null else ctx.options.rootfs,
        .rootfs_mount_id = ctx.rootfs_mount_id,
        .rootfs_mount_boot_id = ctx.rootfs_mount_boot_id,
    };
}

fn killReportedInit(reported: bool, handle: libcontainer.State) void {
    if (reported and handle.pid > 0) {
        const saved_diagnostic = diagnostics.last_diagnostic;
        const saved_len = diagnostics.last_diagnostic_len;
        kill(handle, 9) catch {};
        diagnostics.last_diagnostic = saved_diagnostic;
        diagnostics.last_diagnostic_len = saved_len;
    }
}

fn validateInitResponse(response: CreateResponse) libcontainer.Error!void {
    if (response.failureError()) |err| return err;
    if (response.pid <= 0) return error.CreateFailed;
}

fn awaitInitializedInit(ctx: *CreateContext) libcontainer.Error!CreateResponse {
    var response: CreateResponse = .{};
    var initialized = readAll(ctx.sync.report[0], std.mem.asBytes(&response));
    while (initialized and response.failure == 0 and response.seccomp_fd >= 0) {
        const ack = if (ctx.sync.seccomp_ack) |fds| fds[1] else return error.CreateFailed;
        try deliverSeccompListener(response.pid, response.seccomp_fd, ack, ctx.options.on_seccomp_listener);
        response = .{};
        initialized = readAll(ctx.sync.report[0], std.mem.asBytes(&response));
    }
    ctx.sync.child1_reaped = true;
    const status = try waitChild(ctx.sync.child1);
    if (!initialized) return error.CreateFailed;
    if (response.failureError()) |err| return err;
    if (status != 0 or response.pid <= 0) {
        return error.CreateFailed;
    }
    return response;
}

const InitContext = struct {
    process: ?libcontainer.Process,
    uts: libcontainer.Uts,
    readonly_rootfs: bool,
    capabilities: ?libcontainer.Capabilities,
    rlimits: []const libcontainer.Rlimit,
    flags: usize,
    rootfs: [:0]const u8,
    mounts: []const PreparedMount,
    devices: []const PreparedDevice,
    symlinks: []const libcontainer.Symlink,
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
};

pub fn runInit(
    process: ?libcontainer.Process,
    uts: libcontainer.Uts,
    readonly_rootfs: bool,
    capabilities: ?libcontainer.Capabilities,
    rlimits: []const libcontainer.Rlimit,
    flags: usize,
    rootfs: [:0]const u8,
    mounts: []const PreparedMount,
    devices: []const PreparedDevice,
    symlinks: []const libcontainer.Symlink,
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
    const init: InitContext = .{
        .process = process,
        .uts = uts,
        .readonly_rootfs = readonly_rootfs,
        .capabilities = capabilities,
        .rlimits = rlimits,
        .flags = flags,
        .rootfs = rootfs,
        .mounts = mounts,
        .devices = devices,
        .symlinks = symlinks,
        .cwd = cwd,
        .fifo_fd = fifo_fd,
        .fd_dir = fd_dir,
        .argv = argv,
        .envp = envp,
        .ready_fd = ready_fd,
        .rootfs_options = rootfs_options,
        .start_hooks = start_hooks,
        .start_hook_state = start_hook_state,
        .apparmor_command = apparmor_command,
        .seccomp_program = seccomp_program,
    };
    runPreparedInit(&init);
}

fn runPreparedInit(init: *const InitContext) noreturn {
    // The inherited host descriptors avoid path access to the state directory
    // or /proc inside the container and are closed before or at exec.
    var fifo_buffer: [32]u8 = undefined;
    const fifo_name = std.fmt.bufPrintZ(&fifo_buffer, "{d}", .{init.fifo_fd}) catch unreachable;
    setInitHostname(init);
    setupRootfs(init.rootfs, init.mounts, init.devices, init.symlinks, init.readonly_rootfs, init.rootfs_options) catch |err| failCreate(init.ready_fd, err);
    // Like runc, a cwd only the process user may enter (e.g. a mapped
    // user's 0700 directory) is entered after setuid instead.
    const cwd_result = linux.chdir(init.cwd);
    const retry_cwd = linux.errno(cwd_result) == .ACCES;
    if (!retry_cwd) checkResult(cwd_result) catch |err| failCreate(init.ready_fd, err);
    applyAppArmor(init.apparmor_command) catch |err| failCreate(init.ready_fd, err);
    selinux.applyExecLabel(init.rootfs_options.selinux_label) catch |err| failCreate(init.ready_fd, err);
    // Like runc's ExtraFiles, preserved fds reach the process without CLOEXEC.
    const first_closed: u32 = 3 + init.rootfs_options.preserve_fds;
    for (3..first_closed) |fd| _ = linux.fcntl(@intCast(fd), linux.F.SETFD, 0);
    closeExecFrom(first_closed, init.fd_dir) catch |err| failCreate(init.ready_fd, err);
    applyInitProcess(init, fifo_name);
    if (retry_cwd) checkResult(linux.chdir(init.cwd)) catch |err| failCreate(init.ready_fd, err);
    var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = if (init.process != null)
        resolveExecutable(init.argv, init.envp, &executable_buffer) catch |err| failCreate(init.ready_fd, err)
    else
        null;
    var response: CreateResponse = .{};
    if (!writeAll(init.ready_fd, std.mem.asBytes(&response))) linux.exit_group(1);
    closeFd(init.ready_fd);
    const fd = waitInitStart(init, fifo_name);
    startInitProcess(init, executable, fd);
}

fn setInitHostname(init: *const InitContext) void {
    // Sysctls in setupRootfs may override the configured hostname.
    if (init.flags & linux.CLONE.NEWUTS != 0) {
        if (init.uts.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch |err| failCreate(init.ready_fd, err);
        }
        if (init.uts.domainname) |domainname|
            checkResult(linux.syscall2(.setdomainname, @intFromPtr(domainname.ptr), domainname.len)) catch |err| failCreate(init.ready_fd, err);
    }
}

/// Like runc: before seccomp and the credential change, with privileges.
fn applyInitScheduling(init: *const InitContext, process: libcontainer.Process) void {
    applySchedulerAndIOPriority(process.scheduler, process.io_priority, init.rootfs_options.cpuset) catch |err| failCreate(init.ready_fd, err);
    applyMemoryPolicy(process.memory_policy) catch |err| failCreate(init.ready_fd, err);
}

fn applyInitProcess(init: *const InitContext, fifo_name: [:0]const u8) void {
    if (init.process) |process| {
        // Like runc's finalizeRootfs.
        _ = linux.syscall1(.umask, process.umask orelse 0o022);
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.uid != 0)
            checkResult(linux.fchmodat(init.fd_dir, fifo_name, 0o622)) catch |err| failCreate(init.ready_fd, err);
        applyRlimits(init.rlimits) catch |err| failCreate(init.ready_fd, err);
        applyInitScheduling(init, process);
        // Without NNP the kernel requires CAP_SYS_ADMIN, which applyProcess
        // may drop. Do not change the no_new_privileges setting. With NNP,
        // the filter goes on late (see startInitProcess); start hooks still
        // run filtered, like runc.
        if (!process.no_new_privileges) {
            if (init.seccomp_program) |program|
                installSeccompFor(program, init.ready_fd, init.rootfs_options.seccomp_ack_fd, init.rootfs_options.rootless) catch |err| failCreate(init.ready_fd, err);
        }
        applyProcess(process, init.capabilities, &.{}) catch |err| {
            childError("cannot apply process settings: ", err);
            failCreate(init.ready_fd, err);
        };
        if (process.no_new_privileges) installLateListener(init);
    }
}

/// A listener must reach the runtime while create still waits, so with
/// NNP=true it is installed after the process settings, like runc: start
/// hooks then run filtered.
fn installLateListener(init: *const InitContext) void {
    const program = listenerProgram(init.seccomp_program) orelse return;
    const ack = init.rootfs_options.seccomp_ack_fd orelse failCreate(init.ready_fd, error.CreateFailed);
    installSeccompListener(program, init.ready_fd, ack, init.rootfs_options.rootless) catch |err| failCreate(init.ready_fd, err);
}

fn listenerProgram(program: ?seccomp.Program) ?seccomp.Program {
    const value = program orelse return null;
    return if (value.flags & seccomp.filter_flag_new_listener != 0) value else null;
}

/// runc's Go init has a handler for every signal, so a terminating signal
/// from the host (kill SIGTERM, or one sent through a --pidfd-socket pidfd)
/// ends a created container. A PID namespace init without a handler would
/// drop it. execve resets these handlers to the default.
fn exitOnSignal(signal: linux.SIG) callconv(.c) void {
    linux.exit_group(128 + @as(u8, @intCast(@intFromEnum(signal))));
}

fn catchTerminatingSignals() void {
    const action: linux.Sigaction = .{ .handler = .{ .handler = exitOnSignal }, .mask = linux.sigemptyset(), .flags = 0 };
    // Asynchronous signals whose default ends the process. SIGPIPE stays
    // as is, so a failed pipe write still returns EPIPE here.
    for ([_]linux.SIG{ .HUP, .INT, .QUIT, .ABRT, .USR1, .USR2, .ALRM, .TERM, .STKFLT, .XCPU, .XFSZ, .VTALRM, .PROF, .IO, .PWR, .SYS }) |signal|
        _ = linux.sigaction(signal, &action, null);
}

fn waitInitStart(init: *const InitContext, fifo_name: [:0]const u8) posix.fd_t {
    catchTerminatingSignals();
    // O_WRONLY blocks until start opens a reader; the byte acknowledges that start.
    const fd: posix.fd_t = open: while (true) {
        const result = linux.openat(init.fd_dir, fifo_name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => linux.exit_group(1),
        }
    };
    closeFd(init.fd_dir);
    closeFd(init.fifo_fd);
    return fd;
}

fn startInitProcess(init: *const InitContext, executable: ?[*:0]const u8, fd: posix.fd_t) noreturn {
    // Opening the writer unblocks start. Like runc, acknowledge before the
    // startContainer hooks: a failing hook only stops init, with the error on
    // its stderr. The CLOEXEC writer makes EOF confirm exec or that exit.
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    // A notify filter was already installed during create; without NNP the
    // filter is already on too.
    const nnp = if (init.process) |process| process.no_new_privileges else false;
    var late_program = if (nnp and listenerProgram(init.seccomp_program) == null) init.seccomp_program else null;
    // Like runc, startContainer hooks run with the container's filter.
    if (late_program != null and init.start_hooks.len != 0) {
        installSeccomp(late_program.?) catch |err| {
            childError("cannot install seccomp filter: ", err);
            diagnostics.printDiagnostic();
            linux.exit_group(1);
        };
        late_program = null;
    }
    hooks.runWithCloexecFds(init.start_hooks, init.start_hook_state, "startContainer") catch {
        diagnostics.printDiagnostic();
        linux.exit_group(1);
    };
    runProcess(init.process, executable, init.argv, init.envp, late_program) catch |err| {
        if (err != error.ExecFailed) childError("cannot execute process: ", err);
        startFailed(fd);
    };
}

/// A 0 byte, then the diagnostic, in one write below PIPE_BUF, so start can
/// report why the process could not be executed.
fn startFailed(fd: posix.fd_t) noreturn {
    var buffer: [1 + diagnostics.last_diagnostic.len]u8 = undefined;
    buffer[0] = 0;
    const len = diagnostics.last_diagnostic_len;
    @memcpy(buffer[1..][0..len], diagnostics.last_diagnostic[0..len]);
    _ = writeAll(fd, buffer[0 .. 1 + len]);
    linux.exit_group(1);
}

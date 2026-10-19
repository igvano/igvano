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

const CgroupRoot = @typeInfo(@TypeOf(openCgroupRoot())).error_union.payload;

const CreateNamespaces = struct {
    flags: usize = undefined,
    isolation_flags: usize = undefined,
    private_mount_namespace: bool = undefined,
    user_namespace: bool = undefined,
    joined_user_namespace: bool = undefined,
    joins: std.ArrayList(NamespaceJoin) = .empty,
    uid_mappings: []const oci.Spec.IDMapping = undefined,
    gid_mappings: []const oci.Spec.IDMapping = undefined,
    container_mappings: Backend.MountMappings = .{},
    uid_ranges: []Backend.IDMapping = undefined,
    gid_ranges: []Backend.IDMapping = undefined,
    joined_user_fd: ?posix.fd_t = null,
    joined_user_path: ?[]const u8 = null,
    fifo_uid: u32 = undefined,
    fifo_gid: u32 = undefined,
    uid_map: []const u8 = undefined,
    gid_map: []const u8 = undefined,
};

const CreateInit = struct {
    capabilities: ?Backend.Capabilities = undefined,
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
};

const CreateCgroups = struct {
    cgroup_root: CgroupRoot = undefined,
    systemd_client: dbus.Client = undefined,
    hierarchies: []V1Hierarchy = undefined,
    cgroup_writes: []const Write = undefined,
    v1_writes: []const V1Write = undefined,
    ignored_fields: []const u8 = undefined,
    cgroup: ?posix.fd_t = null,
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
    map_writer: ?posix.fd_t = null,
    child1_reaped: bool = false,
};

const CreateContext = struct {
    ptr: *anyopaque,
    options: Backend.CreateOptions,
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

pub fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        var context: CreateContext = .{ .ptr = ptr, .options = options, .allocator = options.allocator };
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

fn validateCreate(ctx: *CreateContext) Backend.Error!void {
    ctx.namespaces.flags = try namespaceFlags(ctx.options.spec.linux);
    ctx.namespaces.isolation_flags = ctx.namespaces.flags;
    for (if (ctx.options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace|
        ctx.namespaces.isolation_flags |= namespaceFlag(namespace.type);
    ctx.namespaces.private_mount_namespace = ctx.namespaces.isolation_flags & linux.CLONE.NEWNS != 0;
    if (!ctx.namespaces.private_mount_namespace and ctx.options.rootfs_propagation != null) {
        reportDiagnostic("cannot change propagation without a private mount namespace", .{});
        return error.InvalidConfig;
    }
    if (ctx.options.spec.hostname != null and ctx.namespaces.isolation_flags & linux.CLONE.NEWUTS == 0)
        return error.InvalidConfig;
    try validateCreateProcess(ctx);
    try validateDeviceMounts(ctx.options.mounts, ctx.options.devices);
    if (!std.fs.path.isAbsolute(ctx.options.exec_fifo) or
        std.mem.indexOfScalar(u8, ctx.options.exec_fifo, 0) != null)
        return error.InvalidPath;
}

fn validateCreateProcess(ctx: *CreateContext) Backend.Error!void {
    if (ctx.options.spec.process) |process| {
        if (process.args.len == 0) return error.InvalidProcess;
    }
    const terminal = if (ctx.options.spec.process) |process| process.terminal orelse false else false;
    if (terminal != (ctx.options.console_fds != null)) return error.InvalidConfig;
    if (ctx.options.capabilities) |caps| {
        if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
            return error.AmbientCapabilitiesRequirePermittedAndInheritable;
    }
    ctx.init.capabilities = if (ctx.options.capabilities) |caps| try kernelCapabilities(caps) else null;
    for (ctx.options.rlimits) |limit| {
        if (limit.soft > limit.hard) return error.InvalidConfig;
    }
}

fn prepareCreate(ctx: *CreateContext) Backend.Error!Backend.Handle {
    ctx.init.apparmor_command = try prepareAppArmor(ctx.allocator, ctx.options.apparmor_profile);
    ctx.init.seccomp_program = if (ctx.options.seccomp) |config|
        seccomp.compile(ctx.allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
            return error.InvalidConfig;
        }
    else
        null;
    ctx.namespaces.joins = .empty;
    for (if (ctx.options.spec.linux) |settings| settings.namespaces orelse &.{} else &.{}) |namespace| {
        if (namespace.path) |path| try ctx.namespaces.joins.append(ctx.allocator, .{
            .flag = namespaceFlag(namespace.type),
            .path = try pathString(ctx.allocator, path),
        });
    }
    try validateMountNamespaceJoins(ctx);
    try prepareCreateMappings(ctx);
    return prepareJoinedUserNamespace(ctx);
}

fn validateMountNamespaceJoins(ctx: *const CreateContext) Backend.Error!void {
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

fn prepareCreateMappings(ctx: *CreateContext) Backend.Error!void {
    ctx.namespaces.user_namespace = ctx.namespaces.flags & linux.CLONE.NEWUSER != 0;
    ctx.namespaces.joined_user_namespace = !ctx.namespaces.user_namespace and ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0;
    // Library callers bypass frontend validation, so mapping-presence checks are intentional.
    ctx.namespaces.uid_mappings = if (ctx.options.spec.linux) |settings| settings.uidMappings orelse &.{} else &.{};
    ctx.namespaces.gid_mappings = if (ctx.options.spec.linux) |settings| settings.gidMappings orelse &.{} else &.{};
    if (ctx.namespaces.user_namespace and (ctx.namespaces.uid_mappings.len == 0 or ctx.namespaces.gid_mappings.len == 0)) return error.InvalidConfig;
    ctx.namespaces.container_mappings = .{};
    ctx.namespaces.uid_ranges = try ctx.allocator.alloc(Backend.IDMapping, ctx.namespaces.uid_mappings.len);
    for (ctx.namespaces.uid_mappings, ctx.namespaces.uid_ranges) |mapping, *range| range.* = .{
        .container_id = mapping.containerID,
        .host_id = mapping.hostID,
        .size = mapping.size,
    };
    ctx.namespaces.gid_ranges = try ctx.allocator.alloc(Backend.IDMapping, ctx.namespaces.gid_mappings.len);
    for (ctx.namespaces.gid_mappings, ctx.namespaces.gid_ranges) |mapping, *range| range.* = .{
        .container_id = mapping.containerID,
        .host_id = mapping.hostID,
        .size = mapping.size,
    };
    ctx.namespaces.container_mappings = .{ .uid = ctx.namespaces.uid_ranges, .gid = ctx.namespaces.gid_ranges };
}

fn prepareJoinedUserNamespace(ctx: *CreateContext) Backend.Error!Backend.Handle {
    // Pin the validated namespace and use that same descriptor in init.
    ctx.namespaces.joined_user_fd = null;
    ctx.namespaces.joined_user_path = null;
    defer if (ctx.namespaces.joined_user_fd) |fd| closeFd(fd);
    if (ctx.namespaces.joined_user_namespace) {
        for (ctx.namespaces.joins.items) |join| {
            if (join.flag != linux.CLONE.NEWUSER) continue;
            const fd = try openPath(linux.AT.FDCWD, join.path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
            ctx.namespaces.joined_user_fd = fd;
            ctx.namespaces.joined_user_path = join.path;
            try validateNamespaceFd(fd, linux.CLONE.NEWUSER);
            ctx.namespaces.container_mappings = try joinedUserNamespaceMappings(ctx.allocator, fd);
            try validateJoinedMappings(ctx.allocator, ctx.namespaces.container_mappings, .{ .uid = ctx.namespaces.uid_ranges, .gid = ctx.namespaces.gid_ranges });
            break;
        }
    }
    try prepareCreatePaths(ctx);
    return prepareCreateCgroups(ctx);
}

fn prepareCreatePaths(ctx: *CreateContext) Backend.Error!void {
    ctx.namespaces.fifo_uid = if (ctx.namespaces.user_namespace or ctx.namespaces.joined_user_namespace) try mappedRootID(ctx.namespaces.container_mappings.uid) else 0;
    ctx.namespaces.fifo_gid = if (ctx.namespaces.user_namespace or ctx.namespaces.joined_user_namespace) try mappedRootID(ctx.namespaces.container_mappings.gid) else 0;
    ctx.namespaces.uid_map = try formatIDMappings(ctx.allocator, ctx.namespaces.uid_mappings);
    ctx.namespaces.gid_map = try formatIDMappings(ctx.allocator, ctx.namespaces.gid_mappings);
    ctx.init.fifo = try ctx.allocator.dupeZ(u8, ctx.options.exec_fifo);
    ctx.init.rootfs = try processString(ctx.allocator, ctx.options.rootfs);
    ctx.init.cwd = try processString(ctx.allocator, if (ctx.options.spec.process) |process| process.cwd else "/");
    if (!std.fs.path.isAbsolute(ctx.init.cwd)) return error.InvalidProcess;
    if (!std.fs.path.isAbsolute(ctx.init.rootfs)) return error.InvalidPath;
    try probeInheritedRootfs(ctx);
}

fn probeInheritedRootfs(ctx: *CreateContext) Backend.Error!void {
    ctx.rootfs_mount_before = null;
    ctx.rootfs_mount_boot_id = null;
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

fn prepareCreateCgroups(ctx: *CreateContext) Backend.Error!Backend.Handle {
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

fn connectCreateSystemd(ctx: *CreateContext) Backend.Error!void {
    if (ctx.options.systemd) {
        if (!std.mem.eql(u8, ctx.options.systemd_unit, std.fs.path.basename(ctx.options.cgroup_path)) or
            !std.mem.endsWith(u8, ctx.options.systemd_unit, ".scope") or
            !std.mem.endsWith(u8, ctx.options.systemd_slice, ".slice") or
            std.mem.indexOfAny(u8, ctx.options.systemd_slice, "/\x00") != null)
            return error.InvalidConfig;
        ctx.cgroups.systemd_client.connect() catch |err| return systemdFailure(&ctx.cgroups.systemd_client, "create systemd scope", err);
    }
}

fn prepareCreateMounts(ctx: *CreateContext) Backend.Error!Backend.Handle {
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

fn prepareCreateDevices(ctx: *CreateContext) Backend.Error!void {
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

fn prepareCreateProcess(ctx: *CreateContext) Backend.Error!void {
    const args: []const []const u8 = if (ctx.options.spec.process) |process| process.args else &.{};
    const env: []const []const u8 = if (ctx.options.spec.process) |process| process.env orelse &.{} else &.{};
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

fn prepareCreateResources(ctx: *CreateContext) Backend.Error!Backend.Handle {
    ctx.cgroups.cgroup_writes = if (ctx.cgroups.cgroup_root.mode == .unified) try v2Writes(ctx.allocator, ctx.options.resources) else &.{};
    defer if (ctx.cgroups.cgroup_root.mode == .unified) freeWrites(ctx.allocator, ctx.cgroups.cgroup_writes);
    if (ctx.cgroups.cgroup_root.mode == .legacy and ctx.options.resources.unified.len != 0) {
        reportDiagnostic("unified resources require cgroup v2", .{});
        return error.InvalidConfig;
    }
    ctx.cgroups.v1_writes = if (ctx.cgroups.cgroup_root.mode == .legacy) try v1Writes(ctx.allocator, ctx.options.resources) else &.{};
    defer if (ctx.cgroups.cgroup_root.mode == .legacy) freeV1Writes(ctx.allocator, ctx.cgroups.v1_writes);
    ctx.cgroups.ignored_fields = if (ctx.cgroups.cgroup_root.mode == .unified) try v2IgnoredFields(ctx.allocator, ctx.options.resources) else try ctx.allocator.dupe(u8, "");
    defer ctx.allocator.free(ctx.cgroups.ignored_fields);
    if (ctx.cgroups.ignored_fields.len != 0)
        std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ctx.cgroups.ignored_fields});
    return createWithHostDescriptors(ctx);
}

fn createWithHostDescriptors(ctx: *CreateContext) Backend.Error!Backend.Handle {
    // pivot_root also changes child1's root while it waits in the same
    // mount namespace. Pin host /proc so it can still capture identity.
    ctx.proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(ctx.proc_dir);
    // Init must retain the host FIFO across namespace changes without
    // traversing the private state directory as a mapped user.
    ctx.fifo_fd = try openPath(linux.AT.FDCWD, ctx.init.fifo, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
    defer closeFd(ctx.fifo_fd);
    ctx.cgroups.cgroup = null;
    defer if (ctx.cgroups.cgroup) |fd| closeFd(fd);
    ctx.rootfs_mount_id = null;
    errdefer cleanupFailedCreate(ctx);
    // fs cgroups are ready before fork; systemd adopts init at the
    // early mapping exchange, while init is blocked before rootfs work.
    if (!ctx.options.systemd)
        try configureCgroup(ctx.allocator, ctx.cgroups.cgroup_root.fd, ctx.cgroups.cgroup_root.mode, &ctx.cgroups.cgroup, ctx.cgroups.hierarchies, ctx.options, ctx.cgroups.cgroup_writes, ctx.cgroups.v1_writes);
    return createWithMountSources(ctx);
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

fn createWithMountSources(ctx: *CreateContext) Backend.Error!Backend.Handle {
    var needs_mount_sources = false;
    for (ctx.init.mounts) |mount| {
        if (mount.flags & linux.MS.BIND != 0 and
            (ctx.namespaces.isolation_flags & linux.CLONE.NEWUSER != 0 or mount.mappings != null))
        {
            needs_mount_sources = true;
            break;
        }
    }
    const mount_source_helper = if (needs_mount_sources) try startMountSourceHelper(ctx.init.mounts) else null;
    ctx.mount_source_socket = if (mount_source_helper) |helper| helper.socket else null;
    defer if (mount_source_helper) |helper| {
        if (ctx.mount_source_socket) |fd| closeFd(fd);
        _ = waitChild(helper.pid) catch {};
    };
    return forkCreate(ctx);
}

fn forkCreate(ctx: *CreateContext) Backend.Error!Backend.Handle {
    // getpid() in child2 may be 1. Child1 supplies its host PID for
    // opaque hook input; buffers and JSON fragments were prepared above.
    ctx.sync.pid_pipe = try makePipe();
    ctx.sync.owns_pid_pipe = true;
    defer if (ctx.sync.owns_pid_pipe) {
        for (ctx.sync.pid_pipe) |fd| closeFd(fd);
    };
    try prepareCreatePipes(ctx);
    ctx.sync.owns_create_go = true;
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
    return awaitCreateParent(ctx);
}

fn prepareCreatePipes(ctx: *CreateContext) Backend.Error!void {
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

fn runCreateChild(ctx: *const CreateContext) noreturn {
    checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(ctx.sync.report[1], err);
    if (ctx.options.console_fds) |fds| closeFd(fds[0]);
    if (ctx.options.systemd) closeFd(ctx.cgroups.systemd_client.fd);
    closeFd(ctx.sync.create_go[1]);
    if (ctx.sync.map_pipe) |fds| closeFd(fds[1]);
    closeFd(ctx.cgroups.cgroup_root.fd);
    closeFd(ctx.sync.report[0]);
    joinCreateCgroups(ctx);
    // Set with host privileges before entering user namespaces.
    // Child2 inherits the adjustment across fork and exec.
    applyOomScoreAdj(ctx.proc_dir, ctx.options.oom_score_adj) catch |err| failCreate(ctx.sync.report[1], err);
    joinNamespacesWithUser(ctx.namespaces.joins.items, ctx.namespaces.joined_user_fd) catch |err| failCreate(ctx.sync.report[1], err);
    // NEWUSER is unshared together with the others so it owns them.
    const early_flags = if (ctx.options.systemd) ctx.namespaces.flags & ~@as(usize, linux.CLONE.NEWCGROUP) else ctx.namespaces.flags;
    if (early_flags != 0) checkResult(linux.unshare(early_flags)) catch |err| failCreate(ctx.sync.report[1], err);
    // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
    const child2 = forkProcess() catch |err| failCreate(ctx.sync.report[1], err);
    if (child2 == 0) runInitChild(ctx);
    reportCreatedInit(ctx, child2);
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

fn runInitChild(ctx: *const CreateContext) noreturn {
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
        const namespace = openPath(ctx.proc_dir, "self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch |err| failCreate(ctx.sync.ready[1], err);
        receiveMountSources(ctx.init.mounts, socket, namespace) catch |err| failCreate(ctx.sync.ready[1], err);
        closeFd(namespace);
        closeFd(socket);
    }
    closeFd(ctx.proc_dir);
    const create_input = std.fmt.bufPrint(ctx.init.create_state, "{s}{d}{s}", .{
        ctx.options.create_hook_state.prefix, host_pid, ctx.options.create_hook_state.suffix,
    }) catch linux.exit_group(1);
    const start_input = std.fmt.bufPrint(ctx.init.start_state, "{s}{d}{s}", .{
        ctx.options.start_hook_state.prefix, host_pid, ctx.options.start_hook_state.suffix,
    }) catch linux.exit_group(1);
    runInit(ctx.options.spec, ctx.init.capabilities, ctx.options.rlimits, ctx.namespaces.isolation_flags, ctx.init.rootfs, ctx.init.mounts, ctx.init.devices, ctx.options.device_symlinks, ctx.init.cwd, ctx.fifo_fd, fd_dir, ctx.init.argv.ptr, ctx.init.envp.ptr, ctx.sync.ready[1], .{
        .private_mount_namespace = ctx.namespaces.private_mount_namespace,
        .propagation = ctx.options.rootfs_propagation orelse (linux.MS.PRIVATE | linux.MS.REC),
        .create_hooks = ctx.init.create_hooks,
        .create_hook_state = create_input,
        .masked_paths = ctx.init.masked_paths,
        .readonly_paths = ctx.init.readonly_paths,
        .sysctls = ctx.options.sysctls,
        .runtime_sync = .{ .ready_fd = ctx.sync.ready[1], .go_fd = ctx.sync.create_go[0] },
        .console_fd = if (ctx.options.console_fds) |fds| fds[1] else null,
    }, ctx.init.start_hooks, start_input, ctx.init.apparmor_command, ctx.init.seccomp_program);
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
    const initialized = readAll(ctx.sync.ready[0], std.mem.asBytes(&init_response));
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

fn awaitCreateParent(ctx: *CreateContext) Backend.Error!Backend.Handle {
    if (ctx.mount_source_socket) |fd| closeFd(fd);
    ctx.mount_source_socket = null;
    // Only child1 writes the PID. Keeping a writer in this parent
    // would strand child2 if child1 died before sending it, preventing
    // report EOF and hanging create.
    for (ctx.sync.pid_pipe) |fd| closeFd(fd);
    ctx.sync.owns_pid_pipe = false;
    closeFd(ctx.sync.report[1]);
    for (ctx.sync.ready) |fd| closeFd(fd);
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
    ctx.sync.child1_reaped = false;
    errdefer if (!ctx.sync.child1_reaped) reapFailedCreateChild(ctx);
    try releaseInitMappings(ctx);
    try receiveRootfsMount(ctx);
    return finishCreateParent(ctx);
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

fn releaseInitMappings(ctx: *CreateContext) Backend.Error!void {
    if (ctx.sync.map_writer) |fd| {
        var mapping_response: CreateResponse = .{};
        if (!readAll(ctx.sync.report[0], std.mem.asBytes(&mapping_response))) return error.CreateFailed;
        if (mapping_response.failureError()) |err| return err;
        if (mapping_response.pid <= 0) return error.CreateFailed;
        // Child2 cannot exit/reuse its PID while child1 owns it. On
        // any early failure kill it before closing the release pipe.
        errdefer _ = linux.kill(mapping_response.pid, .KILL);
        if (ctx.options.systemd) try adoptInitSystemd(ctx, mapping_response.pid);
        if (ctx.namespaces.user_namespace) {
            try writeUserMappings(mapping_response.pid, ctx.namespaces.gid_map, ctx.namespaces.uid_map);
            // Init needs ownership as namespace root, even for a non-root process.
            try checkResult(linux.chown(ctx.init.fifo, ctx.namespaces.fifo_uid, ctx.namespaces.fifo_gid));
        }
        if (!writeAll(fd, &.{1})) return error.CreateFailed;
        closeFd(fd);
        ctx.sync.map_writer = null;
    }
}

fn adoptInitSystemd(ctx: *CreateContext, init_pid: i32) Backend.Error!void {
    const device_rules = if (ctx.cgroups.cgroup_root.mode == .legacy)
        try v2DeviceRules(ctx.allocator, ctx.options.resources.devices, ctx.options.devices)
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

fn receiveRootfsMount(ctx: *CreateContext) Backend.Error!void {
    if (ctx.rootfs_mount_before) |before| {
        var mount_response: CreateResponse = .{};
        if (!readAll(ctx.sync.report[0], std.mem.asBytes(&mount_response))) return error.CreateFailed;
        if (mount_response.failureError()) |err| return err;
        if (mount_response.rootfs_mount_id == 0 or mount_response.rootfs_mount_id == before)
            return error.CreateFailed;
        ctx.rootfs_mount_id = mount_response.rootfs_mount_id;
    }
}

fn finishCreateParent(ctx: *CreateContext) Backend.Error!Backend.Handle {
    var response: CreateResponse = .{};
    const reported = readAll(ctx.sync.report[0], std.mem.asBytes(&response));
    var starttime_buffer: [20]u8 = undefined;
    const starttime = std.fmt.bufPrint(&starttime_buffer, "{d}", .{response.starttime}) catch unreachable;
    const handle = createHandle(ctx, response.pid, starttime);
    errdefer killReportedInit(ctx, reported, handle);
    if (!reported) return error.CreateFailed;
    try validateInitResponse(response);
    if (ctx.options.on_create) |callback| try callback.run(callback.ptr, handle);
    if (!writeAll(ctx.sync.create_writer.?, &.{1})) return error.CreateFailed;
    closeFd(ctx.sync.create_writer.?);
    ctx.sync.create_writer = null;
    const initialized_response = try awaitInitializedInit(ctx);
    const owned_starttime = try ctx.options.allocator.dupe(u8, starttime);
    errdefer ctx.options.allocator.free(owned_starttime);
    return createHandle(ctx, initialized_response.pid, owned_starttime);
}

fn createHandle(ctx: *const CreateContext, pid: i32, starttime: []const u8) Backend.Handle {
    return .{
        .id = ctx.options.id,
        .pid = pid,
        .starttime = starttime,
        .cgroup_path = ctx.options.cgroup_path,
        .systemd = ctx.options.systemd,
        .device_nodes = ctx.options.devices,
        .rootfs_mount = if (ctx.namespaces.private_mount_namespace) null else ctx.options.rootfs,
        .rootfs_mount_id = ctx.rootfs_mount_id,
        .rootfs_mount_boot_id = ctx.rootfs_mount_boot_id,
    };
}

fn killReportedInit(ctx: *const CreateContext, reported: bool, handle: Backend.Handle) void {
    if (reported and handle.pid > 0) {
        const saved_diagnostic = diagnostics.last_diagnostic;
        const saved_len = diagnostics.last_diagnostic_len;
        kill(ctx.ptr, handle, 9) catch {};
        diagnostics.last_diagnostic = saved_diagnostic;
        diagnostics.last_diagnostic_len = saved_len;
    }
}

fn validateInitResponse(response: CreateResponse) Backend.Error!void {
    if (response.failureError()) |err| return err;
    if (response.pid <= 0) return error.CreateFailed;
}

fn awaitInitializedInit(ctx: *CreateContext) Backend.Error!CreateResponse {
    var response: CreateResponse = .{};
    const initialized = readAll(ctx.sync.report[0], std.mem.asBytes(&response));
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
};

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
    const init: InitContext = .{
        .spec = spec,
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
    setupRootfs(init.rootfs, init.mounts, init.devices, init.symlinks, init.spec.root.readonly, init.rootfs_options) catch |err| failCreate(init.ready_fd, err);
    checkResult(linux.chdir(init.cwd)) catch |err| failCreate(init.ready_fd, err);
    applyAppArmor(init.apparmor_command) catch |err| failCreate(init.ready_fd, err);
    closeExecFrom(3, init.fd_dir) catch |err| failCreate(init.ready_fd, err);
    applyInitProcess(init, fifo_name);
    var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = if (init.spec.process != null)
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
        if (init.spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch |err| failCreate(init.ready_fd, err);
        }
    }
}

fn applyInitProcess(init: *const InitContext, fifo_name: [:0]const u8) void {
    if (init.spec.process) |process| {
        // Allow write-only reopen after setuid while keeping readers root-only.
        if (process.user.uid != 0)
            checkResult(linux.fchmodat(init.fd_dir, fifo_name, 0o622)) catch |err| failCreate(init.ready_fd, err);
        applyRlimits(init.rlimits) catch |err| failCreate(init.ready_fd, err);
        // Without NNP the kernel requires CAP_SYS_ADMIN, which applyProcess
        // may drop. Do not change the OCI noNewPrivileges setting.
        // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
        if (!process.noNewPrivileges) {
            if (init.seccomp_program) |program|
                installSeccomp(program) catch |err| failCreate(init.ready_fd, err);
        }
        applyProcess(process, init.capabilities, &.{}) catch |err| {
            childError("cannot apply process settings: ", err);
            failCreate(init.ready_fd, err);
        };
    }
}

fn waitInitStart(init: *const InitContext, fifo_name: [:0]const u8) posix.fd_t {
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
    // Opening the writer unblocks start. Acknowledge after hooks pass, then
    // retain the CLOEXEC writer so EOF confirms exec before start succeeds.
    hooks.runWithCloexecFds(init.start_hooks, init.start_hook_state) catch {
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    runProcess(init.spec, executable, init.argv, init.envp, init.seccomp_program) catch |err| {
        if (err != error.ExecFailed) childError("cannot execute process: ", err);
        _ = writeAll(fd, &.{0});
        linux.exit_group(1);
    };
}

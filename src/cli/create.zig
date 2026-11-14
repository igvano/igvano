const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const diagnostics = @import("diagnostic.zig");
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const ContainerInstance = @import("state.zig").ContainerInstance;
const createInstance = @import("state.zig").createInstance;
const createDiagnostic = @import("state.zig").createDiagnostic;
const Config = @import("args.zig").Config;
const prepareProcess = @import("process.zig").prepareProcess;
const processEnv = @import("process.zig").processEnv;
const validateConsoleSocket = @import("process.zig").validateConsoleSocket;
const connectConsoleSocket = @import("process.zig").connectConsoleSocket;
const writePidFile = @import("process.zig").writePidFile;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const deleteStateDirectory = @import("state.zig").deleteStateDirectory;
const saveRootfsMount = @import("state.zig").saveRootfsMount;
const requireUnusedRootfs = @import("state.zig").requireUnusedRootfs;
const hookStateTemplate = @import("hooks.zig").hookStateTemplate;
const runHooks = @import("hooks.zig").runHooks;
const SeccompAgent = @import("seccomp_agent.zig").Agent;
const warnHooks = @import("hooks.zig").warnHooks;

pub fn createContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    _ = try createContainerFor(allocator, io, injected, config, null);
}

/// Returns the init's host PID. With `local_console` (run in the foreground),
/// a terminal=true process without --console-socket gets a PTY whose
/// controller is stored there instead of sent to a socket.
pub fn createContainerFor(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, local_console: ?*?std.posix.fd_t) !i32 {
    const cwd = std.Io.Dir.cwd();
    const bundle = try cwd.realPathFileAlloc(io, config.bundle orelse ".", allocator);
    defer allocator.free(bundle);
    const parsed = try oci.loadSpec(allocator, io, bundle);
    defer parsed.deinit();
    try oci.requireCreate(parsed.value);
    const has_console = createHasConsole(parsed.value, config, local_console != null);
    const process_options = try prepareCreateProcess(allocator, parsed.value.process, has_console);
    defer if (process_options) |options| allocator.free(options.rlimits);
    const console_fds = if (has_console) try libcontainer.linux.console.socketpair() else null;
    defer closeConsoleFds(console_fds);
    const rootfs = try oci.resolveRootfs(allocator, bundle, parsed.value.root.path);
    defer allocator.free(rootfs);
    var mount_arena: std.heap.ArenaAllocator = .init(allocator);
    defer mount_arena.deinit();
    const mount_allocator = mount_arena.allocator();
    const settings: oci.Spec.Linux = parsed.value.linux orelse .{};
    const mounts = try prepareCreateMounts(mount_allocator, bundle, rootfs, parsed.value.mounts, settings);
    const seccomp_config = try oci.prepareSeccomp(allocator, settings.seccomp);
    defer oci.freeSeccomp(allocator, seccomp_config);
    const sysctls = try oci.prepareSysctls(mount_allocator, settings);
    const configured_hooks: oci.Spec.Hooks = parsed.value.hooks orelse .{};
    const create_hooks = try oci.prepareHooks(mount_allocator, configured_hooks.createContainer);
    const init_env = try initEnv(mount_allocator, parsed.value.process, rootfs);
    const start_hooks = try startHooks(mount_allocator, configured_hooks.startContainer, init_env);
    const masked_paths = try prepareRestrictionPaths(mount_allocator, settings.maskedPaths);
    const readonly_paths = try prepareRestrictionPaths(mount_allocator, settings.readonlyPaths);
    const devices = try oci.prepareDevices(allocator, settings.devices);
    defer oci.freeDevices(allocator, devices);
    const systemd_config = if (config.systemd) try oci.parseSystemdCgroupPath(allocator, settings.cgroupsPath, config.id) else null;
    defer if (systemd_config) |value| value.deinit(allocator);
    const cgroup_path = if (systemd_config) |value| try allocator.dupe(u8, value.path) else try oci.resolveCgroupPath(allocator, settings.cgroupsPath, config.id);
    defer allocator.free(cgroup_path);
    const resources = try oci.cgroupResources(allocator, settings.resources);
    defer oci.freeCgroupResources(allocator, resources);
    var options: libcontainer.CreateOptions = .{
        .allocator = allocator,
        .id = config.id,
        .rootfs = rootfs,
        .exec_fifo = "",
        .console_fds = console_fds,
        .mounts = mounts,
        .cgroup_path = cgroup_path,
        .cgroup_path_default = settings.cgroupsPath == null,
        .rootless_cgroups = rootlessCgroups(),
        .newuidmap = try mappingTool(mount_allocator, io, config.path_env, "newuidmap"),
        .newgidmap = try mappingTool(mount_allocator, io, config.path_env, "newgidmap"),
        .systemd = config.systemd,
        .systemd_slice = if (systemd_config) |value| value.slice else "system.slice",
        .systemd_unit = if (systemd_config) |value| value.unit else "",
        .resources = resources,
        .devices = devices,
        .device_symlinks = oci.deviceSymlinks(mounts),
        .create_hooks = create_hooks,
        .start_hooks = start_hooks,
        .masked_paths = masked_paths,
        .readonly_paths = readonly_paths,
        .sysctls = sysctls,
        .rootfs_propagation = if (settings.rootfsPropagation) |mode| oci.rootfsPropagation(mode) else null,
        .seccomp = seccomp_config,
        .debug = config.debug_log,
    };
    try applyCreateSpec(mount_allocator, &options, parsed.value);
    applyCreateProcess(&options, process_options, init_env);
    return createPreparedContainer(allocator, mount_allocator, io, injected, config, bundle, parsed.value, options, local_console);
}

/// Like runc, a non-root runtime looks the tools up on PATH before create.
/// The caller's arena owns the result.
fn mappingTool(allocator: std.mem.Allocator, io: std.Io, path_env: ?[]const u8, name: []const u8) !?[]const u8 {
    if (comptime builtin.os.tag != .linux) return null;
    if (std.os.linux.geteuid() == 0) return null;
    const path = path_env orelse return null;
    var dirs = std.mem.tokenizeScalar(u8, path, ':');
    while (dirs.next()) |dir| {
        if (!std.fs.path.isAbsolute(dir)) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, name });
        std.Io.Dir.cwd().access(io, candidate, .{ .execute = true }) catch continue;
        return candidate;
    }
    return null;
}

/// runc's shouldUseRootlessCgroupManager for cgroupfs: a non-root user, or
/// root inside a user namespace, may lack permission for cgroups.
fn rootlessCgroups() bool {
    if (comptime builtin.os.tag != .linux) return false;
    if (std.os.linux.geteuid() != 0) return true;
    // The initial user namespace maps every ID: "0 0 4294967295".
    var buffer: [128]u8 = undefined;
    const fd = std.posix.openat(std.posix.AT.FDCWD, "/proc/self/uid_map", .{ .CLOEXEC = true }, 0) catch return false;
    defer _ = std.os.linux.close(fd);
    const count = std.posix.read(fd, &buffer) catch return false;
    var fields = std.mem.tokenizeAny(u8, buffer[0..count], " \n");
    const expected = [_][]const u8{ "0", "0", "4294967295" };
    for (expected) |field| if (!std.mem.eql(u8, fields.next() orelse "", field)) return true;
    return fields.next() != null;
}

fn initEnv(allocator: std.mem.Allocator, process: ?oci.Spec.Process, rootfs: []const u8) !?[]const []const u8 {
    const value = process orelse return null;
    const env = value.env orelse return null;
    return try processEnv(allocator, env, rootfs, value.user.uid);
}

/// Like runc, a startContainer hook without env inherits the process env.
fn startHooks(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Hook, init_env: ?[]const []const u8) ![]libcontainer.Hook {
    const hooks = try oci.prepareHooks(allocator, configured);
    for (hooks, configured orelse &.{}) |*hook, entry| {
        if (entry.env == null) hook.env = init_env orelse &.{};
    }
    return hooks;
}

fn createHasConsole(spec: oci.Spec, config: Config, local: bool) bool {
    if (config.console_socket != null) return true;
    const process = spec.process orelse return false;
    return local and (process.terminal orelse false);
}

fn prepareCreateProcess(allocator: std.mem.Allocator, process: ?oci.Spec.Process, console_socket: bool) !?libcontainer.ExecOptions {
    return if (process) |value|
        try prepareProcess(allocator, value, console_socket)
    else options: {
        try validateConsoleSocket(null, console_socket);
        break :options @as(?libcontainer.ExecOptions, null);
    };
}

fn closeConsoleFds(console_fds: ?[2]std.posix.fd_t) void {
    if (console_fds) |fds| for (fds) |fd| {
        _ = std.os.linux.close(fd);
    };
}

fn prepareCreateNamespaces(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Namespace) ![]libcontainer.Namespace {
    const namespaces = configured orelse &.{};
    const result = try allocator.alloc(libcontainer.Namespace, namespaces.len);
    for (namespaces, result) |namespace, *prepared| prepared.* = .{
        .kind = namespaceKind(namespace.type),
        .path = namespace.path,
    };
    return result;
}

fn namespaceKind(kind: @FieldType(oci.Spec.Namespace, "type")) libcontainer.Namespace.Kind {
    return switch (kind) {
        .pid => .pid,
        .network => .network,
        .mount => .mount,
        .ipc => .ipc,
        .uts => .uts,
        .user => .user,
        .cgroup => .cgroup,
        .time => .time,
    };
}

fn prepareCreateMounts(mount_allocator: std.mem.Allocator, bundle: []const u8, rootfs: []const u8, configured: ?[]const oci.Spec.Mount, settings: oci.Spec.Linux) ![]libcontainer.Mount {
    const spec_mounts = configured orelse &.{};
    const mounts = try mount_allocator.alloc(libcontainer.Mount, spec_mounts.len);
    for (spec_mounts, mounts, 0..) |mount, *prepared, i| {
        errdefer |err| if (err == error.InvalidConfig) oci.diagnosticContext("mounts[{d}]", .{i});
        const options = try oci.parseMountOptions(mount_allocator, mount.options orelse &.{}, mount.type);
        const source = if (options.flags & std.os.linux.MS.BIND != 0) bind: {
            const path = mount.source orelse {
                oci.recordDiagnostic(error.InvalidConfig, "source: required for a bind mount", .{});
                return error.InvalidConfig;
            };
            break :bind try oci.resolveRootfs(mount_allocator, bundle, path);
        } else mount.source;
        prepared.* = .{
            .destination = try oci.resolveContainerMountDestination(mount_allocator, rootfs, mount.destination),
            .source = source,
            .type = mount.type,
            .flags = options.flags,
            .propagation = options.propagation,
            .data = options.data,
            .recursive_attr = options.recursive_attr,
            .copy_up = options.copy_up,
            .mappings = try oci.mountMappings(mount_allocator, mount, settings),
        };
    }
    return mounts;
}

fn applyCreateSpec(allocator: std.mem.Allocator, options: *libcontainer.CreateOptions, spec: oci.Spec) !void {
    const settings: oci.Spec.Linux = spec.linux orelse .{};
    options.process = if (spec.process) |process| oci.processConfig(process) else null;
    options.namespaces = try prepareCreateNamespaces(allocator, settings.namespaces);
    options.uid_mappings = try oci.containerIDMappings(allocator, settings.uidMappings orelse &.{});
    options.gid_mappings = try oci.containerIDMappings(allocator, settings.gidMappings orelse &.{});
    options.hostname = spec.hostname;
    if (settings.timeOffsets) |offsets| options.time_offsets = .{
        .monotonic = if (offsets.monotonic) |value| .{ .secs = value.secs, .nanosecs = value.nanosecs } else null,
        .boottime = if (offsets.boottime) |value| .{ .secs = value.secs, .nanosecs = value.nanosecs } else null,
    };
    options.readonly_rootfs = spec.root.readonly;
    options.net_devices = try netDevices(allocator, settings.netDevices);
}

fn netDevices(allocator: std.mem.Allocator, devices: ?std.json.ArrayHashMap(oci.Spec.NetDevice)) ![]const libcontainer.NetDevice {
    const map = (devices orelse return &.{}).map;
    const result = try allocator.alloc(libcontainer.NetDevice, map.count());
    for (map.keys(), map.values(), result) |host_name, device, *out| out.* = .{ .host_name = host_name, .name = device.name orelse "" };
    return result;
}

fn applyCreateProcess(options: *libcontainer.CreateOptions, process: ?libcontainer.ExecOptions, init_env: ?[]const []const u8) void {
    if (init_env) |env| options.process.?.env = env;
    if (process) |value| {
        options.capabilities = value.capabilities;
        options.rlimits = value.rlimits;
        options.oom_score_adj = value.oom_score_adj;
        options.apparmor_profile = value.apparmor_profile;
        if (options.process) |*init| {
            init.scheduler = value.scheduler;
            init.io_priority = value.io_priority;
        }
    }
}

fn createPreparedContainer(allocator: std.mem.Allocator, mount_allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, bundle: []const u8, spec: oci.Spec, prepared: libcontainer.CreateOptions, local_console: ?*?std.posix.fd_t) !i32 {
    const cwd = std.Io.Dir.cwd();
    const configured_hooks: oci.Spec.Hooks = spec.hooks orelse .{};
    var options = prepared;
    _ = try cwd.createDirPathStatus(io, config.root, .fromMode(0o700));
    const root = try cwd.realPathFileAlloc(io, config.root, allocator);
    defer allocator.free(root);
    if (inheritsMountNamespace(spec.linux orelse .{})) try requireUnusedRootfs(allocator, io, injected, root, config.id, options.rootfs);
    const state_dir = try std.fs.path.join(allocator, &.{ root, config.id });
    defer allocator.free(state_dir);
    var state: oci.State = .{
        .id = config.id,
        .status = .creating,
        .bundle = bundle,
        .annotations = spec.annotations,
    };
    try createStateDirectory(io, state_dir);
    var lock: ?std.Io.File = null;
    defer if (lock) |file| file.close(io);
    var setup_attempted = false;
    // The errdefer reads setup_attempted when it runs, not when it is registered.
    errdefer cleanupCreateState(allocator, io, state_dir, &lock, &state, configured_hooks.poststop, setup_attempted);
    lock = try openContainerLock(allocator, .{ .root = root, .id = config.id, .subcommand = .create }, true);
    if (lock) |file| _ = try lockContainer(file, true);
    // Setup hooks hold the lock; start and ordinary delete wait, while state, kill and forced delete never block.

    const fifo = try persistCreatingState(allocator, io, root, state_dir, state, spec, options);
    defer allocator.free(fifo);
    const create_hook_state = try hookStateTemplate(mount_allocator, state);
    var start_state = state;
    start_state.status = .created;
    const start_hook_state = try hookStateTemplate(mount_allocator, start_state);
    var create_context: CreateContext = .{
        .allocator = allocator,
        .io = io,
        .root = root,
        .state_dir = state_dir,
        .state = &state,
        .hooks = configured_hooks,
        .lock = lock,
    };
    setup_attempted = true;
    options.exec_fifo = fifo;
    options.create_hook_state = create_hook_state;
    options.start_hook_state = start_hook_state;
    options.on_create = .{ .ptr = &create_context, .run = CreateContext.run };
    // Like runc, the agent sees the container still creating.
    var agent = SeccompAgent.fromSpec(allocator, spec, state);
    options.on_seccomp_listener = SeccompAgent.callbackOf(&agent);
    var instance: ContainerInstance = undefined;
    const created = createInstance(&instance, injected, options);
    const container = try createdContainer(createDiagnostic(injected), created, create_context.failure orelse SeccompAgent.failureOf(agent));
    defer instance.deinit(allocator);
    const handle = instance.state;
    errdefer cleanup: {
        if (lock) |file| requireLinkedLock(io, file) catch break :cleanup;
        container.kill(9) catch {};
        container.delete() catch {};
    }
    state.pid = handle.pid;
    try saveRootfsMount(allocator, io, state_dir, handle);

    try reportCreateConsole(options.console_fds, config.console_socket, local_console);
    state.status = .created;
    if (lock) |file| try requireLinkedLock(io, file);
    try oci.saveState(allocator, io, root, state);
    if (config.pid_file) |path| {
        try writePidFile(allocator, io, path, handle.pid);
    }
    return handle.pid;
}

fn createStateDirectory(io: std.Io, state_dir: []const u8) !void {
    std.Io.Dir.cwd().createDir(io, state_dir, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ContainerExists,
        else => return err,
    };
}

fn createdContainer(detail: ?[]const u8, created: libcontainer.Error!libcontainer.Container, failure: ?anyerror) !libcontainer.Container {
    return diagnostics.resultWithDetail(detail, created) catch |err| {
        if (failure) |reason| {
            diagnostics.last_container_detail = null;
            return reason;
        }
        return err;
    };
}

fn inheritsMountNamespace(settings: oci.Spec.Linux) bool {
    for (settings.namespaces orelse &.{}) |namespace| {
        if (namespace.type == .mount) return false;
    }
    return true;
}

fn cleanupCreateState(allocator: std.mem.Allocator, io: std.Io, state_dir: []const u8, lock: *?std.Io.File, state: *oci.State, poststop: ?[]const oci.Spec.Hook, setup_attempted: bool) void {
    // Forced deletion unlinks our lock; a reused id belongs to another owner.
    if (lock.*) |file| requireLinkedLock(io, file) catch return;
    deleteStateDirectory(io, state_dir) catch {};
    if (lock.*) |file| {
        file.close(io);
        lock.* = null;
    }
    // Library failures clean up init; later failures kill it before this defer.
    if (setup_attempted) {
        state.status = .stopped;
        warnHooks(allocator, poststop, state.*, "poststop");
    }
}

fn persistCreatingState(allocator: std.mem.Allocator, io: std.Io, root: []const u8, state_dir: []const u8, state: oci.State, spec: oci.Spec, options: libcontainer.CreateOptions) ![]u8 {
    const cgroup_state_path = try std.fs.path.join(allocator, &.{ state_dir, oci.cgroup_file_name });
    defer allocator.free(cgroup_state_path);
    try oci.atomicWrite(io, cgroup_state_path, options.cgroup_path);
    const driver_path = try std.fs.path.join(allocator, &.{ state_dir, oci.cgroup_driver_file_name });
    defer allocator.free(driver_path);
    try oci.atomicWrite(io, driver_path, if (options.systemd) "systemd\n" else "cgroupfs\n");
    const process_path = try std.fs.path.join(allocator, &.{ state_dir, oci.process_file_name });
    defer allocator.free(process_path);
    try oci.atomicWrite(io, process_path, if (options.process != null) "true\n" else "false\n");
    // Capture exec defaults independently of later changes to the bundle.
    const saved_config = try std.fs.path.join(allocator, &.{ state_dir, "config.json" });
    defer allocator.free(saved_config);
    const config_json = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false });
    defer allocator.free(config_json);
    try oci.atomicWrite(io, saved_config, config_json);
    const devices_path = try std.fs.path.join(allocator, &.{ state_dir, "devices.json" });
    defer allocator.free(devices_path);
    const devices_json = try std.json.Stringify.valueAlloc(allocator, options.devices, .{});
    defer allocator.free(devices_json);
    try oci.atomicWrite(io, devices_path, devices_json);
    const fifo = try std.fs.path.join(allocator, &.{ state_dir, oci.exec_fifo_name });
    errdefer allocator.free(fifo);
    try makeExecFifo(allocator, fifo);
    try oci.saveState(allocator, io, root, state);
    // Delete must still run poststop if the original bundle was removed.
    if (spec.hooks) |entries| {
        const hooks_path = try std.fs.path.join(allocator, &.{ state_dir, oci.hooks_file_name });
        defer allocator.free(hooks_path);
        const json = try std.json.Stringify.valueAlloc(allocator, entries, .{ .emit_null_optional_fields = false });
        defer allocator.free(json);
        try oci.atomicWrite(io, hooks_path, json);
    }
    return fifo;
}

fn reportCreateConsole(console_fds: ?[2]std.posix.fd_t, console_socket: ?[]const u8, local_console: ?*?std.posix.fd_t) !void {
    if (console_fds) |fds| {
        const controller = try libcontainer.linux.console.receiveFd(fds[0]);
        const path = console_socket orelse {
            // Run in the foreground keeps the controller and copies it to its own stdio.
            local_console.?.* = controller;
            return;
        };
        defer _ = std.os.linux.close(controller);
        // Connect after fork so the blocked init cannot keep this connection
        // alive after create closes its copy.
        const peer = try connectConsoleSocket(path);
        defer _ = std.os.linux.close(peer);
        try libcontainer.linux.console.sendFd(peer, controller);
    }
}

pub const CreateContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    state_dir: []const u8,
    state: *oci.State,
    hooks: oci.Spec.Hooks,
    lock: ?std.Io.File = null,
    failure: ?anyerror = null,

    pub fn run(ptr: *anyopaque, handle: libcontainer.State) libcontainer.Error!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        self.ready(handle) catch |err| {
            // Preserve frontend I/O errors across the library's narrower error set.
            self.failure = err;
            return error.CreateFailed;
        };
    }

    pub fn ready(self: *@This(), handle: libcontainer.State) !void {
        if (self.lock) |file| try requireLinkedLock(self.io, file);
        self.state.pid = handle.pid;
        const path = try std.fs.path.join(self.allocator, &.{ self.state_dir, oci.starttime_file_name });
        defer self.allocator.free(path);
        try oci.atomicWrite(self.io, path, handle.starttime);
        // A rootless create without cgroup permission ran without a cgroup.
        if (handle.cgroup_path == null) {
            const cgroup = try std.fs.path.join(self.allocator, &.{ self.state_dir, oci.cgroup_file_name });
            defer self.allocator.free(cgroup);
            std.Io.Dir.cwd().deleteFile(self.io, cgroup) catch |err| if (err != error.FileNotFound) return err;
        }
        try saveRootfsMount(self.allocator, self.io, self.state_dir, handle);
        try oci.saveState(self.allocator, self.io, self.root, self.state.*);
        // Like runc, the deprecated prestart hooks run with createRuntime.
        try runHooks(self.allocator, self.hooks.prestart, self.state.*, "prestart");
        try runHooks(self.allocator, self.hooks.createRuntime, self.state.*, "createRuntime");
    }
};

fn prepareRestrictionPaths(allocator: std.mem.Allocator, configured: ?[]const []const u8) ![]const []const u8 {
    const paths = configured orelse &.{};
    const prepared = try allocator.alloc([]const u8, paths.len);
    for (paths, prepared) |path, *value| value.* = try oci.resolveMountDestination(allocator, path);
    return prepared;
}

pub fn makeExecFifo(allocator: std.mem.Allocator, path: []const u8) !void {
    if (comptime builtin.os.tag == .linux) {
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        // mkfifo is mknod(S_IFIFO) on Linux; Zig 0.16 exposes the latter.
        switch (std.os.linux.errno(std.os.linux.mknod(path_z, std.os.linux.S.IFIFO | 0o600, 0))) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            .NOSPC => return error.NoSpaceLeft,
            else => return error.CreateFailed,
        }
    } else {
        return error.NotImplemented;
    }
}

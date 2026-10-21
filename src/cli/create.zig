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
const warnHooks = @import("hooks.zig").warnHooks;

pub fn createContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    const cwd = std.Io.Dir.cwd();
    const bundle = try cwd.realPathFileAlloc(io, config.bundle orelse ".", allocator);
    defer allocator.free(bundle);
    const parsed = try oci.loadSpec(allocator, io, bundle);
    defer parsed.deinit();
    try oci.requireCreate(parsed.value);
    const process_options = try prepareCreateProcess(allocator, parsed.value.process, config.console_socket != null);
    defer if (process_options) |options| allocator.free(options.rlimits);
    const console_fds = if (config.console_socket != null) try libcontainer.console.socketpair() else null;
    defer closeConsoleFds(console_fds);
    const rootfs = try oci.resolveRootfs(allocator, bundle, parsed.value.root.path);
    defer allocator.free(rootfs);
    var mount_arena: std.heap.ArenaAllocator = .init(allocator);
    defer mount_arena.deinit();
    const mount_allocator = mount_arena.allocator();
    const settings: oci.Spec.Linux = parsed.value.linux orelse .{};
    const mounts = try prepareCreateMounts(mount_allocator, bundle, parsed.value.mounts, settings);
    const seccomp_config = try oci.prepareSeccomp(allocator, settings.seccomp);
    defer oci.freeSeccomp(allocator, seccomp_config);
    const sysctls = try oci.prepareSysctls(mount_allocator, settings);
    const configured_hooks: oci.Spec.Hooks = parsed.value.hooks orelse .{};
    const create_hooks = try oci.prepareHooks(mount_allocator, configured_hooks.createContainer);
    const start_hooks = try oci.prepareHooks(mount_allocator, configured_hooks.startContainer);
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
    };
    try applyCreateSpec(mount_allocator, &options, parsed.value);
    applyCreateProcess(&options, process_options);
    try createPreparedContainer(allocator, mount_allocator, io, injected, config, bundle, parsed.value, options);
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

fn prepareCreateMounts(mount_allocator: std.mem.Allocator, bundle: []const u8, configured: ?[]const oci.Spec.Mount, settings: oci.Spec.Linux) ![]libcontainer.Mount {
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
            .destination = try oci.resolveMountDestination(mount_allocator, mount.destination),
            .source = source,
            .type = mount.type,
            .flags = options.flags,
            .propagation = options.propagation,
            .data = options.data,
            .recursive_readonly = options.recursive_readonly,
            .mappings = try oci.mountMappings(mount_allocator, mount, settings),
        };
    }
    return mounts;
}

fn applyCreateSpec(allocator: std.mem.Allocator, options: *libcontainer.CreateOptions, spec: oci.Spec) !void {
    const settings: oci.Spec.Linux = spec.linux orelse .{};
    options.process = if (spec.process) |process| oci.processConfig(process) else null;
    options.namespaces = try prepareCreateNamespaces(allocator, settings.namespaces);
    options.uid_mappings = try oci.backendIDMappings(allocator, settings.uidMappings orelse &.{});
    options.gid_mappings = try oci.backendIDMappings(allocator, settings.gidMappings orelse &.{});
    options.hostname = spec.hostname;
    options.readonly_rootfs = spec.root.readonly;
}

fn applyCreateProcess(options: *libcontainer.CreateOptions, process: ?libcontainer.ExecOptions) void {
    if (process) |value| {
        options.capabilities = value.capabilities;
        options.rlimits = value.rlimits;
        options.oom_score_adj = value.oom_score_adj;
        options.apparmor_profile = value.apparmor_profile;
    }
}

fn createPreparedContainer(allocator: std.mem.Allocator, mount_allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, bundle: []const u8, spec: oci.Spec, prepared: libcontainer.CreateOptions) !void {
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
    cwd.createDir(io, state_dir, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ContainerExists,
        else => return err,
    };
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
    var instance: ContainerInstance = undefined;
    const created = createInstance(&instance, injected, options);
    const container = try createdContainer(createDiagnostic(injected), created, create_context.failure);
    defer instance.deinit(allocator);
    const handle = instance.state;
    errdefer cleanup: {
        if (lock) |file| requireLinkedLock(io, file) catch break :cleanup;
        container.kill(9) catch {};
        container.delete() catch {};
    }
    state.pid = handle.pid;
    try saveRootfsMount(allocator, io, state_dir, handle);

    try reportCreateConsole(options.console_fds, config.console_socket);
    state.status = .created;
    if (lock) |file| try requireLinkedLock(io, file);
    try oci.saveState(allocator, io, root, state);
    if (config.pid_file) |path| {
        try writePidFile(allocator, io, path, handle.pid);
    }
}

fn createdContainer(detail: ?[]const u8, created: libcontainer.Error!libcontainer.Container, failure: ?anyerror) !libcontainer.Container {
    return diagnostics.createResult(detail, created) catch |err| {
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

fn reportCreateConsole(console_fds: ?[2]std.posix.fd_t, console_socket: ?[]const u8) !void {
    if (console_fds) |fds| {
        const controller = try libcontainer.console.receiveFd(fds[0]);
        defer _ = std.os.linux.close(controller);
        // Connect after fork so the blocked init cannot keep this connection
        // alive after create closes its copy.
        const peer = try connectConsoleSocket(console_socket.?);
        defer _ = std.os.linux.close(peer);
        try libcontainer.console.sendFd(peer, controller);
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
        try saveRootfsMount(self.allocator, self.io, self.state_dir, handle);
        try oci.saveState(self.allocator, self.io, self.root, self.state.*);
        try runHooks(self.allocator, self.hooks.createRuntime, self.state.*);
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

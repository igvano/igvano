const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;

pub const default_root = "/run/igvano";

const Subcommand = enum {
    state,
    create,
    start,
    kill,
    delete,
};

const Config = struct {
    root: []const u8,
    subcommand: Subcommand,
    id: []const u8,
    bundle: ?[]const u8 = null,
    pid_file: ?[]const u8 = null,
    console_socket: ?[]const u8 = null,
    signal: ?[]const u8 = null,
    force: bool = false,
};

fn parseArgs(args: []const []const u8) !Config {
    var root: []const u8 = default_root;
    var index: usize = 1;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) {
        if (std.mem.eql(u8, args[index], "--root")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) return error.MissingRoot;
            root = args[index];
        } else if (std.mem.startsWith(u8, args[index], "--root=")) {
            root = args[index]["--root=".len..];
            if (root.len == 0) return error.MissingRoot;
        } else {
            return error.UnknownOption;
        }
        index += 1;
    }
    if (index >= args.len) return error.MissingSubcommand;
    const subcommand = std.meta.stringToEnum(Subcommand, args[index]) orelse
        return error.UnknownSubcommand;
    index += 1;

    var bundle: ?[]const u8 = null;
    var pid_file: ?[]const u8 = null;
    var console_socket: ?[]const u8 = null;
    var force = false;
    if (subcommand == .create) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            if (std.mem.eql(u8, args[index], "--bundle")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return error.MissingBundle;
                bundle = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--bundle=")) {
                bundle = args[index]["--bundle=".len..];
                if (bundle.?.len == 0) return error.MissingBundle;
            } else if (std.mem.eql(u8, args[index], "--pid-file")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return error.MissingPidFile;
                pid_file = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--pid-file=")) {
                pid_file = args[index]["--pid-file=".len..];
                if (pid_file.?.len == 0) return error.MissingPidFile;
            } else if (std.mem.eql(u8, args[index], "--console-socket")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return error.MissingConsoleSocket;
                console_socket = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--console-socket=")) {
                console_socket = args[index]["--console-socket=".len..];
                if (console_socket.?.len == 0) return error.MissingConsoleSocket;
            } else {
                return error.UnknownOption;
            }
        }
        if (bundle == null) bundle = ".";
    } else if (subcommand == .delete) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            if (!std.mem.eql(u8, args[index], "--force")) return error.UnknownOption;
            force = true;
        }
    }
    if (index >= args.len) return error.MissingId;
    const remaining = args.len - index;
    if (remaining != 1 and !(subcommand == .kill and remaining == 2)) return error.UnexpectedArgument;
    const id = args[index];
    if (id.len == 0 or std.mem.indexOfScalar(u8, id, 0) != null or std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or std.mem.startsWith(u8, id, "-"))
    {
        return error.InvalidId;
    }
    const signal = if (remaining == 2) args[index + 1] else null;
    if (signal) |value| {
        if (value.len == 0 or std.mem.startsWith(u8, value, "-")) return error.UnexpectedArgument;
    }
    return .{
        .root = root,
        .subcommand = subcommand,
        .id = id,
        .bundle = bundle,
        .pid_file = pid_file,
        .console_socket = console_socket,
        .signal = signal,
        .force = force,
    };
}

fn validateConsoleSocket(terminal: ?bool, socket: ?[]const u8) !void {
    if (terminal orelse false) {
        if (socket == null) return error.MissingConsoleSocket;
    } else if (socket != null) return error.UnexpectedConsoleSocket;
}

fn connectConsoleSocket(path: []const u8) !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len == 0 or path.len >= address.path.len or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    @memcpy(address.path[0..path.len], path);
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.ConsoleSocketFailed;
    const fd: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(fd);
    while (true) {
        const result = linux.connect(fd, &address, @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1));
        switch (linux.errno(result)) {
            .SUCCESS, .ISCONN => return fd,
            .INTR => continue,
            else => return error.ConsoleSocketFailed,
        }
    }
}

fn parseSignal(value: ?[]const u8) !i32 {
    const text = value orelse return 15;
    if (text.len == 0) return error.InvalidSignal;
    if (std.ascii.isDigit(text[0])) {
        for (text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidSignal;
        }
        const signal = std.fmt.parseInt(i32, text, 10) catch return error.InvalidSignal;
        if (signal >= std.os.linux.NSIG) return error.InvalidSignal;
        return signal;
    }
    var buffer: [16]u8 = undefined;
    if (text.len > buffer.len) return error.InvalidSignal;
    for (text, 0..) |byte, i| buffer[i] = std.ascii.toUpper(byte);
    var name: []const u8 = buffer[0..text.len];
    if (std.mem.startsWith(u8, name, "SIG")) name = name[3..];
    // Use Linux numbering even when compiling the frontend's tests on macOS.
    if (std.mem.eql(u8, name, "IOT")) name = "ABRT";
    if (std.mem.eql(u8, name, "POLL")) name = "IO";
    if (std.mem.eql(u8, name, "CLD")) name = "CHLD";
    const signal = std.meta.stringToEnum(std.os.linux.SIG, name) orelse return error.InvalidSignal;
    return @intCast(@intFromEnum(signal));
}

fn openContainerLock(allocator: std.mem.Allocator, config: Config, create: bool) !?std.Io.File {
    if (comptime builtin.os.tag != .linux) return null;
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.lock_file_name });
    defer allocator.free(path);
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDWR,
        .CLOEXEC = true,
        .CREAT = create,
        .EXCL = create,
    }, 0o600) catch |err| switch (err) {
        // Older state directories have no lock file; keep their unlocked behavior.
        error.FileNotFound => if (!create) return null else return err,
        else => return err,
    };
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}

fn lockContainer(file: std.Io.File, blocking: bool) !bool {
    if (comptime builtin.os.tag != .linux) return true;
    const linux = std.os.linux;
    var lock = std.mem.zeroes(linux.Flock);
    lock.type = linux.F.WRLCK;
    lock.whence = linux.SEEK.SET;
    // Record locks are not inherited by the forked init waiting on the exec FIFO.
    // Zig 0.16's F.SETLK/SETLKW compare sizeof(usize) to 64, selecting 32-bit commands.
    const native_fcntl = !@hasField(linux.SYS, "fcntl64");
    const setlk: i32 = if (native_fcntl) (if (builtin.cpu.arch.isSPARC()) 8 else 6) else linux.F.SETLK;
    const setlkw: i32 = if (native_fcntl) (if (builtin.cpu.arch.isSPARC()) 9 else 7) else linux.F.SETLKW;
    while (true) {
        switch (linux.errno(linux.fcntl(file.handle, if (blocking) setlkw else setlk, @intFromPtr(&lock)))) {
            .SUCCESS => return true,
            .INTR => continue,
            .AGAIN, .ACCES => if (!blocking) return false else return error.LockFailed,
            .NOLCK, .NOMEM => return error.SystemResources,
            else => return error.LockFailed,
        }
    }
}

fn requireLinkedLock(io: std.Io, file: std.Io.File) !void {
    if ((try file.stat(io)).nlink == 0) return error.FileNotFound;
}

fn deleteStateDirectory(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var dir = cwd.openDir(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return cwd.deleteTree(io, path),
    };
    defer dir.close(io);
    // Remove state before lock, so callers taking the legacy path see not-found.
    dir.deleteFile(io, oci.state_file_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try cwd.deleteTree(io, path);
}

fn createContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const cwd = std.Io.Dir.cwd();
    const bundle = try cwd.realPathFileAlloc(io, config.bundle orelse ".", allocator);
    defer allocator.free(bundle);
    const parsed = try oci.loadSpec(allocator, io, bundle);
    defer parsed.deinit();
    try oci.requireCreate(parsed.value);
    try validateConsoleSocket(if (parsed.value.process) |process| process.terminal else null, config.console_socket);
    const console_fds = if (config.console_socket != null) try backend_module.console.socketpair() else null;
    defer if (console_fds) |fds| for (fds) |fd| {
        _ = std.os.linux.close(fd);
    };
    const rootfs = try oci.resolveRootfs(allocator, bundle, parsed.value.root.path);
    defer allocator.free(rootfs);
    var mount_arena: std.heap.ArenaAllocator = .init(allocator);
    defer mount_arena.deinit();
    const mount_allocator = mount_arena.allocator();
    const spec_mounts = parsed.value.mounts orelse &.{};
    const mounts = try mount_allocator.alloc(Backend.Mount, spec_mounts.len);
    for (spec_mounts, mounts) |mount, *prepared| {
        const options = try oci.parseMountOptions(mount_allocator, mount.options orelse &.{}, mount.type);
        prepared.* = .{
            .destination = try oci.resolveMountDestination(mount_allocator, mount.destination),
            .source = if (options.flags & std.os.linux.MS.BIND != 0)
                try oci.resolveRootfs(mount_allocator, bundle, mount.source orelse return error.InvalidConfig)
            else
                mount.source,
            .type = mount.type,
            .flags = options.flags,
            .propagation = options.propagation,
            .data = options.data,
            .recursive_readonly = options.recursive_readonly,
        };
    }
    const settings: oci.Spec.Linux = parsed.value.linux orelse .{};
    const configured_hooks: oci.Spec.Hooks = parsed.value.hooks orelse .{};
    const create_hooks = try oci.prepareHooks(mount_allocator, configured_hooks.createContainer);
    const start_hooks = try oci.prepareHooks(mount_allocator, configured_hooks.startContainer);
    const masked_paths = try prepareRestrictionPaths(mount_allocator, settings.maskedPaths);
    const readonly_paths = try prepareRestrictionPaths(mount_allocator, settings.readonlyPaths);
    const devices = try oci.prepareDevices(allocator, settings.devices);
    defer oci.freeDevices(allocator, devices);
    const cgroup_path = try oci.resolveCgroupPath(allocator, settings.cgroupsPath, config.id);
    defer allocator.free(cgroup_path);
    const cgroup_writes = try oci.cgroupWrites(allocator, settings.resources);
    defer oci.freeCgroupWrites(allocator, cgroup_writes);
    const capabilities = if (parsed.value.process) |process|
        if (process.capabilities) |caps| try oci.processCapabilities(caps) else null
    else
        null;
    const rlimits = try oci.processRlimits(allocator, if (parsed.value.process) |process| process.rlimits else null);
    defer allocator.free(rlimits);

    _ = try cwd.createDirPathStatus(io, config.root, .fromMode(0o700));
    const root = try cwd.realPathFileAlloc(io, config.root, allocator);
    defer allocator.free(root);
    const state_dir = try std.fs.path.join(allocator, &.{ root, config.id });
    defer allocator.free(state_dir);
    var state: oci.State = .{
        .id = config.id,
        .status = .creating,
        .bundle = bundle,
        .annotations = parsed.value.annotations,
    };
    cwd.createDir(io, state_dir, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ContainerExists,
        else => return err,
    };
    var lock: ?std.Io.File = null;
    defer if (lock) |file| file.close(io);
    var setup_attempted = false;
    errdefer cleanup: {
        // Forced deletion unlinks our lock; a reused id belongs to another owner.
        if (lock) |file| requireLinkedLock(io, file) catch break :cleanup;
        deleteStateDirectory(io, state_dir) catch {};
        if (lock) |file| {
            file.close(io);
            lock = null;
        }
        // Backend failures clean up init; later failures kill it before this defer.
        if (setup_attempted) {
            state.status = .stopped;
            warnHooks(allocator, configured_hooks.poststop, state, "poststop");
        }
    }
    lock = try openContainerLock(allocator, .{ .root = root, .id = config.id, .subcommand = .create }, true);
    if (lock) |file| _ = try lockContainer(file, true);
    // Setup hooks hold the lock; start and ordinary delete wait, while state, kill and forced delete never block.

    const cgroup_state_path = try std.fs.path.join(allocator, &.{ state_dir, oci.cgroup_file_name });
    defer allocator.free(cgroup_state_path);
    try oci.atomicWrite(io, cgroup_state_path, cgroup_path);
    const process_path = try std.fs.path.join(allocator, &.{ state_dir, oci.process_file_name });
    defer allocator.free(process_path);
    try oci.atomicWrite(io, process_path, if (parsed.value.process != null) "true\n" else "false\n");
    const fifo = try std.fs.path.join(allocator, &.{ state_dir, oci.exec_fifo_name });
    defer allocator.free(fifo);
    try makeExecFifo(allocator, fifo);
    try oci.saveState(allocator, io, root, state);
    // Delete must still run poststop if the original bundle was removed.
    if (parsed.value.hooks) |entries| {
        const hooks_path = try std.fs.path.join(allocator, &.{ state_dir, oci.hooks_file_name });
        defer allocator.free(hooks_path);
        const json = try std.json.Stringify.valueAlloc(allocator, entries, .{ .emit_null_optional_fields = false });
        defer allocator.free(json);
        try oci.atomicWrite(io, hooks_path, json);
    }
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
    const created = backend.create(.{
        .allocator = allocator,
        .id = config.id,
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &parsed.value,
        .console_fds = console_fds,
        .mounts = mounts,
        .cgroup_path = cgroup_path,
        .cgroup_writes = cgroup_writes,
        .capabilities = capabilities,
        .rlimits = rlimits,
        .oom_score_adj = if (parsed.value.process) |process| process.oomScoreAdj else null,
        .devices = devices,
        .device_symlinks = oci.deviceSymlinks(mounts),
        .create_hooks = create_hooks,
        .start_hooks = start_hooks,
        .create_hook_state = create_hook_state,
        .start_hook_state = start_hook_state,
        .masked_paths = masked_paths,
        .readonly_paths = readonly_paths,
        .rootfs_propagation = if (settings.rootfsPropagation) |mode| oci.rootfsPropagation(mode) else null,
        .on_create = .{ .ptr = &create_context, .run = CreateContext.run },
    });
    const handle = created catch |err| return create_context.failure orelse err;
    defer allocator.free(handle.starttime);
    errdefer cleanup: {
        if (lock) |file| requireLinkedLock(io, file) catch break :cleanup;
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    state.pid = handle.pid;
    try saveRootfsMount(allocator, io, state_dir, handle);

    if (console_fds) |fds| {
        const master = try backend_module.console.receiveFd(fds[0]);
        defer _ = std.os.linux.close(master);
        // Connect after fork so the blocked init cannot keep this connection
        // alive after create closes its copy.
        const peer = try connectConsoleSocket(config.console_socket.?);
        defer _ = std.os.linux.close(peer);
        try backend_module.console.sendFd(peer, master);
    }
    state.status = .created;
    if (lock) |file| try requireLinkedLock(io, file);
    try oci.saveState(allocator, io, root, state);
    if (config.pid_file) |path| {
        const pid = try std.fmt.allocPrint(allocator, "{d}", .{handle.pid});
        defer allocator.free(pid);
        try oci.atomicWrite(io, path, pid);
    }
}

const CreateContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    state_dir: []const u8,
    state: *oci.State,
    hooks: oci.Spec.Hooks,
    lock: ?std.Io.File = null,
    failure: ?anyerror = null,

    fn run(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        self.ready(handle) catch |err| {
            // Preserve frontend I/O errors across the backend's narrower error set.
            self.failure = err;
            return error.CreateFailed;
        };
    }

    fn ready(self: *@This(), handle: Backend.Handle) !void {
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

/// State stays frontend-owned. The backend only inserts a decimal host PID
/// into these opaque fragments, using a buffer allocated before fork.
fn hookStateTemplate(allocator: std.mem.Allocator, state: oci.State) !Backend.HookState {
    var template = state;
    template.pid = 0;
    const json = try oci.stateJson(allocator, template);
    defer allocator.free(json);
    const field = "\"pid\":0";
    const index = std.mem.indexOf(u8, json, field) orelse return error.InvalidState;
    const prefix = try allocator.dupe(u8, json[0 .. index + field.len - 1]);
    errdefer allocator.free(prefix);
    return .{ .prefix = prefix, .suffix = try allocator.dupe(u8, json[index + field.len ..]) };
}

fn runHooks(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Hook, state: oci.State) !void {
    const entries = configured orelse return;
    if (entries.len == 0) return;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const hook_allocator = arena.allocator();
    const hooks = try oci.prepareHooks(hook_allocator, entries);
    const prepared = try backend_module.hooks.prepare(hook_allocator, hooks);
    const json = try oci.stateJson(hook_allocator, state);
    try backend_module.hooks.run(prepared, json);
}

fn warnHooks(allocator: std.mem.Allocator, configured: ?[]const oci.Spec.Hook, state: oci.State, stage: []const u8) void {
    // Best-effort hooks remain ordered even if an earlier hook failed.
    for (configured orelse &.{}) |hook| {
        runHooks(allocator, &.{hook}, state) catch |err|
            std.debug.print("igvano: warning: {s} hook '{s}' failed: {s}\n", .{ stage, hook.path, @errorName(err) });
    }
}

fn loadSavedHooks(allocator: std.mem.Allocator, io: std.Io, config: Config) !?std.json.Parsed(oci.Spec.Hooks) {
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.hooks_file_name });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(json);
    return try std.json.parseFromSlice(oci.Spec.Hooks, allocator, json, .{ .allocate = .alloc_always });
}

fn loadHasProcess(allocator: std.mem.Allocator, io: std.Io, config: Config) !bool {
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.process_file_name });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32)) catch |err| switch (err) {
        // Older state directories did not capture whether a process was configured.
        error.FileNotFound => return true,
        error.StreamTooLong => return error.InvalidState,
        else => return err,
    };
    defer allocator.free(json);
    const value = std.mem.trim(u8, json, " \t\r\n");
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidState;
}

fn stateHandle(allocator: std.mem.Allocator, io: std.Io, root: []const u8, state: oci.State) !Backend.Handle {
    const pid = state.pid orelse return error.InvalidState;
    if (pid <= 0) return error.InvalidState;
    const path = try std.fs.path.join(allocator, &.{ root, state.id, oci.starttime_file_name });
    defer allocator.free(path);
    const starttime = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32)) catch |err| switch (err) {
        error.FileNotFound => return error.InvalidState,
        else => return err,
    };
    errdefer allocator.free(starttime);
    if (starttime.len == 0) return error.InvalidState;
    const cgroup_path = try loadCgroupPath(allocator, io, root, state.id);
    errdefer if (cgroup_path) |value| allocator.free(value);
    const rootfs_mount = try loadRootfsMount(allocator, io, root, state.id);
    return .{
        .id = state.id,
        .pid = pid,
        .starttime = starttime,
        .cgroup_path = cgroup_path,
        .rootfs_mount = if (rootfs_mount) |mount| mount.path else null,
        .rootfs_mount_id = if (rootfs_mount) |mount| mount.mount_id_unique else null,
        .rootfs_mount_boot_id = if (rootfs_mount) |mount| mount.boot_id else null,
    };
}

fn loadCgroupPath(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !?[]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, id, oci.cgroup_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(std.fs.max_path_bytes)) catch |err| switch (err) {
        // Handles from earlier runtime versions have no cgroup to clean up.
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return oci.resolveCgroupPath(allocator, bytes, id) catch |err| switch (err) {
        error.InvalidConfig => return error.InvalidState,
        else => return err,
    };
}

const RootfsMount = struct {
    path: []const u8,
    // Legacy reusable IDs never authorize cleanup.
    mount_id: ?u64 = null,
    mount_id_unique: ?u64 = null,
    boot_id: ?[36]u8 = null,
};

fn saveRootfsMount(allocator: std.mem.Allocator, io: std.Io, state_dir: []const u8, handle: Backend.Handle) !void {
    const mount = RootfsMount{
        .path = handle.rootfs_mount orelse return,
        .mount_id_unique = handle.rootfs_mount_id orelse return error.InvalidState,
        .boot_id = handle.rootfs_mount_boot_id orelse return error.InvalidState,
    };
    const path = try std.fs.path.join(allocator, &.{ state_dir, oci.rootfs_mount_file_name });
    defer allocator.free(path);
    const json = try std.json.Stringify.valueAlloc(allocator, mount, .{});
    defer allocator.free(json);
    try oci.atomicWrite(io, path, json);
}

fn loadRootfsMount(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !?RootfsMount {
    const path = try std.fs.path.join(allocator, &.{ root, id, oci.rootfs_mount_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(6 * std.fs.max_path_bytes + 128)) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.StreamTooLong => return error.InvalidState,
        else => return err,
    };
    defer allocator.free(bytes);
    // Older path-only records remain readable, but cannot authorize detach.
    if (std.fs.path.isAbsolute(bytes)) {
        if (std.mem.indexOfScalar(u8, bytes, 0) != null) return error.InvalidState;
        return .{ .path = try allocator.dupe(u8, bytes) };
    }
    const parsed = std.json.parseFromSlice(RootfsMount, allocator, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidState,
    };
    defer parsed.deinit();
    const mount = parsed.value;
    if (!std.fs.path.isAbsolute(mount.path) or std.mem.indexOfScalar(u8, mount.path, 0) != null or
        (mount.mount_id_unique orelse mount.mount_id orelse 0) == 0 or
        (mount.mount_id_unique != null and mount.boot_id == null))
        return error.InvalidState;
    return .{
        .path = try allocator.dupe(u8, mount.path),
        .mount_id_unique = mount.mount_id_unique,
        .boot_id = mount.boot_id,
    };
}

fn freeStateHandle(allocator: std.mem.Allocator, handle: Backend.Handle) void {
    allocator.free(handle.starttime);
    if (handle.cgroup_path) |path| allocator.free(path);
    if (handle.rootfs_mount) |path| allocator.free(path);
}

const LiveState = struct {
    parsed: std.json.Parsed(oci.State),
    handle: ?Backend.Handle,
    allocator: std.mem.Allocator,

    fn deinit(self: LiveState) void {
        if (self.handle) |handle| freeStateHandle(self.allocator, handle);
        self.parsed.deinit();
    }
};

fn readLiveState(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config, persist_recovery: bool) !LiveState {
    var parsed = try oci.loadState(allocator, io, config.root, config.id);
    errdefer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.id, config.id)) return error.InvalidState;
    var handle: ?Backend.Handle = null;
    errdefer if (handle) |value| freeStateHandle(allocator, value);
    if (parsed.value.status == .creating or parsed.value.status == .created or parsed.value.status == .running) {
        handle = stateHandle(allocator, io, config.root, parsed.value) catch |err| switch (err) {
            error.InvalidState => if (parsed.value.status == .creating) null else return err,
            else => return err,
        };
        if (handle == null or !try backend.alive(handle.?)) {
            parsed.value.status = .stopped;
            if (persist_recovery) try oci.saveState(allocator, io, config.root, parsed.value);
        }
    }
    return .{ .parsed = parsed, .handle = handle, .allocator = allocator };
}

fn startContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    var lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    if (lock) |file| {
        _ = try lockContainer(file, true);
        try requireLinkedLock(io, file);
    }
    var state = try readLiveState(allocator, io, backend, config, true);
    defer state.deinit();
    try oci.requireStart(state.parsed.value.status, true);
    try oci.requireStart(state.parsed.value.status, try loadHasProcess(allocator, io, config));
    const saved_hooks = try loadSavedHooks(allocator, io, config);
    defer if (saved_hooks) |entries| entries.deinit();
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.exec_fifo_name });
    defer allocator.free(path);
    runHooks(allocator, if (saved_hooks) |entries| entries.value.prestart else null, state.parsed.value) catch |err| {
        if (lock) |file| requireLinkedLock(io, file) catch return err;
        stopContainer(io, backend, state.handle) catch |cleanup_err|
            std.debug.print("igvano: warning: cannot stop container after prestart failure: {s}\n", .{@errorName(cleanup_err)});
        destroyContainer(allocator, io, backend, config, &state, &lock, if (saved_hooks) |entries| entries.value.poststop else null) catch |cleanup_err|
            std.debug.print("igvano: warning: cannot destroy container after prestart failure: {s}\n", .{@errorName(cleanup_err)});
        return err;
    };
    if (lock) |file| try requireLinkedLock(io, file);
    try waitForStart(allocator, io, backend, state.handle.?, path);
    state.parsed.value.status = .running;
    if (lock) |file| try requireLinkedLock(io, file);
    try oci.saveState(allocator, io, config.root, state.parsed.value);
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    if (lock) |file| {
        file.close(io);
        lock = null;
    }
    warnHooks(allocator, if (saved_hooks) |entries| entries.value.poststart else null, state.parsed.value, "poststart");
}

/// After acknowledgement, CLOEXEC closes the writer at exec; earlier EOF can
/// precede the writer's first open or signal a failure before acknowledgement.
fn startReadComplete(writer_seen: bool, acked: bool, count: usize, byte: u8) !bool {
    if (count == 1) {
        if (byte != 1) return error.StartFailed;
        return false;
    }
    if (acked) return true;
    if (writer_seen) return error.StartFailed;
    return false;
}

fn requireStartWait(is_alive: bool, elapsed: std.Io.Duration) !void {
    if (!is_alive) return error.ProcessNotFound;
    if (elapsed.nanoseconds >= std.Io.Duration.fromSeconds(10).nanoseconds) return error.StartTimeout;
}

fn waitForStart(allocator: std.mem.Allocator, io: std.Io, backend: Backend, handle: Backend.Handle, path: []const u8) !void {
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        const started = std.Io.Clock.awake.now(io);
        const fd: std.posix.fd_t = open: while (true) {
            try requireStartWait(try backend.alive(handle), started.untilNow(io, .awake));
            const result = linux.open(path_z, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
            switch (linux.errno(result)) {
                .SUCCESS => break :open @intCast(result),
                .INTR => continue,
                .NOENT => return error.StartFailed,
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.StartFailed,
            }
        };
        defer _ = linux.close(fd);
        var byte: [1]u8 = undefined;
        var writer_seen = false;
        var acked = false;
        while (true) {
            const is_alive = try backend.alive(handle);
            const result = linux.read(fd, &byte, byte.len);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (try startReadComplete(writer_seen, acked, result, if (result == 1) byte[0] else 0)) return;
                    if (result == 1) acked = true;
                },
                .AGAIN => writer_seen = true,
                .INTR => continue,
                else => return error.StartFailed,
            }
            // After acknowledgement, drain to EOF or 0 even if init exited.
            if (!acked) {
                if (writer_seen) {
                    // Init opened the FIFO and may be running start hooks. Their
                    // configured deadlines govern this phase, including no deadline.
                    if (!is_alive) return error.ProcessNotFound;
                } else {
                    try requireStartWait(is_alive, started.untilNow(io, .awake));
                }
            }
            try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        }
    } else {
        return error.NotImplemented;
    }
}

fn killContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const signal = try parseSignal(config.signal);
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const persist_recovery = if (lock) |file| try lockContainer(file, false) else true;
    if (persist_recovery) {
        if (lock) |file| try requireLinkedLock(io, file);
    } else {
        // Kill only signals a starttime-verified handle, so it is safe unlocked and must work during stuck start/create.
        std.debug.print("igvano: warning: container '{s}' is busy; signalling without the lock\n", .{config.id});
    }
    const state = try readLiveState(allocator, io, backend, config, persist_recovery);
    defer state.deinit();
    try oci.requireKill(state.parsed.value.status);
    try backend.kill(state.handle.?, signal);
}

fn requireDelete(status: oci.Status, force: bool) !void {
    if (!force) try oci.requireDelete(status);
}

fn stopContainer(io: std.Io, backend: Backend, handle: ?Backend.Handle) !void {
    if (handle) |value| {
        if (try backend.alive(value)) {
            backend.kill(value, 9) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => return err,
            };
            const started = std.Io.Clock.awake.now(io);
            while (try backend.alive(value)) {
                if (started.untilNow(io, .awake).nanoseconds >= std.Io.Duration.fromSeconds(1).nanoseconds) {
                    std.debug.print("igvano: warning: container init still alive 1s after SIGKILL\n", .{});
                    break;
                }
                try std.Io.sleep(io, .fromMilliseconds(10), .awake);
            }
        }
    }
}

fn deleteContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    var lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    var persist_recovery = true;
    if (lock) |file| {
        persist_recovery = try lockContainer(file, !config.force);
        if (persist_recovery) {
            try requireLinkedLock(io, file);
        } else {
            std.debug.print("igvano: warning: container '{s}' is busy; forcing deletion without the lock\n", .{config.id});
            file.close(io);
            lock = null;
            // The unlinked lock makes the busy owner skip later cleanup and state writes.
        }
    }
    var state = try readLiveState(allocator, io, backend, config, persist_recovery);
    defer state.deinit();
    try requireDelete(state.parsed.value.status, config.force);
    if (config.force) try stopContainer(io, backend, state.handle);
    const hooks = loadSavedHooks(allocator, io, config) catch |err| hooks: {
        std.debug.print("igvano: warning: cannot load poststop hooks: {s}\n", .{@errorName(err)});
        break :hooks null;
    };
    defer if (hooks) |parsed| parsed.deinit();
    try destroyContainer(allocator, io, backend, config, &state, &lock, if (hooks) |parsed| parsed.value.poststop else null);
}

fn destroyContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config, state: *LiveState, lock: *?std.Io.File, poststop: ?[]const oci.Spec.Hook) !void {
    if (lock.*) |file| try requireLinkedLock(io, file);
    const cgroup_path = if (state.handle) |handle|
        handle.cgroup_path
    else
        try loadCgroupPath(allocator, io, config.root, config.id);
    defer if (state.handle == null) {
        if (cgroup_path) |path| allocator.free(path);
    };
    const rootfs_mount = if (state.handle) |handle|
        if (handle.rootfs_mount) |path| RootfsMount{
            .path = path,
            .mount_id_unique = handle.rootfs_mount_id,
            .boot_id = handle.rootfs_mount_boot_id,
        } else null
    else
        try loadRootfsMount(allocator, io, config.root, config.id);
    defer if (state.handle == null) {
        if (rootfs_mount) |mount| allocator.free(mount.path);
    };
    try backend.delete(state.handle orelse .{
        .id = state.parsed.value.id,
        .pid = state.parsed.value.pid orelse 0,
        .starttime = "",
        .cgroup_path = cgroup_path,
        .rootfs_mount = if (rootfs_mount) |mount| mount.path else null,
        .rootfs_mount_id = if (rootfs_mount) |mount| mount.mount_id_unique else null,
        .rootfs_mount_boot_id = if (rootfs_mount) |mount| mount.boot_id else null,
    });
    state.parsed.value.status = .stopped;
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id });
    defer allocator.free(path);
    try deleteStateDirectory(io, path);
    if (lock.*) |file| {
        file.close(io);
        lock.* = null;
    }
    warnHooks(allocator, poststop, state.parsed.value, "poststop");
}

fn stateContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const persist_recovery = if (lock) |file| try lockContainer(file, false) else true;
    if (persist_recovery) {
        if (lock) |file| try requireLinkedLock(io, file);
    }
    const state = try readLiveState(allocator, io, backend, config, persist_recovery);
    defer state.deinit();
    const json = try oci.stateJson(allocator, state.parsed.value);
    defer allocator.free(json);
    try std.Io.File.stdout().writeStreamingAll(io, json);
}

fn makeExecFifo(allocator: std.mem.Allocator, path: []const u8) !void {
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

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const config = parseArgs(args) catch |err| {
        const message = switch (err) {
            error.MissingRoot => "missing value for --root",
            error.MissingSubcommand => "missing subcommand",
            error.UnknownOption => "unknown option",
            error.UnknownSubcommand => "unknown subcommand",
            error.MissingId => "missing container id",
            error.MissingBundle => "missing value for --bundle",
            error.MissingPidFile => "missing value for --pid-file",
            error.MissingConsoleSocket => "missing value for --console-socket",
            error.UnexpectedArgument => "unexpected argument; global flags must precede the subcommand",
            error.InvalidId => "invalid container id",
        };
        std.debug.print(
            "igvano: {s}\nUsage: igvano [--root <dir>] <state|start> <id>\n" ++
                "       igvano [--root <dir>] delete [--force] <id>\n" ++
                "       igvano [--root <dir>] kill <id> [signal]\n" ++
                "       igvano [--root <dir>] create [--bundle <path>] [--pid-file <file>] [--console-socket <path>] <id>\n",
            .{message},
        );
        return 1;
    };
    var implementation: backend_module.LinuxBackend = .{};
    const backend = implementation.backend();
    const result = switch (config.subcommand) {
        .state => stateContainer(allocator, init.io, backend, config),
        .create => createContainer(allocator, init.io, backend, config),
        .start => startContainer(allocator, init.io, backend, config),
        .kill => killContainer(allocator, init.io, backend, config),
        .delete => deleteContainer(allocator, init.io, backend, config),
    };
    result catch |err| {
        reportError(config, err);
        return 1;
    };
    return 0;
}

fn reportError(config: Config, err: anyerror) void {
    if (err == error.FileNotFound) {
        std.debug.print("igvano: container '{s}' or a required file does not exist\n", .{config.id});
    } else if (err == error.ContainerExists) {
        std.debug.print("igvano: container '{s}' already exists\n", .{config.id});
    } else if (err == error.StartTimeout) {
        std.debug.print("igvano: start for '{s}' timed out waiting for init readiness\n", .{config.id});
    } else if (err == error.MissingConsoleSocket) {
        std.debug.print("igvano: terminal=true requires --console-socket\n", .{});
    } else if (err == error.UnexpectedConsoleSocket) {
        std.debug.print("igvano: --console-socket requires terminal=true\n", .{});
    } else if (config.subcommand == .start and err == error.ProcessNotFound) {
        std.debug.print("igvano: init for '{s}' is no longer alive; start failed\n", .{config.id});
    } else {
        std.debug.print("igvano: {s} for '{s}' failed: {s}\n", .{ @tagName(config.subcommand), config.id, @errorName(err) });
    }
}
test "start wait rejects a dead init before the timeout" {
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .zero));
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .fromSeconds(10)));
}

test "console socket validation matches the terminal setting" {
    for ([_]?bool{ null, false, true }) |terminal| {
        for ([_]?[]const u8{ null, "/tmp/console.sock" }) |socket| {
            if ((terminal orelse false) == (socket != null)) {
                try validateConsoleSocket(terminal, socket);
            } else {
                try std.testing.expectError(
                    if (socket == null) error.MissingConsoleSocket else error.UnexpectedConsoleSocket,
                    validateConsoleSocket(terminal, socket),
                );
            }
        }
    }
}

test "start FIFO EOF before acknowledgement fails only after a writer was observed" {
    try std.testing.expect(!try startReadComplete(false, false, 0, 0));
    try std.testing.expectError(error.StartFailed, startReadComplete(true, false, 0, 0));
    try std.testing.expectError(error.StartFailed, startReadComplete(false, false, 1, 0));
    try std.testing.expectError(error.StartFailed, startReadComplete(true, false, 1, 0));
}

test "start FIFO acknowledgement waits for exec" {
    try std.testing.expect(!try startReadComplete(false, false, 1, 1));
    try std.testing.expect(!try startReadComplete(true, false, 1, 1));
    try std.testing.expect(try startReadComplete(false, true, 0, 0));
    try std.testing.expect(try startReadComplete(true, true, 0, 0));
    try std.testing.expectError(error.StartFailed, startReadComplete(false, true, 1, 0));
    try std.testing.expectError(error.StartFailed, startReadComplete(true, true, 1, 0));
}

test "create argument parsing accepts console sockets and rejects missing values" {
    for ([_][]const []const u8{
        &.{ "igvano", "create", "--console-socket", "/tmp/console.sock", "example" },
        &.{ "igvano", "create", "--console-socket=/tmp/console.sock", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("/tmp/console.sock", config.console_socket.?);
    }
    for ([_][]const []const u8{
        &.{ "igvano", "create", "--console-socket" },
        &.{ "igvano", "create", "--console-socket=" },
        &.{ "igvano", "create", "--console-socket", "--bundle", "/tmp" },
    }) |args| try std.testing.expectError(error.MissingConsoleSocket, parseArgs(args));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "start", "--console-socket", "/tmp/console.sock", "example" }));
}

test "hook state templates reproduce state stdout with a host PID" {
    const state: oci.State = .{ .id = "hook-test", .status = .creating, .pid = 1234, .bundle = "/bundle" };
    const template = try hookStateTemplate(std.testing.allocator, state);
    defer std.testing.allocator.free(template.prefix);
    defer std.testing.allocator.free(template.suffix);
    const actual = try std.fmt.allocPrint(std.testing.allocator, "{s}{d}{s}", .{ template.prefix, 1234, template.suffix });
    defer std.testing.allocator.free(actual);
    const expected = try oci.stateJson(std.testing.allocator, state);
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, actual);
}

test "linux create callback runs only createRuntime with creating state" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const state_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "example" });
    defer std.testing.allocator.free(state_dir);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/order", .{root});
    defer std.testing.allocator.free(output_env);
    var state: oci.State = .{ .id = "example", .status = .creating, .bundle = "/bundle" };
    var context: CreateContext = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .root = root,
        .state_dir = state_dir,
        .state = &state,
        .hooks = .{
            .prestart = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "printf prestart >> \"$OUT\"" },
                .env = &.{output_env},
                .timeout = 2,
            }},
            .createRuntime = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"creating\"'*'\"pid\":1234'*) printf createRuntime >> \"$OUT\";; *) exit 1;; esac" },
                .env = &.{output_env},
                .timeout = 2,
            }},
        },
    };
    try CreateContext.run(&context, .{ .id = "example", .pid = 1234, .starttime = "12345" });
    const order = try tmp.dir.readFileAlloc(std.testing.io, "order", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(order);
    try std.testing.expectEqualStrings("createRuntime", order);
    const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer saved.deinit();
    try std.testing.expectEqual(oci.Status.creating, saved.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), saved.value.pid);
}

test "linux failed create runs poststop after removing runtime state" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        killed: bool = false,
        deleted: bool = false,
        fail_create: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.fail_create) return error.HookFailed;
            const handle: Backend.Handle = .{ .id = options.id, .pid = 1234, .starttime = "12345" };
            if (options.on_create) |callback| callback.run(callback.ptr, handle) catch |err| {
                // A backend owns cleanup when its parent callback aborts create.
                try kill(ptr, handle, 9);
                try delete(ptr, handle);
                return err;
            };
            return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(ptr: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = true;
        }
        fn delete(ptr: *anyopaque, _: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop-input", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    const hook: oci.Spec.Hook = .{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "test \"$ONLY\" = hook || exit 0; IFS= read -r state; case \"$state\" in *'\"status\":\"creating\"'*'\"pid\":1234'*) exit 7;; esac" },
        .env = &.{"ONLY=hook"},
        .timeout = 2,
    };
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "." },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .hooks = .{
            .createRuntime = &.{hook},
            .poststop = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
                .env = &.{ output_env, state_env },
                .timeout = 2,
            }},
        },
    };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    for ([_]bool{ false, true }) |fail_create| {
        var implementation: TestBackend = .{ .fail_create = fail_create };
        try std.testing.expectError(error.HookFailed, createContainer(std.testing.allocator, std.testing.io, .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        }, .{ .root = base, .subcommand = .create, .id = "example", .bundle = bundle }));
        try std.testing.expectEqual(!fail_create, implementation.killed and implementation.deleted);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
        const input = try tmp.dir.readFileAlloc(std.testing.io, "poststop-input", std.testing.allocator, .limited(4096));
        defer std.testing.allocator.free(input);
        const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
        defer state.deinit();
        try std.testing.expectEqual(oci.Status.stopped, state.value.status);
        try std.testing.expectEqualStrings("example", state.value.id);
        try std.testing.expectEqual(@as(?i32, if (fail_create) null else 1234), state.value.pid);
        try tmp.dir.deleteFile(std.testing.io, "poststop-input");
    }
}

test "linux poststop runs after stopped-container deletion despite a missing bundle and earlier hook failure" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return false;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            if (handle.pid != 1234) return error.InvalidProcess;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/hook-state", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    const configured: oci.Spec.Hooks = .{ .poststop = &.{
        .{ .path = "/igvano-missing-hook" },
        .{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
            .env = &.{ output_env, state_env },
            .timeout = 2,
        },
    } };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .pid = 1234,
        .status = .stopped,
        .bundle = "/igvano-missing-bundle",
    });
    var implementation: TestBackend = .{};
    try deleteContainer(std.testing.allocator, std.testing.io, .{
        .ptr = &implementation,
        .vtable = &TestBackend.vtable,
    }, .{ .root = root, .id = "example", .subcommand = .delete });
    const input = try tmp.dir.readFileAlloc(std.testing.io, "hook-state", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(input);
    const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.stopped, state.value.status);
    try std.testing.expectEqualStrings("example", state.value.id);
    try std.testing.expectEqual(@as(?i32, 1234), state.value.pid);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "start wait expires at ten seconds while allowing earlier retries" {
    try requireStartWait(true, .zero);
    try requireStartWait(true, .fromMilliseconds(9999));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromSeconds(10)));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromMilliseconds(10001)));
}

test "linux prestart receives created state before init unblocks and poststart runs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
        ,
    });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/example/exec.fifo", .{root}, 0);
    defer std.testing.allocator.free(fifo);
    try makeExecFifo(std.testing.allocator, fifo);
    const output = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/order", .{root}, 0);
    defer std.testing.allocator.free(output);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        // Opening the write end models init's block before executing the program.
        const fd = linux.open(fifo, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) linux.exit_group(1);
        const order = linux.open(output, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(order) != .SUCCESS) linux.exit_group(2);
        if (linux.errno(linux.write(@intCast(order), " init", 5)) != .SUCCESS) linux.exit_group(3);
        if (linux.errno(linux.write(@intCast(fd), &.{1}, 1)) != .SUCCESS) linux.exit_group(4);
        const argv = [_:null]?[*:0]const u8{"/bin/true"};
        const envp = [_:null]?[*:0]const u8{};
        _ = linux.execve("/bin/true", &argv, &envp);
        _ = linux.write(@intCast(fd), &.{0}, 1);
        linux.exit_group(5);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        _ = posix.system.waitpid(pid, &status, 0);
    };
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = pid,
        .bundle = bundle,
    });
    try saveTestStarttime(root, pid);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}", .{output});
    defer std.testing.allocator.free(output_env);
    const pid_env = try std.fmt.allocPrint(std.testing.allocator, "PID={d}", .{pid});
    defer std.testing.allocator.free(pid_env);
    const configured: oci.Spec.Hooks = .{
        .prestart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"created\"'*'\"pid\":'\"$PID\"*) test ! -e \"$OUT\" && printf prestart > \"$OUT\";; *) exit 1;; esac" },
            .env = &.{ output_env, pid_env },
            .timeout = 2,
        }},
        .poststart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"running\"'*'\"pid\":'\"$PID\"*) printf ' poststart' >> \"$OUT\";; *) exit 1;; esac" },
            .env = &.{ output_env, pid_env },
            .timeout = 2,
        }},
    };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
    var implementation: backend_module.LinuxBackend = .{};
    try startContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .id = "example",
        .subcommand = .start,
    });
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    reaped = true;
    try std.testing.expectEqual(@as(@TypeOf(status), 0), status);
    const order = try tmp.dir.readFileAlloc(std.testing.io, "order", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(order);
    try std.testing.expectEqualStrings("prestart init poststart", order);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{}));
}

test "prestart failure kills init and destroys runtime state" {
    const TestBackend = struct {
        checks: usize = 0,
        killed: bool = false,
        signal: ?i32 = null,
        deleted: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.checks += 1;
            return !self.killed;
        }
        fn kill(ptr: *anyopaque, _: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = true;
            self.signal = signal;
            // A cleanup error must not replace the hook failure.
            return error.KillFailed;
        }
        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.killed or handle.pid != 1234 or
                !std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/persisted"))
                return error.CgroupDeleteFailed;
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop-state", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    for ([_]struct { json: []const u8, failure: anyerror }{
        .{ .json = "{\"prestart\":[{\"path\":\"relative-hook\"}]}", .failure = error.InvalidConfig },
        .{ .json = "{\"prestart\":[{\"path\":\"/igvano-missing-hook\"}]}", .failure = if (builtin.os.tag == .linux) error.HookFailed else error.NotImplemented },
    }) |case| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .created,
            .pid = 1234,
            .bundle = bundle,
        });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "custom/persisted" });
        // A buffered acknowledgement makes an accidental start succeed on Linux.
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const hooks = try std.json.parseFromSlice(oci.Spec.Hooks, std.testing.allocator, case.json, .{});
        defer hooks.deinit();
        var configured = hooks.value;
        configured.poststop = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
            .env = &.{ output_env, state_env },
            .timeout = 2,
        }};
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
        var implementation: TestBackend = .{};
        const backend: Backend = .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        };
        try std.testing.expectError(case.failure, startContainer(std.testing.allocator, std.testing.io, backend, .{
            .root = root,
            .id = "example",
            .subcommand = .start,
        }));
        try std.testing.expect(implementation.killed);
        try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
        try std.testing.expect(implementation.deleted);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
        try std.testing.expectError(error.FileNotFound, readLiveState(std.testing.allocator, std.testing.io, backend, .{
            .root = root,
            .id = "example",
            .subcommand = .state,
        }, true));
        if (comptime builtin.os.tag == .linux) {
            const input = try tmp.dir.readFileAlloc(std.testing.io, "poststop-state", std.testing.allocator, .limited(4096));
            defer std.testing.allocator.free(input);
            const stopped = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
            defer stopped.deinit();
            try std.testing.expectEqual(oci.Status.stopped, stopped.value.status);
            try std.testing.expectEqual(@as(?i32, 1234), stopped.value.pid);
            try tmp.dir.deleteFile(std.testing.io, "poststop-state");
        }
    }
}

test "linux start drains buffered acknowledgements and exec failures after init exits" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const TestBackend = struct {
        writer: ?std.posix.fd_t,
        bytes: []const u8,
        opened: bool = false,

        const vtable: Backend.VTable = .{ .create = unusedCreate, .alive = alive, .kill = unusedKill, .delete = unusedDelete };

        fn unusedCreate(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn unusedKill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn unusedDelete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.opened) {
                self.opened = true;
                return true;
            }
            // Exec closes the writer even if the process exits before start
            // samples liveness. A failed exec queues 0 before closing instead.
            const writer = self.writer orelse return false;
            if (linux.write(writer, self.bytes.ptr, self.bytes.len) != self.bytes.len) return error.CreateFailed;
            _ = linux.close(writer);
            self.writer = null;
            return false;
        }
    };
    for ([_][]const u8{ "\x01", "\x01\x00" }) |bytes| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const fifo = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "exec.fifo" });
        defer std.testing.allocator.free(fifo);
        try makeExecFifo(std.testing.allocator, fifo);
        const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
        defer std.testing.allocator.free(fifo_z);
        const opened = linux.open(fifo_z, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) return error.OpenFailed;
        var implementation: TestBackend = .{ .writer = @intCast(opened), .bytes = bytes };
        defer if (implementation.writer) |writer| {
            _ = linux.close(writer);
        };
        const result = waitForStart(std.testing.allocator, std.testing.io, .{ .ptr = &implementation, .vtable = &TestBackend.vtable }, .{
            .id = "example",
            .pid = 1234,
            .starttime = "12345",
        }, fifo);
        if (bytes.len == 1) {
            try result;
        } else {
            try std.testing.expectError(error.StartFailed, result);
        }
    }
}

test "linux start waits for FIFO close after acknowledgement" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/exec.fifo", .{root}, 0);
    defer std.testing.allocator.free(fifo);
    try makeExecFifo(std.testing.allocator, fifo);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        const opened = linux.open(fifo, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) linux.exit_group(1);
        const writer: posix.fd_t = @intCast(opened);
        if (linux.write(writer, &.{1}, 1) != 1) linux.exit_group(2);
        const delay: linux.timespec = .{ .sec = 0, .nsec = 200_000_000 };
        if (linux.errno(linux.nanosleep(&delay, null)) != .SUCCESS) linux.exit_group(3);
        // Model CLOEXEC closing the writer while the executed process lives on.
        _ = linux.close(writer);
        while (true) _ = linux.pause();
    }
    defer {
        _ = linux.kill(pid, .KILL);
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        _ = posix.system.waitpid(pid, &status, 0);
    }
    try saveTestStarttime(root, pid);
    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(starttime);
    var implementation: backend_module.LinuxBackend = .{};
    const started = std.Io.Clock.awake.now(std.testing.io);
    try waitForStart(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .id = "example",
        .pid = pid,
        .starttime = starttime,
    }, fifo);
    try std.testing.expect(started.untilNow(std.testing.io, .awake).nanoseconds >= std.Io.Duration.fromMilliseconds(200).nanoseconds);
}

test "state handle requires a nonempty starttime file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const state: oci.State = .{ .id = "example", .pid = 1234, .status = .created, .bundle = "/bundle" };
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "" });
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "987654321" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "/custom/from-state" });
    const handle = try stateHandle(std.testing.allocator, std.testing.io, root, state);
    defer freeStateHandle(std.testing.allocator, handle);
    try std.testing.expectEqualStrings("987654321", handle.starttime);
    try std.testing.expectEqualStrings("custom/from-state", handle.cgroup_path.?);
    try std.testing.expect(handle.rootfs_mount == null);
    try std.testing.expect(handle.rootfs_mount_id == null);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id_unique\":12345,\"boot_id\":\"00000000-0000-0000-0000-000000000000\"}",
    });
    const mounted_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state);
    defer freeStateHandle(std.testing.allocator, mounted_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", mounted_handle.rootfs_mount.?);
    try std.testing.expectEqual(@as(?u64, 12345), mounted_handle.rootfs_mount_id);
    try std.testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &mounted_handle.rootfs_mount_boot_id.?);
    // A reusable ID from older state must not be mistaken for a unique ID.
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id\":12345}",
    });
    const old_id_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state);
    defer freeStateHandle(std.testing.allocator, old_id_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", old_id_handle.rootfs_mount.?);
    try std.testing.expect(old_id_handle.rootfs_mount_id == null);
    try std.testing.expect(old_id_handle.rootfs_mount_boot_id == null);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/rootfs_mount", .data = "/bundle/rootfs" });
    const legacy_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state);
    defer freeStateHandle(std.testing.allocator, legacy_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", legacy_handle.rootfs_mount.?);
    try std.testing.expect(legacy_handle.rootfs_mount_id == null);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/rootfs_mount", .data = "relative" });
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state));
}

test "loading rootfs mounts rejects invalid ownership records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    for ([_][]const u8{
        "",
        "{\"path\":\"relative\",\"mount_id\":12345}",
        "{\"path\":\"/rootfs\\u0000\",\"mount_id\":12345}",
        "{\"path\":\"/rootfs\"}",
        "{\"path\":\"/rootfs\",\"mount_id\":null}",
        "{\"path\":\"/rootfs\",\"mount_id\":0}",
        "{\"path\":\"/rootfs\",\"mount_id\":-1}",
        "{\"path\":\"/rootfs\",\"mount_id\":\"unknown\"}",
        "{\"path\":\"/rootfs\",\"mount_id_unique\":12345}",
        "{\"path\":\"/rootfs\",\"mount_id_unique\":12345,\"boot_id\":\"short\"}",
        "{\"path\":\"/rootfs\",\"mount_id_unique\":0,\"boot_id\":\"00000000-0000-0000-0000-000000000000\"}",
    }) |record| {
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/rootfs_mount", .data = record });
        try std.testing.expectError(error.InvalidState, loadRootfsMount(std.testing.allocator, std.testing.io, root, "example"));
    }
}

test "delete requires stopped containers unless forced and waits after SIGKILL" {
    const TestBackend = struct {
        is_alive: bool,
        deleted: bool = false,
        signal: ?i32 = null,
        polls_after_kill: usize = 0,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };

        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.signal != null) {
                self.polls_after_kill += 1;
                return self.polls_after_kill == 1;
            }
            return self.is_alive;
        }
        fn kill(ptr: *anyopaque, _: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.signal = signal;
        }
        fn delete(ptr: *anyopaque, _: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    for ([_]bool{ false, true }) |force| {
        const config: Config = .{ .root = root, .subcommand = .delete, .id = "example", .force = force };
        for ([_]oci.Status{ .creating, .created, .running, .stopped }) |status| {
            for ([_]bool{ true, false }) |is_alive| {
                try tmp.dir.createDir(std.testing.io, "example", .default_dir);
                try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
                try oci.saveState(std.testing.allocator, std.testing.io, root, .{
                    .id = "example",
                    .pid = 1234,
                    .status = status,
                    .bundle = "/bundle",
                });
                var implementation: TestBackend = .{ .is_alive = is_alive };
                const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
                if (!force and is_alive and status != .stopped) {
                    const before = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(4096));
                    defer std.testing.allocator.free(before);
                    try std.testing.expectError(error.InvalidStatus, deleteContainer(std.testing.allocator, std.testing.io, backend, config));
                    try std.testing.expect(!implementation.deleted);
                    try std.testing.expect(implementation.signal == null);
                    const after = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(4096));
                    defer std.testing.allocator.free(after);
                    try std.testing.expectEqualStrings(before, after);
                    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
                    defer std.testing.allocator.free(starttime);
                    try std.testing.expectEqualStrings("12345", starttime);
                    try tmp.dir.deleteTree(std.testing.io, "example");
                } else {
                    try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
                    try std.testing.expect(implementation.deleted);
                    if (force and is_alive and status != .stopped) {
                        try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
                        try std.testing.expectEqual(@as(usize, 2), implementation.polls_after_kill);
                    } else {
                        try std.testing.expect(implementation.signal == null);
                    }
                    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
                }
            }
        }
    }
}

test "delete uses persisted cgroup and rootfs mounts and preserves state on backend failure" {
    const TestBackend = struct {
        fail_delete: bool = true,
        deleted: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };

        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return error.NotImplemented;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/persisted"))
                return error.InvalidPath;
            if (!std.mem.eql(u8, handle.rootfs_mount orelse return error.InvalidPath, "/bundle/rootfs"))
                return error.InvalidPath;
            if (handle.rootfs_mount_id != 12345) return error.InvalidPath;
            if (self.fail_delete) return error.CgroupDeleteFailed;
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .stopped,
        .bundle = "/no-longer-present",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "custom/persisted" });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id_unique\":12345,\"boot_id\":\"00000000-0000-0000-0000-000000000000\"}",
    });
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    const config: Config = .{ .root = root, .subcommand = .delete, .id = "example" };
    try std.testing.expectError(error.CgroupDeleteFailed, deleteContainer(std.testing.allocator, std.testing.io, backend, config));
    const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    state.deinit();
    implementation.fail_delete = false;
    try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
    try std.testing.expect(implementation.deleted);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "loading persisted cgroup paths rejects escapes and the mount root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expect(try loadCgroupPath(std.testing.allocator, std.testing.io, root, "example") == null);
    for ([_][]const u8{ "", "/", "../outside", "a/../../outside", "a/..", "a\x00b" }) |path| {
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = path });
        try std.testing.expectError(error.InvalidState, loadCgroupPath(std.testing.allocator, std.testing.io, root, "example"));
    }
}

test "kill reuses the handle loaded during the liveness check" {
    const TestBackend = struct {
        starttime_path: []const u8,
        cgroup_path: []const u8,
        killed: bool = false,

        const vtable: Backend.VTable = .{ .create = unusedCreate, .alive = alive, .kill = kill, .delete = unusedDelete };

        fn unusedCreate(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn unusedDelete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            std.Io.Dir.cwd().deleteFile(std.testing.io, self.starttime_path) catch return error.LivenessFailed;
            std.Io.Dir.cwd().deleteFile(std.testing.io, self.cgroup_path) catch return error.LivenessFailed;
            return true;
        }
        fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, handle.starttime, "12345") or signal != 15 or
                !std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/from-state"))
                return error.KillFailed;
            self.killed = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .pid = 1234,
        .status = .created,
        .bundle = "/bundle",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "custom/from-state" });
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example/starttime" });
    defer std.testing.allocator.free(path);
    const cgroup_path = try std.fs.path.join(std.testing.allocator, &.{ root, "example/cgroup" });
    defer std.testing.allocator.free(cgroup_path);
    var implementation: TestBackend = .{ .starttime_path = path, .cgroup_path = cgroup_path };
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    try killContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .subcommand = .kill, .id = "example" });
    try std.testing.expect(implementation.killed);
}

test "dispatch recognizes lifecycle subcommands and rejects unknown commands" {
    try std.testing.expectEqual(@as(?Subcommand, .state), std.meta.stringToEnum(Subcommand, "state"));
    try std.testing.expectEqual(@as(?Subcommand, .create), std.meta.stringToEnum(Subcommand, "create"));
    try std.testing.expectEqual(@as(?Subcommand, .start), std.meta.stringToEnum(Subcommand, "start"));
    try std.testing.expectEqual(@as(?Subcommand, .kill), std.meta.stringToEnum(Subcommand, "kill"));
    try std.testing.expectEqual(@as(?Subcommand, .delete), std.meta.stringToEnum(Subcommand, "delete"));
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "unknown") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "STATE") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "starting") == null);
}

test "argument parsing uses the default root and positional container id" {
    const config = try parseArgs(&.{ "igvano", "state", "example" });
    try std.testing.expectEqualStrings(default_root, config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
}

test "argument parsing accepts a global root before the subcommand" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "state", "example" });
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
}

test "argument parsing accepts a global root with an equals sign" {
    const config = try parseArgs(&.{ "igvano", "--root=/tmp/containers", "state", "example" });
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
}

test "argument parsing rejects missing arguments and misplaced global flags" {
    try std.testing.expectError(error.MissingSubcommand, parseArgs(&.{"igvano"}));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root" }));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root", "" }));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root=" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "state" }));
    try std.testing.expectError(error.UnknownSubcommand, parseArgs(&.{ "igvano", "unknown", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "--unknown", "state", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "example", "extra" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "--root", "/tmp", "example" }));
}

test "argument parsing rejects ids that escape the container directory" {
    for ([_][]const u8{ "", ".", "..", "../example", "/example", "example/other", "example\x00other", "-example" }) |id| {
        try std.testing.expectError(error.InvalidId, parseArgs(&.{ "igvano", "state", id }));
    }
}

test "create parsing accepts bundle and optional pid file after the subcommand" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "create", "--bundle", "/tmp/bundle", "--pid-file", "/tmp/init.pid", "example" });
    try std.testing.expectEqual(Subcommand.create, config.subcommand);
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqualStrings("example", config.id);
    try std.testing.expectEqualStrings("/tmp/bundle", config.bundle.?);
    try std.testing.expectEqualStrings("/tmp/init.pid", config.pid_file.?);

    const no_pid = try parseArgs(&.{ "igvano", "create", "--bundle", "bundle", "example" });
    try std.testing.expectEqualStrings("bundle", no_pid.bundle.?);
    try std.testing.expect(no_pid.pid_file == null);
    const equals = try parseArgs(&.{ "igvano", "create", "--pid-file=/tmp/init.pid", "--bundle=/tmp/bundle", "example" });
    try std.testing.expectEqualStrings("/tmp/bundle", equals.bundle.?);
    try std.testing.expectEqualStrings("/tmp/init.pid", equals.pid_file.?);
}

test "create parsing defaults the bundle to the current directory" {
    const config = try parseArgs(&.{ "igvano", "create", "example" });
    try std.testing.expectEqualStrings(".", config.bundle.?);
    const with_pid = try parseArgs(&.{ "igvano", "create", "--pid-file", "init.pid", "example" });
    try std.testing.expectEqualStrings(".", with_pid.bundle.?);
    try std.testing.expectEqualStrings("init.pid", with_pid.pid_file.?);
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "create" }));
}

test "create parsing rejects missing bundle and pid file values" {
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle", "", "example" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle=" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle", "--pid-file", "init.pid", "example" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle" }));
    try std.testing.expectError(error.MissingPidFile, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "--pid-file" }));
    try std.testing.expectError(error.MissingPidFile, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "--pid-file=" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "create", "--root", "/tmp", "--bundle", "/tmp/bundle", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "example", "--pid-file", "init.pid" }));
}

test "kill parsing preserves an optional positional signal" {
    const default_signal = try parseArgs(&.{ "igvano", "kill", "example" });
    try std.testing.expect(default_signal.signal == null);
    const explicit_signal = try parseArgs(&.{ "igvano", "kill", "example", "TERM" });
    try std.testing.expectEqualStrings("TERM", explicit_signal.signal.?);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "kill", "example", "TERM", "extra" }));
}

test "argument parsing accepts force only for delete" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "delete", "--force", "example" });
    try std.testing.expectEqual(Subcommand.delete, config.subcommand);
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqualStrings("example", config.id);
    try std.testing.expect(config.force);
    try std.testing.expect(!(try parseArgs(&.{ "igvano", "delete", "example" })).force);
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "delete", "--force" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "--force", "delete", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "delete", "--force=true", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "delete", "example", "--force" }));
    const rejected = [_]struct { subcommand: []const u8, err: anyerror }{
        .{ .subcommand = "create", .err = error.UnknownOption },
        .{ .subcommand = "state", .err = error.UnexpectedArgument },
        .{ .subcommand = "start", .err = error.UnexpectedArgument },
        .{ .subcommand = "kill", .err = error.InvalidId },
    };
    for (rejected) |case| {
        try std.testing.expectError(case.err, parseArgs(&.{ "igvano", case.subcommand, "--force", "example" }));
    }
}

test "forced delete accepts every lifecycle status while ordinary delete requires stopped" {
    for ([_]oci.Status{ .creating, .created, .running, .stopped }) |status| {
        try requireDelete(status, true);
        if (status == .stopped) {
            try requireDelete(status, false);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireDelete(status, false));
        }
    }
}

test "signal parsing accepts Linux names, prefixes, aliases and numbers" {
    const cases = [_]struct { value: []const u8, signal: i32 }{
        .{ .value = "TERM", .signal = 15 },
        .{ .value = "SIGTERM", .signal = 15 },
        .{ .value = "sigterm", .signal = 15 },
        .{ .value = "KILL", .signal = 9 },
        .{ .value = "SIGINT", .signal = 2 },
        .{ .value = "USR1", .signal = 10 },
        .{ .value = "CHLD", .signal = 17 },
        .{ .value = "IOT", .signal = 6 },
        .{ .value = "POLL", .signal = 29 },
        .{ .value = "CLD", .signal = 17 },
        .{ .value = "0", .signal = 0 },
        .{ .value = "15", .signal = 15 },
        .{ .value = "64", .signal = 64 },
    };
    try std.testing.expectEqual(@as(i32, 15), try parseSignal(null));
    for (cases) |case| try std.testing.expectEqual(case.signal, try parseSignal(case.value));
    for ([_][]const u8{ "", "SIG", "unknown", "-1", "65", "999999999999999", "9x", " 9", "+9" }) |value| {
        try std.testing.expectError(error.InvalidSignal, parseSignal(value));
    }
}

test "create uses private state directories and preserves existing root permissions" {
    const TestBackend = struct {
        state_mode: ?std.posix.mode_t = null,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const state_dir = std.fs.path.dirname(options.exec_fifo) orelse return error.InvalidPath;
            const stat = std.Io.Dir.cwd().statFile(std.testing.io, state_dir, .{}) catch return error.InvalidPath;
            // Inspect the real directory before setup failure rolls it back.
            self.state_mode = stat.permissions.toMode() & 0o7777;
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return error.NotImplemented;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}]}}
        ,
    });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    try tmp.dir.createDir(std.testing.io, "existing", .fromMode(0o755));
    const existing = try tmp.dir.statFile(std.testing.io, "existing", .{});
    for ([_][]const u8{ "new/containers", "existing" }) |root_name| {
        const root = try std.fs.path.join(std.testing.allocator, &.{ base, root_name });
        defer std.testing.allocator.free(root);
        var implementation: TestBackend = .{};
        try std.testing.expectError(error.NotImplemented, createContainer(std.testing.allocator, std.testing.io, .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        }, .{ .root = root, .subcommand = .create, .id = "example", .bundle = bundle }));
        if (comptime builtin.os.tag == .linux)
            try std.testing.expectEqual(@as(?std.posix.mode_t, 0o700), implementation.state_mode);
        const stat = try tmp.dir.statFile(std.testing.io, root_name, .{});
        const expected = if (std.mem.eql(u8, root_name, "existing")) existing.permissions.toMode() & 0o7777 else 0o700;
        try std.testing.expectEqual(expected, stat.permissions.toMode() & 0o7777);
    }
    const parent = try tmp.dir.statFile(std.testing.io, "new", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), parent.permissions.toMode() & 0o7777);
}

test "create rejects a duplicate id without changing existing state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"}]}}
        ,
    });
    try tmp.dir.createDirPath(std.testing.io, "containers/example");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "containers/example/state.json", .data = "existing state" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "containers/example/lock", .data = "existing lock" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.fs.path.join(std.testing.allocator, &.{ base, "containers" });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.ContainerExists, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    const state = try tmp.dir.readFileAlloc(std.testing.io, "containers/example/state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(state);
    try std.testing.expectEqualStrings("existing state", state);
    const lock = try tmp.dir.readFileAlloc(std.testing.io, "containers/example/lock", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(lock);
    try std.testing.expectEqualStrings("existing lock", lock);
}

test "create rejects a missing bundle before creating the state directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "missing" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.FileNotFound, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = base,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create rejects propagation without mount isolation before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"rootfsPropagation":"private"},"mounts":[{"destination":"/proc","type":"proc"}]}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create rejects invalid process settings before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const cases = [_]struct { settings: []const u8, expected: anyerror }{
        .{ .settings = "\"capabilities\":{\"bounding\":[\"not-a-capability\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"bounding\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"effective\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"permitted\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"inheritable\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"ambient\":[\"CAP_FUTURE\"]}", .expected = error.InvalidConfig },
        .{ .settings = "\"capabilities\":{\"ambient\":[\"CAP_CHOWN\"]}", .expected = error.AmbientCapabilitiesRequirePermittedAndInheritable },
        .{ .settings = "\"rlimits\":[{\"type\":\"RLIMIT_UNKNOWN\",\"hard\":1024,\"soft\":512}]", .expected = error.InvalidConfig },
        .{ .settings = "\"rlimits\":[{\"type\":\"RLIMIT_NOFILE\",\"hard\":512,\"soft\":1024}]", .expected = error.InvalidConfig },
    };
    for (cases) |case| {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"ociVersion\":\"1.0.2\",\"root\":{{\"path\":\"rootfs\"}},\"linux\":{{\"namespaces\":[{{\"type\":\"mount\"}}]}},\"process\":{{\"args\":[\"/bin/sh\"],\"cwd\":\"/\",\"user\":{{\"uid\":0,\"gid\":0}},{s}}}}}",
            .{case.settings},
        );
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        var implementation: backend_module.LinuxBackend = .{};
        try std.testing.expectError(case.expected, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        }));
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    }
}

test "create rejects invalid devices before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"}],"devices":[{"path":"/dev/null","type":"p"},{"path":"/dev/null","type":"c","major":1,"minor":3}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.InvalidConfig, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .create,
        .id = "example",
        .bundle = bundle,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create removes its new state directory when setup fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"},{"type":"network"},{"type":"network","path":"/proc/1/ns/net"}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidConfig else error.NotImplemented,
        createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        }),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create with inherited mount isolation persists backend resources and rolls back a failed pid file" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        rootfs: [std.fs.max_path_bytes]u8 = undefined,
        rootfs_len: usize = 0,
        mounts_checked: bool = false,
        killed: bool = false,
        deleted: bool = false,

        const vtable: Backend.VTable = .{
            .create = create,
            .alive = alive,
            .kill = kill,
            .delete = delete,
        };

        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.rootfs_len = options.rootfs.len;
            @memcpy(self.rootfs[0..self.rootfs_len], options.rootfs);
            if (options.mounts.len != 2) return error.InvalidConfig;
            const bind = options.mounts[0];
            if (!std.mem.eql(u8, bind.destination, "/mnt") or
                !std.fs.path.isAbsolute(bind.source orelse return error.InvalidConfig) or
                !std.mem.endsWith(u8, bind.source.?, "/bundle/source") or
                bind.flags != (std.os.linux.MS.BIND | std.os.linux.MS.RDONLY) or
                bind.propagation != (std.os.linux.MS.PRIVATE | std.os.linux.MS.REC))
                return error.InvalidConfig;
            const proc = options.mounts[1];
            if (!std.mem.eql(u8, proc.destination, "/proc") or
                !std.mem.eql(u8, proc.source orelse return error.InvalidConfig, "proc") or
                proc.flags != std.os.linux.MS.NOSUID or !std.mem.eql(u8, proc.data, "mode=755"))
                return error.InvalidConfig;
            self.mounts_checked = true;
            if (!std.mem.eql(u8, options.cgroup_path, "custom/test") or options.cgroup_writes.len != 2)
                return error.InvalidConfig;
            if (!std.mem.eql(u8, options.cgroup_writes[0].name, "memory.max") or
                !std.mem.eql(u8, options.cgroup_writes[0].value, "33554432") or
                !std.mem.eql(u8, options.cgroup_writes[1].name, "pids.max") or
                !std.mem.eql(u8, options.cgroup_writes[1].value, "5"))
                return error.InvalidConfig;
            const caps = options.capabilities orelse return error.InvalidConfig;
            if (!std.meta.eql(caps, Backend.Capabilities{
                .bounding = 1 | (@as(u64, 1) << 39),
                .effective = 1,
                .permitted = 1,
                .inheritable = 1,
                .ambient = 1,
            })) return error.InvalidConfig;
            if (options.rlimits.len != 1 or !std.meta.eql(options.rlimits[0], Backend.Rlimit{
                .resource = .NOFILE,
                .hard = 1024,
                .soft = 512,
            })) return error.InvalidConfig;
            if (options.oom_score_adj != 100) return error.InvalidConfig;
            if (options.devices.len != 6 or
                !std.mem.eql(u8, options.devices[0].path, "/dev/null") or
                options.devices[0].kind != .character or options.devices[0].mode != 0o600 or
                options.devices[0].uid != 1000 or options.devices[0].gid != 1001 or
                options.device_symlinks.len != 4)
                return error.InvalidConfig;
            if (options.on_create) |callback| try callback.run(callback.ptr, .{
                .id = options.id,
                .pid = 1234,
                .starttime = "987654321",
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = options.rootfs,
                .rootfs_mount_id = 12345,
                .rootfs_mount_boot_id = "00000000-0000-0000-0000-000000000000".*,
            });
            return .{
                .id = options.id,
                .pid = 1234,
                .starttime = try options.allocator.dupe(u8, "987654321"),
                .cgroup_path = options.cgroup_path,
                .rootfs_mount = options.rootfs,
                .rootfs_mount_id = 12345,
                .rootfs_mount_boot_id = "00000000-0000-0000-0000-000000000000".*,
            };
        }

        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/test"))
                return error.InvalidPath;
            if (!std.mem.eql(u8, handle.rootfs_mount orelse return error.InvalidPath, self.rootfs[0..self.rootfs_len]))
                return error.InvalidPath;
            if (handle.rootfs_mount_id != 12345) return error.InvalidPath;
            self.deleted = true;
        }

        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (handle.pid != 1234 or signal != 9) return error.CreateFailed;
            self.killed = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"9.9.9","root":{"path":"rootfs"},"linux":{"cgroupsPath":"/custom/test","devices":[{"path":"/dev/null","type":"c","major":1,"minor":3,"fileMode":384,"uid":1000,"gid":1001}],"resources":{"memory":{"limit":33554432},"pids":{"limit":5}}},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":1000,"gid":1000},"capabilities":{"bounding":["CAP_CHOWN","CAP_BPF"],"effective":["CAP_CHOWN"],"inheritable":["CAP_CHOWN"],"permitted":["CAP_CHOWN"],"ambient":["CAP_CHOWN"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":512}],"oomScoreAdj":100},"mounts":[{"destination":"/a/../mnt","type":"bind","source":"source","options":["ro","rprivate"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","mode=755"]}],"annotations":{"org.example.description":"hello"}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const pid_file = try std.fs.path.join(std.testing.allocator, &.{ root, "init.pid" });
    defer std.testing.allocator.free(pid_file);
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    var config: Config = .{ .root = root, .subcommand = .create, .id = "example", .bundle = bundle, .pid_file = pid_file };
    try createContainer(std.testing.allocator, std.testing.io, backend, config);

    const json = try tmp.dir.readFileAlloc(std.testing.io, "example/state.json", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(json);
    const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, json, .{});
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.created, state.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), state.value.pid);
    try std.testing.expectEqualStrings("example", state.value.id);
    try std.testing.expectEqualStrings("1.0.2", state.value.ociVersion);
    try std.testing.expectEqualStrings("hello", state.value.annotations.?.map.get("org.example.description").?);
    const absolute_bundle = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, bundle, std.testing.allocator);
    defer std.testing.allocator.free(absolute_bundle);
    try std.testing.expectEqualStrings(absolute_bundle, state.value.bundle);
    const expected_rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_bundle, "rootfs" });
    defer std.testing.allocator.free(expected_rootfs);
    try std.testing.expectEqualStrings(expected_rootfs, implementation.rootfs[0..implementation.rootfs_len]);
    const pid = try tmp.dir.readFileAlloc(std.testing.io, "init.pid", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(pid);
    try std.testing.expectEqualStrings("1234", pid);
    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(starttime);
    try std.testing.expectEqualStrings("987654321", starttime);
    const cgroup = try tmp.dir.readFileAlloc(std.testing.io, "example/cgroup", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(cgroup);
    try std.testing.expectEqualStrings("custom/test", cgroup);
    const rootfs_mount = (try loadRootfsMount(std.testing.allocator, std.testing.io, root, "example")).?;
    defer std.testing.allocator.free(rootfs_mount.path);
    try std.testing.expectEqualStrings(expected_rootfs, rootfs_mount.path);
    try std.testing.expectEqual(@as(?u64, 12345), rootfs_mount.mount_id_unique);
    try std.testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &rootfs_mount.boot_id.?);
    const fifo = try tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{});
    try std.testing.expectEqual(std.Io.File.Kind.named_pipe, fifo.kind);
    try std.testing.expect(!implementation.killed);
    try std.testing.expect(!implementation.deleted);
    try std.testing.expect(implementation.mounts_checked);

    const bad_pid_file = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "init.pid" });
    defer std.testing.allocator.free(bad_pid_file);
    config.id = "other";
    config.pid_file = bad_pid_file;
    try std.testing.expectError(error.FileNotFound, createContainer(std.testing.allocator, std.testing.io, backend, config));
    try std.testing.expect(implementation.killed);
    try std.testing.expect(implementation.deleted);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "other", .{}));
}

test "linux lifecycle waits for exec FIFO EOF and persists running then stopped" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
        ,
    });
    const relative = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(relative);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, relative, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ root, "example", oci.exec_fifo_name });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    const prestart_input = try std.fs.path.join(std.testing.allocator, &.{ root, "prestart-input" });
    defer std.testing.allocator.free(prestart_input);
    const prestart_input_z = try std.testing.allocator.dupeZ(u8, prestart_input);
    defer std.testing.allocator.free(prestart_input_z);
    try makeExecFifo(std.testing.allocator, fifo);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        // Model an init waiting for the frontend's start handshake, without chroot.
        const opened = linux.open(fifo_z, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) linux.exit_group(1);
        const fd: posix.fd_t = @intCast(opened);
        // Prestart must have finished before opening the FIFO releases init.
        const input = linux.open(prestart_input_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(input) != .SUCCESS) linux.exit_group(1);
        _ = linux.close(@intCast(input));
        if (posix.system.write(fd, &[_]u8{1}, 1) != 1) linux.exit_group(1);
        const argv = [_:null]?[*:0]const u8{ "/bin/sleep", "60" };
        const envp = [_:null]?[*:0]const u8{};
        _ = linux.execve("/bin/sleep", &argv, &envp);
        _ = linux.write(fd, &.{0}, 1);
        linux.exit_group(1);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        _ = posix.system.waitpid(pid, &status, 0);
    };
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = pid,
        .bundle = bundle,
    });
    try saveTestStarttime(root, pid);
    var implementation: backend_module.LinuxBackend = .{};
    const backend = implementation.backend();
    const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
    try killContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .subcommand = .kill, .id = "example", .signal = "0" });
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststart-source", .{root});
    defer std.testing.allocator.free(output_env);
    const prestart_env = try std.fmt.allocPrint(std.testing.allocator, "PRESTART={s}", .{prestart_input});
    defer std.testing.allocator.free(prestart_env);
    const saved_hooks: oci.Spec.Hooks = .{
        .prestart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "/bin/cat > \"$PRESTART\"" },
            .env = &.{prestart_env},
            .timeout = 2,
        }},
        .poststart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test -s \"$PRESTART\" && printf saved > \"$OUT\"" },
            .env = &.{ output_env, prestart_env },
        }},
    };
    const hook_json = try std.json.Stringify.valueAlloc(std.testing.allocator, saved_hooks, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(hook_json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = hook_json });
    // A replaced bundle must not change the hooks captured at create.
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}},"hooks":{"prestart":[{"path":"/igvano-missing-hook"}],"poststart":[{"path":"/igvano-missing-hook"}]}}
        ,
    });
    try startContainer(std.testing.allocator, std.testing.io, backend, config);
    const input = try tmp.dir.readFileAlloc(std.testing.io, "prestart-input", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(input);
    const hook_state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
    defer hook_state.deinit();
    try std.testing.expectEqual(oci.Status.created, hook_state.value.status);
    try std.testing.expectEqual(@as(?i32, pid), hook_state.value.pid);
    const hook_output = try tmp.dir.readFileAlloc(std.testing.io, "poststart-source", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(hook_output);
    try std.testing.expectEqualStrings("saved", hook_output);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{}));
    const running = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer running.deinit();
    try std.testing.expectEqual(oci.Status.running, running.value.status);
    try std.testing.expectError(error.InvalidStatus, startContainer(std.testing.allocator, std.testing.io, backend, config));
    try std.testing.expectError(error.InvalidStatus, deleteContainer(std.testing.allocator, std.testing.io, backend, config));
    try killContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .subcommand = .kill, .id = "example", .signal = "SIGKILL" });
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    reaped = true;
    const stopped = try readLiveState(std.testing.allocator, std.testing.io, backend, config, true);
    defer stopped.deinit();
    try std.testing.expectEqual(oci.Status.stopped, stopped.parsed.value.status);
    const persisted = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer persisted.deinit();
    try std.testing.expectEqual(oci.Status.stopped, persisted.value.status);
    try std.testing.expectError(error.InvalidStatus, killContainer(std.testing.allocator, std.testing.io, backend, config));
    try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
    try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
}

test "start uses saved process presence after bundle config changes" {
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const start_result: ?anyerror = if (builtin.os.tag == .linux) null else error.NotImplemented;
    const cases = [_]struct { process: ?[]const u8, json: []const u8, failure: ?anyerror }{
        .{ .process = "true\n", .json = "garbage", .failure = start_result },
        .{ .process = " \ttrue\r\n", .json = "garbage", .failure = start_result },
        .{ .process = "true\n", .json = "{}", .failure = start_result },
        .{ .process = "true\n", .json = "{\"ociVersion\":\"1.0.2\",\"root\":{\"path\":\"/\"}}", .failure = start_result },
        .{ .process = "false\n", .json = "{\"ociVersion\":\"1.0.2\",\"root\":{\"path\":\"/\"},\"process\":{\"args\":[\"/bin/sh\"],\"cwd\":\"/\",\"user\":{\"uid\":0,\"gid\":0}}}", .failure = error.MissingProcess },
        .{ .process = "false\n", .json = "garbage", .failure = error.MissingProcess },
        .{ .process = " \tfalse\r\n", .json = "garbage", .failure = error.MissingProcess },
        .{ .process = "garbage\n", .json = "garbage", .failure = error.InvalidState },
        .{ .process = "", .json = "garbage", .failure = error.InvalidState },
        .{ .process = "x" ** 33, .json = "garbage", .failure = error.InvalidState },
        .{ .process = null, .json = "garbage", .failure = start_result },
    };
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
    for (cases) |case| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        defer tmp.dir.deleteTree(std.testing.io, "example") catch {};
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = case.json });
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .created,
            .pid = 1234,
            .bundle = bundle,
        });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
        if (case.process) |value|
            try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/process", .data = value });
        // A buffered acknowledgement exercises start without a real init process.
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        if (case.failure) |failure| {
            try std.testing.expectError(failure, startContainer(std.testing.allocator, std.testing.io, backend, config));
        } else {
            try startContainer(std.testing.allocator, std.testing.io, backend, config);
            const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer state.deinit();
            try std.testing.expectEqual(oci.Status.running, state.value.status);
        }
    }
}

test "linux start preserves process presence captured at create" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(_: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            if (options.on_create) |callback| try callback.run(callback.ptr, .{
                .id = options.id,
                .pid = 1234,
                .starttime = "12345",
            });
            return .{ .id = options.id, .pid = 1234, .starttime = try options.allocator.dupe(u8, "12345") };
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    for ([_]bool{ false, true }) |has_process| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "." },
            .linux = .{ .namespaces = &.{.{ .type = .mount }} },
            .process = if (has_process) .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } } else null,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        try createContainer(std.testing.allocator, std.testing.io, backend, .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        });
        defer tmp.dir.deleteTree(std.testing.io, "example") catch {};
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = "bundle/config.json",
            .data = if (has_process) "garbage" else
                \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
            ,
        });
        try tmp.dir.deleteFile(std.testing.io, "example/exec.fifo");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
        if (has_process) {
            try startContainer(std.testing.allocator, std.testing.io, backend, config);
            const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer state.deinit();
            try std.testing.expectEqual(oci.Status.running, state.value.status);
        } else {
            try std.testing.expectError(error.MissingProcess, startContainer(std.testing.allocator, std.testing.io, backend, config));
        }
    }
}

test "linux state kill and delete refresh stale creating created and running states" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) linux.exit_group(0);
    var child_status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &child_status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var implementation: backend_module.LinuxBackend = .{};
    const backend = implementation.backend();
    for ([_]oci.Status{ .creating, .created, .running }) |status| {
        for ([_]Subcommand{ .state, .kill, .delete }) |subcommand| {
            try tmp.dir.createDirPath(std.testing.io, "example");
            try oci.saveState(std.testing.allocator, std.testing.io, root, .{
                .id = "example",
                .status = status,
                .pid = pid,
                .bundle = "/bundle",
            });
            try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
            const config: Config = .{ .root = root, .subcommand = subcommand, .id = "example" };
            switch (subcommand) {
                .state => {
                    const state = try readLiveState(std.testing.allocator, std.testing.io, backend, config, true);
                    defer state.deinit();
                    try std.testing.expectEqual(oci.Status.stopped, state.parsed.value.status);
                },
                .kill => try std.testing.expectError(error.InvalidStatus, killContainer(std.testing.allocator, std.testing.io, backend, config)),
                .delete => {
                    try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
                    try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
                    continue;
                },
                else => unreachable,
            }
            const persisted = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer persisted.deinit();
            try std.testing.expectEqual(oci.Status.stopped, persisted.value.status);
        }
    }
}

test "creating state without a process identity becomes stopped and deletable" {
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
            return std.mem.eql(u8, handle.starttime, "alive");
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {}
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var implementation: TestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &TestBackend.vtable };
    for ([_]?i32{ null, 1234 }) |pid| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .creating,
            .pid = pid,
            .bundle = "/bundle",
        });
        const config: Config = .{ .root = root, .id = "example", .subcommand = .delete };
        const state = try readLiveState(std.testing.allocator, std.testing.io, backend, config, true);
        defer state.deinit();
        try std.testing.expectEqual(oci.Status.stopped, state.parsed.value.status);
        try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    }
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .creating,
        .pid = 1234,
        .bundle = "/bundle",
    });
    const state = try readLiveState(std.testing.allocator, std.testing.io, backend, .{
        .root = root,
        .id = "example",
        .subcommand = .state,
    }, true);
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.creating, state.parsed.value.status);
}

const LockTestBackend = struct {
    create_pid: ?i32 = null,
    fail_create: bool = false,
    killed: bool = false,

    const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .delete = delete };
    fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        const handle: Backend.Handle = .{ .id = options.id, .pid = self.create_pid orelse return error.NotImplemented, .starttime = "alive" };
        if (options.on_create) |callback| try callback.run(callback.ptr, handle);
        if (self.fail_create) return error.CreateFailed;
        return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
    }
    fn alive(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return !self.killed and std.mem.eql(u8, handle.starttime, "alive");
    }
    fn kill(ptr: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        self.killed = true;
    }
    fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {}
};

const LockTestProcess = struct {
    pid: i32,
    fd: std.posix.fd_t,

    fn isHeld(path: []const u8) !bool {
        const linux = std.os.linux;
        const path_z = try std.testing.allocator.dupeZ(u8, path);
        defer std.testing.allocator.free(path_z);
        const result = linux.fork();
        if (linux.errno(result) != .SUCCESS) return error.ForkFailed;
        const pid: i32 = @intCast(result);
        if (pid == 0) {
            const opened = linux.open(path_z, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
            if (linux.errno(opened) != .SUCCESS) linux.exit_group(2);
            const acquired = lockContainer(.{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } }, false) catch linux.exit_group(3);
            linux.exit_group(if (acquired) 1 else 0);
        }
        var status: u32 = undefined;
        while (true) {
            switch (linux.errno(linux.waitpid(pid, &status, 0))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.WaitFailed,
            }
        }
        return switch (status) {
            0 => true,
            256 => false,
            else => error.LockProbeFailed,
        };
    }

    fn hold(path: []const u8) !LockTestProcess {
        const linux = std.os.linux;
        const path_z = try std.testing.allocator.dupeZ(u8, path);
        defer std.testing.allocator.free(path_z);
        const sockets = try backend_module.console.socketpair();
        const result = linux.fork();
        if (linux.errno(result) != .SUCCESS) {
            for (sockets) |fd| _ = linux.close(fd);
            return error.ForkFailed;
        }
        const pid: i32 = @intCast(result);
        if (pid == 0) {
            _ = linux.close(sockets[0]);
            const opened = linux.open(path_z, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
            if (linux.errno(opened) != .SUCCESS) linux.exit_group(1);
            _ = lockContainer(.{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } }, true) catch linux.exit_group(2);
            if (linux.write(sockets[1], &.{1}, 1) != 1) linux.exit_group(3);
            var byte: [1]u8 = undefined;
            if (linux.read(sockets[1], &byte, 1) != 1) linux.exit_group(4);
            _ = linux.close(@intCast(opened));
            linux.exit_group(0);
        }
        _ = linux.close(sockets[1]);
        var child: LockTestProcess = .{ .pid = pid, .fd = sockets[0] };
        errdefer child.deinit();
        try child.expectByte();
        return child;
    }

    fn command(config: Config, expected_error: ?anyerror) !LockTestProcess {
        var implementation: LockTestBackend = .{};
        return commandWithBackend(config, expected_error, .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable });
    }

    fn commandWithBackend(config: Config, expected_error: ?anyerror, backend: Backend) !LockTestProcess {
        const linux = std.os.linux;
        const sockets = try backend_module.console.socketpair();
        const result = linux.fork();
        if (linux.errno(result) != .SUCCESS) {
            for (sockets) |fd| _ = linux.close(fd);
            return error.ForkFailed;
        }
        const pid: i32 = @intCast(result);
        if (pid == 0) {
            _ = linux.close(sockets[0]);
            if (config.subcommand == .state and linux.errno(linux.dup2(sockets[1], 1)) != .SUCCESS)
                linux.exit_group(1);
            if (linux.write(sockets[1], &.{1}, 1) != 1) linux.exit_group(2);
            // Avoid using the test runner's allocator and I/O locks after fork.
            var threaded: std.Io.Threaded = .init_single_threaded;
            const io = threaded.io();
            const operation = switch (config.subcommand) {
                .state => stateContainer(std.heap.page_allocator, io, backend, config),
                .create => createContainer(std.heap.page_allocator, io, backend, config),
                .start => startContainer(std.heap.page_allocator, io, backend, config),
                .delete => deleteContainer(std.heap.page_allocator, io, backend, config),
                .kill => unreachable,
            };
            if (operation) |_| {
                if (expected_error != null) linux.exit_group(3);
            } else |err| {
                if (expected_error == null or err != expected_error.?) linux.exit_group(4);
            }
            if (linux.write(sockets[1], &.{1}, 1) != 1) linux.exit_group(5);
            linux.exit_group(0);
        }
        _ = linux.close(sockets[1]);
        var child: LockTestProcess = .{ .pid = pid, .fd = sockets[0] };
        errdefer child.deinit();
        try child.expectByte();
        return child;
    }

    fn readable(self: LockTestProcess, timeout_ms: i32) !bool {
        var poll = [_]std.posix.pollfd{.{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 }};
        return try std.posix.poll(&poll, timeout_ms) != 0;
    }

    fn expectByte(self: LockTestProcess) !void {
        try std.testing.expect(try self.readable(2000));
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try std.posix.read(self.fd, &byte));
        try std.testing.expectEqual(@as(u8, 1), byte[0]);
    }

    fn release(self: LockTestProcess) !void {
        try std.testing.expectEqual(@as(usize, 1), std.os.linux.write(self.fd, &.{1}, 1));
    }

    fn releaseAfterTimeout(self: LockTestProcess) void {
        // Bound parent-process recovery tests if an operation regresses to blocking.
        if (!(self.readable(2000) catch false)) _ = std.os.linux.write(self.fd, &.{1}, 1);
    }

    fn wait(self: *LockTestProcess) !void {
        var status: u32 = undefined;
        while (true) {
            switch (std.os.linux.errno(std.os.linux.waitpid(self.pid, &status, 0))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.WaitFailed,
            }
        }
        self.pid = 0;
        try std.testing.expectEqual(@as(u32, 0), status);
    }

    fn deinit(self: *LockTestProcess) void {
        _ = std.os.linux.close(self.fd);
        if (self.pid != 0) {
            _ = std.os.linux.kill(self.pid, .KILL);
            var status: u32 = undefined;
            while (std.os.linux.errno(std.os.linux.waitpid(self.pid, &status, 0)) == .INTR) {}
        }
    }

    fn waitForLockFd(self: LockTestProcess, path: []const u8) !void {
        const allocator = std.testing.allocator;
        const proc_path = try std.fmt.allocPrint(allocator, "/proc/{d}/fd", .{self.pid});
        defer allocator.free(proc_path);
        var dir = try std.Io.Dir.cwd().openDir(std.testing.io, proc_path, .{ .iterate = true });
        defer dir.close(std.testing.io);
        const started = std.Io.Clock.awake.now(std.testing.io);
        while (started.untilNow(std.testing.io, .awake).nanoseconds < std.Io.Duration.fromSeconds(2).nanoseconds) {
            var iterator = dir.iterate();
            while (try iterator.next(std.testing.io)) |entry| {
                var buffer: [std.fs.max_path_bytes]u8 = undefined;
                const len = dir.readLink(std.testing.io, entry.name, &buffer) catch continue;
                if (std.mem.eql(u8, buffer[0..len], path)) return;
            }
            try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
        }
        return error.LockWaitTimeout;
    }
};

test "linux held lock lets state report stopped without persisting recovery" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "dead" });
    for ([_]oci.Status{ .creating, .created, .running }) |status| {
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = status,
            .pid = if (status == .creating) null else 1234,
            .bundle = "/bundle",
        });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        const config: Config = .{ .root = root, .id = "example", .subcommand = .state };
        var command = try LockTestProcess.command(config, null);
        defer command.deinit();
        var output: [4096]u8 = undefined;
        var len: usize = 0;
        while (true) {
            try std.testing.expect(try command.readable(2000));
            const count = try std.posix.read(command.fd, output[len..]);
            if (count == 0) break;
            len += count;
        }
        try command.wait();
        try std.testing.expect(len > 1 and output[len - 1] == 1);
        const reported = try std.json.parseFromSlice(oci.State, std.testing.allocator, output[0 .. len - 1], .{});
        defer reported.deinit();
        try std.testing.expectEqual(oci.Status.stopped, reported.value.status);
        const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer saved.deinit();
        try std.testing.expectEqual(status, saved.value.status);
        try holder.release();
        try holder.wait();
        var unlocked = try LockTestProcess.command(config, null);
        defer unlocked.deinit();
        // State output is small enough to fit in the socket before wait.
        try unlocked.wait();
        const recovered = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer recovered.deinit();
        try std.testing.expectEqual(oci.Status.stopped, recovered.value.status);
    }
}

test "linux start and ordinary delete wait for a held container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    for ([_]Subcommand{ .start, .delete }) |subcommand| {
        try tmp.dir.createDirPath(std.testing.io, "example");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const status: oci.Status = if (subcommand == .delete) .stopped else .created;
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = status,
            .pid = 1234,
            .bundle = "/bundle",
        });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        var command = try LockTestProcess.command(.{ .root = root, .id = "example", .subcommand = subcommand }, null);
        defer command.deinit();
        try command.waitForLockFd(path);
        try std.testing.expect(!try command.readable(100));
        try holder.release();
        try holder.wait();
        try command.expectByte();
        try command.wait();
        if (subcommand == .delete) {
            try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
        } else {
            const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer saved.deinit();
            try std.testing.expectEqual(if (subcommand == .start) oci.Status.running else status, saved.value.status);
        }
    }
}

test "linux kill delivers a signal while another process holds the container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .running,
        .pid = holder.pid,
        .bundle = "/bundle",
    });
    try saveTestStarttime(root, holder.pid);
    const watchdog = try std.Thread.spawn(.{}, LockTestProcess.releaseAfterTimeout, .{holder});
    defer watchdog.join();
    var implementation: backend_module.LinuxBackend = .{};
    // Recovery operations run in the parent; busy warnings must not print after fork.
    try killContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .id = "example",
        .subcommand = .kill,
        .signal = "SIGTERM",
    });
    var status: u32 = undefined;
    while (true) {
        switch (std.os.linux.errno(std.os.linux.waitpid(holder.pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    holder.pid = 0;
    try std.testing.expectEqual(@as(u32, 15), status);
}

test "linux forced delete removes state while another process holds the container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestIo = struct {
        fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_path: []const u8, new_dir: std.Io.Dir, new_path: []const u8) std.Io.Dir.RenameError!void {
            // Recovery must not persist stale state while the lock is busy.
            if (std.mem.eql(u8, std.fs.path.basename(new_path), oci.state_file_name)) return error.AccessDenied;
            return std.testing.io.vtable.dirRename(userdata, old_dir, old_path, new_dir, new_path);
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "dead" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .running,
        .pid = 1234,
        .bundle = "/bundle",
    });
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    const watchdog = try std.Thread.spawn(.{}, LockTestProcess.releaseAfterTimeout, .{holder});
    defer watchdog.join();
    var vtable = std.testing.io.vtable.*;
    vtable.dirRename = TestIo.rename;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var implementation: LockTestBackend = .{};
    try deleteContainer(std.testing.allocator, io, .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable }, .{
        .root = root,
        .id = "example",
        .subcommand = .delete,
        .force = true,
    });
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    try std.testing.expect(!try holder.readable(0));
    try holder.release();
    try holder.wait();
}

test "linux lock waiters reject deleted containers even when the id is recreated" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    for ([_]Subcommand{ .start, .delete }) |subcommand| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        var command = try LockTestProcess.command(.{ .root = root, .id = "example", .subcommand = subcommand }, error.FileNotFound);
        defer command.deinit();
        try command.waitForLockFd(path);
        try tmp.dir.deleteTree(std.testing.io, "example");
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = if (subcommand == .delete) .stopped else .created,
            .pid = 1234,
            .bundle = "/bundle",
        });
        try holder.release();
        try holder.wait();
        try command.expectByte();
        try command.wait();
        try tmp.dir.deleteTree(std.testing.io, "example");
    }
}

test "linux busy owners preserve a recreated id after forced delete" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { subcommand: Subcommand, fail: bool, failure: anyerror }{
        .{ .subcommand = .create, .fail = true, .failure = error.CreateFailed },
        .{ .subcommand = .create, .fail = false, .failure = error.FileNotFound },
        .{ .subcommand = .start, .fail = true, .failure = error.HookFailed },
        .{ .subcommand = .start, .fail = false, .failure = error.FileNotFound },
    }) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
        try tmp.dir.createDir(std.testing.io, "replacement", .default_dir);
        const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        defer std.testing.allocator.free(base);
        const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
        defer std.testing.allocator.free(root);
        const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
        defer std.testing.allocator.free(bundle);
        const replacement = try std.fs.path.join(std.testing.allocator, &.{ root, "replacement" });
        defer std.testing.allocator.free(replacement);
        const ready_env = try std.fmt.allocPrint(std.testing.allocator, "READY={s}/ready", .{root});
        defer std.testing.allocator.free(ready_env);
        const resume_env = try std.fmt.allocPrint(std.testing.allocator, "RESUME={s}/resume", .{root});
        defer std.testing.allocator.free(resume_env);
        const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop", .{root});
        defer std.testing.allocator.free(output_env);
        const hook: oci.Spec.Hook = .{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "printf ready > \"$READY\"; while test ! -e \"$RESUME\"; do /bin/sleep 0.01; done; exit \"$FAIL\"" },
            .env = &.{ ready_env, resume_env, if (case.subcommand == .start and case.fail) "FAIL=7" else "FAIL=0" },
            .timeout = 5,
        };
        const hooks: oci.Spec.Hooks = .{
            .createRuntime = if (case.subcommand == .create) &.{hook} else null,
            .prestart = if (case.subcommand == .start) &.{hook} else null,
            .poststop = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "printf x >> \"$OUT\"" },
                .env = &.{output_env},
                .timeout = 2,
            }},
        };
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "/" },
            .process = .{ .args = &.{"/bin/true"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
            .linux = .{ .namespaces = &.{.{ .type = .mount }} },
            .hooks = hooks,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        var replacement_spec = spec;
        replacement_spec.hooks = null;
        const replacement_json = try std.json.Stringify.valueAlloc(std.testing.allocator, replacement_spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(replacement_json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "replacement/config.json", .data = replacement_json });
        var implementation: LockTestBackend = .{ .create_pid = 1234 };
        const backend: Backend = .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable };
        const config: Config = .{ .root = root, .id = "example", .subcommand = case.subcommand, .bundle = bundle };
        if (case.subcommand == .start)
            try createContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .id = "example", .subcommand = .create, .bundle = bundle });
        implementation.fail_create = case.fail;
        var owner = try LockTestProcess.commandWithBackend(config, case.failure, backend);
        defer owner.deinit();
        const started = std.Io.Clock.awake.now(std.testing.io);
        while (true) {
            if (tmp.dir.statFile(std.testing.io, "ready", .{})) |_| break else |err| {
                if (err != error.FileNotFound) return err;
            }
            if (started.untilNow(std.testing.io, .awake).nanoseconds >= std.Io.Duration.fromSeconds(2).nanoseconds)
                return error.HookWaitTimeout;
            try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
        }
        try deleteContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .id = "example", .subcommand = .delete, .force = true });
        implementation = .{ .create_pid = 5678 };
        try createContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .id = "example", .subcommand = .create, .bundle = replacement });
        // A stale starter would consume the replacement's acknowledgement and overwrite its state.
        try tmp.dir.deleteFile(std.testing.io, "example/exec.fifo");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "resume", .data = "" });
        try owner.expectByte();
        try owner.wait();
        const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer saved.deinit();
        try std.testing.expectEqual(oci.Status.created, saved.value.status);
        try std.testing.expectEqual(@as(?i32, 5678), saved.value.pid);
        try std.testing.expectEqualStrings(replacement, saved.value.bundle);
        const poststop = try tmp.dir.readFileAlloc(std.testing.io, "poststop", std.testing.allocator, .limited(32));
        defer std.testing.allocator.free(poststop);
        try std.testing.expectEqualStrings("x", poststop);
        const fifo = try tmp.dir.readFileAlloc(std.testing.io, "example/exec.fifo", std.testing.allocator, .limited(32));
        defer std.testing.allocator.free(fifo);
        try std.testing.expectEqualStrings("\x01", fifo);
    }
}

test "unlinked owner lock prevents create callback writes and destruction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    var lock: ?std.Io.File = try tmp.dir.createFile(std.testing.io, "example/lock", .{ .read = true });
    defer if (lock) |file| file.close(std.testing.io);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const state_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "example" });
    defer std.testing.allocator.free(state_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .creating,
        .pid = 1234,
        .bundle = "/old",
    });
    var implementation: LockTestBackend = .{};
    const backend: Backend = .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable };
    const config: Config = .{ .root = root, .id = "example", .subcommand = .start };
    var state = try readLiveState(std.testing.allocator, std.testing.io, backend, config, false);
    defer state.deinit();
    try deleteStateDirectory(std.testing.io, state_dir);
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "replacement" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = 5678,
        .bundle = "/new",
    });
    var context: CreateContext = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .root = root,
        .state_dir = state_dir,
        .state = &state.parsed.value,
        .hooks = .{},
        .lock = lock,
    };
    try std.testing.expectError(error.FileNotFound, context.ready(state.handle.?));
    try std.testing.expectError(error.FileNotFound, destroyContainer(std.testing.allocator, std.testing.io, backend, config, &state, &lock, null));
    const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer saved.deinit();
    try std.testing.expectEqual(oci.Status.created, saved.value.status);
    try std.testing.expectEqual(@as(?i32, 5678), saved.value.pid);
    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(starttime);
    try std.testing.expectEqualStrings("replacement", starttime);
}

test "state directory cleanup falls back to deleteTree when opening fails" {
    const TestIo = struct {
        fn openDir(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!std.Io.Dir {
            if (!options.iterate and std.mem.endsWith(u8, path, "/example")) return error.AccessDenied;
            return std.testing.io.vtable.dirOpenDir(userdata, dir, path, options);
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/state.json", .data = "{}" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "example" });
    defer std.testing.allocator.free(path);
    var vtable = std.testing.io.vtable.*;
    vtable.dirOpenDir = TestIo.openDir;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try deleteStateDirectory(io, path);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    try deleteStateDirectory(std.testing.io, path);
}

test "linux create never reuses an existing lock file" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "existing lock" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.PathAlreadyExists, openContainerLock(std.testing.allocator, .{
        .root = root,
        .id = "example",
        .subcommand = .create,
    }, true));
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "example/lock", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("existing lock", contents);
}

test "linux early create failure removes state while holding the lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestIo = struct {
        var checked = false;
        var held = false;
        var state_removed = false;

        fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_path: []const u8, new_dir: std.Io.Dir, new_path: []const u8) std.Io.Dir.RenameError!void {
            // Fail after creating state.json, but before backend setup begins.
            if (std.mem.eql(u8, std.fs.path.basename(new_path), oci.hooks_file_name)) return error.AccessDenied;
            return std.testing.io.vtable.dirRename(userdata, old_dir, old_path, new_dir, new_path);
        }

        fn openDir(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!std.Io.Dir {
            const opened = try std.testing.io.vtable.dirOpenDir(userdata, dir, path, options);
            errdefer opened.close(std.testing.io);
            if (options.iterate and std.mem.endsWith(u8, path, "/example")) {
                checked = true;
                var buffer: [std.fs.max_path_bytes]u8 = undefined;
                const lock_path = std.fmt.bufPrint(&buffer, "{s}/lock", .{path}) catch return error.Unexpected;
                held = LockTestProcess.isHeld(lock_path) catch return error.Unexpected;
                if (opened.statFile(std.testing.io, oci.state_file_name, .{})) |_| {
                    state_removed = false;
                } else |err| {
                    state_removed = err == error.FileNotFound;
                }
            }
            return opened;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}]},"hooks":{}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var vtable = std.testing.io.vtable.*;
    vtable.dirRename = TestIo.rename;
    vtable.dirOpenDir = TestIo.openDir;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var implementation: LockTestBackend = .{};
    try std.testing.expectError(error.AccessDenied, createContainer(std.testing.allocator, io, .{
        .ptr = &implementation,
        .vtable = &LockTestBackend.vtable,
    }, .{ .root = root, .id = "example", .subcommand = .create, .bundle = bundle }));
    try std.testing.expect(TestIo.checked);
    try std.testing.expect(TestIo.held);
    try std.testing.expect(TestIo.state_removed);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "linux create holds a private lock until backend setup finishes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = LockTestBackend.alive, .kill = LockTestBackend.kill, .delete = LockTestBackend.delete };
        fn create(_: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const path = std.fmt.bufPrintZ(&buffer, "{s}/lock", .{std.fs.path.dirname(options.exec_fifo).?}) catch return error.InvalidPath;
            if (!(LockTestProcess.isHeld(path) catch return error.CreateFailed)) return error.CreateFailed;
            const handle: Backend.Handle = .{ .id = options.id, .pid = 1234, .starttime = "alive" };
            if (options.on_create) |callback| try callback.run(callback.ptr, handle);
            return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: TestBackend = .{};
    try createContainer(std.testing.allocator, std.testing.io, .{ .ptr = &implementation, .vtable = &TestBackend.vtable }, .{
        .root = root,
        .id = "example",
        .subcommand = .create,
        .bundle = bundle,
    });
    const stat = try tmp.dir.statFile(std.testing.io, "example/lock", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    try holder.release();
    try holder.wait();
}

fn saveTestStarttime(root: []const u8, pid: i32) !void {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/stat", .{pid});
    defer allocator.free(path);
    const file = try std.Io.Dir.cwd().openFile(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    // proc files report size zero; a streaming reader must read through EOF.
    var reader = file.readerStreaming(std.testing.io, &.{});
    const bytes = try reader.interface.allocRemaining(allocator, .limited(4096));
    defer allocator.free(bytes);
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.InvalidState;
    var fields = std.mem.tokenizeAny(u8, bytes[end + 1 ..], " \t\n");
    for (3..22) |_| _ = fields.next() orelse return error.InvalidState;
    const starttime = fields.next() orelse return error.InvalidState;
    const destination = try std.fs.path.join(allocator, &.{ root, "example/starttime" });
    defer allocator.free(destination);
    try oci.atomicWrite(std.testing.io, destination, starttime);
}

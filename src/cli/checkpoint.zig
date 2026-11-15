//! runc checkpoint and restore, through CRIU (see libcontainer criu.zig).
const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const attached = @import("../attached.zig");
const Config = @import("args.zig").Config;
const ContainerOverride = @import("state.zig").ContainerOverride;
const ContainerInstance = @import("state.zig").ContainerInstance;
const bindContainer = @import("state.zig").bindContainer;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const readLiveState = @import("state.zig").readLiveState;
const loadSavedHooks = @import("state.zig").loadSavedHooks;
const containerResult = @import("diagnostic.zig").containerResult;
const diagnostics = @import("diagnostic.zig");
const create = @import("create.zig");
const stopContainer = @import("delete.zig").stopContainer;
const destroyContainer = @import("delete.zig").destroyContainer;
const deleteContainer = @import("delete.zig").deleteContainer;
const connectConsoleSocket = @import("process.zig").connectConsoleSocket;
const reserveStdio = @import("exec.zig").reserveStdio;
const enableExecSubreaper = @import("exec.zig").enableExecSubreaper;
const restoreExecSubreaper = @import("exec.zig").restoreExecSubreaper;

pub fn criuCommand(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !u8 {
    if (config.subcommand == .restore) return restoreContainer(allocator, io, injected, config);
    try checkpointContainer(allocator, io, injected, config);
    return 0;
}

fn warnRootless() void {
    if (comptime builtin.os.tag != .linux) return;
    if (std.os.linux.geteuid() != 0 or libcontainer.linux.dbus.userBusOwner() != null)
        std.debug.print("igvano: warning: checkpoint is untested with rootless containers\n", .{});
}

pub fn checkpointContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    warnRootless();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    if (lock) |file| {
        _ = try lockContainer(file, true);
        try requireLinkedLock(io, file);
    }
    var state = try readLiveState(allocator, io, injected, config, true);
    defer state.deinit();
    const status = state.parsed.value.status;
    if (status != .running and status != .paused)
        return oci.validationError(error.InvalidStatus, "Container cannot be checkpointed in {s} state", .{@tagName(status)});
    const handle = state.container_state.?;
    const state_dir = try std.fs.path.join(a, &.{ config.root, config.id });
    const saved = try oci.loadSpec(a, io, state_dir);
    const spec = saved.value;
    const settings: oci.Spec.Linux = spec.linux orelse .{};
    const rootfs = try oci.resolveRootfs(a, state.parsed.value.bundle, spec.root.path);
    const criu = try criuOptions(a, io, config, spec.annotations);
    const result = libcontainer.linux.checkpoint(a, .{
        .criu = criu,
        .pid = handle.pid,
        .rootfs = rootfs,
        .freeze_cgroup = try freezeCgroup(a, handle),
        .mounts = try create.prepareCreateMounts(a, state.parsed.value.bundle, rootfs, spec.mounts, settings),
        .masked_paths = try create.prepareRestrictionPaths(a, settings.maskedPaths),
        .devices = handle.device_nodes,
        .namespaces = try create.prepareCreateNamespaces(a, settings.namespaces),
    });
    try diagnostics.resultWithDetail(libcontainer.linux.diagnostic(), result);
    if (criu.leave_running or criu.pre_dump) return;
    // Like runc, the dumped container is destroyed; its init is gone.
    var instance: ContainerInstance = undefined;
    try stopContainer(io, bindContainer(&instance, injected, handle));
    const hooks = loadSavedHooks(allocator, io, config) catch null;
    defer if (hooks) |parsed| parsed.deinit();
    destroyContainer(allocator, io, injected, config, &state, &lock, if (hooks) |parsed| parsed.value.poststop else null) catch |err|
        std.debug.print("igvano: warning: cannot destroy the checkpointed container: {s}\n", .{@errorName(err)});
}

/// runc gives CRIU the cgroup v2 directory to freeze.
fn freezeCgroup(a: std.mem.Allocator, handle: libcontainer.State) !?[]const u8 {
    const path = handle.cgroup_path orelse return null;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const controllers = try std.fmt.bufPrintZ(&buffer, "/sys/fs/cgroup/{s}/cgroup.controllers", .{path});
    if (std.os.linux.errno(std.os.linux.access(controllers, std.os.linux.F_OK)) != .SUCCESS) return null;
    return try std.fmt.allocPrint(a, "/sys/fs/cgroup/{s}", .{path});
}

/// runc's criuOptions and prepareImagePaths. Allocations belong to `a`.
fn criuOptions(a: std.mem.Allocator, io: std.Io, config: Config, annotations: ?std.json.ArrayHashMap([]const u8)) !libcontainer.CriuOptions {
    const flags = config.criu;
    const cwd = std.Io.Dir.cwd();
    const criu_path = try create.lookPath(a, io, config.path_env, "criu") orelse
        return oci.validationError(error.FileNotFound, "exec: \"criu\": executable file not found in $PATH", .{});
    const image_dir = flags.image_path orelse try std.fs.path.join(a, &.{ try cwd.realPathFileAlloc(io, ".", a), "checkpoint" });
    _ = try cwd.createDirPathStatus(io, image_dir, .fromMode(0o700));
    if (flags.parent_path) |parent| {
        if (std.fs.path.isAbsolute(parent)) return oci.validationError(error.InvalidCriuValue, "--parent-path must be relative", .{});
        const full = try std.fs.path.join(a, &.{ image_dir, parent });
        const stat = cwd.statFile(io, full, .{}) catch |err|
            return oci.validationError(error.InvalidCriuValue, "invalid --parent-path: stat {s}: {s}", .{ full, @errorName(err) });
        if (stat.kind != .directory) return oci.validationError(error.InvalidCriuValue, "invalid --parent-path: {s}: not a directory", .{full});
    }
    var options: libcontainer.CriuOptions = .{
        .path = try a.dupeZ(u8, criu_path),
        .env = if (config.path_env) |path| try a.dupe([:0]const u8, &.{try std.fmt.allocPrintSentinel(a, "PATH={s}", .{path}, 0)}) else &.{},
        .image_dir = image_dir,
        .work_dir = flags.work_path,
        .parent_image = flags.parent_path,
        .leave_running = flags.leave_running,
        .tcp_established = flags.tcp_established,
        .tcp_skip_in_flight = flags.tcp_skip_in_flight,
        .link_remap = flags.link_remap,
        .ext_unix_sk = flags.ext_unix_sk,
        .shell_job = flags.shell_job,
        .file_locks = flags.file_locks,
        .pre_dump = flags.pre_dump,
        .auto_dedup = flags.auto_dedup,
        .lazy_pages = flags.lazy_pages,
        .empty_ns = std.os.linux.CLONE.NEWNET | flags.empty_ns,
        .lsm_profile = flags.lsm_profile,
        .lsm_mount_context = flags.lsm_mount_context,
        .manage_cgroups_mode = try cgroupMode(flags.manage_cgroups_mode),
        .page_server = try pageServer(flags.page_server),
        .status_fd = try statusFd(flags),
        .debug = config.debug_log,
        .log = if (config.log != null) try @import("log.zig").openDebugLog(config.log, config.log_format) else null,
    };
    // A container-specific CRIU config; an empty annotation means none.
    if (annotations) |values| if (values.map.get("org.criu.config")) |file| {
        options.config_file = if (file.len == 0) null else file;
    };
    return options;
}

fn cgroupMode(value: ?[]const u8) !libcontainer.CriuOptions.CgroupMode {
    const mode = value orelse return .default;
    if (mode.len == 0) return .default;
    const parsed = if (std.mem.eql(u8, mode, "default")) null else std.meta.stringToEnum(libcontainer.CriuOptions.CgroupMode, mode);
    return parsed orelse oci.validationError(error.InvalidCriuValue, "invalid manage-cgroups-mode value", .{});
}

fn pageServer(value: ?[]const u8) !?libcontainer.CriuOptions.PageServer {
    const text = value orelse return null;
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
        return oci.validationError(error.InvalidCriuValue, "Use --page-server ADDRESS:PORT to specify page server", .{});
    const address = std.mem.trim(u8, text[0..colon], "[]");
    if (address.len == 0 or colon + 1 == text.len)
        return oci.validationError(error.InvalidCriuValue, "Use --page-server ADDRESS:PORT to specify page server", .{});
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
        return oci.validationError(error.InvalidCriuValue, "Invalid port number", .{});
    return .{ .address = address, .port = port };
}

fn statusFd(flags: @import("args.zig").CriuFlags) !?std.posix.fd_t {
    const fd = flags.status_fd orelse return null;
    if (fd < 0 or !flags.lazy_pages) return null;
    const linux = std.os.linux;
    const result = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(result) != .SUCCESS)
        return oci.validationError(error.InvalidCriuValue, "invalid --status-fd argument {d}: {s}", .{ fd, @tagName(linux.errno(result)) });
    if (result & 3 == 0)
        return oci.validationError(error.InvalidCriuValue, "invalid --status-fd argument {d}: not writable", .{fd});
    return fd;
}

test "criu option values follow runc's parsing" {
    try std.testing.expectEqual(libcontainer.CriuOptions.CgroupMode.default, try cgroupMode(null));
    try std.testing.expectEqual(libcontainer.CriuOptions.CgroupMode.ignore, try cgroupMode("ignore"));
    try std.testing.expectError(error.InvalidCriuValue, cgroupMode("default"));
    try std.testing.expectError(error.InvalidCriuValue, cgroupMode("x"));
    const server = (try pageServer("0.0.0.0:27277")).?;
    try std.testing.expectEqualStrings("0.0.0.0", server.address);
    try std.testing.expectEqual(@as(i32, 27277), server.port);
    try std.testing.expectEqualStrings("::1", (try pageServer("[::1]:1")).?.address);
    for ([_][]const u8{ "x", ":1", "x:", "x:y", "x:-1", "x:65536" }) |bad| try std.testing.expectError(error.InvalidCriuValue, pageServer(bad));
    oci.clearDiagnostic();
}

/// runc restore: like run, but CRIU recreates the processes. Returns the
/// exit status of the restored init when attached.
pub fn restoreContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !u8 {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    warnRootless();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const bundle = try cwd.realPathFileAlloc(io, config.bundle orelse ".", a);
    const spec = try oci.loadSpec(a, io, bundle);
    _ = try cwd.createDirPathStatus(io, config.root, .fromMode(0o700));
    const root = try cwd.realPathFileAlloc(io, config.root, a);
    var restore: libcontainer.Restore = .{
        .criu = try criuOptions(a, io, config, spec.value.annotations),
        .criu_root = try std.fs.path.join(a, &.{ root, config.id, "criu-root" }),
    };
    const console = if (config.console_socket) |path| try connectConsoleSocket(path) else null;
    defer if (console) |fd| {
        _ = std.os.linux.close(fd);
    };
    restore.console_socket = console;
    if (config.detach) {
        _ = try create.createOrRestore(allocator, io, injected, config, null, &restore);
        return 0;
    }
    try reserveStdio();
    const was_subreaper = if (config.criu.no_subreaper) 0 else try enableExecSubreaper();
    defer if (!config.criu.no_subreaper) restoreExecSubreaper(was_subreaper);
    var signals = try attached.Signals.init();
    defer signals.deinit();
    const pid = try create.createOrRestore(allocator, io, injected, config, null, &restore);
    var reaped = false;
    errdefer if (!reaped) {
        _ = std.os.linux.kill(pid, .KILL);
    };
    const status = try attached.wait(pid, &reaped, &signals, null, 0, 1);
    // Like run, the attached container is destroyed after its init exits.
    const saved: diagnostics.SavedDetail = .save();
    defer saved.restore();
    var delete = config;
    delete.subcommand = .delete;
    delete.force = true;
    deleteContainer(allocator, io, injected, delete) catch |err|
        std.debug.print("igvano: warning: cannot delete container '{s}' after restore: {s}\n", .{ config.id, @errorName(err) });
    return status;
}

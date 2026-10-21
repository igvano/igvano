const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("state.zig").ContainerInstance;
const diagnostics = @import("diagnostic.zig");
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const bindContainer = @import("state.zig").bindContainer;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const deleteStateDirectory = @import("state.zig").deleteStateDirectory;
const loadSavedHooks = @import("state.zig").loadSavedHooks;
const loadCgroupPath = @import("state.zig").loadCgroupPath;
const loadCleanupSystemdDriver = @import("state.zig").loadCleanupSystemdDriver;
const RootfsMount = @import("state.zig").RootfsMount;
const loadRootfsMount = @import("state.zig").loadRootfsMount;
const LiveState = @import("state.zig").LiveState;
const recoverLiveState = @import("state.zig").recoverLiveState;
const warnHooks = @import("hooks.zig").warnHooks;

fn requireDelete(status: oci.Status, force: bool) !void {
    if (!force) try oci.requireDelete(status);
}

pub fn stopContainer(io: std.Io, container: ?libcontainer.Container) !void {
    if (container) |value| {
        if (try containerResult(value, value.alive())) {
            containerResult(value, value.kill(9)) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => return err,
            };
            const started = std.Io.Clock.awake.now(io);
            while (try containerResult(value, value.alive())) {
                if (started.untilNow(io, .awake).nanoseconds >= std.Io.Duration.fromSeconds(1).nanoseconds) {
                    std.debug.print("igvano: warning: container init still alive 1s after SIGKILL\n", .{});
                    break;
                }
                try std.Io.sleep(io, .fromMilliseconds(10), .awake);
            }
        }
    }
}

pub fn deleteContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
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
    const saved = oci.loadState(allocator, io, config.root, config.id) catch |err| switch (err) {
        error.FileNotFound => {
            if (!config.force) return err;
            if (!persist_recovery) {
                // ponytail: A concurrent create may finish after this forced delete reports success; runc has the same window.
                return;
            }
            const path = try std.fs.path.join(allocator, &.{ config.root, config.id });
            defer allocator.free(path);
            try deleteStateDirectory(io, path);
            return;
        },
        else => return err,
    };
    var state = try recoverLiveState(allocator, io, injected, config, saved, persist_recovery);
    defer state.deinit();
    try requireDelete(state.parsed.value.status, config.force);
    var instance: ContainerInstance = undefined;
    const container = if (state.container_state) |value| bindContainer(&instance, injected, value) else null;
    if (config.force) try stopContainer(io, container);
    const hooks = loadSavedHooks(allocator, io, config) catch |err| hooks: {
        std.debug.print("igvano: warning: cannot load poststop hooks: {s}\n", .{@errorName(err)});
        oci.clearDiagnostic();
        break :hooks null;
    };
    defer if (hooks) |parsed| parsed.deinit();
    try destroyContainer(allocator, io, injected, config, &state, &lock, if (hooks) |parsed| parsed.value.poststop else null);
}

pub fn destroyContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, state: *LiveState, lock: *?std.Io.File, poststop: ?[]const oci.Spec.Hook) !void {
    if (lock.*) |file| try requireLinkedLock(io, file);
    const cgroup_path = if (state.container_state) |handle|
        handle.cgroup_path
    else
        try loadCgroupPath(allocator, io, config.root, config.id);
    defer if (state.container_state == null) {
        if (cgroup_path) |path| allocator.free(path);
    };
    const rootfs_mount = if (state.container_state) |handle|
        stateRootfsMount(handle)
    else
        try loadRootfsMount(allocator, io, config.root, config.id);
    defer if (state.container_state == null) {
        if (rootfs_mount) |mount| allocator.free(mount.path);
    };
    const systemd = if (state.container_state) |handle| handle.systemd else try loadCleanupSystemdDriver(allocator, io, config.root, config.id, cgroup_path, config.force);
    const cleanup_handle = state.container_state orelse savedCleanupState(state.parsed.value, cgroup_path, systemd, rootfs_mount);
    try deleteLibraryContainer(injected, cleanup_handle, config);
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

fn stateRootfsMount(handle: libcontainer.State) ?RootfsMount {
    return if (handle.rootfs_mount) |path| RootfsMount{
        .path = path,
        .mount_id_unique = handle.rootfs_mount_id,
        .boot_id = handle.rootfs_mount_boot_id,
    } else null;
}

fn savedCleanupState(state: oci.State, cgroup_path: ?[]const u8, systemd: bool, rootfs_mount: ?RootfsMount) libcontainer.State {
    return .{
        .id = state.id,
        .pid = state.pid orelse 0,
        .starttime = "",
        .cgroup_path = cgroup_path,
        .systemd = systemd,
        .rootfs_mount = if (rootfs_mount) |mount| mount.path else null,
        .rootfs_mount_id = if (rootfs_mount) |mount| mount.mount_id_unique else null,
        .rootfs_mount_boot_id = if (rootfs_mount) |mount| mount.boot_id else null,
    };
}

fn deleteLibraryContainer(injected: ?ContainerOverride, handle: libcontainer.State, config: Config) !void {
    var cleanup_handle = handle;
    var instance: ContainerInstance = undefined;
    var container = bindContainer(&instance, injected, cleanup_handle);
    containerResult(container, container.delete()) catch |err| {
        if (!config.force or !cleanup_handle.systemd) return err;
        std.debug.print("igvano: warning: systemd cleanup failed for '{s}': {s}; trying cgroupfs cleanup\n", .{ config.id, @errorName(err) });
        diagnostics.last_container_detail = null;
        cleanup_handle.systemd = false;
        cleanup_handle.systemd_cleanup = true;
        container = bindContainer(&instance, injected, cleanup_handle);
        try containerResult(container, container.delete());
    };
}

test "forced delete accepts every lifecycle status while ordinary delete requires stopped" {
    for ([_]oci.Status{ .creating, .created, .running, .paused, .stopped }) |status| {
        try requireDelete(status, true);
        if (status == .stopped) {
            try requireDelete(status, false);
        } else {
            try std.testing.expectError(error.InvalidStatus, requireDelete(status, false));
        }
    }
}

test "forced delete of a missing container succeeds while ordinary delete errors" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const config: Config = .{ .root = root, .subcommand = .delete, .id = "missing" };
    try std.testing.expectError(error.FileNotFound, deleteContainer(std.testing.allocator, std.testing.io, null, config));
    var forced = config;
    forced.force = true;
    try deleteContainer(std.testing.allocator, std.testing.io, null, forced);
    for ([_]bool{ false, true }) |has_lock| {
        try tmp.dir.createDir(std.testing.io, "missing", .default_dir);
        if (has_lock) try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "missing/lock", .data = "" });
        try deleteContainer(std.testing.allocator, std.testing.io, null, forced);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "missing", .{}));
    }
}

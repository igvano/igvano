const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Backend = libcontainer.Backend;
const backendResult = @import("diagnostic.zig").backendResult;
const Config = @import("args.zig").Config;

pub fn openContainerLock(allocator: std.mem.Allocator, config: Config, create: bool) !?std.Io.File {
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

pub fn lockContainer(file: std.Io.File, blocking: bool) !bool {
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

pub fn requireLinkedLock(io: std.Io, file: std.Io.File) !void {
    if ((try file.stat(io)).nlink == 0) return error.FileNotFound;
}

pub fn deleteStateDirectory(io: std.Io, path: []const u8) !void {
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

pub fn loadSavedHooks(allocator: std.mem.Allocator, io: std.Io, config: Config) !?std.json.Parsed(oci.Spec.Hooks) {
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.hooks_file_name });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.StreamTooLong => {
            oci.recordDiagnostic(err, "saved hooks: JSON exceeds 1 MiB", .{});
            return err;
        },
        else => return err,
    };
    defer allocator.free(json);
    return std.json.parseFromSlice(oci.Spec.Hooks, allocator, json, .{ .allocate = .alloc_always }) catch |err| {
        if (err != error.OutOfMemory) oci.recordDiagnostic(err, "saved hooks: invalid JSON or schema ({s})", .{@errorName(err)});
        return err;
    };
}

pub fn loadHasProcess(allocator: std.mem.Allocator, io: std.Io, config: Config) !bool {
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.process_file_name });
    defer allocator.free(path);
    const json = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32)) catch |err| switch (err) {
        // Older state directories did not capture whether a process was configured.
        error.FileNotFound => return true,
        error.StreamTooLong => return oci.validationError(error.InvalidState, "has-process record: exceeds 32 bytes", .{}),
        else => return err,
    };
    defer allocator.free(json);
    const value = std.mem.trim(u8, json, " \t\r\n");
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return oci.validationError(error.InvalidState, "has-process record: expected true or false", .{});
}

pub fn stateHandle(allocator: std.mem.Allocator, io: std.Io, root: []const u8, state: oci.State, force_cleanup: bool) !Backend.Handle {
    const pid = state.pid orelse return oci.validationError(error.InvalidState, "state.pid: required for a live container", .{});
    if (pid <= 0) return oci.validationError(error.InvalidState, "state.pid: must be positive", .{});
    const path = try std.fs.path.join(allocator, &.{ root, state.id, oci.starttime_file_name });
    defer allocator.free(path);
    const starttime = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32)) catch |err| switch (err) {
        error.FileNotFound => return oci.validationError(error.InvalidState, "starttime record: missing for a live container", .{}),
        else => return err,
    };
    errdefer allocator.free(starttime);
    if (starttime.len == 0) return oci.validationError(error.InvalidState, "starttime record: must not be empty", .{});
    const cgroup_path = try loadCgroupPath(allocator, io, root, state.id);
    errdefer if (cgroup_path) |value| allocator.free(value);
    const systemd = try loadCleanupSystemdDriver(allocator, io, root, state.id, cgroup_path, force_cleanup);
    const rootfs_mount = try loadRootfsMount(allocator, io, root, state.id);
    return .{
        .id = state.id,
        .pid = pid,
        .starttime = starttime,
        .cgroup_path = cgroup_path,
        .systemd = systemd,
        .rootfs_mount = if (rootfs_mount) |mount| mount.path else null,
        .rootfs_mount_id = if (rootfs_mount) |mount| mount.mount_id_unique else null,
        .rootfs_mount_boot_id = if (rootfs_mount) |mount| mount.boot_id else null,
    };
}

pub fn loadDeviceNodes(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) ![]const Backend.Device {
    const path = try std.fs.path.join(allocator, &.{ root, id, "devices.json" });
    defer allocator.free(path);
    // Prepared records include defaults and fields absent from compact config.json.
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 << 20)) catch |err| switch (err) {
        error.FileNotFound => {
            // Older containers already captured their create-time config for exec.
            const saved = oci.loadSpec(allocator, io, std.fs.path.dirname(path).?) catch |load_err| switch (load_err) {
                error.FileNotFound => return &.{},
                else => return load_err,
            };
            defer saved.deinit();
            return oci.prepareDevices(allocator, if (saved.value.linux) |settings| settings.devices else null);
        },
        else => return err,
    };
    defer allocator.free(text);
    const parsed = std.json.parseFromSlice([]Backend.Device, allocator, text, .{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        return oci.validationError(error.InvalidState, "saved device nodes: invalid JSON or schema ({s})", .{@errorName(err)});
    };
    defer parsed.deinit();
    const result = try allocator.alloc(Backend.Device, parsed.value.len);
    var used: usize = 0;
    errdefer {
        for (result[0..used]) |device| allocator.free(device.path);
        allocator.free(result);
    }
    for (parsed.value, result) |device, *copy| {
        copy.* = device;
        copy.path = try allocator.dupe(u8, device.path);
        used += 1;
    }
    return result;
}

test "saved device nodes survive reload and allocation failure, with legacy snapshot fallback" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator, root: []const u8) !void {
            const nodes = try loadDeviceNodes(allocator, std.testing.io, root, "example");
            defer oci.freeDevices(allocator, nodes);
            for (nodes) |node| {
                if (std.mem.eql(u8, node.path, "/dev/custom")) {
                    try std.testing.expectEqual(Backend.Device.Kind.character, node.kind);
                    try std.testing.expectEqual(@as(u32, 10), node.major);
                    try std.testing.expectEqual(@as(u32, 237), node.minor);
                    return;
                }
            }
            return error.TestUnexpectedResult;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(root);
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/devices.json",
        .data =
        \\[{"path":"/dev/custom","kind":"character","major":10,"minor":237}]
        ,
    });
    try AllocationTest.run(allocator, root);
    try std.testing.checkAllAllocationFailures(allocator, AllocationTest.run, .{root});
    try tmp.dir.deleteFile(std.testing.io, "example/devices.json");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"devices":[{"path":"/dev/custom","type":"c","major":10,"minor":237}]}}
        ,
    });
    try AllocationTest.run(allocator, root);
    try std.testing.checkAllAllocationFailures(allocator, AllocationTest.run, .{root});
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/devices.json", .data = "{" });
    defer oci.clearDiagnostic();
    try std.testing.expectError(error.InvalidState, loadDeviceNodes(allocator, std.testing.io, root, "example"));
}

pub fn loadCgroupPath(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !?[]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, id, oci.cgroup_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(std.fs.max_path_bytes)) catch |err| switch (err) {
        // Handles from earlier runtime versions have no cgroup to clean up.
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return oci.resolveCgroupPath(allocator, bytes, id) catch |err| switch (err) {
        error.InvalidConfig => {
            return oci.validationError(error.InvalidState, "saved cgroup path: invalid or escapes the cgroup root", .{});
        },
        else => return err,
    };
}

fn loadSystemdDriver(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !bool {
    const path = try std.fs.path.join(allocator, &.{ root, id, oci.cgroup_driver_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(bytes);
    const driver = std.mem.trim(u8, bytes, " \t\r\n");
    if (std.mem.eql(u8, driver, "systemd")) return true;
    if (std.mem.eql(u8, driver, "cgroupfs")) return false;
    return oci.validationError(error.InvalidState, "saved cgroup driver: expected systemd or cgroupfs", .{});
}

pub fn loadCleanupSystemdDriver(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8, cgroup_path: ?[]const u8, force: bool) !bool {
    return loadSystemdDriver(allocator, io, root, id) catch |err| {
        if (!force or err == error.OutOfMemory) return err;
        std.debug.print("igvano: warning: cannot load cgroup driver for '{s}': {s}; checking scope ownership before systemd cleanup\n", .{ id, @errorName(err) });
        oci.clearDiagnostic();
        return inferCleanupSystemdDriver(allocator, io, root, id, cgroup_path);
    };
}

fn inferCleanupSystemdDriver(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8, cgroup_path: ?[]const u8) !bool {
    const path = cgroup_path orelse return false;
    const unit = std.fs.path.basename(path);
    const state_dir = try std.fs.path.join(allocator, &.{ root, id });
    defer allocator.free(state_dir);
    const saved_spec: ?std.json.Parsed(oci.Spec) = oci.loadSpec(allocator, io, state_dir) catch |spec_err| switch (spec_err) {
        error.OutOfMemory => return spec_err,
        error.FileNotFound => null,
        else => {
            oci.clearDiagnostic();
            return false;
        },
    };
    defer if (saved_spec) |spec| spec.deinit();
    const configured = if (saved_spec) |spec| if (spec.value.linux) |settings| settings.cgroupsPath else null else null;
    if (!try systemdUnitMatchesContainer(allocator, unit, id, configured)) return false;
    return libcontainer.systemdCgroupMatches(allocator, unit, path) catch |query_err| {
        if (query_err == error.OutOfMemory) return query_err;
        return false;
    };
}

fn systemdUnitMatchesContainer(allocator: std.mem.Allocator, unit: []const u8, id: []const u8, configured: ?[]const u8) !bool {
    const suffix = try std.fmt.allocPrint(allocator, "-{s}.scope", .{id});
    defer allocator.free(suffix);
    if (!std.mem.endsWith(u8, unit, suffix)) return false;
    const expected = oci.parseSystemdCgroupPath(allocator, configured, id) catch |err| {
        if (err == error.OutOfMemory) return err;
        oci.clearDiagnostic();
        return false;
    };
    defer expected.deinit(allocator);
    return std.mem.eql(u8, unit, expected.unit);
}

pub const RootfsMount = struct {
    path: []const u8,
    // Legacy reusable IDs never authorize cleanup.
    mount_id: ?u64 = null,
    mount_id_unique: ?u64 = null,
    boot_id: ?[36]u8 = null,
};

pub fn saveRootfsMount(allocator: std.mem.Allocator, io: std.Io, state_dir: []const u8, handle: Backend.Handle) !void {
    const mount = RootfsMount{
        .path = handle.rootfs_mount orelse return,
        .mount_id_unique = handle.rootfs_mount_id orelse return oci.validationError(error.InvalidState, "rootfs mount record: missing unique mount ID", .{}),
        .boot_id = handle.rootfs_mount_boot_id orelse return oci.validationError(error.InvalidState, "rootfs mount record: missing boot ID", .{}),
    };
    const path = try std.fs.path.join(allocator, &.{ state_dir, oci.rootfs_mount_file_name });
    defer allocator.free(path);
    const json = try std.json.Stringify.valueAlloc(allocator, mount, .{});
    defer allocator.free(json);
    try oci.atomicWrite(io, path, json);
}

pub fn loadRootfsMount(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !?RootfsMount {
    const path = try std.fs.path.join(allocator, &.{ root, id, oci.rootfs_mount_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(6 * std.fs.max_path_bytes + 128)) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.StreamTooLong => return oci.validationError(error.InvalidState, "rootfs mount record: exceeds size limit", .{}),
        else => return err,
    };
    defer allocator.free(bytes);
    // Older path-only records remain readable, but cannot authorize detach.
    if (std.fs.path.isAbsolute(bytes)) {
        if (std.mem.indexOfScalar(u8, bytes, 0) != null) return oci.validationError(error.InvalidState, "rootfs mount record: path contains NUL", .{});
        return .{ .path = try allocator.dupe(u8, bytes) };
    }
    const parsed = std.json.parseFromSlice(RootfsMount, allocator, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return oci.validationError(error.InvalidState, "rootfs mount record: invalid JSON or schema", .{}),
    };
    defer parsed.deinit();
    const mount = parsed.value;
    if (!std.fs.path.isAbsolute(mount.path) or std.mem.indexOfScalar(u8, mount.path, 0) != null or
        (mount.mount_id_unique orelse mount.mount_id orelse 0) == 0 or
        (mount.mount_id_unique != null and mount.boot_id == null))
        return oci.validationError(error.InvalidState, "rootfs mount record: requires an absolute NUL-free path, mount ID and boot ID", .{});
    return .{
        .path = try allocator.dupe(u8, mount.path),
        .mount_id_unique = mount.mount_id_unique,
        .boot_id = mount.boot_id,
    };
}

fn rootfsComparisonPath(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![:0]u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator) catch |err| switch (err) {
        error.FileNotFound => normalized: {
            const resolved = try std.fs.path.resolve(allocator, &.{path});
            defer allocator.free(resolved);
            break :normalized try allocator.dupeZ(u8, resolved);
        },
        else => return err,
    };
}

pub fn requireUnusedRootfs(allocator: std.mem.Allocator, io: std.Io, backend: Backend, root: []const u8, id: []const u8, rootfs: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const resolved = try rootfsComparisonPath(allocator, io, rootfs);
    defer allocator.free(resolved);
    var directory = try cwd.openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    // ponytail: sibling creates hold only their own locks; a sibling still in
    // creating may not have saved its mount record or PID yet (TOCTOU).
    // Corrupt siblings are skipped, so their rootfs ownership is not detected.
    // This best-effort check assumes --root is trusted runtime storage.
    var entries = directory.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory or std.mem.eql(u8, entry.name, id)) continue;
        if (!try rootfsSiblingMatches(allocator, io, root, entry.name, resolved)) continue;
        if (try rootfsSiblingAlive(allocator, io, backend, root, entry.name))
            return oci.validationError(error.InvalidConfig, "rootfs '{s}' is already used by live container '{s}' in the inherited mount namespace", .{ rootfs, entry.name });
    }
}

fn rootfsSiblingMatches(allocator: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8, resolved: []const u8) !bool {
    const mount = (loadRootfsMount(allocator, io, root, id) catch |err| {
        if (err == error.OutOfMemory) return err;
        warnRootfsSibling(id, err);
        return false;
    }) orelse return false;
    defer allocator.free(mount.path);
    const mounted_path = rootfsComparisonPath(allocator, io, mount.path) catch |err| {
        if (err == error.OutOfMemory) return err;
        warnRootfsSibling(id, err);
        return false;
    };
    defer allocator.free(mounted_path);
    return std.mem.eql(u8, mounted_path, resolved);
}

fn rootfsSiblingAlive(allocator: std.mem.Allocator, io: std.Io, backend: Backend, root: []const u8, id: []const u8) !bool {
    const saved = oci.loadState(allocator, io, root, id) catch |err| switch (err) {
        error.FileNotFound => return false, // Concurrent deletion.
        error.OutOfMemory => return err,
        else => {
            warnRootfsSibling(id, err);
            return false;
        },
    };
    defer saved.deinit();
    if (!std.mem.eql(u8, saved.value.id, id)) {
        warnRootfsSibling(id, error.InvalidState);
        return false;
    }
    if (saved.value.pid == null) return false;
    const handle = stateHandle(allocator, io, root, saved.value, false) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.OutOfMemory => return err,
        else => {
            warnRootfsSibling(id, err);
            return false;
        },
    };
    defer freeStateHandle(allocator, handle);
    return backendResult(backend, backend.alive(handle));
}

fn warnRootfsSibling(id: []const u8, err: anyerror) void {
    std.debug.print("igvano: warning: cannot check rootfs ownership for sibling '{s}': {s}; skipping\n", .{ id, @errorName(err) });
    oci.clearDiagnostic();
}

test "inherited rootfs ownership rejects live aliases and permits dead or private containers" {
    const LockTestBackend = @import("tests/helpers.zig").LockTestBackend;
    defer oci.clearDiagnostic();
    const TestBackend = struct {
        fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
            return std.mem.eql(u8, handle.starttime, "live");
        }
        fn check(allocator: std.mem.Allocator, backend: Backend, root: []const u8, rootfs: []const u8) !void {
            requireUnusedRootfs(allocator, std.testing.io, backend, root, "other", rootfs) catch |err| {
                if (err == error.OutOfMemory) return err;
                try std.testing.expectEqual(error.InvalidConfig, err);
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    try tmp.dir.createDirPath(io, "example");
    try tmp.dir.createDirPath(io, "rootfs");
    try tmp.dir.symLink(io, "rootfs", "alias", .{ .is_directory = true });
    const rootfs = try std.fs.path.join(allocator, &.{ root, "rootfs" });
    defer allocator.free(rootfs);
    const alias = try std.fs.path.join(allocator, &.{ root, "alias" });
    defer allocator.free(alias);
    const state_dir = try std.fs.path.join(allocator, &.{ root, "example" });
    defer allocator.free(state_dir);
    try saveRootfsMount(allocator, io, state_dir, .{
        .id = "example",
        .pid = 1234,
        .starttime = "live",
        .rootfs_mount = alias,
        .rootfs_mount_id = 12345,
        .rootfs_mount_boot_id = "00000000-0000-0000-0000-000000000000".*,
    });
    try tmp.dir.writeFile(io, .{ .sub_path = "example/starttime", .data = "live" });
    var implementation: LockTestBackend = .{};
    var vtable = LockTestBackend.vtable;
    vtable.alive = TestBackend.alive;
    const backend: Backend = .{ .ptr = &implementation, .vtable = &vtable };
    for ([_]oci.Status{ .creating, .created, .running, .paused }) |status| {
        try oci.saveState(allocator, io, root, .{ .id = "example", .status = status, .pid = 1234, .bundle = root });
        try TestBackend.check(allocator, backend, root, rootfs);
    }
    try std.testing.checkAllAllocationFailures(allocator, TestBackend.check, .{ backend, root, rootfs });
    try requireUnusedRootfs(allocator, io, backend, root, "example", rootfs);
    try requireUnusedRootfs(allocator, io, backend, root, "other", "/unrelated/rootfs");
    try tmp.dir.writeFile(io, .{ .sub_path = "example/starttime", .data = "dead" });
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/starttime", .data = "live" });
    const good_state = try tmp.dir.readFileAlloc(io, "example/state.json", allocator, .unlimited);
    defer allocator.free(good_state);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/state.json", .data = "{" });
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try std.testing.expect(oci.diagnostic() == null);
    try oci.saveState(allocator, io, root, .{ .id = "example", .status = .running, .pid = -1, .bundle = root });
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/state.json", .data =
        \\{"ociVersion":"1.0.2","id":"wrong","status":"running","pid":1234,"bundle":"/"}
    });
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/state.json", .data = good_state });
    try tmp.dir.deleteFile(io, "example/starttime");
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/starttime", .data = "live" });
    try TestBackend.check(allocator, backend, root, rootfs);
    try tmp.dir.writeFile(io, .{ .sub_path = "example/rootfs_mount", .data = "{" });
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.deleteFile(io, "example/rootfs_mount");
    try tmp.dir.createDir(io, "example/rootfs_mount", .default_dir);
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
    try tmp.dir.deleteDir(io, "example/rootfs_mount");
    try tmp.dir.writeFile(io, .{ .sub_path = "example/rootfs_mount", .data = alias });
    try tmp.dir.deleteFile(io, "example/rootfs_mount");
    try requireUnusedRootfs(allocator, io, backend, root, "other", rootfs);
}

fn freeStateHandle(allocator: std.mem.Allocator, handle: Backend.Handle) void {
    allocator.free(handle.starttime);
    if (handle.cgroup_path) |path| allocator.free(path);
    if (handle.rootfs_mount) |path| allocator.free(path);
}

pub const LiveState = struct {
    parsed: std.json.Parsed(oci.State),
    handle: ?Backend.Handle,
    allocator: std.mem.Allocator,

    pub fn deinit(self: LiveState) void {
        if (self.handle) |handle| freeStateHandle(self.allocator, handle);
        self.parsed.deinit();
    }
};

pub fn readLiveState(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config, persist_recovery: bool) !LiveState {
    return recoverLiveState(allocator, io, backend, config, try oci.loadState(allocator, io, config.root, config.id), persist_recovery);
}

pub fn recoverLiveState(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config, saved: std.json.Parsed(oci.State), persist_recovery: bool) !LiveState {
    var parsed = saved;
    errdefer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.id, config.id)) return oci.validationError(error.InvalidState, "state.id: does not match requested container", .{});
    var handle: ?Backend.Handle = null;
    errdefer if (handle) |value| freeStateHandle(allocator, value);
    if (parsed.value.status == .creating or parsed.value.status == .created or parsed.value.status == .running or parsed.value.status == .paused) {
        handle = try loadLiveHandle(allocator, io, config, parsed.value);
        if (handle == null or !try backendResult(backend, backend.alive(handle.?))) {
            parsed.value.status = .stopped;
            if (persist_recovery) try oci.saveState(allocator, io, config.root, parsed.value);
        } else if (parsed.value.status != .creating) {
            try recoverFrozenState(backend, config, &parsed.value, handle.?);
        }
    }
    return .{ .parsed = parsed, .handle = handle, .allocator = allocator };
}

fn loadLiveHandle(allocator: std.mem.Allocator, io: std.Io, config: Config, state: oci.State) !?Backend.Handle {
    return stateHandle(allocator, io, config.root, state, config.subcommand == .delete and config.force) catch |err| switch (err) {
        error.InvalidState => if (state.status == .creating) recovered: {
            oci.clearDiagnostic();
            break :recovered null;
        } else return err,
        else => return err,
    };
}

fn recoverFrozenState(backend: Backend, config: Config, state: *oci.State, handle: Backend.Handle) !void {
    const frozen = if (config.subcommand == .kill or (config.subcommand == .delete and config.force))
        backend.frozen(handle) catch false
    else
        try backendResult(backend, backend.frozen(handle));
    if (frozen) {
        state.status = .paused;
    } else if (state.status == .paused) {
        state.status = .running;
    }
}

test "state handle requires a nonempty starttime file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const state: oci.State = .{ .id = "example", .pid = 1234, .status = .created, .bundle = "/bundle" };
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state, false));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "" });
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state, false));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "987654321" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "/custom/from-state" });
    const handle = try stateHandle(std.testing.allocator, std.testing.io, root, state, false);
    defer freeStateHandle(std.testing.allocator, handle);
    try std.testing.expectEqualStrings("987654321", handle.starttime);
    try std.testing.expectEqualStrings("custom/from-state", handle.cgroup_path.?);
    try std.testing.expect(handle.rootfs_mount == null);
    try std.testing.expect(handle.rootfs_mount_id == null);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id_unique\":12345,\"boot_id\":\"00000000-0000-0000-0000-000000000000\"}",
    });
    const mounted_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state, false);
    defer freeStateHandle(std.testing.allocator, mounted_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", mounted_handle.rootfs_mount.?);
    try std.testing.expectEqual(@as(?u64, 12345), mounted_handle.rootfs_mount_id);
    try std.testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &mounted_handle.rootfs_mount_boot_id.?);
    // A reusable ID from older state must not be mistaken for a unique ID.
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "example/rootfs_mount",
        .data = "{\"path\":\"/bundle/rootfs\",\"mount_id\":12345}",
    });
    const old_id_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state, false);
    defer freeStateHandle(std.testing.allocator, old_id_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", old_id_handle.rootfs_mount.?);
    try std.testing.expect(old_id_handle.rootfs_mount_id == null);
    try std.testing.expect(old_id_handle.rootfs_mount_boot_id == null);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/rootfs_mount", .data = "/bundle/rootfs" });
    const legacy_handle = try stateHandle(std.testing.allocator, std.testing.io, root, state, false);
    defer freeStateHandle(std.testing.allocator, legacy_handle);
    try std.testing.expectEqualStrings("/bundle/rootfs", legacy_handle.rootfs_mount.?);
    try std.testing.expect(legacy_handle.rootfs_mount_id == null);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/rootfs_mount", .data = "relative" });
    try std.testing.expectError(error.InvalidState, stateHandle(std.testing.allocator, std.testing.io, root, state, false));
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

test "saved systemd driver survives commands without the global flag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "123" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "system.slice/test-example.scope" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup-driver", .data = "systemd\n" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const handle = try stateHandle(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .pid = 42,
        .status = .created,
        .bundle = "/bundle",
    }, false);
    defer freeStateHandle(std.testing.allocator, handle);
    try std.testing.expect(handle.systemd);
    try std.testing.expectEqualStrings("system.slice/test-example.scope", handle.cgroup_path.?);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup-driver", .data = "unknown" });
    try std.testing.expectError(error.InvalidState, loadSystemdDriver(std.testing.allocator, std.testing.io, root, "example"));
    try tmp.dir.deleteFile(std.testing.io, "example/cgroup-driver");
    try std.testing.expect(!try loadSystemdDriver(std.testing.allocator, std.testing.io, root, "example"));
}

test "inferred systemd cleanup requires the scope name create would use for this id" {
    for ([_]struct { unit: []const u8, id: []const u8 = "example", configured: ?[]const u8 = null, matches: bool = false }{
        .{ .unit = "igvano-example.scope", .matches = true },
        .{ .unit = "test-prefix-example.scope", .configured = ":test-prefix:example", .matches = true },
        .{ .unit = "test-prefix-example.scope" },
        .{ .unit = "igvano-example-other.scope", .id = "example-other", .matches = true },
        .{ .unit = "session-1.scope" },
        .{ .unit = "session-1.scope", .id = "1" },
        .{ .unit = "igvano-other.scope" },
        .{ .unit = "test-other.scope", .configured = ":test:other" },
        .{ .unit = "igvano-example-other.scope" },
        .{ .unit = "example.scope" },
        .{ .unit = "bad prefix-example.scope" },
        .{ .unit = "p" ** 242 ++ "-example.scope" },
    }) |case|
        try std.testing.expectEqual(case.matches, try systemdUnitMatchesContainer(std.testing.allocator, case.unit, case.id, case.configured));
}

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
    signal: ?[]const u8 = null,
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
            } else {
                return error.UnknownOption;
            }
        }
        if (bundle == null) bundle = ".";
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
        .signal = signal,
    };
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

fn createContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const cwd = std.Io.Dir.cwd();
    const bundle = try cwd.realPathFileAlloc(io, config.bundle orelse ".", allocator);
    defer allocator.free(bundle);
    const parsed = try oci.loadSpec(allocator, io, bundle);
    defer parsed.deinit();
    try oci.requireCreate(parsed.value);
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
    const settings = parsed.value.linux.?;
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

    try cwd.createDirPath(io, config.root);
    const root = try cwd.realPathFileAlloc(io, config.root, allocator);
    defer allocator.free(root);
    const state_dir = try std.fs.path.join(allocator, &.{ root, config.id });
    defer allocator.free(state_dir);
    cwd.createDir(io, state_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ContainerExists,
        else => return err,
    };
    errdefer cwd.deleteTree(io, state_dir) catch {};

    const cgroup_state_path = try std.fs.path.join(allocator, &.{ state_dir, oci.cgroup_file_name });
    defer allocator.free(cgroup_state_path);
    try oci.atomicWrite(io, cgroup_state_path, cgroup_path);
    const fifo = try std.fs.path.join(allocator, &.{ state_dir, oci.exec_fifo_name });
    defer allocator.free(fifo);
    try makeExecFifo(allocator, fifo);
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = config.id,
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &parsed.value,
        .mounts = mounts,
        .cgroup_path = cgroup_path,
        .cgroup_writes = cgroup_writes,
        .capabilities = capabilities,
        .rlimits = rlimits,
    });
    defer allocator.free(handle.starttime);
    errdefer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }

    const starttime_path = try std.fs.path.join(allocator, &.{ state_dir, oci.starttime_file_name });
    defer allocator.free(starttime_path);
    try oci.atomicWrite(io, starttime_path, handle.starttime);
    try oci.saveState(allocator, io, root, .{
        .id = config.id,
        .status = .created,
        .pid = handle.pid,
        .bundle = bundle,
        .annotations = parsed.value.annotations,
    });
    if (config.pid_file) |path| {
        const pid = try std.fmt.allocPrint(allocator, "{d}", .{handle.pid});
        defer allocator.free(pid);
        try oci.atomicWrite(io, path, pid);
    }
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
    return .{
        .id = state.id,
        .pid = pid,
        .starttime = starttime,
        .cgroup_path = try loadCgroupPath(allocator, io, root, state.id),
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

fn freeStateHandle(allocator: std.mem.Allocator, handle: Backend.Handle) void {
    allocator.free(handle.starttime);
    if (handle.cgroup_path) |path| allocator.free(path);
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

fn readLiveState(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !LiveState {
    var parsed = try oci.loadState(allocator, io, config.root, config.id);
    errdefer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.id, config.id)) return error.InvalidState;
    var handle: ?Backend.Handle = null;
    errdefer if (handle) |value| freeStateHandle(allocator, value);
    if (parsed.value.status == .created or parsed.value.status == .running) {
        handle = try stateHandle(allocator, io, config.root, parsed.value);
        if (!try backend.alive(handle.?)) {
            parsed.value.status = .stopped;
            try oci.saveState(allocator, io, config.root, parsed.value);
        }
    }
    return .{ .parsed = parsed, .handle = handle, .allocator = allocator };
}

fn startContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    var state = try readLiveState(allocator, io, backend, config);
    defer state.deinit();
    try oci.requireStart(state.parsed.value.status, true);
    const spec = try oci.loadSpec(allocator, io, state.parsed.value.bundle);
    defer spec.deinit();
    try oci.requireStart(state.parsed.value.status, spec.value.process != null);
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.exec_fifo_name });
    defer allocator.free(path);
    try waitForStart(allocator, io, backend, state.handle.?, path);
    state.parsed.value.status = .running;
    try oci.saveState(allocator, io, config.root, state.parsed.value);
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
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
        while (true) {
            const is_alive = try backend.alive(handle);
            const result = linux.read(fd, &byte, byte.len);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 1) {
                        if (byte[0] != 1) return error.StartFailed;
                        return;
                    }
                    // EOF also occurs before the init's blocked writer opens.
                },
                .AGAIN => {},
                .INTR => continue,
                else => return error.StartFailed,
            }
            // A short-lived init may exit after acknowledging start. Drain its
            // byte before rejecting the dead process sampled above.
            try requireStartWait(is_alive, started.untilNow(io, .awake));
            try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        }
    } else {
        return error.NotImplemented;
    }
}

fn killContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const signal = try parseSignal(config.signal);
    const state = try readLiveState(allocator, io, backend, config);
    defer state.deinit();
    try oci.requireKill(state.parsed.value.status);
    try backend.kill(state.handle.?, signal);
}

fn deleteContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const state = try readLiveState(allocator, io, backend, config);
    defer state.deinit();
    try oci.requireDelete(state.parsed.value.status);
    const cgroup_path = if (state.handle) |handle|
        handle.cgroup_path
    else
        try loadCgroupPath(allocator, io, config.root, config.id);
    defer if (state.handle == null) {
        if (cgroup_path) |path| allocator.free(path);
    };
    try backend.delete(state.handle orelse .{
        .id = state.parsed.value.id,
        .pid = state.parsed.value.pid orelse 0,
        .starttime = "",
        .cgroup_path = cgroup_path,
    });
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id });
    defer allocator.free(path);
    try std.Io.Dir.cwd().deleteTree(io, path);
}

fn stateContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const state = try readLiveState(allocator, io, backend, config);
    defer state.deinit();
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(state.parsed.value, .{ .emit_null_optional_fields = false }, &stdout.interface);
    try stdout.interface.writeByte('\n');
    try stdout.interface.flush();
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
            error.UnexpectedArgument => "unexpected argument; global flags must precede the subcommand",
            error.InvalidId => "invalid container id",
        };
        std.debug.print(
            "igvano: {s}\nUsage: igvano [--root <dir>] <state|start|delete> <id>\n" ++
                "       igvano [--root <dir>] kill <id> [signal]\n" ++
                "       igvano [--root <dir>] create [--bundle <path>] [--pid-file <file>] <id>\n",
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
    } else if (config.subcommand == .start and err == error.ProcessNotFound) {
        std.debug.print("igvano: init for '{s}' is no longer alive; start failed\n", .{config.id});
    } else if (err == error.MissingMountNamespace) {
        std.debug.print("igvano: {s} for '{s}' failed: requires a mount namespace (spec allows inheriting; unsupported here)\n", .{ @tagName(config.subcommand), config.id });
    } else {
        std.debug.print("igvano: {s} for '{s}' failed: {s}\n", .{ @tagName(config.subcommand), config.id, @errorName(err) });
    }
}
test "start wait rejects a dead init before the timeout" {
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .zero));
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .fromSeconds(10)));
}

test "start wait expires at ten seconds while allowing earlier retries" {
    try requireStartWait(true, .zero);
    try requireStartWait(true, .fromMilliseconds(9999));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromSeconds(10)));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromMilliseconds(10001)));
}

test "linux start accepts a buffered acknowledgement after init exits" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const TestBackend = struct {
        writer: std.posix.fd_t,
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
            // Model init writing its acknowledgement and exiting before start
            // samples liveness. The real FIFO still holds that acknowledgement.
            if (linux.errno(linux.write(self.writer, &.{1}, 1)) != .SUCCESS) return error.CreateFailed;
            return false;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    try makeExecFifo(std.testing.allocator, fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    const opened = linux.open(fifo_z, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.OpenFailed;
    const writer: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(writer);
    var implementation: TestBackend = .{ .writer = writer };
    try waitForStart(std.testing.allocator, std.testing.io, .{ .ptr = &implementation, .vtable = &TestBackend.vtable }, .{
        .id = "example",
        .pid = 1234,
        .starttime = "12345",
    }, fifo);
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
}

test "delete uses the persisted cgroup path and preserves state on backend failure" {
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

test "create rejects missing mount isolation before creating runtime state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"mounts":[{"destination":"/proc","type":"proc"}]}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.MissingMountNamespace, createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
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

test "create removes its new state directory when setup fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"},{"type":"network","path":"/proc/1/ns/net"}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.Unsupported else error.NotImplemented,
        createContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        }),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "create persists backend pid and absolute paths and rolls back a failed pid file" {
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
            return .{
                .id = options.id,
                .pid = 1234,
                .starttime = try options.allocator.dupe(u8, "987654321"),
                .cgroup_path = options.cgroup_path,
            };
        }

        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/test"))
                return error.InvalidPath;
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
        \\{"ociVersion":"9.9.9","root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"mount"}],"cgroupsPath":"/custom/test","resources":{"memory":{"limit":33554432},"pids":{"limit":5}}},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":1000,"gid":1000},"capabilities":{"bounding":["CAP_CHOWN","CAP_BPF"],"effective":["CAP_CHOWN"],"permitted":["CAP_CHOWN"],"inheritable":["CAP_CHOWN"],"ambient":["CAP_CHOWN"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":512}]},"mounts":[{"destination":"/a/../mnt","type":"bind","source":"source","options":["ro","rprivate"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","mode=755"]}],"annotations":{"org.example.description":"hello"}}
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

test "linux lifecycle exchanges the FIFO byte and persists running then stopped" {
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
    try makeExecFifo(std.testing.allocator, fifo);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        // Model an init waiting for the frontend's start handshake, without chroot.
        const opened = linux.open(fifo_z, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) linux.exit_group(1);
        const fd: posix.fd_t = @intCast(opened);
        if (posix.system.write(fd, &[_]u8{1}, 1) != 1) linux.exit_group(1);
        _ = linux.close(fd);
        while (true) _ = linux.pause();
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
    try std.testing.expectError(error.InvalidStatus, deleteContainer(std.testing.allocator, std.testing.io, backend, config));
    try killContainer(std.testing.allocator, std.testing.io, backend, .{ .root = root, .subcommand = .kill, .id = "example", .signal = "0" });
    try startContainer(std.testing.allocator, std.testing.io, backend, config);
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
    const stopped = try readLiveState(std.testing.allocator, std.testing.io, backend, config);
    defer stopped.deinit();
    try std.testing.expectEqual(oci.Status.stopped, stopped.parsed.value.status);
    const persisted = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer persisted.deinit();
    try std.testing.expectEqual(oci.Status.stopped, persisted.value.status);
    try std.testing.expectError(error.InvalidStatus, killContainer(std.testing.allocator, std.testing.io, backend, config));
    try deleteContainer(std.testing.allocator, std.testing.io, backend, config);
    try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
}

test "linux start rejects an absent process before opening the FIFO" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = std.os.linux.getpid(),
        .bundle = bundle,
    });
    try saveTestStarttime(root, std.os.linux.getpid());
    var implementation: backend_module.LinuxBackend = .{};
    try std.testing.expectError(error.MissingProcess, startContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .subcommand = .start,
        .id = "example",
    }));
}

test "linux state kill and delete refresh stale created and running states" {
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
    for ([_]oci.Status{ .created, .running }) |status| {
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
                    const state = try readLiveState(std.testing.allocator, std.testing.io, backend, config);
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

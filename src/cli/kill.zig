const std = @import("std");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const backendResult = @import("diagnostic.zig").backendResult;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const stateHandle = @import("state.zig").stateHandle;
const readLiveState = @import("state.zig").readLiveState;

fn parseSignal(value: ?[]const u8) !i32 {
    const text = value orelse return 15;
    if (text.len == 0) return oci.validationError(error.InvalidSignal, "signal: must not be empty", .{});
    if (std.ascii.isDigit(text[0])) {
        for (text) |byte| {
            if (!std.ascii.isDigit(byte)) return oci.validationError(error.InvalidSignal, "signal: invalid decimal number", .{});
        }
        const signal = std.fmt.parseInt(i32, text, 10) catch return oci.validationError(error.InvalidSignal, "signal: number is out of range", .{});
        if (signal >= std.os.linux.NSIG) return oci.validationError(error.InvalidSignal, "signal: number exceeds Linux signal range", .{});
        return signal;
    }
    var buffer: [16]u8 = undefined;
    if (text.len > buffer.len) return oci.validationError(error.InvalidSignal, "signal: name is too long", .{});
    for (text, 0..) |byte, i| buffer[i] = std.ascii.toUpper(byte);
    var name: []const u8 = buffer[0..text.len];
    if (std.mem.startsWith(u8, name, "SIG")) name = name[3..];
    // Use Linux numbering even when compiling the frontend's tests on macOS.
    if (std.mem.eql(u8, name, "IOT")) name = "ABRT";
    if (std.mem.eql(u8, name, "POLL")) name = "IO";
    if (std.mem.eql(u8, name, "CLD")) name = "CHLD";
    const signal = std.meta.stringToEnum(std.os.linux.SIG, name) orelse return oci.validationError(error.InvalidSignal, "signal: unknown name '{s}'", .{text});
    return @intCast(@intFromEnum(signal));
}

pub fn killContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const signal = try parseSignal(config.signal);
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const persist_recovery = if (lock) |file| try lockContainer(file, false) else true;
    if (persist_recovery) {
        if (lock) |file| try requireLinkedLock(io, file);
    } else {
        // Signal a verified init or the saved cgroup during stuck start/create.
        std.debug.print("igvano: warning: container '{s}' is busy; signalling without the lock\n", .{config.id});
    }
    var state = try readLiveState(allocator, io, backend, config, persist_recovery);
    defer state.deinit();
    if (!config.all or state.parsed.value.status != .stopped)
        oci.requireKill(state.parsed.value.status) catch return oci.validationError(error.ContainerNotRunning, "kill: container is not running", .{});
    if (config.all) {
        if (state.handle == null)
            state.handle = try stateHandle(allocator, io, config.root, state.parsed.value, false);
        try backendResult(backend, backend.killAll(state.handle.?, signal));
    } else {
        try backendResult(backend, backend.kill(state.handle.?, signal));
    }
}

test "kill reuses the handle loaded during the liveness check" {
    const TestBackend = struct {
        starttime_path: []const u8,
        cgroup_path: []const u8,
        killed: bool = false,

        const vtable: Backend.VTable = .{ .create = unusedCreate, .alive = alive, .kill = kill, .killAll = kill, .delete = unusedDelete, .frozen = frozen };

        fn unusedCreate(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn unusedDelete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
            return error.NotImplemented;
        }
        fn frozen(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return error.CgroupWriteFailed;
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

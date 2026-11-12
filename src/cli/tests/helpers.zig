const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Config = @import("../args.zig").Config;
const lockContainer = @import("../state.zig").lockContainer;
const createContainer = @import("../create.zig").createContainer;
const startContainer = @import("../start.zig").startContainer;
const execContainer = @import("../exec.zig").execContainer;
const waitExec = @import("../exec.zig").waitExec;
const deleteContainer = @import("../delete.zig").deleteContainer;
const stateContainer = @import("../state_cmd.zig").stateContainer;

pub fn runIsolatedSecurityTest(comptime run: fn ([]const u8) anyerror!void) !void {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    if (linux.errno(linux.access("/sys/fs/cgroup/cgroup.controllers", linux.F_OK)) == .SUCCESS and
        linux.errno(linux.access("/sys/fs/cgroup", linux.W_OK)) != .SUCCESS)
        return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.SystemResources;
    const child: i32 = @intCast(forked);
    if (child == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) linux.exit_group(77);
        if (linux.errno(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) != .SUCCESS)
            linux.exit_group(1);
        run(absolute) catch |err| {
            if (err == error.SkipZigTest) linux.exit_group(77);
            std.debug.print("security lifecycle test: {s}\n", .{@errorName(err)});
            if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }
    const status = try waitExec(child);
    if (status == 77) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), status);
}

pub fn readTestCgroup(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var reader = file.readerStreaming(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(4096));
}

pub fn execTestCommand(config: Config, stdout: ?std.posix.fd_t) !u8 {
    const linux = std.os.linux;
    const result = std.posix.system.fork();
    if (std.posix.errno(result) != .SUCCESS) return error.SystemResources;
    const child: i32 = @intCast(result);
    if (child == 0) {
        if (stdout) |fd| {
            if (linux.errno(linux.dup2(fd, 1)) != .SUCCESS) linux.exit_group(1);
        }
        var threaded: std.Io.Threaded = .init_single_threaded;
        const status = execContainer(std.heap.page_allocator, threaded.io(), null, config) catch linux.exit_group(1);
        linux.exit_group(status);
    }
    return waitExec(child);
}

pub fn testPtyPair() ![2]std.posix.fd_t {
    const linux = std.os.linux;
    const opened = linux.open("/dev/ptmx", .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.ConsoleFailed;
    const controller: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(controller);
    var unlock: i32 = 0;
    if (linux.errno(linux.ioctl(controller, linux.T.IOCSPTLCK, @intFromPtr(&unlock))) != .SUCCESS) return error.ConsoleFailed;
    const flags: linux.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
    const replica = linux.ioctl(controller, linux.T.IOCGPTPEER, @as(u32, @bitCast(flags)));
    if (linux.errno(replica) != .SUCCESS) return error.ConsoleFailed;
    return .{ controller, @intCast(replica) };
}

pub fn waitTestExec(io: std.Io, pid: i32) !u8 {
    const linux = std.os.linux;
    const start = std.Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).nanoseconds < std.Io.Duration.fromSeconds(5).nanoseconds) {
        var status: u32 = undefined;
        const result = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => if (result != 0) return @intCast(if (status & 0x7f == 0) (status >> 8) & 0xff else 128 + (status & 0x7f)),
            .INTR => continue,
            else => return error.WaitFailed,
        }
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
    return error.Timeout;
}

pub fn overrideContainer(implementation: anytype, container: libcontainer.Container) @import("../state.zig").ContainerOverride {
    const Implementation = @typeInfo(@TypeOf(implementation)).pointer.child;
    return .{
        .container = container,
        .state = &implementation.state,
        .create = if (@hasDecl(Implementation, "create")) Implementation.create else null,
    };
}

pub fn withState(implementation: anytype, container: libcontainer.Container, state: libcontainer.State) libcontainer.Container {
    implementation.state = state;
    return container;
}

pub const LockTestContainer = struct {
    state: libcontainer.State = undefined,
    create_pid: ?i32 = null,
    fail_create: bool = false,
    killed: bool = false,
    detail: ?[]const u8 = null,

    pub const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete, .diagnostic = diagnostic };
    pub fn create(ptr: *anyopaque, options: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        const handle: libcontainer.State = .{ .id = options.id, .pid = self.create_pid orelse return error.NotImplemented, .starttime = "alive" };
        if (options.on_create) |callback| try callback.run(callback.ptr, handle);
        if (self.fail_create) return error.CreateFailed;
        return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
    }
    pub fn alive(ptr: *anyopaque) libcontainer.Error!bool {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        const handle = self.state;
        return !self.killed and std.mem.eql(u8, handle.starttime, "alive");
    }
    pub fn kill(ptr: *anyopaque, _: i32) libcontainer.Error!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        self.killed = true;
    }
    pub fn delete(_: *anyopaque) libcontainer.Error!void {}
    fn diagnostic(ptr: *anyopaque) ?[]const u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return self.detail;
    }
};

pub const LockTestProcess = struct {
    pid: i32,
    fd: std.posix.fd_t,

    pub fn isHeld(path: []const u8) !bool {
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

    pub fn hold(path: []const u8) !LockTestProcess {
        const linux = std.os.linux;
        const path_z = try std.testing.allocator.dupeZ(u8, path);
        defer std.testing.allocator.free(path_z);
        const sockets = try libcontainer.linux.console.socketpair();
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

    pub fn command(config: Config, expected_error: ?anyerror) !LockTestProcess {
        var implementation: LockTestContainer = .{};
        return commandWithContainer(config, expected_error, overrideContainer(&implementation, .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable }));
    }

    pub fn commandWithContainer(config: Config, expected_error: ?anyerror, container: ?@import("../state.zig").ContainerOverride) !LockTestProcess {
        const linux = std.os.linux;
        const sockets = try libcontainer.linux.console.socketpair();
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
                .state => stateContainer(std.heap.page_allocator, io, container, config),
                .create => createContainer(std.heap.page_allocator, io, container, config),
                .start => startContainer(std.heap.page_allocator, io, container, config),
                .delete => deleteContainer(std.heap.page_allocator, io, container, config),
                .features, .ps, .pause, .@"resume", .kill, .update, .exec, .spec, .run, .list, .events => unreachable,
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

    pub fn readable(self: LockTestProcess, timeout_ms: i32) !bool {
        var poll = [_]std.posix.pollfd{.{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 }};
        return try std.posix.poll(&poll, timeout_ms) != 0;
    }

    pub fn expectByte(self: LockTestProcess) !void {
        try std.testing.expect(try self.readable(2000));
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try std.posix.read(self.fd, &byte));
        try std.testing.expectEqual(@as(u8, 1), byte[0]);
    }

    pub fn release(self: LockTestProcess) !void {
        try std.testing.expectEqual(@as(usize, 1), std.os.linux.write(self.fd, &.{1}, 1));
    }

    pub fn releaseAfterTimeout(self: LockTestProcess) void {
        // Bound parent-process recovery tests if an operation regresses to blocking.
        if (!(self.readable(2000) catch false)) _ = std.os.linux.write(self.fd, &.{1}, 1);
    }

    pub fn wait(self: *LockTestProcess) !void {
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

    pub fn deinit(self: *LockTestProcess) void {
        _ = std.os.linux.close(self.fd);
        if (self.pid != 0) {
            _ = std.os.linux.kill(self.pid, .KILL);
            var status: u32 = undefined;
            while (std.os.linux.errno(std.os.linux.waitpid(self.pid, &status, 0)) == .INTR) {}
        }
    }

    pub fn waitForLockFd(self: LockTestProcess, path: []const u8) !void {
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

pub fn saveTestStarttime(root: []const u8, pid: i32) !void {
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

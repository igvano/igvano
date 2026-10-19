const std = @import("std");
const builtin = @import("builtin");
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const makeExecFifo = @import("../create.zig").makeExecFifo;
const waitForStart = @import("../start.zig").waitForStart;
const saveTestStarttime = @import("helpers.zig").saveTestStarttime;

test "linux start drains buffered acknowledgements and exec failures after init exits" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const TestBackend = struct {
        writer: ?std.posix.fd_t,
        bytes: []const u8,
        opened: bool = false,

        const vtable: Backend.VTable = .{ .create = unusedCreate, .alive = alive, .kill = unusedKill, .killAll = unusedKill, .delete = unusedDelete };

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

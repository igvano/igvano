const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const diagnostics = @import("diagnostic.zig");
const backendResult = @import("diagnostic.zig").backendResult;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const loadSavedHooks = @import("state.zig").loadSavedHooks;
const loadHasProcess = @import("state.zig").loadHasProcess;
const readLiveState = @import("state.zig").readLiveState;
const runHooks = @import("hooks.zig").runHooks;
const warnHooks = @import("hooks.zig").warnHooks;
const stopContainer = @import("delete.zig").stopContainer;
const destroyContainer = @import("delete.zig").destroyContainer;

pub fn startContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
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
        // Cleanup failures must not add backend detail to this frontend failure.
        defer diagnostics.last_backend_detail = null;
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

pub fn waitForStart(allocator: std.mem.Allocator, io: std.Io, backend: Backend, handle: Backend.Handle, path: []const u8) !void {
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        const started = std.Io.Clock.awake.now(io);
        const fd: std.posix.fd_t = open: while (true) {
            try requireStartWait(try backendResult(backend, backend.alive(handle)), started.untilNow(io, .awake));
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
            const is_alive = try backendResult(backend, backend.alive(handle));
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

test "start wait rejects a dead init before the timeout" {
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .zero));
    try std.testing.expectError(error.ProcessNotFound, requireStartWait(false, .fromSeconds(10)));
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

test "start wait expires at ten seconds while allowing earlier retries" {
    try requireStartWait(true, .zero);
    try requireStartWait(true, .fromMilliseconds(9999));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromSeconds(10)));
    try std.testing.expectError(error.StartTimeout, requireStartWait(true, .fromMilliseconds(10001)));
}

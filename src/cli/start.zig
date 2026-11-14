const std = @import("std");
const builtin = @import("builtin");
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
const loadSavedHooks = @import("state.zig").loadSavedHooks;
const loadHasProcess = @import("state.zig").loadHasProcess;
const readLiveState = @import("state.zig").readLiveState;
const runHooks = @import("hooks.zig").runHooks;
const stopContainer = @import("delete.zig").stopContainer;

pub fn startContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    var lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    if (lock) |file| {
        _ = try lockContainer(file, true);
        try requireLinkedLock(io, file);
    }
    var state = try readLiveState(allocator, io, injected, config, true);
    defer state.deinit();
    var instance: ContainerInstance = undefined;
    const container = if (state.container_state) |value| bindContainer(&instance, injected, value) else null;
    try oci.requireStart(state.parsed.value.status, true);
    try oci.requireStart(state.parsed.value.status, try loadHasProcess(allocator, io, config));
    const saved_hooks = try loadSavedHooks(allocator, io, config);
    defer if (saved_hooks) |entries| entries.deinit();
    const path = try std.fs.path.join(allocator, &.{ config.root, config.id, oci.exec_fifo_name });
    defer allocator.free(path);
    if (lock) |file| try requireLinkedLock(io, file);
    try waitForStart(allocator, io, container.?, path);
    state.parsed.value.status = .running;
    if (lock) |file| try requireLinkedLock(io, file);
    try oci.saveState(allocator, io, config.root, state.parsed.value);
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    if (lock) |file| {
        file.close(io);
        lock = null;
    }
    // Like runc, a failed poststart hook stops the container and fails start.
    runHooks(allocator, if (saved_hooks) |entries| entries.value.poststart else null, state.parsed.value, "poststart") catch |err| {
        // Stopping may replace the detail; keep the hook's.
        const saved: diagnostics.SavedDetail = .save();
        defer saved.restore();
        stopContainer(io, container) catch |cleanup_err|
            std.debug.print("igvano: warning: cannot stop container after poststart failure: {s}\n", .{@errorName(cleanup_err)});
        return err;
    };
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

pub fn waitForStart(allocator: std.mem.Allocator, io: std.Io, container: libcontainer.Container, path: []const u8) !void {
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        const started = std.Io.Clock.awake.now(io);
        const fd = try openStartFifo(io, container, path_z, started);
        defer _ = linux.close(fd);
        var writer_seen = false;
        var acked = false;
        while (true) {
            const is_alive = try containerResult(container, container.alive());
            if (try readStartFifo(fd, &writer_seen, &acked) orelse continue) return;
            try requireStartProgress(io, started, is_alive, writer_seen, acked);
            try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        }
    } else {
        return error.NotImplemented;
    }
}

fn openStartFifo(io: std.Io, container: libcontainer.Container, path_z: [:0]const u8, started: std.Io.Timestamp) !std.posix.fd_t {
    const linux = std.os.linux;
    return open: while (true) {
        try requireStartWait(try containerResult(container, container.alive()), started.untilNow(io, .awake));
        const result = linux.open(path_z, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @as(std.posix.fd_t, @intCast(result)),
            .INTR => continue,
            .NOENT => return error.StartFailed,
            .ACCES, .PERM => return error.PermissionDenied,
            else => return error.StartFailed,
        }
    };
}

fn readStartFifo(fd: std.posix.fd_t, writer_seen: *bool, acked: *bool) !?bool {
    const linux = std.os.linux;
    // An ack byte, or a 0 byte followed by init's diagnostic (one write).
    var bytes: [1 + 512]u8 = undefined;
    const result = linux.read(fd, &bytes, bytes.len);
    switch (linux.errno(result)) {
        .SUCCESS => {
            if (result == 0) return try startReadComplete(writer_seen.*, acked.*, 0, 0);
            for (bytes[0..result], 0..) |byte, i| {
                if (byte == 0 and i + 1 < result)
                    return oci.validationError(error.ProcessExecFailed, "{s}", .{bytes[i + 1 .. result]});
                if (try startReadComplete(writer_seen.*, acked.*, 1, byte)) return true;
                acked.* = true;
            }
        },
        .AGAIN => writer_seen.* = true,
        .INTR => return null,
        else => return error.StartFailed,
    }
    return false;
}

fn requireStartProgress(io: std.Io, started: std.Io.Timestamp, is_alive: bool, writer_seen: bool, acked: bool) !void {
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

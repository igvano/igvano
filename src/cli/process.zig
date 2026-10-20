const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Backend = libcontainer.Backend;

pub fn prepareProcess(allocator: std.mem.Allocator, process: oci.Spec.Process, has_console: bool) !Backend.ExecOptions {
    try validateConsoleSocket(process.terminal, has_console);
    const config = oci.processConfig(process);
    return .{
        .allocator = allocator,
        .argv = config.args,
        .envp = config.env,
        .cwd = config.cwd,
        .uid = config.uid,
        .gid = config.gid,
        .additional_gids = config.additional_gids,
        .capabilities = if (process.capabilities) |caps| try oci.processCapabilities(caps) else null,
        .rlimits = try oci.processRlimits(allocator, process.rlimits),
        .no_new_privileges = config.no_new_privileges,
        .apparmor_profile = process.apparmorProfile,
        .oom_score_adj = process.oomScoreAdj,
    };
}

pub fn validateConsoleSocket(terminal: ?bool, has_console: bool) !void {
    if (terminal orelse false) {
        if (!has_console) return oci.validationError(error.MissingConsoleSocket, "process.terminal: requires --console-socket", .{});
    } else if (has_console) return oci.validationError(error.UnexpectedConsoleSocket, "--console-socket: requires process.terminal=true", .{});
}

pub fn connectConsoleSocket(path: []const u8) !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len == 0 or path.len >= address.path.len or std.mem.indexOfScalar(u8, path, 0) != null)
        return oci.validationError(error.InvalidPath, "--console-socket: path is empty, too long or contains NUL", .{});
    @memcpy(address.path[0..path.len], path);
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.ConsoleSocketFailed;
    const fd: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(fd);
    try connectConsoleSocketFd(fd, &address, @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1), linux);
    return fd;
}

fn connectConsoleSocketFd(fd: std.posix.fd_t, address: *const std.os.linux.sockaddr.un, length: std.os.linux.socklen_t, comptime system: type) !void {
    const linux = std.os.linux;
    while (true) {
        const result = system.connect(fd, address, length);
        switch (linux.errno(result)) {
            .SUCCESS, .ISCONN => return,
            .INTR, .ALREADY, .INPROGRESS => {},
            else => return error.ConsoleSocketFailed,
        }
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
        while (true) {
            switch (linux.errno(system.poll(&fds, fds.len, -1))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.ConsoleSocketFailed,
            }
        }
        var socket_error: i32 = 0;
        var length_out: linux.socklen_t = @sizeOf(i32);
        while (true) {
            switch (linux.errno(system.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&socket_error), &length_out))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.ConsoleSocketFailed,
            }
        }
        switch (@as(linux.E, @enumFromInt(socket_error))) {
            // Retry connect too: an interrupted AF_UNIX backlog wait may
            // leave an unconnected socket with SO_ERROR=0.
            .SUCCESS, .ALREADY, .INPROGRESS => continue,
            else => return error.ConsoleSocketFailed,
        }
    }
}

pub fn writePidFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, pid: i32) !void {
    const text = try std.fmt.allocPrint(allocator, "{d}", .{pid});
    defer allocator.free(text);
    try oci.atomicWrite(io, path, text);
}

test "console socket validation matches the terminal setting" {
    for ([_]?bool{ null, false, true }) |terminal| {
        for ([_]?[]const u8{ null, "/tmp/console.sock" }) |socket| {
            if ((terminal orelse false) == (socket != null)) {
                try validateConsoleSocket(terminal, socket != null);
            } else {
                try std.testing.expectError(
                    if (socket == null) error.MissingConsoleSocket else error.UnexpectedConsoleSocket,
                    validateConsoleSocket(terminal, socket != null),
                );
            }
        }
    }
}

test "console socket connect retries interruptions and checks pending errors" {
    const linux = std.os.linux;
    const System = struct {
        var connect_calls: usize = 0;
        var poll_calls: usize = 0;
        var socket_error: linux.E = .SUCCESS;

        fn failure(err: linux.E) usize {
            return @bitCast(-@as(isize, @intFromEnum(err)));
        }

        fn connect(_: i32, _: *const anyopaque, _: linux.socklen_t) usize {
            const results = [_]linux.E{ .INTR, .ALREADY, .INPROGRESS, .ISCONN };
            const result = results[@min(connect_calls, results.len - 1)];
            connect_calls += 1;
            return failure(result);
        }

        fn poll(fds: [*]linux.pollfd, count: linux.nfds_t, timeout: i32) usize {
            std.debug.assert(count == 1 and timeout == -1 and fds[0].events == linux.POLL.OUT);
            poll_calls += 1;
            if (poll_calls == 1) return failure(.INTR);
            fds[0].revents = linux.POLL.OUT;
            return 1;
        }

        fn getsockopt(_: i32, level: i32, option: u32, value: [*]u8, length: *linux.socklen_t) usize {
            std.debug.assert(level == linux.SOL.SOCKET and option == linux.SO.ERROR and length.* == @sizeOf(i32));
            const code: *i32 = @ptrCast(@alignCast(value));
            code.* = @intFromEnum(socket_error);
            return 0;
        }
    };
    const address: linux.sockaddr.un = .{ .path = @splat(0) };
    try connectConsoleSocketFd(42, &address, @sizeOf(linux.sockaddr.un), System);
    // A writable socket can still have failed asynchronously.
    System.connect_calls = 0;
    System.poll_calls = 0;
    System.socket_error = .CONNREFUSED;
    try std.testing.expectError(error.ConsoleSocketFailed, connectConsoleSocketFd(42, &address, @sizeOf(linux.sockaddr.un), System));
}

test "process validation and typed translation serve create and exec" {
    const process: oci.Spec.Process = .{
        .args = &.{ "sh", "-c", "true" },
        .env = &.{"PATH=/bin"},
        .cwd = "/",
        .user = .{ .uid = 1000, .gid = 1001, .additionalGids = &.{42} },
        .capabilities = .{ .bounding = &.{"CAP_CHOWN"} },
        .rlimits = &.{.{ .type = "RLIMIT_NOFILE", .hard = 1024, .soft = 512 }},
        .noNewPrivileges = true,
        .apparmorProfile = "igvano-deny-write",
        .oomScoreAdj = 50,
    };
    const options = try prepareProcess(std.testing.allocator, process, false);
    defer std.testing.allocator.free(options.rlimits);
    const config = oci.processConfig(process);
    try std.testing.expectEqualDeep(process.args, config.args);
    try std.testing.expectEqualDeep(process.env.?, config.env);
    try std.testing.expectEqualStrings(process.cwd, config.cwd);
    try std.testing.expectEqual(@as(u32, 1000), config.uid);
    try std.testing.expectEqual(@as(u32, 1001), config.gid);
    try std.testing.expectEqualSlices(u32, &.{42}, config.additional_gids);
    try std.testing.expect(config.no_new_privileges);
    try std.testing.expect(!config.terminal);
    const defaults = oci.processConfig(.{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } });
    try std.testing.expectEqual(@as(usize, 0), defaults.env.len);
    try std.testing.expectEqual(@as(usize, 0), defaults.additional_gids.len);
    try std.testing.expect(!defaults.terminal and !defaults.no_new_privileges);
    try std.testing.expectEqual(@as(u64, 1), options.capabilities.?.bounding);
    try std.testing.expectEqual(@as(u64, 512), options.rlimits[0].soft);
    try std.testing.expectEqual(@as(u32, 42), options.additional_gids[0]);
    try std.testing.expect(options.no_new_privileges);
    try std.testing.expectEqualStrings("igvano-deny-write", options.apparmor_profile.?);
    try std.testing.expectEqual(@as(?i32, 50), options.oom_score_adj);
    var invalid = process;
    invalid.env = &.{"NO_EQUALS"};
    try std.testing.expectError(error.InvalidProcess, oci.validateProcess(invalid));
    invalid = process;
    invalid.args = &.{"bad\x00arg"};
    try std.testing.expectError(error.InvalidProcess, oci.validateProcess(invalid));
    invalid = process;
    invalid.apparmorProfile = "bad\x00profile";
    try std.testing.expectError(error.InvalidProcess, oci.validateProcess(invalid));
    invalid = process;
    invalid.terminal = true;
    try std.testing.expect(oci.processConfig(invalid).terminal);
    try std.testing.expectError(error.MissingConsoleSocket, prepareProcess(std.testing.allocator, invalid, false));
}

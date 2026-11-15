const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");

pub fn prepareProcess(allocator: std.mem.Allocator, process: oci.Spec.Process, has_console: bool) !libcontainer.ExecOptions {
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
        .console_size = config.console_size,
        .apparmor_profile = process.apparmorProfile,
        .selinux_label = process.selinuxLabel,
        .oom_score_adj = process.oomScoreAdj,
        .cpu_affinity = try oci.cpuAffinity(process.execCPUAffinity),
        .scheduler = try oci.processScheduler(process.scheduler),
        .io_priority = try oci.processIOPriority(process.ioPriority),
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

pub fn connectPidfdSocket(path: []const u8) !std.posix.fd_t {
    return connectConsoleSocket(path) catch |err| switch (err) {
        error.InvalidPath => oci.validationError(error.InvalidPath, "--pidfd-socket: path is empty, too long or contains NUL", .{}),
        else => err,
    };
}

/// runc's --pidfd-socket: send a pidfd of `pid`, with runc's init type
/// ("standard" or "setns") as the message, like setupPidfd.
pub fn sendPidfd(path: []const u8, pid: i32, kind: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    const socket = try connectPidfdSocket(path);
    defer _ = linux.close(socket);
    const opened = linux.pidfd_open(pid, 0);
    if (linux.errno(opened) != .SUCCESS) return oci.validationError(error.PidfdFailed, "failed to pidfd_open: {s}", .{@tagName(linux.errno(opened))});
    const pidfd: std.posix.fd_t = @intCast(opened);
    defer _ = linux.close(pidfd);
    libcontainer.linux.console.sendFdWithData(socket, pidfd, kind) catch
        return oci.validationError(error.PidfdFailed, "failed to send pidfd on socket", .{});
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

/// runc's prepareEnv: keep the last value of each key, drop an empty HOME,
/// and add HOME from the container's /etc/passwd for `uid` (default "/").
/// `root` is the container root; /etc/passwd resolves inside it.
// ponytail: create reads the bundle rootfs before mounts, so a passwd file
// bind-mounted over /etc is not seen; runc reads it inside init instead.
pub fn processEnv(allocator: std.mem.Allocator, env: []const []const u8, root: []const u8, uid: u32) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    var home_seen = false;
    var home_set = false;
    var index = env.len;
    while (index > 0) {
        index -= 1;
        const entry = env[index];
        const key = entry[0 .. std.mem.indexOfScalar(u8, entry, '=') orelse entry.len];
        if (std.mem.eql(u8, key, "HOME")) {
            // The last HOME wins even when empty, which means "default".
            if (home_seen) continue;
            home_seen = true;
            if (entry.len == key.len + 1) continue;
            home_set = true;
        }
        const seen = for (out.items) |kept| {
            const kept_key = kept[0 .. std.mem.indexOfScalar(u8, kept, '=') orelse kept.len];
            if (std.mem.eql(u8, kept_key, key)) break true;
        } else false;
        if (!seen) try out.append(allocator, entry);
    }
    std.mem.reverse([]const u8, out.items);
    if (!home_set) {
        const home = (try passwdHome(allocator, root, uid)) orelse "/";
        try out.append(allocator, try std.fmt.allocPrint(allocator, "HOME={s}", .{home}));
    }
    return out.toOwnedSlice(allocator);
}

fn passwdHome(allocator: std.mem.Allocator, root: []const u8, uid: u32) !?[]const u8 {
    if (comptime builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    const dir = linux.open(root_z, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(dir));
    // openat2(RESOLVE_IN_ROOT): symlinks in the rootfs cannot reach the host.
    const How = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
    const how: How = .{ .flags = @as(u32, @bitCast(linux.O{ .CLOEXEC = true })), .resolve = 0x10 | 0x02 };
    const opened = linux.syscall4(.openat2, dir, @intFromPtr("etc/passwd"), @intFromPtr(&how), @sizeOf(How));
    if (linux.errno(opened) != .SUCCESS) return null;
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } };
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer file.close(threaded.io());
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(threaded.io(), &buffer);
    const text = reader.interface.allocRemaining(allocator, .limited(1 << 20)) catch return null;
    return passwdHomeIn(text, uid);
}

/// name:password:uid:gid:gecos:home:shell
fn passwdHomeIn(text: []const u8, uid: u32) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const id = std.fmt.parseUnsigned(u32, fields.next() orelse continue, 10) catch continue;
        if (id != uid) continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        return fields.next();
    }
    return null;
}

test "process env keeps the last value of each key and defaults HOME like runc" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const env = try processEnv(arena.allocator(), &.{ "A=1", "HOME=", "B=2", "A=3" }, "/igvano-missing-root", 0);
    try std.testing.expectEqual(@as(usize, 3), env.len);
    try std.testing.expectEqualStrings("B=2", env[0]);
    try std.testing.expectEqualStrings("A=3", env[1]);
    try std.testing.expectEqualStrings("HOME=/", env[2]);
    const reset = try processEnv(arena.allocator(), &.{ "HOME=/x", "HOME=" }, "/igvano-missing-root", 0);
    try std.testing.expectEqualStrings("HOME=/", reset[0]);
    const kept = try processEnv(arena.allocator(), &.{ "HOME=", "HOME=/x" }, "/igvano-missing-root", 0);
    try std.testing.expectEqualStrings("HOME=/x", kept[0]);
    try std.testing.expectEqualStrings("/home/t", passwdHomeIn("root:x:0:0::/root:/bin/sh\nt:x:2000:2000:t:/home/t:/bin/sh\n", 2000).?);
    try std.testing.expect(passwdHomeIn("bad\n", 1) == null);
}

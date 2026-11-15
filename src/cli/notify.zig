//! systemd's sd_notify from inside the container, like runc's
//! notify_socket.go: with $NOTIFY_SOCKET set, create and run bind the state
//! directory's notify/ into the container as /run/notify, and start relays
//! the container's READY= to the host socket with MAINPID and a barrier.
const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const linux = std.os.linux;
const posix = std.posix;

const dir_name = "notify";
const socket_name = "notify.sock";
const container_dir = "/run/notify";

/// runc's setupSpec: the bind mount and the process's NOTIFY_SOCKET.
/// `root` must be absolute; the arena owns the new slices.
pub fn addToSpec(arena: std.mem.Allocator, spec: *oci.Spec, root: []const u8, id: []const u8) !void {
    const source = try std.fs.path.join(arena, &.{ root, id, dir_name });
    var mounts: std.ArrayList(oci.Spec.Mount) = .empty;
    try mounts.appendSlice(arena, spec.mounts orelse &.{});
    try mounts.append(arena, .{
        .destination = container_dir,
        .source = source,
        .options = &.{ "bind", "nosuid", "noexec", "nodev", "ro" },
    });
    spec.mounts = mounts.items;
    if (spec.process) |*process| {
        var env: std.ArrayList([]const u8) = .empty;
        try env.appendSlice(arena, process.env orelse &.{});
        try env.append(arena, "NOTIFY_SOCKET=" ++ container_dir ++ "/" ++ socket_name);
        process.env = env.items;
    }
}

/// The bind source, made once the state directory exists.
pub fn makeDir(io: std.Io, state_dir: []const u8) !void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, "{s}/" ++ dir_name, .{state_dir});
    try std.Io.Dir.cwd().createDir(io, path, .fromMode(0o755));
}

/// The container's end: a datagram socket in the state directory.
pub const Relay = struct {
    fd: posix.fd_t,
    host: []const u8,

    /// runc's bindSocket, before start so no READY= is missed.
    pub fn bind(root: []const u8, id: []const u8, host: []const u8) !Relay {
        var address: linux.sockaddr.un = .{ .path = @splat(0) };
        const path = std.fmt.bufPrint(&address.path, "{s}/{s}/" ++ dir_name ++ "/" ++ socket_name, .{ root, id }) catch
            return oci.validationError(error.InvalidPath, "notify socket path is too long", .{});
        if (path.len >= address.path.len) return oci.validationError(error.InvalidPath, "notify socket path is too long", .{});
        const opened = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(opened) != .SUCCESS) return error.SocketFailed;
        const fd: posix.fd_t = @intCast(opened);
        errdefer _ = linux.close(fd);
        // A socket left by an earlier start of this container.
        _ = linux.unlink(@ptrCast(&address.path));
        if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.SocketFailed;
        // Any user in the container may notify, as with runc's 0777.
        if (linux.errno(linux.chmod(@ptrCast(&address.path), 0o777)) != .SUCCESS) return error.SocketFailed;
        return .{ .fd = fd, .host = host };
    }

    pub fn deinit(self: Relay) void {
        _ = linux.close(self.fd);
    }

    /// runc's notifySocket.run: wait for READY= while `watched` lives, then
    /// tell the host READY, MAINPID=`main_pid` and wait for the barrier.
    pub fn run(self: Relay, watched: i32, main_pid: i32) !void {
        var buffer: [4096]u8 = undefined;
        const ready = (try self.waitReady(watched, &buffer)) orelse return;
        const client = try connectHost(self.host);
        defer _ = linux.close(client);
        try sendLine(client, ready);
        var pid_buffer: [32]u8 = undefined;
        try sendLine(client, std.fmt.bufPrint(&pid_buffer, "MAINPID={d}", .{main_pid}) catch unreachable);
        try barrier(client);
    }

    /// The READY= line of the first datagram that has one; null once
    /// `watched` is gone.
    fn waitReady(self: Relay, watched: i32, buffer: []u8) !?[]const u8 {
        while (true) {
            // Checked every round, so a flood of datagrams cannot hide an
            // exited container.
            if (!alive(watched)) return null;
            var poll = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
            const ready = linux.poll(&poll, 1, 100);
            if (linux.errno(ready) == .INTR) continue;
            if (linux.errno(ready) != .SUCCESS) return error.SocketFailed;
            if (ready == 0) continue;
            const count = linux.recvfrom(self.fd, buffer.ptr, buffer.len, linux.MSG.DONTWAIT, null, null);
            if (linux.errno(count) != .SUCCESS) continue;
            if (readyLine(buffer[0..count])) |line| return line;
        }
    }
};

/// Like runc, only a datagram that starts with READY= counts.
fn readyLine(datagram: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, datagram, "READY=")) return null;
    return datagram[0 .. std.mem.indexOfScalar(u8, datagram, '\n') orelse datagram.len];
}

fn alive(pid: i32) bool {
    var buffer: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buffer, "/proc/{d}", .{pid}) catch unreachable;
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

/// The host's $NOTIFY_SOCKET; a leading '@' is an abstract address.
fn connectHost(host: []const u8) !posix.fd_t {
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (host.len == 0 or host.len >= address.path.len) return oci.validationError(error.InvalidPath, "NOTIFY_SOCKET: invalid path", .{});
    @memcpy(address.path[0..host.len], host);
    const abstract = host[0] == '@';
    if (abstract) address.path[0] = 0;
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(fd);
    const len = @offsetOf(linux.sockaddr.un, "path") + host.len + @intFromBool(!abstract);
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @intCast(len))) != .SUCCESS)
        return oci.validationError(error.SocketFailed, "cannot connect to NOTIFY_SOCKET {s}", .{host});
    return fd;
}

fn sendLine(fd: posix.fd_t, line: []const u8) !void {
    var buffer: [4097]u8 = undefined;
    const message = std.fmt.bufPrint(&buffer, "{s}\n", .{line}) catch return error.SocketFailed;
    if (linux.errno(linux.sendto(fd, message.ptr, message.len, 0, null, 0)) != .SUCCESS) return error.SocketFailed;
}

/// sd_notify_barrier: send BARRIER=1 with a pipe's write end, then wait up
/// to 30s for systemd to close it. A timeout is ignored, as in runc.
fn barrier(fd: posix.fd_t) !void {
    var pipe: [2]posix.fd_t = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.SocketFailed;
    defer _ = linux.close(pipe[0]);
    const Rights = @import("libcontainer").linux.console.Rights;
    var rights: Rights = std.mem.zeroes(Rights);
    rights.header = .{ .len = @import("libcontainer").linux.console.rights_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    rights.fd = pipe[1];
    const text = "BARRIER=1";
    const iov = [_]posix.iovec_const{.{ .base = text, .len = text.len }};
    const message: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &rights, .controllen = @sizeOf(Rights), .flags = 0 };
    const sent = linux.sendmsg(fd, &message, 0);
    _ = linux.close(pipe[1]);
    if (linux.errno(sent) != .SUCCESS) return error.SocketFailed;
    var poll = [_]posix.pollfd{.{ .fd = pipe[0], .events = posix.POLL.IN, .revents = 0 }};
    while (true) {
        const ready = linux.poll(&poll, 1, 30_000);
        if (linux.errno(ready) == .INTR) continue;
        if (ready == 0) {
            std.debug.print("igvano: warning: timeout after waiting 30s for barrier; ignored\n", .{});
            return;
        }
        break;
    }
    var byte: [1]u8 = undefined;
    if (linux.read(pipe[0], &byte, 1) != 0) return oci.validationError(error.SocketFailed, "unexpected read from synchronization pipe", .{});
}

test "only datagrams starting with READY= are forwarded, up to the first newline" {
    try std.testing.expectEqualStrings("READY=1", readyLine("READY=1\nSTATUS=up").?);
    try std.testing.expectEqualStrings("READY=1", readyLine("READY=1").?);
    try std.testing.expect(readyLine("STATUS=x\nREADY=1") == null);
}

test "the spec gets runc's read-only bind mount and NOTIFY_SOCKET" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" }, .process = .{ .cwd = "/", .args = &.{"sh"}, .env = &.{"A=1"} } };
    try addToSpec(arena.allocator(), &spec, "/run/igvano", "c1");
    const mount = spec.mounts.?[0];
    try std.testing.expectEqualStrings("/run/notify", mount.destination);
    try std.testing.expectEqualStrings("/run/igvano/c1/notify", mount.source.?);
    try std.testing.expectEqualStrings("ro", mount.options.?[4]);
    try std.testing.expectEqualStrings("NOTIFY_SOCKET=/run/notify/notify.sock", spec.process.?.env.?[1]);
}

test "a relay forwards READY, MAINPID and the barrier to the host socket" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, "c/notify");
    // The host side: another bound socket stands in for systemd's.
    const host = try Relay.bind(root, "c", "unused");
    defer host.deinit();
    var host_address: linux.sockaddr.un = .{ .path = @splat(0) };
    _ = try std.fmt.bufPrint(&host_address.path, "{s}/c/notify/notify.sock", .{root});
    const relay_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/r", .{root});
    defer std.testing.allocator.free(relay_root);
    try tmp.dir.createDirPath(std.testing.io, "r/c/notify");
    const relay = try Relay.bind(relay_root, "c", std.mem.sliceTo(&host_address.path, 0));
    defer relay.deinit();
    var container_address: linux.sockaddr.un = .{ .path = @splat(0) };
    _ = try std.fmt.bufPrint(&container_address.path, "{s}/c/notify/notify.sock", .{relay_root});
    const sender: posix.fd_t = @intCast(linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0));
    defer _ = linux.close(sender);
    _ = linux.sendto(sender, "STATUS=x", 8, 0, @ptrCast(&container_address), @sizeOf(linux.sockaddr.un));
    _ = linux.sendto(sender, "READY=1", 7, 0, @ptrCast(&container_address), @sizeOf(linux.sockaddr.un));
    const thread = try std.Thread.spawn(.{}, struct {
        fn run(r: Relay) void {
            r.run(linux.getpid(), 42) catch {};
        }
    }.run, .{relay});
    var buffer: [128]u8 = undefined;
    for ([_][]const u8{ "READY=1\n", "MAINPID=42\n" }) |expected| {
        const count = linux.recvfrom(host.fd, &buffer, buffer.len, 0, null, null);
        try std.testing.expectEqualStrings(expected, buffer[0..count]);
    }
    // BARRIER=1 carries the pipe; closing our copy releases the relay.
    var rights: @import("libcontainer").linux.console.Rights = undefined;
    var iov = [_]posix.iovec{.{ .base = &buffer, .len = buffer.len }};
    var message: linux.msghdr = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &rights, .controllen = @sizeOf(@TypeOf(rights)), .flags = 0 };
    const count = linux.recvmsg(host.fd, &message, linux.MSG.CMSG_CLOEXEC);
    try std.testing.expectEqualStrings("BARRIER=1", buffer[0..count]);
    _ = linux.close(rights.fd);
    thread.join();
}

test "a flood of non-READY datagrams does not hide an exited container" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, "c/notify");
    const relay = try Relay.bind(root, "c", "unused");
    defer relay.deinit();
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    _ = try std.fmt.bufPrint(&address.path, "{s}/c/notify/notify.sock", .{root});
    const sender: posix.fd_t = @intCast(linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0));
    defer _ = linux.close(sender);
    for (0..64) |_| _ = linux.sendto(sender, "STATUS=x", 8, 0, @ptrCast(&address), @sizeOf(linux.sockaddr.un));
    // A reaped child's PID is gone, as an exited container's init is.
    const child: i32 = @intCast(linux.fork());
    if (child == 0) linux.exit(0);
    var status: u32 = undefined;
    _ = linux.waitpid(child, &status, 0);
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try relay.waitReady(child, &buffer));
}

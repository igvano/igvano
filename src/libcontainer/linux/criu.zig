//! Checkpoint and restore through CRIU's RPC (`criu swrk`), like runc's
//! libcontainer/criu_linux.go. Messages follow CRIU's rpc.proto; only the
//! fields igvano sends or reads are encoded here.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const forkProcess = @import("syscall.zig").forkProcess;
const openPath = @import("syscall.zig").openPath;
const fdPath = @import("syscall.zig").fdPath;
const waitChild = @import("syscall.zig").waitChild;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const debugLog = @import("diagnostic.zig").debugLog;
const mountDestination = @import("mount.zig").mountDestination;
const console = @import("console.zig").console;

const Error = libcontainer.Error;
const Options = libcontainer.CriuOptions;

const ReqType = enum(u32) { dump = 1, restore = 2, pre_dump = 4, notify = 6, feature_check = 9, version = 10 };

/// A protobuf message under construction (proto2 wire format).
const Encoder = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn varint(self: *Encoder, value: u64) Error!void {
        var rest = value;
        while (rest >= 0x80) : (rest >>= 7) try self.bytes.append(self.allocator, @as(u8, @truncate(rest)) | 0x80);
        try self.bytes.append(self.allocator, @truncate(rest));
    }

    fn uint(self: *Encoder, field: u32, value: u64) Error!void {
        try self.varint(@as(u64, field) << 3);
        try self.varint(value);
    }

    fn boolean(self: *Encoder, field: u32, value: bool) Error!void {
        try self.uint(field, @intFromBool(value));
    }

    fn string(self: *Encoder, field: u32, value: []const u8) Error!void {
        try self.varint(@as(u64, field) << 3 | 2);
        try self.varint(value.len);
        try self.bytes.appendSlice(self.allocator, value);
    }

    /// A submessage of string fields: {1: first, 2: second}.
    fn pair(self: *Encoder, field: u32, first: []const u8, second: []const u8) Error!void {
        var sub: Encoder = .{ .allocator = self.allocator };
        try sub.string(1, first);
        try sub.string(2, second);
        try self.string(field, sub.bytes.items);
    }
};

/// One field of a received message; varints are widened to u64.
const Field = struct { number: u32, value: u64 = 0, bytes: []const u8 = "" };

const Decoder = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn varint(self: *Decoder) Error!u64 {
        var value: u64 = 0;
        var shift: u7 = 0;
        while (self.offset < self.bytes.len and shift < 64) : (shift += 7) {
            const byte = self.bytes[self.offset];
            self.offset += 1;
            value |= @as(u64, byte & 0x7f) << @intCast(shift);
            if (byte & 0x80 == 0) return value;
        }
        return error.CriuFailed;
    }

    fn next(self: *Decoder) Error!?Field {
        if (self.offset == self.bytes.len) return null;
        const key = try self.varint();
        var field: Field = .{ .number = @intCast(key >> 3 & 0x1fffffff) };
        switch (key & 7) {
            0 => field.value = try self.varint(),
            1, 5 => {
                const size: usize = if (key & 7 == 1) 8 else 4;
                if (self.bytes.len - self.offset < size) return error.CriuFailed;
                self.offset += size;
            },
            2 => {
                const len = try self.varint();
                if (len > self.bytes.len - self.offset) return error.CriuFailed;
                field.bytes = self.bytes[self.offset..][0..@intCast(len)];
                self.offset += @intCast(len);
            },
            else => return error.CriuFailed,
        }
        return field;
    }
};

/// The criu_resp fields igvano reads. Slices borrow the received message.
const Response = struct {
    type: u32 = 0,
    success: bool = false,
    cr_errno: u32 = 0,
    cr_errmsg: []const u8 = "",
    notify_script: []const u8 = "",
    notify_pid: i32 = 0,
    restore_pid: i32 = 0,
    version: u32 = 0,
    mem_track: bool = false,
    lazy_pages: bool = false,

    fn parse(bytes: []const u8) Error!Response {
        var response: Response = .{};
        var decoder: Decoder = .{ .bytes = bytes };
        while (try decoder.next()) |field| switch (field.number) {
            1 => response.type = @truncate(field.value),
            2 => response.success = field.value != 0,
            4 => if (try subField(field.bytes, 1)) |pid| {
                response.restore_pid = @bitCast(@as(u32, @truncate(pid.value)));
            },
            5 => try response.parseNotify(field.bytes),
            7 => response.cr_errno = @truncate(field.value),
            8 => try response.parseFeatures(field.bytes),
            9 => response.cr_errmsg = field.bytes,
            10 => try response.parseVersion(field.bytes),
            else => {},
        };
        return response;
    }

    fn parseNotify(self: *Response, bytes: []const u8) Error!void {
        var decoder: Decoder = .{ .bytes = bytes };
        while (try decoder.next()) |item| switch (item.number) {
            1 => self.notify_script = item.bytes,
            2 => self.notify_pid = @bitCast(@as(u32, @truncate(item.value))),
            else => {},
        };
    }

    fn parseFeatures(self: *Response, bytes: []const u8) Error!void {
        var decoder: Decoder = .{ .bytes = bytes };
        while (try decoder.next()) |item| switch (item.number) {
            1 => self.mem_track = item.value != 0,
            2 => self.lazy_pages = item.value != 0,
            else => {},
        };
    }

    fn parseVersion(self: *Response, bytes: []const u8) Error!void {
        var decoder: Decoder = .{ .bytes = bytes };
        var parts: [3]u64 = .{ 0, 0, 0 };
        while (try decoder.next()) |item| switch (item.number) {
            1 => parts[0] = item.value,
            2 => parts[1] = item.value,
            4 => parts[2] = item.value,
            else => {},
        };
        self.version = @truncate(parts[0] * 10000 + parts[1] * 100 + parts[2]);
    }
};

fn subField(bytes: []const u8, number: u32) Error!?Field {
    var decoder: Decoder = .{ .bytes = bytes };
    while (try decoder.next()) |field| if (field.number == number) return field;
    return null;
}

test "criu requests encode proto2 fields and responses decode notify, restore and version" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var encoder: Encoder = .{ .allocator = arena.allocator() };
    try encoder.uint(1, @intFromEnum(ReqType.version));
    try encoder.boolean(3, true);
    try encoder.pair(23, "/a", "/b");
    try encoder.uint(2, 300);
    try std.testing.expectEqualSlices(u8, "\x08\x0a\x18\x01\xba\x01\x08\x0a\x02/a\x12\x02/b\x10\xac\x02", encoder.bytes.items);
    // type=NOTIFY success notify{script="post-restore" pid=42} version{3.17.1} restore{pid=7}
    const reply = "\x08\x06\x10\x01\x2a\x10\x0a\x0cpost-restore\x10\x2a" ++
        "\x52\x06\x08\x03\x10\x11\x20\x01" ++ "\x22\x02\x08\x07";
    const response = try Response.parse(reply);
    try std.testing.expectEqual(@as(u32, 6), response.type);
    try std.testing.expect(response.success);
    try std.testing.expectEqualStrings("post-restore", response.notify_script);
    try std.testing.expectEqual(@as(i32, 42), response.notify_pid);
    try std.testing.expectEqual(@as(u32, 31701), response.version);
    try std.testing.expectEqual(@as(i32, 7), response.restore_pid);
    try std.testing.expectError(error.CriuFailed, Response.parse("\x0a\x05ab"));
}

/// A `criu swrk 3` process and our end of its SEQPACKET socket.
const Swrk = struct {
    pid: i32,
    socket: posix.fd_t,
    received_fd: ?posix.fd_t = null,
    buffer: [10 * 4096]u8 = undefined,

    /// criu's stdio is ours when `inherit_stdio`, otherwise /dev/null, as
    /// runc's exec.Cmd leaves it. `extra` become fds 4, 5, ... in criu.
    fn spawn(allocator: std.mem.Allocator, options: Options, inherit_stdio: bool, extra: []const posix.fd_t) Error!Swrk {
        var fds: [2]posix.fd_t = undefined;
        try checkResult(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds));
        defer closeFd(fds[1]);
        errdefer closeFd(fds[0]);
        const envp = try allocator.allocSentinel(?[*:0]const u8, options.env.len, null);
        defer allocator.free(envp);
        for (options.env, 0..) |entry, i| envp[i] = entry.ptr;
        const argv = [_:null]?[*:0]const u8{ options.path.ptr, "swrk", "3" };
        const pid = try forkProcess();
        if (pid == 0) execSwrk(options.path, &argv, envp, inherit_stdio, fds[1], extra);
        return .{ .pid = pid, .socket = fds[0] };
    }

    fn execSwrk(path: [:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, inherit_stdio: bool, server: posix.fd_t, extra: []const posix.fd_t) noreturn {
        if (!inherit_stdio) {
            const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
            if (linux.errno(null_fd) != .SUCCESS) linux.exit(127);
            for (0..3) |target| _ = linux.dup2(@intCast(null_fd), @intCast(target));
        }
        // Move every source above the targets first, so no dup2 clobbers one.
        var sources: [9]posix.fd_t = undefined;
        const count = @min(extra.len + 1, sources.len);
        for (0..count) |i| {
            const fd = if (i == 0) server else extra[i - 1];
            const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 64);
            if (linux.errno(moved) != .SUCCESS) linux.exit(127);
            sources[i] = @intCast(moved);
        }
        for (sources[0..count], 0..) |fd, i| {
            if (linux.errno(linux.dup2(fd, @intCast(3 + i))) != .SUCCESS) linux.exit(127);
        }
        _ = linux.execve(path, argv, envp);
        linux.exit(127);
    }

    fn deinit(self: *Swrk) void {
        if (self.received_fd) |fd| closeFd(fd);
        if (self.socket >= 0) closeFd(self.socket);
        // Closing the socket ends criu; reap it unless finish already did.
        if (self.pid > 0) _ = waitChild(self.pid) catch {};
    }

    fn send(self: *Swrk, bytes: []const u8) Error!void {
        while (true) {
            const result = linux.write(self.socket, bytes.ptr, bytes.len);
            switch (linux.errno(result)) {
                .SUCCESS => return if (result == bytes.len) {} else error.CriuFailed,
                .INTR => continue,
                else => {
                    reportDiagnostic("cannot send a request to criu: {s}", .{@tagName(linux.errno(result))});
                    return error.CriuFailed;
                },
            }
        }
    }

    /// One response; an SCM_RIGHTS fd arrives in received_fd.
    fn receive(self: *Swrk) Error!Response {
        var rights: console.Rights = std.mem.zeroes(console.Rights);
        var iov = [_]posix.iovec{.{ .base = &self.buffer, .len = self.buffer.len }};
        var message: linux.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &rights,
            .controllen = @sizeOf(console.Rights),
            .flags = 0,
        };
        const count = while (true) {
            const result = linux.recvmsg(self.socket, &message, linux.MSG.CMSG_CLOEXEC);
            switch (linux.errno(result)) {
                .SUCCESS => break result,
                .INTR => continue,
                else => {
                    reportDiagnostic("cannot read the criu response: {s}", .{@tagName(linux.errno(result))});
                    return error.CriuFailed;
                },
            }
        };
        if (message.controllen >= console.rights_len and rights.header.level == linux.SOL.SOCKET and rights.header.type == linux.SCM.RIGHTS)
            self.received_fd = rights.fd;
        if (count == 0) {
            reportDiagnostic("criu closed its socket unexpectedly", .{});
            return error.CriuFailed;
        }
        if (count == self.buffer.len) {
            reportDiagnostic("criu response is too large", .{});
            return error.CriuFailed;
        }
        const response = try Response.parse(self.buffer[0..count]);
        if (!response.success) {
            if (response.cr_errmsg.len != 0)
                reportDiagnostic("criu failed: type {d} errno {d}: {s}", .{ response.type, response.cr_errno, response.cr_errmsg })
            else
                reportDiagnostic("criu failed: type {s} errno {d}", .{ reqTypeName(response.type), response.cr_errno });
            return error.CriuFailed;
        }
        return response;
    }

    /// Sends the request and answers notifications until the final reply.
    fn exchange(self: *Swrk, allocator: std.mem.Allocator, request: []const u8, events: anytype) Error!Response {
        try self.send(request);
        while (true) {
            const response = try self.receive();
            if (response.type != @intFromEnum(ReqType.notify)) return response;
            defer if (self.received_fd) |fd| {
                closeFd(fd);
                self.received_fd = null;
            };
            try events.notify(response.notify_script, response.notify_pid, self.received_fd);
            var reply: Encoder = .{ .allocator = allocator };
            defer reply.bytes.deinit(allocator);
            try reply.uint(1, @intFromEnum(ReqType.notify));
            try reply.boolean(3, true);
            try self.send(reply.bytes.items);
        }
    }

    /// Closes the socket and waits for criu; a pre-dump criu may fail here.
    fn finish(self: *Swrk, require_success: bool) Error!void {
        closeFd(self.socket);
        self.socket = -1;
        const status = try waitChild(self.pid);
        self.pid = 0;
        if (require_success and status != 0) {
            reportDiagnostic("criu failed: wait status {d}", .{status});
            return error.CriuFailed;
        }
    }
};

fn reqTypeName(value: u32) []const u8 {
    return switch (value) {
        1 => "DUMP",
        2 => "RESTORE",
        4 => "PRE_DUMP",
        9 => "FEATURE_CHECK",
        10 => "VERSION",
        else => "UNKNOWN",
    };
}

const NoEvents = struct {
    fn notify(_: NoEvents, _: []const u8, _: i32, _: ?posix.fd_t) Error!void {}
};

/// CRIU's version as major*10000 + minor*100 + sublevel, like go-criu.
fn criuVersion(allocator: std.mem.Allocator, options: Options) Error!u32 {
    var swrk = try Swrk.spawn(allocator, options, false, &.{});
    defer swrk.deinit();
    var request: Encoder = .{ .allocator = allocator };
    defer request.bytes.deinit(allocator);
    try request.uint(1, @intFromEnum(ReqType.version));
    const response = swrk.exchange(allocator, request.bytes.items, NoEvents{}) catch |err| {
        reportDiagnostic("CRIU version check failed: {s}", .{@errorName(err)});
        return err;
    };
    try swrk.finish(false);
    if (response.version < 30000) {
        reportDiagnostic("CRIU version {d} must be 30000 or higher", .{response.version});
        return error.CriuFailed;
    }
    debugLog(options.debug, "Using CRIU {d}", .{response.version});
    return response.version;
}

/// runc's checkCriuFeatures: fails when CRIU lacks mem_track or lazy_pages.
fn requireFeatures(allocator: std.mem.Allocator, options: Options, mem_track: bool, lazy_pages: bool) Error!void {
    var swrk = try Swrk.spawn(allocator, options, false, &.{});
    defer swrk.deinit();
    var request: Encoder = .{ .allocator = allocator };
    defer request.bytes.deinit(allocator);
    var features: Encoder = .{ .allocator = allocator };
    defer features.bytes.deinit(allocator);
    if (mem_track) try features.boolean(1, true);
    if (lazy_pages) try features.boolean(2, true);
    try request.uint(1, @intFromEnum(ReqType.feature_check));
    try request.string(5, features.bytes.items);
    const response = try swrk.exchange(allocator, request.bytes.items, NoEvents{});
    try swrk.finish(false);
    if ((mem_track and !response.mem_track) or (lazy_pages and !response.lazy_pages)) {
        reportDiagnostic("criu is missing features: [{s}]", .{if (mem_track and !response.mem_track) "MemTrack" else "LazyPages"});
        return error.CriuFailed;
    }
}

const Directories = struct {
    image: posix.fd_t,
    work: ?posix.fd_t = null,
    log: []const u8,

    fn open(options: Options) Error!Directories {
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const image = try openDir(&path_buffer, options.image_dir);
        errdefer closeFd(image);
        const work = if (options.work_dir) |dir| try openDir(&path_buffer, dir) else null;
        return .{ .image = image, .work = work, .log = options.work_dir orelse options.image_dir };
    }

    fn openDir(buffer: []u8, path: []const u8) Error!posix.fd_t {
        const z = std.fmt.bufPrintZ(buffer, "{s}", .{path}) catch return error.InvalidPath;
        // Since a container can be C/R'ed multiple times, it may exist.
        const made = linux.mkdir(z, 0o700);
        if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) try checkResult(made);
        return openPath(linux.AT.FDCWD, z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    }

    fn close(self: Directories) void {
        closeFd(self.image);
        if (self.work) |fd| closeFd(fd);
    }
};

/// Options common to dump and restore.
fn encodeCommon(opts: *Encoder, options: Options, dirs: Directories, log_file: []const u8) Error!void {
    try opts.uint(1, @intCast(dirs.image));
    try opts.uint(9, 4);
    try opts.string(10, log_file);
    try opts.boolean(24, true);
    try opts.uint(34, @intFromEnum(options.manage_cgroups_mode));
    try opts.boolean(12, true);
    try opts.boolean(7, options.shell_job);
    try opts.boolean(5, options.tcp_established);
    try opts.boolean(4, options.ext_unix_sk);
    try opts.boolean(8, options.file_locks);
    try opts.uint(38, options.empty_ns);
    try opts.boolean(50, true);
    try opts.boolean(16, options.auto_dedup);
    try opts.boolean(48, options.lazy_pages);
    if (dirs.work) |fd| try opts.uint(17, @intCast(fd));
    if (options.config_file) |file| try opts.string(51, file);
}

fn namespaceName(kind: libcontainer.Namespace.Kind) []const u8 {
    return switch (kind) {
        .network => "net",
        .mount => "mnt",
        else => @tagName(kind),
    };
}

fn namespaceKey(kind: libcontainer.Namespace.Kind) []const u8 {
    return if (kind == .network) "extRootNetNS" else "extRootPidNS";
}

/// runc's minimum CRIU versions for external network and PID namespaces.
fn requireExternalNamespace(kind: libcontainer.Namespace.Kind, version: u32, during: []const u8) Error!void {
    if (version >= @as(u32, if (kind == .network) 31100 else 31500)) return;
    reportDiagnostic("criu lacks support for external {s} namespace during {s} (old criu version?)", .{ namespaceName(kind), during });
    return error.CriuFailed;
}

/// The path of `destination` inside `rootfs` after following symlinks, as
/// runc's securejoin gives it; the literal path when it does not exist.
fn resolvedDestination(allocator: std.mem.Allocator, root_fd: posix.fd_t, root_path: []const u8, destination: []const u8, is_file: bool, create: bool) Error![]const u8 {
    const fd = mountDestination(root_fd, destination, is_file, create) catch |err| {
        if (create) return err;
        return allocator.dupe(u8, destination);
    };
    defer closeFd(fd);
    var fd_buffer: [64]u8 = undefined;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const size = linux.readlink(fdPath(&fd_buffer, fd), &buffer, buffer.len);
    try checkResult(size);
    const resolved = buffer[0..size];
    if (!std.mem.startsWith(u8, resolved, root_path)) return allocator.dupe(u8, destination);
    const relative = resolved[root_path.len..];
    return allocator.dupe(u8, if (relative.len == 0) "/" else relative);
}

fn realPath(buffer: []u8, path: []const u8) Error![]const u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return error.InvalidPath;
    const fd = try openPath(linux.AT.FDCWD, z, .{ .PATH = true, .CLOEXEC = true });
    defer closeFd(fd);
    var fd_buffer: [64]u8 = undefined;
    const size = linux.readlink(fdPath(&fd_buffer, fd), buffer.ptr, buffer.len);
    try checkResult(size);
    return buffer[0..size];
}

fn isBind(mount: libcontainer.Mount) bool {
    return mount.flags & linux.MS.BIND != 0;
}

fn isCgroup(mount: libcontainer.Mount) bool {
    const kind = mount.type orelse return false;
    return std.mem.eql(u8, kind, "cgroup") or std.mem.eql(u8, kind, "cgroup2");
}

fn sourceIsFile(source: ?[]const u8) bool {
    const path = source orelse return false;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return false;
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, z, 0, .{ .TYPE = true }, &stat)) != .SUCCESS) return false;
    return stat.mode & linux.S.IFMT != linux.S.IFDIR;
}

/// Writes the targets of init's fds 0-2, which restore turns into
/// inherited pipes (runc's descriptors.json).
fn saveDescriptors(allocator: std.mem.Allocator, pid: i32, image: posix.fd_t) Error!void {
    var targets: [3][]const u8 = undefined;
    var buffers: [3][std.fs.max_path_bytes]u8 = undefined;
    for (&targets, &buffers, 0..) |*target, *buffer, fd| {
        var path_buffer: [64]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/fd/{d}", .{ pid, fd }) catch unreachable;
        const size = linux.readlink(path, buffer, buffer.len);
        target.* = if (linux.errno(size) == .SUCCESS) buffer[0..size] else "";
    }
    const json = try std.json.Stringify.valueAlloc(allocator, targets, .{});
    defer allocator.free(json);
    const fd = linux.openat(image, "descriptors.json", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    try checkResult(fd);
    defer closeFd(@intCast(fd));
    if (!@import("syscall.zig").writeAll(@intCast(fd), json)) return error.CriuFailed;
}

/// runc's logCriuErrors: quote the log lines mentioning an error.
fn logErrors(dir: []const u8, file: []const u8) void {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "{s}/{s}", .{ dir, file }) catch return;
    const fd = openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return;
    defer closeFd(fd);
    var buffer: [64 * 1024]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const count = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(count) != .SUCCESS or count == 0) break;
        used += count;
    }
    std.debug.print("igvano: warning: --- Quoting \"{s}\"\n", .{path});
    var lines = std.mem.splitScalar(u8, buffer[0..used], '\n');
    var number: usize = 0;
    while (lines.next()) |line| {
        number += 1;
        if (std.mem.indexOf(u8, line, "Error") != null) std.debug.print("igvano: warning: {d}:{s}\n", .{ number, line });
    }
}

/// runc's Checkpoint. The caller destroys the container afterwards unless
/// leave_running or pre_dump.
pub fn checkpoint(allocator: std.mem.Allocator, target: libcontainer.Checkpoint) Error!void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const options = target.criu;
    const version = try criuVersion(a, options);
    const dirs = try Directories.open(options);
    defer dirs.close();
    var opts: Encoder = .{ .allocator = a };
    try encodeCommon(&opts, options, dirs, "dump.log");
    try encodeDump(a, &opts, target, version);
    if (options.pre_dump) try requireFeatures(a, options, true, false);
    if (options.lazy_pages) {
        try requireFeatures(a, options, false, true);
        // For criu 3.15+, the status-ready notification writes the fd.
        if (options.status_fd) |fd| if (version < 31500) try opts.uint(49, @intCast(fd));
    }
    if (!options.pre_dump) {
        try dumpMounts(a, &opts, target);
        try saveDescriptors(a, target.pid, dirs.image);
    }
    var request: Encoder = .{ .allocator = a };
    try request.uint(1, @intFromEnum(if (options.pre_dump) ReqType.pre_dump else ReqType.dump));
    try request.string(2, opts.bytes.items);
    var swrk = try Swrk.spawn(a, options, false, &.{});
    defer swrk.deinit();
    var events: DumpEvents = .{ .status_fd = if (version >= 31500) options.status_fd else null };
    errdefer logErrors(dirs.log, "dump.log");
    _ = try swrk.exchange(a, request.bytes.items, &events);
    try swrk.finish(!options.pre_dump);
}

/// Dump-only options: the target, external namespaces, freezer, page
/// server and pre-dump parent.
fn encodeDump(a: std.mem.Allocator, opts: *Encoder, target: libcontainer.Checkpoint, version: u32) Error!void {
    const options = target.criu;
    try opts.string(13, target.rootfs);
    try opts.uint(2, @intCast(target.pid));
    try opts.boolean(3, options.leave_running);
    try opts.boolean(46, options.tcp_skip_in_flight);
    try opts.boolean(18, options.link_remap);
    for (target.namespaces) |namespace| {
        if (namespace.kind != .network and namespace.kind != .pid) continue;
        try requireExternalNamespace(namespace.kind, version, "checkpointing process");
        const path = namespace.path orelse continue;
        var stat: linux.Statx = undefined;
        try checkResult(linux.statx(linux.AT.FDCWD, try a.dupeZ(u8, path), 0, .{ .INO = true }, &stat));
        try opts.string(37, try std.fmt.allocPrint(a, "{s}[{d}]:{s}", .{ namespaceName(namespace.kind), stat.ino, namespaceKey(namespace.kind) }));
    }
    // Note cgroup v2 freezer is only supported since CRIU release 3.14.
    if (target.freeze_cgroup) |path| if (version >= 31400) try opts.string(44, path);
    if (options.page_server) |server| {
        var ps: Encoder = .{ .allocator = a };
        try ps.string(1, server.address);
        try ps.uint(2, @intCast(server.port));
        try opts.string(11, ps.bytes.items);
    }
    if (options.parent_image) |parent| {
        try opts.string(14, parent);
        try opts.boolean(15, true);
    }
}

const DumpEvents = struct {
    status_fd: ?posix.fd_t,

    fn notify(self: *DumpEvents, script: []const u8, _: i32, _: ?posix.fd_t) Error!void {
        if (!std.mem.eql(u8, script, "status-ready")) return;
        // Tell the waiting side that the lazy-pages server is ready.
        const fd = self.status_fd orelse return;
        _ = linux.write(fd, "\x00", 1);
        closeFd(fd);
        self.status_fd = null;
    }
};

/// External bind mounts, masked files and device nodes, keyed by their
/// resolved path in the rootfs, like runc's addCriuDumpMount.
fn dumpMounts(a: std.mem.Allocator, opts: *Encoder, target: libcontainer.Checkpoint) Error!void {
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try realPath(&root_buffer, target.rootfs);
    var z_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_fd = try openPath(linux.AT.FDCWD, std.fmt.bufPrintZ(&z_buffer, "{s}", .{root_path}) catch return error.InvalidPath, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    for (target.mounts) |mount| {
        if (!isBind(mount)) continue;
        const key = try resolvedDestination(a, root_fd, root_path, mount.destination, sourceIsFile(mount.source), false);
        try opts.pair(23, key, key);
    }
    for (target.masked_paths) |path| {
        var stat: linux.Statx = undefined;
        const proc_path = std.fmt.bufPrintZ(&z_buffer, "/proc/{d}/root/{s}", .{ target.pid, path }) catch continue;
        if (linux.errno(linux.statx(linux.AT.FDCWD, proc_path, 0, .{ .TYPE = true }, &stat)) != .SUCCESS) continue;
        if (stat.mode & linux.S.IFMT == linux.S.IFDIR) continue;
        try opts.pair(23, path, "/dev/null");
    }
    for (target.devices) |device| {
        const key = try resolvedDestination(a, root_fd, root_path, device.path, true, false);
        try opts.pair(23, key, key);
    }
}

/// What restore reports to its caller, which owns cgroups and state.
pub const RestoreEvents = struct {
    ptr: *anyopaque,
    /// criu is running and waits for its request: place it in the cgroup.
    started: *const fn (ptr: *anyopaque, criu_pid: i32) Error!void,
    /// The container's init exists (setup-namespaces, then post-restore).
    restored: *const fn (ptr: *anyopaque, pid: i32) Error!void,
};

pub const RestoreTarget = struct {
    rootfs: []const u8,
    mounts: []const libcontainer.Mount,
    masked_paths: []const []const u8,
    devices: []const libcontainer.Device,
    namespaces: []const libcontainer.Namespace,
};

/// runc's Restore through `criu swrk`, with criu's stdio as ours. Returns
/// the restored init, a child of this process (rst_sibling).
pub fn restore(allocator: std.mem.Allocator, settings: *const libcontainer.Restore, target: RestoreTarget, events: RestoreEvents) Error!i32 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const options = settings.criu;
    const version = try criuVersion(a, options);
    if ((options.lsm_profile != null or options.lsm_mount_context != null) and version < 31600) {
        reportDiagnostic("--lsm-profile and --lsm-mount-context require at least CRIU 3.16", .{});
        return error.CriuFailed;
    }
    const dirs = try Directories.open(options);
    defer dirs.close();
    var root = try CriuRoot.mount(a, settings.criu_root, target.rootfs);
    defer root.unmount();
    var opts: Encoder = .{ .allocator = a };
    try encodeCommon(&opts, options, dirs, "restore.log");
    try opts.string(13, root.path);
    try opts.boolean(6, true);
    try opts.boolean(26, true);
    if (options.lsm_profile) |profile| try opts.string(53, profile);
    if (options.lsm_mount_context) |context| try opts.string(63, context);
    var extra: std.ArrayList(posix.fd_t) = .empty;
    defer for (extra.items) |fd| closeFd(fd);
    try restoreNamespaces(a, &opts, target.namespaces, version, &extra);
    var mounts: TemporaryMounts = .{};
    defer mounts.unmount();
    try prepareRestoreMounts(a, &opts, target, &mounts);
    try inheritPipes(a, &opts, dirs.image);
    var swrk = try Swrk.spawn(a, options, true, extra.items);
    defer swrk.deinit();
    try events.started(events.ptr, swrk.pid);
    try cgroupRoots(a, &opts, swrk.pid);
    var request: Encoder = .{ .allocator = a };
    try request.uint(1, @intFromEnum(ReqType.restore));
    try request.string(2, opts.bytes.items);
    var handler: RestoreHandler = .{ .events = events, .console_socket = settings.console_socket };
    errdefer logErrors(dirs.log, "restore.log");
    const response = try swrk.exchange(a, request.bytes.items, &handler);
    try swrk.finish(true);
    const pid = if (handler.pid != 0) handler.pid else response.restore_pid;
    if (pid <= 0) {
        reportDiagnostic("criu did not report the restored process", .{});
        return error.CriuFailed;
    }
    if (handler.pid == 0) try events.restored(events.ptr, pid);
    return pid;
}

const RestoreHandler = struct {
    events: RestoreEvents,
    console_socket: ?posix.fd_t,
    pid: i32 = 0,

    fn notify(self: *RestoreHandler, script: []const u8, pid: i32, fd: ?posix.fd_t) Error!void {
        if (std.mem.eql(u8, script, "setup-namespaces") or std.mem.eql(u8, script, "post-restore")) {
            if (self.pid != 0 or pid <= 0) return;
            self.pid = pid;
            return self.events.restored(self.events.ptr, pid);
        }
        if (std.mem.eql(u8, script, "orphan-pts-master")) {
            const controller = fd orelse return error.CriuFailed;
            const socket = self.console_socket orelse {
                reportDiagnostic("restoring a terminal requires --console-socket", .{});
                return error.ConsoleFailed;
            };
            try console.sendFd(socket, controller);
        }
    }
};

/// CRIU wants its root to be a mount point whose parent is not overmounted.
const CriuRoot = struct {
    path: [:0]const u8,

    fn mount(a: std.mem.Allocator, path: []const u8, rootfs: []const u8) Error!CriuRoot {
        const root = try a.dupeZ(u8, path);
        try checkResult(linux.mkdir(root, 0o755));
        errdefer _ = linux.rmdir(root);
        const source = try a.dupeZ(u8, rootfs);
        try checkResult(linux.mount(source, root, null, linux.MS.BIND | linux.MS.REC, 0));
        return .{ .path = root };
    }

    fn unmount(self: *CriuRoot) void {
        _ = linux.umount2(self.path, linux.MNT.DETACH);
        _ = linux.rmdir(self.path);
    }
};

/// Bind mounts made so nested mountpoints can be created, undone after.
const TemporaryMounts = struct {
    paths: [64][:0]const u8 = undefined,
    len: usize = 0,

    fn unmount(self: *TemporaryMounts) void {
        var i = self.len;
        while (i > 0) {
            i -= 1;
            _ = linux.umount2(self.paths[i], linux.MNT.DETACH);
        }
    }
};

fn onTmpfs(path: []const u8, mounts: []const libcontainer.Mount) bool {
    for (mounts) |mount| {
        const kind = mount.type orelse continue;
        if (!std.mem.eql(u8, kind, "tmpfs")) continue;
        if (std.mem.startsWith(u8, path, mount.destination) and path.len > mount.destination.len and path[mount.destination.len] == '/') return true;
    }
    return false;
}

/// runc's prepareCriuRestoreMounts and addCriuRestoreMount: create missing
/// mountpoints like create does, and map bind mounts to their sources.
fn prepareRestoreMounts(a: std.mem.Allocator, opts: *Encoder, target: RestoreTarget, temporary: *TemporaryMounts) Error!void {
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try realPath(&root_buffer, target.rootfs);
    const root_fd = try openPath(linux.AT.FDCWD, try a.dupeZ(u8, root_path), .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root_fd);
    for (target.mounts) |mount| {
        // cgroup mountpoints appear with /sys; CRIU restores tmpfs contents.
        if (isCgroup(mount) or onTmpfs(mount.destination, target.mounts)) continue;
        const is_file = isBind(mount) and sourceIsFile(mount.source);
        const key = try resolvedDestination(a, root_fd, root_path, mount.destination, is_file, true);
        if (!isBind(mount)) continue;
        const source = mount.source orelse continue;
        try opts.pair(23, key, source);
        if (temporary.len == temporary.paths.len) return error.SystemResources;
        const destination = try std.fmt.allocPrintSentinel(a, "{s}{s}", .{ root_path, key }, 0);
        try checkResult(linux.mount(try a.dupeZ(u8, source), destination, null, linux.MS.BIND | linux.MS.REC, 0));
        temporary.paths[temporary.len] = destination;
        temporary.len += 1;
    }
    if (target.masked_paths.len != 0) try opts.pair(23, "/dev/null", "/dev/null");
    for (target.devices) |device| try opts.pair(23, device.path, device.path);
}

/// runc's handleRestoringNamespaces: net and pid namespaces given by path are
/// external and passed as fds; others are joined by CRIU.
fn restoreNamespaces(a: std.mem.Allocator, opts: *Encoder, namespaces: []const libcontainer.Namespace, version: u32, extra: *std.ArrayList(posix.fd_t)) Error!void {
    for (namespaces) |namespace| {
        if (namespace.kind == .network or namespace.kind == .pid) {
            try requireExternalNamespace(namespace.kind, version, "the restoration process");
            const path = namespace.path orelse continue;
            const fd = openPath(linux.AT.FDCWD, try a.dupeZ(u8, path), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch {
                reportDiagnostic("Requested network namespace {s} does not exist", .{path});
                return error.InvalidConfig;
            };
            extra.append(a, fd) catch |err| {
                closeFd(fd);
                return err;
            };
            var inherit: Encoder = .{ .allocator = a };
            try inherit.string(1, namespaceKey(namespace.kind));
            // 0-2 are stdio and 3 is the swrk socket.
            try inherit.uint(2, 3 + extra.items.len);
            try opts.string(27, inherit.bytes.items);
            continue;
        }
        const path = namespace.path orelse continue;
        if (namespace.kind == .cgroup) {
            reportDiagnostic("Do not know how to handle namespace cgroup", .{});
            return error.InvalidConfig;
        }
        try opts.pair(39, namespaceName(namespace.kind), path);
    }
}

/// Pipes from descriptors.json become criu's own stdio in the restored init.
fn inheritPipes(a: std.mem.Allocator, opts: *Encoder, image: posix.fd_t) Error!void {
    const fd = linux.openat(image, "descriptors.json", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    checkResult(fd) catch |err| {
        reportDiagnostic("cannot open descriptors.json in the image directory: {s}", .{@tagName(linux.errno(fd))});
        return err;
    };
    defer closeFd(@intCast(fd));
    var buffer: [3 * std.fs.max_path_bytes + 64]u8 = undefined;
    const count = linux.read(@intCast(fd), &buffer, buffer.len);
    try checkResult(count);
    const parsed = std.json.parseFromSliceLeaky([]const []const u8, a, buffer[0..count], .{}) catch {
        reportDiagnostic("descriptors.json: invalid JSON", .{});
        return error.CriuFailed;
    };
    for (parsed, 0..) |target, i| {
        if (std.mem.indexOf(u8, target, "pipe:") == null) continue;
        var inherit: Encoder = .{ .allocator = a };
        try inherit.string(1, target);
        try inherit.uint(2, i);
        try opts.string(27, inherit.bytes.items);
    }
}

/// runc's criuApplyCgroups: every hierarchy criu is in becomes a cg_root.
fn cgroupRoots(a: std.mem.Allocator, opts: *Encoder, pid: i32) Error!void {
    var buffer: [4096]u8 = undefined;
    const text = try @import("proc.zig").readProcFileAt(linux.AT.FDCWD, pid, "cgroup", &buffer);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.splitScalar(u8, line, ':');
        _ = parts.next();
        const controllers = parts.next() orelse continue;
        const path = parts.rest();
        var names = std.mem.splitScalar(u8, controllers, ',');
        while (names.next()) |name| {
            var root: Encoder = .{ .allocator = a };
            try root.string(1, name);
            try root.string(2, path);
            try opts.string(25, root.bytes.items);
        }
    }
}

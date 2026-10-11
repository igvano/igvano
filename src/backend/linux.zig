const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../backend.zig").Backend;
const oci = @import("../oci.zig");

/// Pure translation and validation; Linux flag constants are available on macOS too.
pub fn namespaceFlags(config: ?oci.Spec.Linux) Backend.Error!usize {
    const settings = config orelse return 0;
    const namespaces = settings.namespaces orelse return 0;
    var flags: usize = 0;
    var seen: usize = 0;
    for (namespaces) |namespace| {
        const flag: usize = switch (namespace.type) {
            .pid => linux.CLONE.NEWPID,
            .network => linux.CLONE.NEWNET,
            .mount => linux.CLONE.NEWNS,
            .ipc => linux.CLONE.NEWIPC,
            .uts => linux.CLONE.NEWUTS,
            .user => return error.Unsupported,
            .cgroup => linux.CLONE.NEWCGROUP,
            .time => linux.CLONE.NEWTIME,
        };
        if (seen & flag != 0) return error.InvalidConfig;
        seen |= flag;
        if (namespace.path != null) return error.Unsupported;
        flags |= flag;
    }
    return flags;
}

pub const LinuxBackend = struct {
    pub fn backend(self: *LinuxBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .create = create,
        .alive = alive,
        .kill = kill,
        .delete = delete,
    };

    fn create(_: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
        if (comptime builtin.os.tag == .linux) {
            const flags = try namespaceFlags(options.spec.linux);
            if (options.spec.hostname != null and flags & linux.CLONE.NEWUTS == 0)
                return error.InvalidConfig;
            if (options.spec.process) |process| {
                if (process.terminal orelse false) return error.Unsupported;
                if (process.args.len == 0) return error.InvalidProcess;
            }
            if (!std.fs.path.isAbsolute(options.exec_fifo) or
                std.mem.indexOfScalar(u8, options.exec_fifo, 0) != null)
                return error.InvalidPath;

            // All allocation and string termination happen before either fork.
            var arena: std.heap.ArenaAllocator = .init(options.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            const fifo = try allocator.dupeZ(u8, options.exec_fifo);
            const rootfs = try processString(allocator, options.rootfs);
            const cwd = try processString(allocator, if (options.spec.process) |process| process.cwd else "/");
            // chroot does not reset cwd; relative paths could retain a host cwd.
            if (!std.fs.path.isAbsolute(cwd)) return error.InvalidProcess;
            // Validate the host path before create can report success.
            const host_cwd = try std.fs.path.join(allocator, &.{ rootfs, cwd });
            try checkResult(linux.access(try allocator.dupeZ(u8, host_cwd), linux.F_OK));
            const args: []const []const u8 = if (options.spec.process) |process| process.args else &.{};
            const env: []const []const u8 = if (options.spec.process) |process| process.env orelse &.{} else &.{};
            const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);
            for (args, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
            const envp = try allocator.allocSentinel(?[*:0]const u8, env.len, null);
            for (env, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;

            const report = try makePipe();
            const ready = makePipe() catch |err| {
                for (report) |fd| closeFd(fd);
                return err;
            };
            const child1 = forkProcess() catch |err| {
                for (report) |fd| closeFd(fd);
                for (ready) |fd| closeFd(fd);
                return err;
            };
            if (child1 == 0) {
                closeFd(report[0]);
                if (flags != 0) checkResult(linux.unshare(flags)) catch |err| failCreate(report[1], err);
                // NEWPID affects the next fork, making child2 pid 1 inside the namespace.
                const child2 = forkProcess() catch |err| failCreate(report[1], err);
                if (child2 == 0) {
                    // ponytail: a create that dies mid-flight can leak a blocked init.
                    // PDEATHSIG races with child1's normal exit; fix with a parent pidfd watch.
                    closeFd(report[1]);
                    closeFd(ready[0]);
                    runInit(options.spec, flags, rootfs, cwd, fifo, argv.ptr, envp.ptr, ready[1]);
                }
                closeFd(ready[1]);
                var byte: [1]u8 = undefined;
                const initialized = readAll(ready[0], &byte);
                closeFd(ready[0]);
                if (!initialized) {
                    _ = waitChild(child2) catch {};
                    failCreate(report[1], error.CreateFailed);
                }
                var response: CreateResponse = .{ .pid = child2 };
                if (!writeAll(report[1], std.mem.asBytes(&response))) {
                    _ = linux.kill(child2, .KILL);
                    _ = waitChild(child2) catch {};
                    linux.exit_group(1);
                }
                // No shim: exiting child1 reparents the blocked init to host init.
                linux.exit_group(0);
            }

            closeFd(report[1]);
            for (ready) |fd| closeFd(fd);
            defer closeFd(report[0]);
            var response: CreateResponse = .{};
            const reported = readAll(report[0], std.mem.asBytes(&response));
            const status = waitChild(child1) catch |err| {
                if (reported and response.pid > 0) _ = linux.kill(response.pid, .KILL);
                return err;
            };
            if (!reported) return error.CreateFailed;
            if (response.failure != 0) return @errorCast(@errorFromInt(@as(u16, @intCast(response.failure))));
            if (status != 0 or response.pid <= 0) {
                if (response.pid > 0) _ = linux.kill(response.pid, .KILL);
                return error.CreateFailed;
            }
            return .{ .id = options.id, .pid = response.pid };
        } else {
            return error.NotImplemented;
        }
    }

    fn alive(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            return switch (linux.errno(linux.kill(handle.pid, @enumFromInt(0)))) {
                .SUCCESS, .PERM => true,
                .SRCH => false,
                else => error.LivenessFailed,
            };
        } else {
            return error.NotImplemented;
        }
    }

    fn kill(_: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        if (comptime builtin.os.tag == .linux) {
            if (handle.pid <= 0) return error.InvalidProcess;
            if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
            switch (linux.errno(linux.kill(handle.pid, @enumFromInt(@as(u32, @intCast(signal)))))) {
                .SUCCESS => {},
                .SRCH => return error.ProcessNotFound,
                .PERM => return error.PermissionDenied,
                else => return error.KillFailed,
            }
        } else {
            return error.NotImplemented;
        }
    }

    fn delete(_: *anyopaque, _: Backend.Handle) Backend.Error!void {
        if (comptime builtin.os.tag == .linux) {
            // No backend resources to clean up until cgroups are implemented.
            // The frontend owns and removes the runtime state directory.
        } else {
            return error.NotImplemented;
        }
    }
};

const CreateResponse = extern struct {
    pid: i32 = 0,
    failure: u32 = 0,
};

fn processString(allocator: std.mem.Allocator, value: []const u8) Backend.Error![:0]u8 {
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidProcess;
    return allocator.dupeZ(u8, value);
}

fn checkResult(result: usize) Backend.Error!void {
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .AGAIN, .MFILE, .NFILE => return error.SystemResources,
        .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

// Zig 0.16 exposes fork/pipe/waitpid through std.posix.system.
fn forkProcess() Backend.Error!i32 {
    const result = posix.system.fork();
    switch (posix.errno(result)) {
        .SUCCESS => return @intCast(result),
        .NOMEM, .AGAIN => return error.SystemResources,
        .NOSYS => return error.Unsupported,
        else => return error.CreateFailed,
    }
}

fn makePipe() Backend.Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    switch (posix.errno(posix.system.pipe2(&fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => return fds,
        .MFILE, .NFILE => return error.SystemResources,
        else => return error.CreateFailed,
    }
}

fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

fn waitChild(pid: i32) Backend.Error!u32 {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => return @bitCast(status),
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

fn readAll(fd: posix.fd_t, bytes: []u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = posix.system.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn failCreate(fd: posix.fd_t, err: Backend.Error) noreturn {
    var response: CreateResponse = .{ .failure = @intFromError(err) };
    _ = writeAll(fd, std.mem.asBytes(&response));
    linux.exit_group(1);
}

fn runInit(
    spec: *const oci.Spec,
    flags: usize,
    rootfs: [:0]const u8,
    cwd: [:0]const u8,
    fifo: [:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    ready_fd: posix.fd_t,
) noreturn {
    // Chroot-only filesystem isolation: no mount namespace cleanup, mounts, or cgroups.
    // pivot_root comes in a later milestone.
    if (flags & linux.CLONE.NEWUTS != 0) {
        if (spec.hostname) |hostname| {
            // Zig 0.16 has no sethostname wrapper.
            checkResult(linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len)) catch linux.exit_group(1);
        }
    }
    if (!writeAll(ready_fd, &.{1})) linux.exit_group(1);
    closeFd(ready_fd);

    // O_WRONLY blocks until start opens a reader; the byte acknowledges that start.
    const fd: posix.fd_t = open: while (true) {
        const result = linux.open(fifo, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break :open @intCast(result),
            .INTR => continue,
            else => linux.exit_group(1),
        }
    };
    if (!writeAll(fd, &.{1})) linux.exit_group(1);
    closeFd(fd);
    checkResult(linux.chroot(rootfs)) catch linux.exit_group(1);
    checkResult(linux.chdir(cwd)) catch linux.exit_group(1);
    // A process-less config can be created; it cannot be started.
    const process = spec.process orelse linux.exit_group(1);
    // Replace inherited groups and set the primary GID before dropping UID privileges.
    const groups = process.user.additionalGids orelse &.{};
    checkResult(linux.setgroups(groups.len, groups.ptr)) catch linux.exit_group(1);
    checkResult(linux.setgid(process.user.gid)) catch linux.exit_group(1);
    checkResult(linux.setuid(process.user.uid)) catch linux.exit_group(1);
    if (process.noNewPrivileges) {
        checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(1);
    }
    // Linux CLOSE_RANGE_CLOEXEC is 1 << 2; Zig 0.16's packed flags use 1 << 1.
    checkResult(linux.syscall3(.close_range, 3, std.math.maxInt(u32), 1 << 2)) catch linux.exit_group(1);
    execProcess(argv, envp);
}

fn execProcess(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) noreturn {
    const executable = argv[0] orelse linux.exit_group(1);
    const name = std.mem.span(executable);
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        _ = linux.execve(executable, argv, envp);
        linux.exit_group(1);
    }
    var path: []const u8 = "/bin:/usr/bin";
    var index: usize = 0;
    while (envp[index]) |entry| : (index += 1) {
        const variable = std.mem.span(entry);
        if (std.mem.startsWith(u8, variable, "PATH=")) {
            path = variable["PATH=".len..];
            break;
        }
    }
    // Lookup happens inside the chroot, without allocating after fork.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    var directories = std.mem.splitScalar(u8, path, ':');
    while (directories.next()) |directory| {
        const candidate = if (directory.len == 0) executable else (std.fmt.bufPrintZ(&buffer, "{s}/{s}", .{ directory, name }) catch continue).ptr;
        switch (linux.errno(linux.execve(candidate, argv, envp))) {
            .NOENT, .NOTDIR, .ACCES => continue,
            else => linux.exit_group(1),
        }
    }
    linux.exit_group(1);
}

test "linux backend is unavailable on other platforms" {
    if (comptime builtin.os.tag == .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234 };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.NotImplemented, backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = "/tmp/bundle/rootfs",
            .exec_fifo = "/tmp/containers/example/exec.fifo",
            .spec = &spec,
        }));
    }
    try std.testing.expectError(error.NotImplemented, backend.alive(handle));
    try std.testing.expectError(error.NotImplemented, backend.kill(handle, 15));
    try std.testing.expectError(error.NotImplemented, backend.delete(handle));
}

test "linux liveness and signaling work with a handle loaded by a new backend" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const pipe = try makePipe();
    defer closeFd(pipe[0]);
    defer closeFd(pipe[1]);
    const pid = try forkProcess();
    if (pid == 0) {
        closeFd(pipe[1]);
        var byte: [1]u8 = undefined;
        _ = readAll(pipe[0], &byte);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitChild(pid) catch {};
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle: Backend.Handle = .{ .id = "persisted", .pid = pid };
    try std.testing.expect(try backend.alive(handle));
    try backend.kill(handle, 0);
    try std.testing.expectError(error.InvalidProcess, backend.kill(.{ .id = "invalid", .pid = 0 }, 9));
    try std.testing.expectError(error.InvalidProcess, backend.alive(.{ .id = "invalid", .pid = -1 }));
    try std.testing.expectError(error.KillFailed, backend.kill(handle, 65));
    try backend.kill(handle, 9);
    _ = try waitChild(pid);
    reaped = true;
    try std.testing.expect(!try backend.alive(handle));
    try std.testing.expectError(error.ProcessNotFound, backend.kill(handle, 15));
    try backend.delete(handle);
}

test "linux create rejects hostname without UTS isolation and unsupported terminals" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .hostname = "must-not-change-the-host",
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const options: Backend.CreateOptions = .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
    };
    try std.testing.expectError(error.InvalidConfig, backend.create(options));
    spec.hostname = null;
    spec.process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .terminal = true, .user = .{ .uid = 0, .gid = 0 } };
    try std.testing.expectError(error.Unsupported, backend.create(options));
}

test "linux create rejects relative process cwd" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // These paths exist under rootfs, so existence alone cannot validate cwd.
    for ([_][]const u8{ "rootfs", ".", "" }) |cwd| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = rootfs },
            .process = .{ .args = &.{"/bin/sh"}, .cwd = cwd, .user = .{ .uid = 0, .gid = 0 } },
        };
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const result = backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = "/dev/null",
            .spec = &spec,
        });
        if (result) |handle| {
            // Clean up if a regression incorrectly creates an init.
            backend.kill(handle, 9) catch {};
        } else |_| {}
        try std.testing.expectError(
            if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
            result,
        );
    }
}

test "linux create rejects empty process args" {
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = "/dev/null",
        .spec = &spec,
    });
    if (result) |handle| {
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.InvalidProcess else error.NotImplemented,
        result,
    );
}

test "linux create rejects a cwd missing from the resolved rootfs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(rootfs);
    // The resolved backend option is authoritative, even when root.path is "/".
    // /proc exists on the Linux host, but not inside this empty rootfs.
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/proc", .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const result = backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = rootfs,
        .exec_fifo = "/dev/null",
        .spec = &spec,
    });
    if (result) |handle| {
        // Clean up if a regression incorrectly creates an init.
        backend.kill(handle, 9) catch {};
    } else |_| {}
    try std.testing.expectError(
        if (builtin.os.tag == .linux) error.CreateFailed else error.NotImplemented,
        result,
    );
}

test "namespace flags map each namespace and combine flags without system calls" {
    const cases = .{
        .{ .pid, linux.CLONE.NEWPID },
        .{ .network, linux.CLONE.NEWNET },
        .{ .mount, linux.CLONE.NEWNS },
        .{ .ipc, linux.CLONE.NEWIPC },
        .{ .uts, linux.CLONE.NEWUTS },
        .{ .cgroup, linux.CLONE.NEWCGROUP },
        .{ .time, linux.CLONE.NEWTIME },
    };
    inline for (cases) |case| {
        try std.testing.expectEqual(@as(usize, case[1]), try namespaceFlags(.{ .namespaces = &.{.{ .type = case[0] }} }));
    }
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(null));
    try std.testing.expectEqual(@as(usize, 0), try namespaceFlags(.{}));
    try std.testing.expectEqual(
        @as(usize, linux.CLONE.NEWPID | linux.CLONE.NEWUTS | linux.CLONE.NEWNS),
        try namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount } } }),
    );
}

test "namespace flags reject duplicate types" {
    try std.testing.expectError(
        error.InvalidConfig,
        namespaceFlags(.{ .namespaces = &.{ .{ .type = .pid }, .{ .type = .uts }, .{ .type = .mount }, .{ .type = .pid } } }),
    );
}

test "namespace flags reject joins and user namespaces" {
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .network, .path = "/proc/1234/ns/net" }},
    }));
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .user }},
    }));
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .user }},
        .uidMappings = &.{},
        .gidMappings = &.{},
    }));
    const mappings: []const oci.Spec.IDMapping = &.{.{ .containerID = 0, .hostID = 1000, .size = 1 }};
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .user }},
        .uidMappings = mappings,
    }));
    try std.testing.expectError(error.Unsupported, namespaceFlags(.{
        .namespaces = &.{.{ .type = .user }},
        .gidMappings = mappings,
    }));
}

test "linux exec searches the process PATH and preserves explicit paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct {
        executable: [*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        cwd: [:0]const u8 = "/",
        status: u32 = 0,
    }{
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:/bin:/usr/bin"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"}, .status = 1 << 8 },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{} },
        .{ .executable = "/bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "bin/sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist"} },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH="}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=:/does-not-exist"}, .cwd = "/bin" },
        .{ .executable = "sh", .envp = &[_:null]?[*:0]const u8{"PATH=/does-not-exist:"}, .cwd = "/bin" },
    };
    for (cases) |case| {
        const argv = [_:null]?[*:0]const u8{ case.executable, "-c", "exit 0" };
        const pid = try forkProcess();
        if (pid == 0) {
            checkResult(linux.chdir(case.cwd)) catch linux.exit_group(2);
            execProcess(&argv, case.envp);
        }
        try std.testing.expectEqual(case.status, try waitChild(pid));
    }
}

test "linux init applies uid gid and replaces inherited supplementary groups before exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const cases = [_]struct { user_json: []const u8, expected: []const u8 }{
        .{ .user_json = "{\"uid\":1000,\"gid\":1000}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[]}", .expected = "1000\n1000\n1000\n" },
        .{ .user_json = "{\"uid\":1000,\"gid\":1000,\"additionalGids\":[1001,1002]}", .expected = "1000\n1000\n1000 1001 1002\n" },
    };
    for (cases) |case| {
        const user = try std.json.parseFromSlice(oci.Spec.User, std.testing.allocator, case.user_json, .{
            .ignore_unknown_fields = true,
        });
        defer user.deinit();
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "/" },
            .process = .{ .args = &.{ "sh", "-c", "id -u; id -g; id -G" }, .cwd = "/", .user = user.value },
        };
        const argv = [_:null]?[*:0]const u8{ "sh", "-c", "id -u; id -g; id -G" };
        const envp = [_:null]?[*:0]const u8{"PATH=/does-not-exist:/usr/bin:/bin"};
        const output = try makePipe();
        defer closeFd(output[0]);
        const ready = makePipe() catch |err| {
            closeFd(output[1]);
            return err;
        };
        defer closeFd(ready[0]);
        const pid = forkProcess() catch |err| {
            closeFd(output[1]);
            closeFd(ready[1]);
            return err;
        };
        if (pid == 0) {
            closeFd(output[0]);
            closeFd(ready[0]);
            checkResult(linux.setgroups(1, &.{42})) catch linux.exit_group(1);
            checkResult(linux.dup2(output[1], posix.STDOUT_FILENO)) catch linux.exit_group(1);
            closeFd(output[1]);
            // /dev/null lets this focused init test complete the FIFO writes immediately.
            runInit(&spec, 0, "/", "/", "/dev/null", &argv, &envp, ready[1]);
        }
        closeFd(output[1]);
        closeFd(ready[1]);
        try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
        var bytes: [64]u8 = undefined;
        const result = bytes[0..case.expected.len];
        try std.testing.expect(readAll(output[0], result));
        try std.testing.expectEqualStrings(case.expected, result);
    }
}

test "linux init exits nonzero instead of exec when it cannot apply process user" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{ "/bin/sh", "-c", "exit 0" }, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 0" };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        if (linux.geteuid() == 0) {
            checkResult(linux.setgid(1000)) catch linux.exit_group(2);
            checkResult(linux.setuid(1000)) catch linux.exit_group(2);
        }
        runInit(&spec, 0, "/", "/", "/dev/null", &argv, &envp, ready[1]);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 1 << 8), try waitChild(pid));
}

test "linux init marks inherited descriptors CLOEXEC and sets noNewPrivileges" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const command = "test ! -e /proc/self/fd/200 && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status";
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{
            .args = &.{ "/bin/sh", "-c", command },
            .cwd = "/",
            .user = .{ .uid = 0, .gid = 0 },
            .noNewPrivileges = true,
        },
    };
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", command };
    const envp = [_:null]?[*:0]const u8{};
    const ready = try makePipe();
    defer closeFd(ready[0]);
    const pid = forkProcess() catch |err| {
        closeFd(ready[1]);
        return err;
    };
    if (pid == 0) {
        closeFd(ready[0]);
        checkResult(linux.dup2(ready[1], 200)) catch linux.exit_group(2);
        runInit(&spec, 0, "/", "/", "/dev/null", &argv, &envp, ready[1]);
    }
    closeFd(ready[1]);
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux create reports child setup failures without leaving an init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const missing_cwd = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "missing" });
    defer std.testing.allocator.free(missing_cwd);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "/" },
        .process = .{ .args = &.{"/bin/sh"}, .cwd = missing_cwd, .user = .{ .uid = 0, .gid = 0 } },
    };
    var implementation: LinuxBackend = .{};
    try std.testing.expectError(error.CreateFailed, implementation.backend().create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/",
        .exec_fifo = fifo,
        .spec = &spec,
    }));
}

test "linux create accepts an empty rootfs and returns a live blocked init" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute_base = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute_base);
    const rootfs = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "rootfs" });
    defer std.testing.allocator.free(rootfs);
    try tmp.dir.createDir(std.testing.io, "rootfs", .default_dir);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ absolute_base, "exec.fifo" });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    try checkResult(linux.mknod(fifo_z, linux.S.IFIFO | 0o600, 0));
    const specs = [_]oci.Spec{
        .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .process = .{ .args = &.{ "/bin/sleep", "1000" }, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        },
        .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" } },
    };
    for (specs) |spec| {
        var implementation: LinuxBackend = .{};
        const backend = implementation.backend();
        const handle = try backend.create(.{
            .allocator = std.testing.allocator,
            .id = "example",
            .rootfs = rootfs,
            .exec_fifo = fifo,
            .spec = &spec,
        });
        defer backend.kill(handle, 9) catch {};
        try std.testing.expect(handle.pid > 0);
        try std.testing.expectEqualStrings("example", handle.id);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(handle.pid, @enumFromInt(0))));
        try backend.kill(handle, 9);
    }
}

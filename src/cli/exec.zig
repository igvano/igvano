const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("state.zig").ContainerInstance;
const attached = @import("../attached.zig");
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const bindContainer = @import("state.zig").bindContainer;
const Config = @import("args.zig").Config;
const parseArgs = @import("args.zig").parseArgs;
const optionValue = @import("args.zig").optionValue;
const prepareProcess = @import("process.zig").prepareProcess;
const connectConsoleSocket = @import("process.zig").connectConsoleSocket;
const writePidFile = @import("process.zig").writePidFile;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const LiveState = @import("state.zig").LiveState;
const readLiveState = @import("state.zig").readLiveState;
const SeccompAgent = @import("seccomp_agent.zig").Agent;

fn execProcessConfig(allocator: std.mem.Allocator, inherited: oci.Spec.Process, config: Config) !oci.Spec.Process {
    var process = inherited;
    process.args = config.exec_args;
    if (config.exec_cwd) |value| process.cwd = value;
    process.terminal = config.tty orelse false;
    if (config.exec_user) |value| {
        process.user.uid = value.uid;
        if (value.gid) |gid| process.user.gid = gid;
    }
    var env: std.ArrayList([]const u8) = .empty;
    errdefer env.deinit(allocator);
    try env.appendSlice(allocator, process.env orelse &.{});
    var index: usize = 0;
    while (index < config.exec_flags.len) : (index += 1) {
        const flag = config.exec_flags[index];
        if (std.mem.eql(u8, flag, "--env") or std.mem.startsWith(u8, flag, "--env=")) {
            const value = try optionValue(config.exec_flags, &index, error.MissingEnv);
            try replaceExecEnv(allocator, &env, value);
        } else if (std.mem.indexOfScalar(u8, flag, '=') == null and
            !std.mem.eql(u8, flag, "--detach") and !std.mem.eql(u8, flag, "-d") and
            !std.mem.eql(u8, flag, "--tty") and !std.mem.eql(u8, flag, "-t"))
        {
            index += 1; // Skip the value of another parsed option.
        }
    }
    process.env = try env.toOwnedSlice(allocator);
    return process;
}

fn replaceExecEnv(allocator: std.mem.Allocator, env: *std.ArrayList([]const u8), value: []const u8) !void {
    const key_len = std.mem.indexOfScalar(u8, value, '=').?;
    // Later values override the saved environment and earlier --envs.
    var entry: usize = 0;
    while (entry < env.items.len) {
        const existing = env.items[entry];
        if (existing.len > key_len and existing[key_len] == '=' and
            std.mem.eql(u8, existing[0..key_len], value[0..key_len]))
            _ = env.orderedRemove(entry)
        else
            entry += 1;
    }
    try env.append(allocator, value);
}

pub fn execContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !u8 {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    if (!config.detach) try reserveStdio();
    var lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const locked = if (lock) |file| try lockContainer(file, false) else true;
    if (locked) {
        if (lock) |file| try requireLinkedLock(io, file);
    }
    const state = try readLiveState(allocator, io, injected, config, locked);
    defer state.deinit();
    var instance: ContainerInstance = undefined;
    const container = if (state.container_state) |value| bindContainer(&instance, injected, value) else null;
    if (state.parsed.value.status != .created and state.parsed.value.status != .running) return oci.validationError(error.InvalidStatus, "exec: requires created or running state", .{});

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const process_allocator = arena.allocator();
    var agent: ?SeccompAgent = null;
    const options = try prepareExecOptions(process_allocator, io, state, config, &agent);
    defer if (options.console_fds) |fds| for (fds) |fd| {
        _ = linux.close(fd);
    };
    return runExec(allocator, io, container.?, config, options, &lock, locked) catch |err| {
        // The agent's own error carries the reason, e.g. a failed connect.
        if (agent) |value| if (value.failure) |reason| return reason;
        return err;
    };
}

pub fn reserveStdio() !void {
    const linux = std.os.linux;
    // Reserve stdio before locks, console sockets, or the signal
    // pipe can reuse their numbers and become attached-loop I/O.
    for ([_]std.posix.fd_t{ 0, 1, 2 }) |fd| {
        switch (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0))) {
            .SUCCESS => continue,
            .BADF => {},
            else => return error.ConsoleFailed,
        }
        // open returns the lowest free fd; earlier stdio slots are reserved.
        while (true) {
            const opened = linux.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
            switch (linux.errno(opened)) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.ConsoleFailed,
            }
        }
    }
}

fn prepareExecOptions(process_allocator: std.mem.Allocator, io: std.Io, state: LiveState, config: Config, agent: *?SeccompAgent) !libcontainer.ExecOptions {
    const saved_bundle = try std.fs.path.join(process_allocator, &.{ config.root, config.id });
    // Legacy containers did not snapshot config.json at create.
    const saved_spec = try loadExecSpec(process_allocator, io, saved_bundle, state.parsed.value.bundle, config.process_file != null);
    var process = try loadExecProcess(process_allocator, io, saved_spec, config);
    inheritExecProfile(&process, saved_spec);
    try oci.validateProcess(process);
    const local_console = (process.terminal orelse false) and !config.detach and config.console_socket == null;
    var options = try prepareProcess(process_allocator, process, local_console or config.console_socket != null);
    const seccomp = seccomp: {
        const spec = saved_spec orelse break :seccomp null;
        const settings = spec.value.linux orelse break :seccomp null;
        break :seccomp settings.seccomp;
    };
    options.seccomp = try oci.prepareSeccomp(process_allocator, seccomp);
    agent.* = SeccompAgent.init(process_allocator, seccomp, state.parsed.value);
    if (agent.*) |*value| options.on_seccomp_listener = value.callback();
    // Empty means no cgroup to join: a rootless create that had no permission.
    options.cgroup_path = state.container_state.?.cgroup_path orelse "";
    options.console_fds = if (process.terminal orelse false) try libcontainer.linux.console.socketpair() else null;
    options.debug = config.debug_log;
    return options;
}

fn loadExecSpec(process_allocator: std.mem.Allocator, io: std.Io, saved_bundle: []const u8, bundle: []const u8, has_process_file: bool) !?std.json.Parsed(oci.Spec) {
    return oci.loadSpec(process_allocator, io, saved_bundle) catch |err| switch (err) {
        error.FileNotFound => oci.loadSpec(process_allocator, io, bundle) catch |bundle_err| switch (bundle_err) {
            // Legacy containers created before seccomp support can exec --process without either config.
            error.FileNotFound => if (has_process_file) null else return bundle_err,
            else => return bundle_err,
        },
        else => return err,
    };
}

fn loadExecProcess(process_allocator: std.mem.Allocator, io: std.Io, saved_spec: ?std.json.Parsed(oci.Spec), config: Config) !oci.Spec.Process {
    return if (config.process_file) |path| process: {
        const json = std.Io.Dir.cwd().readFileAlloc(io, path, process_allocator, .limited(1 << 20)) catch |err| {
            if (err == error.StreamTooLong) oci.recordDiagnostic(err, "--process: JSON exceeds 1 MiB", .{});
            return err;
        };
        const parsed = std.json.parseFromSlice(oci.Spec.Process, process_allocator, json, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        }) catch |err| {
            if (err != error.OutOfMemory) oci.recordDiagnostic(err, "--process: invalid JSON or schema ({s})", .{@errorName(err)});
            return err;
        };
        break :process parsed.value;
    } else process: {
        const spec = saved_spec orelse return error.FileNotFound;
        break :process try execProcessConfig(process_allocator, spec.value.process orelse return oci.validationError(error.MissingProcess, "exec: bundle has no process to inherit", .{}), config);
    };
}

fn inheritExecProfile(process: *oci.Spec.Process, saved_spec: ?std.json.Parsed(oci.Spec)) void {
    const spec = saved_spec orelse return;
    const inherited = spec.value.process orelse return;
    // Like runc, an omitted or empty exec profile inherits the container default.
    if (process.apparmorProfile == null or process.apparmorProfile.?.len == 0)
        process.apparmorProfile = inherited.apparmorProfile;
    // config.json's execCPUAffinity is the default for every exec.
    if (process.execCPUAffinity == null) process.execCPUAffinity = inherited.execCPUAffinity;
    // So are the scheduler and I/O priority, as in runc.
    if (process.scheduler == null) process.scheduler = inherited.scheduler;
    if (process.ioPriority == null) process.ioPriority = inherited.ioPriority;
}

pub fn enableExecSubreaper() !u32 {
    const linux = std.os.linux;
    var was_subreaper: u32 = 0;
    // The helper exits after exec; adoption lets this frontend waitpid the
    // grandchild. Detached exec leaves adoption/reaping to the shim.
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_CHILD_SUBREAPER), @intFromPtr(&was_subreaper), 0, 0, 0)) != .SUCCESS or
        linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)) != .SUCCESS)
        return error.SubreaperFailed;
    return was_subreaper;
}

pub fn restoreExecSubreaper(was_subreaper: u32) void {
    const linux = std.os.linux;
    _ = linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), was_subreaper, 0, 0, 0);
}

fn runExec(allocator: std.mem.Allocator, io: std.Io, container: libcontainer.Container, config: Config, options: libcontainer.ExecOptions, lock: *?std.Io.File, locked: bool) !u8 {
    const linux = std.os.linux;
    const was_subreaper = if (!config.detach) try enableExecSubreaper() else 0;
    defer if (!config.detach) restoreExecSubreaper(was_subreaper);
    var signals: ?attached.Signals = if (!config.detach) try attached.Signals.init() else null;
    defer if (signals) |*handler| handler.deinit();
    const pid = try containerResult(container, container.exec(options));
    var reaped = false;
    errdefer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        if (!config.detach) _ = waitExec(pid) catch {};
    };
    const controller = try receiveExecConsole(options.console_fds, config.console_socket);
    defer if (controller) |fd| {
        _ = linux.close(fd);
    };
    if (config.pid_file) |path| try writePidFile(allocator, io, path, pid);
    // Do not hold the container lock while waiting for a long-running command.
    if (locked) {
        if (lock.*) |file| {
            file.close(io);
            lock.* = null;
        }
    }
    if (config.detach) return 0;
    return try attached.wait(pid, &reaped, &signals.?, controller, 0, 1);
}

fn receiveExecConsole(console_fds: ?[2]std.posix.fd_t, console_socket: ?[]const u8) !?std.posix.fd_t {
    const linux = std.os.linux;
    var controller: ?std.posix.fd_t = null;
    errdefer if (controller) |fd| {
        _ = linux.close(fd);
    };
    if (console_fds) |fds| {
        controller = try libcontainer.linux.console.receiveFd(fds[0]);
        if (console_socket) |path| {
            const peer = try connectConsoleSocket(path);
            defer _ = linux.close(peer);
            try libcontainer.linux.console.sendFd(peer, controller.?);
            _ = linux.close(controller.?);
            controller = null;
        }
    }
    return controller;
}

pub fn waitExec(pid: i32) !u8 {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (std.posix.errno(std.posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => {
                const value: u32 = @bitCast(status);
                const signal = value & 0x7f;
                return @intCast(if (signal == 0) (value >> 8) & 0xff else 128 + signal);
            },
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}

test "exec command overrides inherit process settings and replace environment keys" {
    const config = try parseArgs(&.{
        "igvano", "exec", "--cwd", "/work", "--env", "A=first", "--env=A=last", "--env", "NEW=x=y", "--user=1000:1001", "-t", "example", "sh", "-c", "exit 7",
    });
    const original: oci.Spec.Process = .{
        .args = &.{"sleep"},
        .env = &.{ "A=old", "KEEP=value" },
        .cwd = "/",
        .user = .{ .uid = 0, .gid = 1002, .additionalGids = &.{42} },
        .noNewPrivileges = true,
        .apparmorProfile = "igvano-default",
        .oomScoreAdj = 100,
        .capabilities = .{ .bounding = &.{"CAP_CHOWN"} },
        .rlimits = &.{.{ .type = "RLIMIT_NOFILE", .hard = 1024, .soft = 512 }},
    };
    const process = try execProcessConfig(std.testing.allocator, original, config);
    defer std.testing.allocator.free(process.env.?);
    try std.testing.expectEqualSlices([]const u8, config.exec_args, process.args);
    try std.testing.expectEqualStrings("/work", process.cwd);
    try std.testing.expect(process.terminal.?);
    try std.testing.expectEqual(@as(u32, 1000), process.user.uid);
    try std.testing.expectEqual(@as(u32, 1001), process.user.gid);
    try std.testing.expectEqual(@as(u32, 42), process.user.additionalGids.?[0]);
    try std.testing.expect(process.noNewPrivileges);
    try std.testing.expectEqualStrings("igvano-default", process.apparmorProfile.?);
    try std.testing.expectEqual(original.oomScoreAdj, process.oomScoreAdj);
    try std.testing.expectEqualStrings("CAP_CHOWN", process.capabilities.?.bounding.?[0]);
    try std.testing.expectEqual(original.rlimits.?[0].hard, process.rlimits.?[0].hard);
    try std.testing.expectEqual(@as(usize, 3), process.env.?.len);
    try std.testing.expectEqualStrings("KEEP=value", process.env.?[0]);
    try std.testing.expectEqualStrings("A=last", process.env.?[1]);
    try std.testing.expectEqualStrings("NEW=x=y", process.env.?[2]);
    const uid_only = try parseArgs(&.{ "igvano", "exec", "--user", "99", "example", "true" });
    try std.testing.expectEqual(@as(?u32, null), uid_only.exec_user.?.gid);
    var terminal_init = original;
    terminal_init.terminal = true;
    const no_tty = try execProcessConfig(std.testing.allocator, terminal_init, uid_only);
    defer std.testing.allocator.free(no_tty.env.?);
    try std.testing.expect(!no_tty.terminal.?);
    try std.testing.expectEqual(@as(u32, 99), no_tty.user.uid);
    try std.testing.expectEqual(@as(u32, 1002), no_tty.user.gid);
}

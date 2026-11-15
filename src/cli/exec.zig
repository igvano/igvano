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
const ExecValues = @import("args.zig").ExecValues;
const prepareProcess = @import("process.zig").prepareProcess;
const processEnv = @import("process.zig").processEnv;
const connectConsoleSocket = @import("process.zig").connectConsoleSocket;
const writePidFile = @import("process.zig").writePidFile;
const connectPidfdSocket = @import("process.zig").connectPidfdSocket;
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
    if (config.exec_no_new_privs) |value| process.noNewPrivileges = value;
    if (config.exec_apparmor) |value| process.apparmorProfile = value;
    if (config.exec_process_label) |value| process.selinuxLabel = value;
    var env: std.ArrayList([]const u8) = .empty;
    errdefer env.deinit(allocator);
    try env.appendSlice(allocator, process.env orelse &.{});
    var envs: ExecValues = .{ .flags = config.exec_flags, .option = .env };
    while (envs.next()) |value| try replaceExecEnv(allocator, &env, value);
    process.env = try env.toOwnedSlice(allocator);
    var gids: std.ArrayList(u32) = .empty;
    try gids.appendSlice(allocator, process.user.additionalGids orelse &.{});
    var gid_values: ExecValues = .{ .flags = config.exec_flags, .option = .additional_gids };
    while (gid_values.next()) |value| try gids.append(allocator, try std.fmt.parseUnsigned(u32, value, 10));
    process.user.additionalGids = try gids.toOwnedSlice(allocator);
    try addExecCapabilities(allocator, &process, config.exec_flags);
    return process;
}

/// runc exec --cap: add to bounding, effective and permitted, and to ambient
/// only when the spec already sets inheritable.
fn addExecCapabilities(allocator: std.mem.Allocator, process: *oci.Spec.Process, flags: []const []const u8) !void {
    var caps: ExecValues = .{ .flags = flags, .option = .cap };
    if (caps.next() == null) return;
    caps.index = 0;
    var current = process.capabilities orelse oci.Spec.Capabilities{};
    inline for (.{ "bounding", "effective", "permitted", "ambient" }) |field| {
        if (!std.mem.eql(u8, field, "ambient") or current.inheritable != null) {
            var list: std.ArrayList([]const u8) = .empty;
            try list.appendSlice(allocator, @field(current, field) orelse &.{});
            var values: ExecValues = .{ .flags = flags, .option = .cap };
            while (values.next()) |value| try list.append(allocator, value);
            @field(current, field) = try list.toOwnedSlice(allocator);
        }
    }
    process.capabilities = current;
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
    try requireExecStatus(state.parsed.value.status, config.ignore_paused);

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

/// runc's messages; a paused container needs --ignore-paused.
fn requireExecStatus(status: oci.Status, ignore_paused: bool) !void {
    switch (status) {
        .created, .running => {},
        .paused => if (!ignore_paused) return oci.validationError(error.InvalidStatus, "cannot exec in a paused container (use --ignore-paused to override)", .{}),
        .stopped => return oci.validationError(error.InvalidStatus, "cannot exec in a stopped container", .{}),
        else => return oci.validationError(error.InvalidStatus, "exec: requires created or running state", .{}),
    }
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
    options.rootless_cgroups = @import("create.zig").rootlessCgroups();
    options.console_fds = if (process.terminal orelse false) try libcontainer.linux.console.socketpair() else null;
    options.debug = config.debug_log;
    options.sub_cgroups = try subCgroups(process_allocator, config.exec_flags);
    options.preserve_fds = config.preserve_fds;
    try applySavedSettings(&options, saved_spec);
    if (process.env != null) {
        const root = try std.fmt.allocPrint(process_allocator, "/proc/{d}/root", .{state.parsed.value.pid orelse 0});
        options.envp = try processEnv(process_allocator, options.envp, root, options.uid);
    }
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

/// Like runc, exec applies the container's umask and personality (youki
/// also its memory policy), not ones from --process.
fn applySavedSettings(options: *libcontainer.ExecOptions, saved_spec: ?std.json.Parsed(oci.Spec)) !void {
    options.umask = savedUmask(saved_spec);
    const spec = saved_spec orelse return;
    const settings = spec.value.linux orelse return;
    options.memory_policy = try oci.memoryPolicy(settings.memoryPolicy);
    options.personality = try oci.personality(settings.personality);
}

/// runc exec applies the container's umask, not one from --process.
fn savedUmask(saved_spec: ?std.json.Parsed(oci.Spec)) ?u32 {
    const spec = saved_spec orelse return null;
    const init = spec.value.process orelse return null;
    return init.user.umask;
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
    if (process.selinuxLabel == null or process.selinuxLabel.?.len == 0)
        process.selinuxLabel = inherited.selinuxLabel;
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
    var exec_options = options;
    // Connected before exec; the process itself sends its pidfd, like runc.
    exec_options.pidfd_socket = if (config.pidfd_socket) |path| try connectPidfdSocket(path) else null;
    defer if (exec_options.pidfd_socket) |fd| {
        _ = linux.close(fd);
    };
    const pid = try containerResult(container, container.exec(exec_options));
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
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const config = try parseArgs(&.{
        "igvano", "exec",           "--cwd", "/work", "-e",                  "A=first", "--env=A=last", "--env",   "NEW=x=y", "--user=1000:1001",
        "-t",     "--no-new-privs", "-g",    "7",     "--additional-gids=8", "--cap",   "CAP_KILL",     "example", "sh",      "-c",
        "exit 7",
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
    const process = try execProcessConfig(allocator, original, config);
    try std.testing.expectEqualSlices([]const u8, config.exec_args, process.args);
    try std.testing.expectEqualStrings("/work", process.cwd);
    try std.testing.expect(process.terminal.?);
    try std.testing.expectEqual(@as(u32, 1000), process.user.uid);
    try std.testing.expectEqual(@as(u32, 1001), process.user.gid);
    try std.testing.expectEqualSlices(u32, &.{ 42, 7, 8 }, process.user.additionalGids.?);
    try std.testing.expect(process.noNewPrivileges);
    try std.testing.expectEqualStrings("igvano-default", process.apparmorProfile.?);
    try std.testing.expectEqual(original.oomScoreAdj, process.oomScoreAdj);
    try std.testing.expectEqualStrings("CAP_CHOWN", process.capabilities.?.bounding.?[0]);
    try std.testing.expectEqualStrings("CAP_KILL", process.capabilities.?.bounding.?[1]);
    try std.testing.expectEqualStrings("CAP_KILL", process.capabilities.?.permitted.?[0]);
    try std.testing.expect(process.capabilities.?.ambient == null);
    try std.testing.expectEqual(original.rlimits.?[0].hard, process.rlimits.?[0].hard);
    try std.testing.expectEqual(@as(usize, 3), process.env.?.len);
    try std.testing.expectEqualStrings("KEEP=value", process.env.?[0]);
    try std.testing.expectEqualStrings("A=last", process.env.?[1]);
    try std.testing.expectEqualStrings("NEW=x=y", process.env.?[2]);
    const uid_only = try parseArgs(&.{ "igvano", "exec", "--user", "99", "example", "true" });
    try std.testing.expectEqual(@as(?u32, null), uid_only.exec_user.?.gid);
    var terminal_init = original;
    terminal_init.terminal = true;
    const no_tty = try execProcessConfig(allocator, terminal_init, uid_only);
    try std.testing.expect(!no_tty.terminal.?);
    try std.testing.expectEqual(@as(u32, 99), no_tty.user.uid);
    try std.testing.expectEqual(@as(u32, 1002), no_tty.user.gid);
}

/// runc's getSubCgroupPaths: one plain path (cgroup v2), or
/// controller[,controller]:path entries (cgroup v1), each controller once.
fn subCgroups(allocator: std.mem.Allocator, flags: []const []const u8) ![]const libcontainer.SubCgroup {
    var count: usize = 0;
    var values: ExecValues = .{ .flags = flags, .option = .cgroup };
    while (values.next()) |_| count += 1;
    var result: std.ArrayList(libcontainer.SubCgroup) = .empty;
    values = .{ .flags = flags, .option = .cgroup };
    while (values.next()) |value| {
        const colon = std.mem.indexOfScalar(u8, value, ':') orelse {
            if (count != 1) return oci.validationError(error.InvalidExecValue, "invalid --cgroup argument: {s} (missing <controller>: prefix)", .{value});
            try result.append(allocator, .{ .path = value });
            continue;
        };
        var controllers = std.mem.splitScalar(u8, value[0..colon], ',');
        while (controllers.next()) |controller| {
            if (controller.len == 0) return oci.validationError(error.InvalidExecValue, "invalid --cgroup argument: {s} (empty <controller> prefix)", .{value});
            for (result.items) |seen| if (std.mem.eql(u8, seen.controller, controller))
                return oci.validationError(error.InvalidExecValue, "invalid --cgroup argument(s): controller {s} specified multiple times", .{controller});
            try result.append(allocator, .{ .controller = controller, .path = value[colon + 1 ..] });
        }
    }
    return result.items;
}

test "exec --cgroup parses like runc's getSubCgroupPaths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plain = try subCgroups(a, &.{ "--cgroup", "sub" });
    try std.testing.expectEqual(@as(usize, 1), plain.len);
    try std.testing.expectEqualStrings("", plain[0].controller);
    const split = try subCgroups(a, &.{ "--cgroup=cpu,memory:a", "--cgroup", "pids:b" });
    try std.testing.expectEqual(@as(usize, 3), split.len);
    try std.testing.expectEqualStrings("memory", split[1].controller);
    try std.testing.expectEqualStrings("b", split[2].path);
    for ([_][]const []const u8{ &.{ "--cgroup", "a", "--cgroup", "cpu:b" }, &.{ "--cgroup", ":a" }, &.{ "--cgroup", "cpu:a", "--cgroup", "cpu:b" } }) |flags|
        try std.testing.expectError(error.InvalidExecValue, subCgroups(a, flags));
}

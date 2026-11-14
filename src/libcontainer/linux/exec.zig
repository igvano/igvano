const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const seccomp = @import("../seccomp.zig");
const diagnostics = @import("diagnostic.zig");
const processString = @import("syscall.zig").processString;
const pathString = @import("syscall.zig").pathString;
const checkResult = @import("syscall.zig").checkResult;
const forkProcess = @import("syscall.zig").forkProcess;
const makePipe = @import("syscall.zig").makePipe;
const closeFd = @import("syscall.zig").closeFd;
const waitChild = @import("syscall.zig").waitChild;
const readAll = @import("syscall.zig").readAll;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const debugLog = @import("diagnostic.zig").debugLog;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const childError = @import("diagnostic.zig").childError;
const failCreate = @import("diagnostic.zig").failCreate;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const tryV1Write = @import("cgroup_v1.zig").tryV1Write;
const readCgroupFile = @import("cgroup.zig").readCgroupFile;
const V1Hierarchy = @import("cgroup_v1.zig").V1Hierarchy;
const freeV1Hierarchies = @import("cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("cgroup_v1.zig").openV1Hierarchies;
const walkV1Cgroup = @import("cgroup_v1.zig").walkV1Cgroup;
const NamespaceJoin = @import("namespaces.zig").NamespaceJoin;
const validateNamespaceFd = @import("namespaces.zig").validateNamespaceFd;
const joinNamespaceFds = @import("namespaces.zig").joinNamespaceFds;
const alive = @import("proc.zig").alive;
const readProcStatAt = @import("proc.zig").readProcStatAt;
const closeExecFrom = @import("process.zig").closeExecFrom;
const closeFdRange = @import("process.zig").closeFdRange;
const kernelCapabilities = @import("process.zig").kernelCapabilities;
const installSeccompFor = @import("process.zig").installSeccompFor;
const deliverSeccompListener = @import("process.zig").deliverSeccompListener;
const applyOomScoreAdj = @import("process.zig").applyOomScoreAdj;
const setCpuAffinity = @import("process.zig").setCpuAffinity;
const resetCpuAffinity = @import("process.zig").resetCpuAffinity;
const ProcessSettings = @import("process.zig").ProcessSettings;
const applyProcessSettings = @import("process.zig").applyProcessSettings;
const applyMemoryPolicy = @import("process.zig").applyMemoryPolicy;
const applyPersonality = @import("process.zig").applyPersonality;
const applySchedulerAndIOPriority = @import("process.zig").applySchedulerAndIOPriority;
const applyRlimits = @import("process.zig").applyRlimits;
const resolveExecutable = @import("process.zig").resolveExecutable;
const execResolved = @import("process.zig").execResolved;
const setupConsole = @import("console.zig").setupConsole;
const prepareAppArmor = @import("procfs.zig").prepareAppArmor;
const applyAppArmor = @import("procfs.zig").applyAppArmor;

const namespace_names = [_][]const u8{ "user", "cgroup", "ipc", "uts", "net", "pid", "mnt", "time" };

const ExecProcess = struct {
    apparmor_command: ?[]const u8,
    seccomp_program: ?seccomp.Program,
    cwd: [:0]const u8,
    argv: [:null]?[*:0]const u8,
    envp: [:null]?[*:0]const u8,
    settings: ProcessSettings,
};

const ExecContext = struct {
    options: libcontainer.ExecOptions,
    handle: libcontainer.State,
    process: ExecProcess,
    proc_dir: posix.fd_t,
    root: posix.fd_t,
    cgroup: ?posix.fd_t,
    /// cgroup v2: init's current cgroup, when it moved below the container's.
    init_cgroup: ?posix.fd_t = null,
    hierarchies: []V1Hierarchy,
    joins: [8]NamespaceJoin,
    ns_fds: [8]posix.fd_t,
    report: [2]posix.fd_t = undefined,
    ready: [2]posix.fd_t = undefined,
    /// Held only by the helper: its EOF tells the child the helper has
    /// left the container cgroup, so exec cannot race the helper's exit.
    gate: [2]posix.fd_t = .{ -1, -1 },
    /// Runtime -> exec child: "seccomp listener copied"; only with notify rules.
    seccomp_ack: ?[2]posix.fd_t = null,
};

pub fn exec(handle: libcontainer.State, options: libcontainer.ExecOptions) libcontainer.Error!i32 {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    if (!try alive(handle)) return error.ProcessNotFound;
    if (options.argv.len == 0 or options.argv[0].len == 0 or !std.fs.path.isAbsolute(options.cwd))
        return error.InvalidProcess;
    // Empty: the container has no cgroup (rootless without permission).
    if (options.cgroup_path.len != 0) try validateCgroupPath(options.cgroup_path);
    var arena: std.heap.ArenaAllocator = .init(options.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const prepared = try prepareExecProcess(allocator, options);
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const root_path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/root", .{handle.pid}, 0);
    const root = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    return execWithCgroups(handle, options, allocator, prepared, proc_dir, root);
}

fn prepareExecProcess(allocator: std.mem.Allocator, options: libcontainer.ExecOptions) libcontainer.Error!ExecProcess {
    const apparmor_command = try prepareAppArmor(allocator, options.apparmor_profile);
    const seccomp_program = if (options.seccomp) |config|
        seccomp.compile(allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
            return error.InvalidConfig;
        }
    else
        null;
    if (seccomp_program) |program| debugLog(options.debug, "seccomp filter flags: {d}", .{program.flags});
    const cwd = try pathString(allocator, options.cwd);
    const argv = try allocator.allocSentinel(?[*:0]const u8, options.argv.len, null);
    for (options.argv, 0..) |arg, i| argv[i] = (try processString(allocator, arg)).ptr;
    const envp = try allocator.allocSentinel(?[*:0]const u8, options.envp.len, null);
    for (options.envp, 0..) |entry, i| envp[i] = (try processString(allocator, entry)).ptr;
    const process: ProcessSettings = .{
        .uid = options.uid,
        .gid = options.gid,
        .additional_gids = options.additional_gids,
        .no_new_privileges = options.no_new_privileges,
        .capabilities = if (options.capabilities) |caps| try kernelCapabilities(caps) else null,
        .rlimits = options.rlimits,
    };
    for (options.rlimits) |limit| if (limit.soft > limit.hard) return error.InvalidConfig;
    return .{ .apparmor_command = apparmor_command, .seccomp_program = seccomp_program, .cwd = cwd, .argv = argv, .envp = envp, .settings = process };
}

/// runc's SubCgroupPaths check: path.Join(base, sub) must stay below base.
/// Returns the joined path, without the leading slash.
pub fn subCgroupPath(allocator: std.mem.Allocator, base: []const u8, sub: []const u8) libcontainer.Error![]const u8 {
    // Like Go's path.Join, an absolute sub is still below base.
    const joined = try std.fs.path.resolvePosix(allocator, &.{try std.fmt.allocPrint(allocator, "/{s}/{s}", .{ base, sub })});
    const prefix = try std.fs.path.resolvePosix(allocator, &.{ "/", base });
    if (!std.mem.startsWith(u8, joined, prefix) or (joined.len > prefix.len and joined[prefix.len] != '/')) {
        reportDiagnostic("{s} is not a sub cgroup path", .{sub});
        return error.InvalidConfig;
    }
    return joined[1..];
}

test "exec per-controller sub-cgroups pick each v1 hierarchy's path" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    defer diagnostics.last_diagnostic_len = 0;
    const subs = [_]libcontainer.SubCgroup{ .{ .controller = "memory", .path = "m" }, .{ .controller = "cpuacct", .path = "c" } };
    const memory: V1Hierarchy = .{ .mountpoint = "", .mount_root = "/", .controllers = &.{"memory"} };
    const cpu: V1Hierarchy = .{ .mountpoint = "", .mount_root = "/", .controllers = &.{ "cpu", "cpuacct" } };
    const pids: V1Hierarchy = .{ .mountpoint = "", .mount_root = "/", .controllers = &.{"pids"} };
    try requireKnownControllers(&subs, &.{ memory, cpu, pids });
    try std.testing.expectEqualStrings("b/m", try v1SubCgroupPath(a, "b", &subs, memory));
    try std.testing.expectEqualStrings("b/c", try v1SubCgroupPath(a, "b", &subs, cpu));
    try std.testing.expectEqualStrings("b", try v1SubCgroupPath(a, "b", &subs, pids));
    try std.testing.expectError(error.InvalidConfig, requireKnownControllers(&.{.{ .controller = "whaaat", .path = "/" }}, &.{memory}));
}

test "exec sub-cgroups stay below the container cgroup, like runc" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    defer diagnostics.last_diagnostic_len = 0;
    try std.testing.expectEqualStrings("c/x", try subCgroupPath(a, "c", "x"));
    try std.testing.expectEqualStrings("c", try subCgroupPath(a, "c", "/"));
    try std.testing.expectEqualStrings("c/y", try subCgroupPath(a, "c", "x/../y"));
    try std.testing.expectError(error.InvalidConfig, subCgroupPath(a, "c", ".."));
    try std.testing.expectError(error.InvalidConfig, subCgroupPath(a, "a/c", "../cc"));
}

fn execWithCgroups(handle: libcontainer.State, base_options: libcontainer.ExecOptions, allocator: std.mem.Allocator, prepared: ExecProcess, proc_dir: posix.fd_t, root: posix.fd_t) libcontainer.Error!i32 {
    var options = base_options;
    if (options.cgroup_path.len == 0) return execWithNamespacesOf(handle, options, allocator, prepared, proc_dir, root, .{}, &.{});
    const base = options.cgroup_path;
    // One plain --cgroup path applies to every controller, like runc.
    const all = plainSubCgroup(options.sub_cgroups);
    if (all) |sub| options.cgroup_path = try subCgroupPath(allocator, base, sub);
    errdefer |err| if (err == error.ProcessNotFound and options.sub_cgroups.len != 0)
        reportDiagnostic("error adding pid to cgroups: /sys/fs/cgroup/{s}/cgroup.procs: no such file or directory", .{options.cgroup_path});
    const cgroup_root = try openCgroupRoot();
    defer closeFd(cgroup_root.fd);
    const cgroup: ?posix.fd_t = if (cgroup_root.mode == .unified)
        try openV2ExecCgroup(cgroup_root.fd, if (all == null) options.sub_cgroups else &.{}, options.cgroup_path)
    else
        null;
    defer if (cgroup) |fd| closeFd(fd);
    const hierarchies: []V1Hierarchy = if (cgroup_root.mode == .legacy) try openV1Hierarchies(allocator, handle.systemd) else &.{};
    defer if (cgroup_root.mode == .legacy) freeV1Hierarchies(allocator, hierarchies);
    try openV1ExecLeaves(allocator, hierarchies, base, if (all == null) options.sub_cgroups else &.{}, options.cgroup_path);
    // runc: --cgroup disables the fallback to init's cgroup.
    const init_cgroup = if (cgroup != null and options.sub_cgroups.len == 0) try openInitCgroup(allocator, cgroup_root.fd, handle.pid, options.cgroup_path) else null;
    defer if (init_cgroup) |fd| closeFd(fd);
    return execWithNamespacesOf(handle, options, allocator, prepared, proc_dir, root, .{ .cgroup = cgroup, .init_cgroup = init_cgroup }, hierarchies);
}

fn plainSubCgroup(subs: []const libcontainer.SubCgroup) ?[]const u8 {
    return if (subs.len == 1 and subs[0].controller.len == 0) subs[0].path else null;
}

/// runc's cgroup v2 paths have only the "" key, so any controller is unknown.
fn openV2ExecCgroup(root: posix.fd_t, subs: []const libcontainer.SubCgroup, path: []const u8) libcontainer.Error!posix.fd_t {
    if (subs.len != 0) try unknownController(subs[0].controller);
    return (try walkCgroup(root, path, false, &.{})) orelse error.ProcessNotFound;
}

/// Per-controller subs pick each hierarchy's path; otherwise all use `path`.
fn openV1ExecLeaves(allocator: std.mem.Allocator, hierarchies: []V1Hierarchy, base: []const u8, subs: []const libcontainer.SubCgroup, path: []const u8) libcontainer.Error!void {
    try requireKnownControllers(subs, hierarchies);
    for (hierarchies) |*hierarchy| {
        const leaf = if (subs.len != 0) try v1SubCgroupPath(allocator, base, subs, hierarchy.*) else path;
        hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, leaf, false, false)) orelse return error.ProcessNotFound;
    }
}

fn unknownController(controller: []const u8) libcontainer.Error!noreturn {
    reportDiagnostic("unknown controller {s} in SubCgroupPaths", .{controller});
    return error.InvalidConfig;
}

fn requireKnownControllers(subs: []const libcontainer.SubCgroup, hierarchies: []const V1Hierarchy) libcontainer.Error!void {
    outer: for (subs) |sub| {
        for (hierarchies) |hierarchy| if (hierarchy.has(sub.controller)) continue :outer;
        try unknownController(sub.controller);
    }
}

/// A v1 hierarchy joins the sub-cgroup of the first controller it mounts.
fn v1SubCgroupPath(allocator: std.mem.Allocator, base: []const u8, subs: []const libcontainer.SubCgroup, hierarchy: V1Hierarchy) libcontainer.Error![]const u8 {
    for (subs) |sub| if (hierarchy.has(sub.controller)) return subCgroupPath(allocator, base, sub.path);
    return base;
}

/// Init's cgroup v2 path from /proc/<pid>/cgroup, if it is below `base`.
fn openInitCgroup(allocator: std.mem.Allocator, cgroup_root: posix.fd_t, pid: i32, base: []const u8) libcontainer.Error!?posix.fd_t {
    var path_buffer: [32]u8 = undefined;
    const proc = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}", .{pid}) catch unreachable;
    const dir = openPath(linux.AT.FDCWD, proc, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }) catch return null;
    defer closeFd(dir);
    const text = readCgroupFile(allocator, dir, "cgroup") catch return null;
    const line = std.mem.trim(u8, text, " \n");
    if (!std.mem.startsWith(u8, line, "0::/")) return null;
    const current = line["0::/".len..];
    if (std.mem.eql(u8, current, base) or !std.mem.startsWith(u8, current, base) or current.len <= base.len or current[base.len] != '/') return null;
    return walkCgroup(cgroup_root, current, false, &.{}) catch null;
}

const ExecCgroups = struct { cgroup: ?posix.fd_t = null, init_cgroup: ?posix.fd_t = null };

fn execWithNamespacesOf(handle: libcontainer.State, options: libcontainer.ExecOptions, allocator: std.mem.Allocator, prepared: ExecProcess, proc_dir: posix.fd_t, root: posix.fd_t, cgroups: ExecCgroups, hierarchies: []V1Hierarchy) libcontainer.Error!i32 {
    var joins: [8]NamespaceJoin = undefined;
    var ns_fds: [8]posix.fd_t = @splat(-1);
    defer for (ns_fds) |fd| if (fd >= 0) closeFd(fd);
    try prepareExecNamespaces(allocator, handle, &joins, &ns_fds);
    // Recheck after pinning root and namespaces, before entering any of them.
    if (!try alive(handle)) return error.ProcessNotFound;
    var context: ExecContext = .{
        .options = options,
        .handle = handle,
        .process = prepared,
        .proc_dir = proc_dir,
        .root = root,
        .cgroup = cgroups.cgroup,
        .init_cgroup = cgroups.init_cgroup,
        .hierarchies = hierarchies,
        .joins = joins,
        .ns_fds = ns_fds,
    };
    return execWithNamespaces(&context);
}

fn prepareExecNamespaces(allocator: std.mem.Allocator, handle: libcontainer.State, joins: *[8]NamespaceJoin, ns_fds: *[8]posix.fd_t) libcontainer.Error!void {
    const flags = [_]usize{
        linux.CLONE.NEWUSER, linux.CLONE.NEWCGROUP, linux.CLONE.NEWIPC, linux.CLONE.NEWUTS,
        linux.CLONE.NEWNET,  linux.CLONE.NEWPID,    linux.CLONE.NEWNS,  linux.CLONE.NEWTIME,
    };
    for (namespace_names, flags, 0..) |name, flag, i| {
        const path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/ns/{s}", .{ handle.pid, name }, 0);
        joins[i] = .{ .flag = flag, .path = path };
        const opened = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (std.mem.eql(u8, name, "time") and linux.errno(opened) == .NOENT) continue;
        try checkResult(opened);
        ns_fds[i] = @intCast(opened);
        try validateNamespaceFd(ns_fds[i], flag);
    }
}

fn execWithNamespaces(context: *ExecContext) libcontainer.Error!i32 {
    const report = try makePipe();
    defer closeFd(report[0]);
    var report_writer: ?posix.fd_t = report[1];
    defer if (report_writer) |fd| closeFd(fd);
    const ready = try makePipe();
    var owns_ready = true;
    defer if (owns_ready) for (ready) |fd| closeFd(fd);
    context.report = report;
    context.ready = ready;
    context.seccomp_ack = try listenerAckPipe(context.process.seccomp_program, context.options.on_seccomp_listener != null);
    defer closeAckEnd(context, 0);
    defer closeAckEnd(context, 1);
    const helper = try forkProcess();
    if (helper == 0) runExecHelper(context);
    debugLog(context.options.debug, "nsexec[{d}]: nsexec container setup", .{helper});
    closeFd(ready[1]);
    owns_ready = false;
    defer closeFd(ready[0]);
    closeFd(report_writer.?);
    report_writer = null;
    closeAckEnd(context, 0);
    var response: CreateResponse = .{};
    const reported = readAll(report[0], std.mem.asBytes(&response));
    const status = try waitChild(helper);
    if (!reported) return error.CreateFailed;
    if (response.failureError()) |err| return err;
    if (status != 0 or response.pid <= 0) return error.CreateFailed;
    // Like runc's parent: the setup helper is gone before the process execs.
    awaitExecReady(context, ready[0], response.pid) catch |err| {
        _ = linux.kill(response.pid, .KILL);
        // A subreaper caller adopted the child when the helper exited.
        _ = waitChild(response.pid) catch {};
        return err;
    };
    debugLog(context.options.debug, "child process in init()", .{});
    debugLog(context.options.debug, "setns_init: about to exec", .{});
    return response.pid;
}

fn listenerAckPipe(program: ?seccomp.Program, has_callback: bool) libcontainer.Error!?[2]posix.fd_t {
    const value = program orelse return null;
    if (value.flags & seccomp.filter_flag_new_listener == 0) return null;
    // Checked before fork: without a callback the listener fd has nowhere to go.
    if (!has_callback) {
        reportDiagnostic("seccomp notify rules need a listener callback", .{});
        return error.InvalidConfig;
    }
    return try makePipe();
}

/// Idempotent: a closed end is marked -1.
fn closeAckEnd(context: *ExecContext, end: usize) void {
    if (context.seccomp_ack) |*fds| {
        if (fds[end] >= 0) closeFd(fds[end]);
        fds[end] = -1;
    }
}

fn runExecHelper(context: *ExecContext) noreturn {
    const options = context.options;
    const handle = context.handle;
    const proc_dir = context.proc_dir;
    const report = context.report;
    const joins = context.joins;
    resetExecSignals(context.report[1]);
    // Hide the host runtime and its descriptors from container ptrace/procfs.
    checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) catch |err| failCreate(report[1], err);
    closeFd(report[0]);
    if (options.console_fds) |fds| closeFd(fds[0]);
    if (context.seccomp_ack) |fds| closeFd(fds[1]);
    joinExecCgroupsWithAffinity(context);
    skipCurrentNamespaces(context);
    var stat_buffer: [4096]u8 = undefined;
    const stat = readProcStatAt(proc_dir, handle.pid, &stat_buffer) catch |err| failCreate(report[1], err);
    if (!stat.matches(handle.starttime)) failCreate(report[1], error.ProcessNotFound);
    // Negative adjustments require CAP_SYS_RESOURCE in the initial user
    // namespace. Set it here; the grandchild inherits it across fork.
    applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
    joinNamespaceFds(&joins, &context.ns_fds) catch |err| failCreate(report[1], err);
    context.gate = makePipe() catch |err| failCreate(report[1], err);
    const child = forkProcess() catch |err| failCreate(report[1], err);
    if (child == 0) {
        closeFd(context.gate[1]);
        runExecChild(context);
    }
    finishExecHelper(context, child);
}

/// Initial affinity applies before the cgroup join, and final affinity (or a
/// reset) inside the container cgroup, like runc's setnsProcess.
fn joinExecCgroupsWithAffinity(context: *const ExecContext) void {
    const options = context.options;
    const report = context.report;
    const affinity = options.cpu_affinity orelse libcontainer.CPUAffinity{};
    if (affinity.initial) |*set| setCpuAffinity(set) catch |err| {
        reportDiagnostic("error setting initial CPU affinity: {s}", .{@errorName(err)});
        failCreate(report[1], err);
    };
    logCpuAffinity(options.debug);
    joinExecCgroups(context);
    if (affinity.final) |*set| setCpuAffinity(set) catch |err| {
        reportDiagnostic("error setting final CPU affinity: {s}", .{@errorName(err)});
        failCreate(report[1], err);
    } else if (affinity.initial == null) resetCpuAffinity();
}

/// runc's nsexec logs the first 64 CPUs of the starting affinity for its tests.
fn logCpuAffinity(debug: ?libcontainer.DebugLog) void {
    if (debug == null) return;
    var set: libcontainer.CpuSet = @splat(0);
    if (linux.errno(linux.syscall3(.sched_getaffinity, 0, @sizeOf(libcontainer.CpuSet), @intFromPtr(&set))) != .SUCCESS) return;
    debugLog(debug, "nsexec[{d}]: affinity: 0x{x}", .{ linux.getpid(), set[0] });
}

fn resetExecSignals(report_fd: posix.fd_t) void {
    // Reset inherited handlers before any descriptor is closed/reused.
    // The frontend's self-pipe handler must not run in the helper or
    // grandchild. Keep the mask unchanged so pending signals can run.
    const default: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.DFL }, .mask = linux.sigemptyset(), .flags = 0 };
    for (1..linux.NSIG) |number| {
        const signal: linux.SIG = @enumFromInt(number);
        if (signal == .KILL or signal == .STOP) continue;
        var previous: linux.Sigaction = undefined;
        checkResult(linux.sigaction(signal, null, &previous)) catch |err| failCreate(report_fd, err);
        if (previous.handler.handler != linux.SIG.DFL and previous.handler.handler != linux.SIG.IGN)
            checkResult(linux.sigaction(signal, &default, null)) catch |err| failCreate(report_fd, err);
    }
}

fn joinExecCgroups(context: *const ExecContext) void {
    const options = context.options;
    const cgroup = context.cgroup;
    const hierarchies = context.hierarchies;
    const report = context.report;
    // Membership must be established while still in the host cgroup
    // namespace; the grandchild inherits it across the second fork.
    if (cgroup) |fd| switch (tryV1Write(fd, "cgroup.procs", "0")) {
        .SUCCESS => {},
        // Like runc: a cgroup with domain controllers and a moved init
        // refuses new members; join init's own cgroup instead.
        .BUSY => if (context.init_cgroup) |init_fd|
            writeCgroupFile(init_fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err)
        else
            cgroupJoinFailed(report[1], options.cgroup_path, "device or resource busy"),
        else => |errno| cgroupJoinFailed(report[1], options.cgroup_path, @tagName(errno)),
    };
    for (hierarchies) |hierarchy|
        writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
}

fn cgroupJoinFailed(report: posix.fd_t, path: []const u8, reason: []const u8) noreturn {
    reportDiagnostic("error adding pid {d} to cgroups: write /sys/fs/cgroup/{s}/cgroup.procs: {s}", .{ linux.getpid(), path, reason });
    failCreate(report, error.CgroupWriteFailed);
}

fn skipCurrentNamespaces(context: *ExecContext) void {
    const proc_dir = context.proc_dir;
    const report = context.report;
    const ns_fds = &context.ns_fds;
    for (namespace_names, 0..) |name, i| {
        if (ns_fds[i] < 0) continue;
        var buffer: [64]u8 = undefined;
        const own_path = std.fmt.bufPrintZ(&buffer, "self/ns/{s}", .{name}) catch unreachable;
        const own = openPath(proc_dir, own_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch |err| failCreate(report[1], err);
        var own_stat: linux.Statx = undefined;
        var target_stat: linux.Statx = undefined;
        checkResult(linux.statx(own, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &own_stat)) catch |err| failCreate(report[1], err);
        checkResult(linux.statx(ns_fds[i], "", linux.AT.EMPTY_PATH, .{ .INO = true }, &target_stat)) catch |err| failCreate(report[1], err);
        closeFd(own);
        if (!own_stat.mask.INO or !target_stat.mask.INO) failCreate(report[1], error.CreateFailed);
        // In particular, setns into the current user namespace is EINVAL.
        if (own_stat.dev_major == target_stat.dev_major and own_stat.dev_minor == target_stat.dev_minor and own_stat.ino == target_stat.ino) {
            closeFd(ns_fds[i]);
            ns_fds[i] = -1;
        }
    }
}

fn runExecChild(context: *const ExecContext) noreturn {
    const options = context.options;
    const process = context.process.settings;
    const proc_dir = context.proc_dir;
    const root = context.root;
    const report = context.report;
    const ready = context.ready;
    const apparmor_command = context.process.apparmor_command;
    closeFd(report[1]);
    closeFd(ready[0]);
    if (options.umask) |mask| _ = linux.syscall1(.umask, mask);
    // setns(mnt) changes mount visibility, not our inherited root
    // and cwd. Use init's pinned root from the joined mount tree;
    // fchdir + chroot(".") avoids resolving a host PID in container /proc.
    checkResult(linux.fchdir(root)) catch |err| failCreate(ready[1], err);
    checkResult(linux.chroot(".")) catch |err| failCreate(ready[1], err);
    const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch |err| failCreate(ready[1], err);
    const first_closed: u32 = 3 + context.options.preserve_fds;
    // Like runc's ExtraFiles, preserved fds are inherited without CLOEXEC.
    for (3..first_closed) |fd| _ = linux.fcntl(@intCast(fd), linux.F.SETFD, 0);
    closeExecFrom(first_closed, fd_dir) catch |err| failCreate(ready[1], err);
    closeExecHostFds(context, fd_dir);
    changeExecCwd(context);
    // Exec shares init's mount namespace; preserve its /dev/console.
    if (options.console_fds) |fds| setupConsole(fds[1], false, options.console_size) catch |err| {
        childError("cannot set up exec console: ", err);
        failCreate(ready[1], err);
    };
    if (options.pidfd_socket) |socket| sendOwnPidfd(socket) catch |err| failCreate(ready[1], err);
    applyAppArmor(apparmor_command) catch |err| failCreate(ready[1], err);
    applyRlimits(process.rlimits) catch |err| failCreate(ready[1], err);
    finishExecProcess(context);
}

fn closeExecHostFds(context: *const ExecContext, fd_dir: posix.fd_t) void {
    const options = context.options;
    const ready = context.ready;
    // Actually close host directories before cwd can follow /proc/self/fd.
    // Keep stdio, the sync pipe, console socket and the fd scan handle.
    const console_fd = if (options.console_fds) |fds| fds[1] else ready[1];
    const ack_fd = if (context.seccomp_ack) |fds| fds[0] else ready[1];
    var keep = [_]posix.fd_t{ ready[1], console_fd, fd_dir, ack_fd, context.gate[0], options.pidfd_socket orelse ready[1] };
    std.mem.sort(posix.fd_t, &keep, {}, std.sort.asc(posix.fd_t));
    var next_fd: u32 = 3 + options.preserve_fds;
    for (keep) |fd| {
        const keep_fd: u32 = @intCast(fd);
        if (keep_fd < next_fd) continue;
        if (next_fd < keep_fd)
            closeFdRange(next_fd, keep_fd - 1, false, fd_dir) catch |err| failCreate(ready[1], err);
        next_fd = keep_fd + 1;
    }
    closeFdRange(next_fd, std.math.maxInt(u32), false, fd_dir) catch |err| failCreate(ready[1], err);
    closeFd(fd_dir);
}

fn changeExecCwd(context: *const ExecContext) void {
    const ready = context.ready;
    const cwd = context.process.cwd;
    checkResult(linux.chdir(cwd)) catch |err| {
        childError("cannot change exec cwd: ", err);
        failCreate(ready[1], err);
    };
    var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_len = linux.getcwd(&cwd_buffer, cwd_buffer.len);
    checkResult(cwd_len) catch |err| {
        childError("cannot verify exec cwd: ", err);
        failCreate(ready[1], err);
    };
    if (std.mem.startsWith(u8, cwd_buffer[0..cwd_len], "(unreachable)")) {
        childError("exec cwd is outside the container root: ", error.InvalidPath);
        failCreate(ready[1], error.InvalidPath);
    }
}

fn finishExecProcess(context: *const ExecContext) noreturn {
    const process = context.process.settings;
    const ready = context.ready;
    const argv = context.process.argv;
    const envp = context.process.envp;
    const seccomp_program = context.process.seccomp_program;
    // Retain CAP_SYS_ADMIN for installation when NNP is false,
    // matching init's ordering before dropping process privileges.
    const ack_fd = if (context.seccomp_ack) |fds| fds[0] else null;
    // Like runc: before seccomp and the credential change, with privileges.
    applySchedulerAndIOPriority(context.options.scheduler, context.options.io_priority, false) catch |err| failCreate(ready[1], err);
    applyMemoryPolicy(context.options.memory_policy) catch |err| failCreate(ready[1], err);
    if (!process.no_new_privileges) {
        if (seccomp_program) |program|
            installSeccompFor(program, ready[1], ack_fd, false) catch |err| failCreate(ready[1], err);
    }
    var finalized_process = process;
    finalized_process.rlimits = &.{};
    applyProcessSettings(finalized_process) catch |err| {
        childError("cannot apply exec process settings: ", err);
        failCreate(ready[1], err);
    };
    var executable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = resolveExecutable(argv.ptr, envp.ptr, &executable_buffer) catch
        failCreate(ready[1], error.CreateFailed);
    if (process.no_new_privileges) {
        if (seccomp_program) |program|
            installSeccompFor(program, ready[1], ack_fd, false) catch |err| failCreate(ready[1], err);
    }
    applyPersonality(context.options.personality) catch |err| failCreate(ready[1], err);
    waitHelperExit(context.gate[0]);
    execResolved(executable, argv.ptr, envp.ptr) catch {
        failCreate(ready[1], error.CreateFailed);
    };
}

/// Before seccomp and exec, so the pidfd names this process and nothing else.
fn sendOwnPidfd(socket: posix.fd_t) libcontainer.Error!void {
    defer closeFd(socket);
    const opened = linux.pidfd_open(linux.getpid(), 0);
    checkResult(opened) catch |err| {
        reportDiagnostic("failed to pidfd_open: {s}", .{@tagName(linux.errno(opened))});
        return err;
    };
    const pidfd: posix.fd_t = @intCast(opened);
    defer closeFd(pidfd);
    @import("console.zig").console.sendFdWithData(socket, pidfd, "setns") catch |err| {
        reportDiagnostic("failed to send pidfd on socket", .{});
        return err;
    };
}

fn finishExecHelper(context: *const ExecContext, child: i32) noreturn {
    closeFd(context.ready[0]);
    closeFd(context.ready[1]);
    closeFd(context.gate[0]);
    // The frontend waits for the child's exec; leave the child to the
    // nearest subreaper (the shim for detached exec, else the frontend).
    // Exiting closes gate[1], which releases the child.
    var response: CreateResponse = .{ .pid = child };
    if (!writeAll(context.report[1], std.mem.asBytes(&response))) {
        _ = linux.kill(child, .KILL);
        linux.exit_group(1);
    }
    linux.exit_group(0);
}

fn waitHelperExit(gate: posix.fd_t) void {
    var byte: u8 = undefined;
    while (posix.errno(posix.system.read(gate, @ptrCast(&byte), 1)) == .INTR) {}
    closeFd(gate);
}

/// EOF on the CLOEXEC ready pipe means execve succeeded or the child died
/// before execve without reporting an error, as runc's parseSync accepts.
/// Seccomp listener reports are delivered on the way.
fn awaitExecReady(context: *ExecContext, fd: posix.fd_t, child: i32) libcontainer.Error!void {
    var response: CreateResponse = .{};
    const bytes = std.mem.asBytes(&response);
    while (true) {
        const result = posix.system.read(fd, bytes.ptr, 1);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return;
                if (!readAll(fd, bytes[1..])) return error.CreateFailed;
                if (response.failureError()) |err| return err;
                if (response.seccomp_fd < 0) return error.CreateFailed;
                const ack = if (context.seccomp_ack) |fds| fds[1] else -1;
                try deliverSeccompListener(child, response.seccomp_fd, ack, context.options.on_seccomp_listener);
                response = .{};
            },
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

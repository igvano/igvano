const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
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
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const childError = @import("diagnostic.zig").childError;
const failCreate = @import("diagnostic.zig").failCreate;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
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
const installSeccomp = @import("process.zig").installSeccomp;
const applyOomScoreAdj = @import("process.zig").applyOomScoreAdj;
const ProcessSettings = @import("process.zig").ProcessSettings;
const applyProcessSettings = @import("process.zig").applyProcessSettings;
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
    options: Backend.ExecOptions,
    handle: Backend.Handle,
    process: ExecProcess,
    proc_dir: posix.fd_t,
    root: posix.fd_t,
    cgroup: ?posix.fd_t,
    hierarchies: []V1Hierarchy,
    joins: [8]NamespaceJoin,
    ns_fds: [8]posix.fd_t,
    report: [2]posix.fd_t = undefined,
    ready: [2]posix.fd_t = undefined,
};

pub fn exec(ptr: *anyopaque, handle: Backend.Handle, options: Backend.ExecOptions) Backend.Error!i32 {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    if (!try alive(ptr, handle)) return error.ProcessNotFound;
    if (options.argv.len == 0 or options.argv[0].len == 0 or !std.fs.path.isAbsolute(options.cwd))
        return error.InvalidProcess;
    try validateCgroupPath(options.cgroup_path);
    var arena: std.heap.ArenaAllocator = .init(options.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const prepared = try prepareExecProcess(allocator, options);
    const proc_dir = try openPath(linux.AT.FDCWD, "/proc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(proc_dir);
    const root_path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/root", .{handle.pid}, 0);
    const root = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    return execWithCgroups(ptr, handle, options, allocator, prepared, proc_dir, root);
}

fn prepareExecProcess(allocator: std.mem.Allocator, options: Backend.ExecOptions) Backend.Error!ExecProcess {
    const apparmor_command = try prepareAppArmor(allocator, options.apparmor_profile);
    const seccomp_program = if (options.seccomp) |config|
        seccomp.compile(allocator, config, seccomp.Arch.native() orelse return error.Unsupported) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            reportDiagnostic("cannot compile seccomp filter: {s} (maximum 4096 instructions)", .{@errorName(err)});
            return error.InvalidConfig;
        }
    else
        null;
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
    if (process.capabilities) |caps| {
        if (caps.ambient & ~(caps.permitted & caps.inheritable) != 0)
            return error.AmbientCapabilitiesRequirePermittedAndInheritable;
    }
    for (options.rlimits) |limit| if (limit.soft > limit.hard) return error.InvalidConfig;
    return .{ .apparmor_command = apparmor_command, .seccomp_program = seccomp_program, .cwd = cwd, .argv = argv, .envp = envp, .settings = process };
}

fn execWithCgroups(ptr: *anyopaque, handle: Backend.Handle, options: Backend.ExecOptions, allocator: std.mem.Allocator, prepared: ExecProcess, proc_dir: posix.fd_t, root: posix.fd_t) Backend.Error!i32 {
    const cgroup_root = try openCgroupRoot();
    defer closeFd(cgroup_root.fd);
    const cgroup: ?posix.fd_t = if (cgroup_root.mode == .unified)
        (try walkCgroup(cgroup_root.fd, options.cgroup_path, false, &.{})) orelse return error.ProcessNotFound
    else
        null;
    defer if (cgroup) |fd| closeFd(fd);
    const hierarchies: []V1Hierarchy = if (cgroup_root.mode == .legacy) try openV1Hierarchies(allocator, handle.systemd) else &.{};
    defer if (cgroup_root.mode == .legacy) freeV1Hierarchies(allocator, hierarchies);
    for (hierarchies) |*hierarchy|
        hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, options.cgroup_path, false, false)) orelse return error.ProcessNotFound;

    var joins: [8]NamespaceJoin = undefined;
    var ns_fds: [8]posix.fd_t = @splat(-1);
    defer for (ns_fds) |fd| if (fd >= 0) closeFd(fd);
    try prepareExecNamespaces(allocator, handle, &joins, &ns_fds);
    // Recheck after pinning root and namespaces, before entering any of them.
    if (!try alive(ptr, handle)) return error.ProcessNotFound;
    var context: ExecContext = .{
        .options = options,
        .handle = handle,
        .process = prepared,
        .proc_dir = proc_dir,
        .root = root,
        .cgroup = cgroup,
        .hierarchies = hierarchies,
        .joins = joins,
        .ns_fds = ns_fds,
    };
    return execWithNamespaces(&context);
}

fn prepareExecNamespaces(allocator: std.mem.Allocator, handle: Backend.Handle, joins: *[8]NamespaceJoin, ns_fds: *[8]posix.fd_t) Backend.Error!void {
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

fn execWithNamespaces(context: *ExecContext) Backend.Error!i32 {
    const report = try makePipe();
    defer closeFd(report[0]);
    var report_writer: ?posix.fd_t = report[1];
    defer if (report_writer) |fd| closeFd(fd);
    const ready = try makePipe();
    var owns_ready = true;
    defer if (owns_ready) for (ready) |fd| closeFd(fd);
    context.report = report;
    context.ready = ready;
    const helper = try forkProcess();
    if (helper == 0) runExecHelper(context);
    for (ready) |fd| closeFd(fd);
    owns_ready = false;
    closeFd(report_writer.?);
    report_writer = null;
    var response: CreateResponse = .{};
    const reported = readAll(report[0], std.mem.asBytes(&response));
    const status = try waitChild(helper);
    if (!reported) return error.CreateFailed;
    if (response.failureError()) |err| return err;
    if (status != 0 or response.pid <= 0) return error.CreateFailed;
    return response.pid;
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
    joinExecCgroups(context);
    skipCurrentNamespaces(context);
    var stat_buffer: [4096]u8 = undefined;
    const stat = readProcStatAt(proc_dir, handle.pid, &stat_buffer) catch |err| failCreate(report[1], err);
    if (!stat.matches(handle.starttime)) failCreate(report[1], error.ProcessNotFound);
    // Negative adjustments require CAP_SYS_RESOURCE in the initial user
    // namespace. Set it here; the grandchild inherits it across fork.
    applyOomScoreAdj(proc_dir, options.oom_score_adj) catch |err| failCreate(report[1], err);
    joinNamespaceFds(&joins, &context.ns_fds) catch |err| failCreate(report[1], err);
    const child = forkProcess() catch |err| failCreate(report[1], err);
    if (child == 0) runExecChild(context);
    finishExecHelper(context, child);
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
    if (cgroup) |fd| {
        writeCgroupFile(fd, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
    }
    for (hierarchies) |hierarchy|
        writeCgroupFile(hierarchy.leaf.?, "cgroup.procs", "0", options.cgroup_path) catch |err| failCreate(report[1], err);
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
    // setns(mnt) changes mount visibility, not our inherited root
    // and cwd. Use init's pinned root from the joined mount tree;
    // fchdir + chroot(".") avoids resolving a host PID in container /proc.
    checkResult(linux.fchdir(root)) catch |err| failCreate(ready[1], err);
    checkResult(linux.chroot(".")) catch |err| failCreate(ready[1], err);
    const fd_dir = openPath(proc_dir, "self/fd", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }) catch |err| failCreate(ready[1], err);
    closeExecFrom(3, fd_dir) catch |err| failCreate(ready[1], err);
    closeExecHostFds(context, fd_dir);
    changeExecCwd(context);
    // Exec shares init's mount namespace; preserve its /dev/console.
    if (options.console_fds) |fds| setupConsole(fds[1], false) catch |err| {
        childError("cannot set up exec console: ", err);
        failCreate(ready[1], err);
    };
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
    var keep = [_]posix.fd_t{ ready[1], console_fd, fd_dir };
    std.mem.sort(posix.fd_t, &keep, {}, std.sort.asc(posix.fd_t));
    var next_fd: u32 = 3;
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
    if (!process.no_new_privileges) {
        if (seccomp_program) |program|
            installSeccomp(program) catch |err| failCreate(ready[1], err);
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
            installSeccomp(program) catch |err| failCreate(ready[1], err);
    }
    execResolved(executable, argv.ptr, envp.ptr) catch {
        failCreate(ready[1], error.CreateFailed);
    };
}

fn finishExecHelper(context: *const ExecContext, child: i32) noreturn {
    const report = context.report;
    const ready = context.ready;
    closeFd(ready[1]);
    // EOF on this CLOEXEC pipe means execve succeeded or the child died
    // before execve without reporting an error. runc's setnsProcess.start
    // similarly accepts sync-socket EOF after procReady (parseSync).
    // Leave either child for the caller to reap.
    waitExecReady(ready[0]) catch |err| {
        _ = linux.kill(child, .KILL);
        _ = waitChild(child) catch {};
        failCreate(report[1], err);
    };
    // Leave even an already-exited child for the frontend or shim to reap.
    var response: CreateResponse = .{ .pid = child };
    if (!writeAll(report[1], std.mem.asBytes(&response))) {
        _ = linux.kill(child, .KILL);
        _ = waitChild(child) catch {};
        linux.exit_group(1);
    }
    // Adoption is by the nearest subreaper: the shim for detached exec,
    // or the frontend (which enables subreaping) for an attached exec.
    linux.exit_group(0);
}

fn waitExecReady(fd: posix.fd_t) Backend.Error!void {
    var response: CreateResponse = .{};
    const bytes = std.mem.asBytes(&response);
    while (true) {
        const result = posix.system.read(fd, bytes.ptr, 1);
        switch (posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return;
                if (!readAll(fd, bytes[1..])) return error.CreateFailed;
                return response.failureError() orelse error.CreateFailed;
            },
            .INTR => continue,
            else => return error.CreateFailed,
        }
    }
}

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const seccomp = @import("../seccomp.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const CreateResponse = @import("diagnostic.zig").CreateResponse;
const readAll = @import("syscall.zig").readAll;

/// sched_setaffinity(2) on the caller; children inherit it across fork and exec.
pub fn setCpuAffinity(set: *const libcontainer.CpuSet) libcontainer.Error!void {
    return checkResult(linux.syscall3(.sched_setaffinity, 0, @sizeOf(libcontainer.CpuSet), @intFromPtr(set)));
}

/// Like runc's tryResetCPUAffinity: drop an affinity inherited from the caller
/// (taskset, systemd). The kernel clamps all-ones to the CPUs online and in
/// the cgroup cpuset. Best effort, as in runc.
pub fn resetCpuAffinity() void {
    const all: libcontainer.CpuSet = @splat(std.math.maxInt(u64));
    _ = linux.syscall3(.sched_setaffinity, 0, @sizeOf(libcontainer.CpuSet), @intFromPtr(&all));
}

/// Mark inherited descriptors before installing seccomp. A pinned self/fd
/// directory allows the fallback even when the container has no /proc mount.
pub fn closeExecFrom(first: u32, fd_dir: ?posix.fd_t) libcontainer.Error!void {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    return closeFdRange(first, std.math.maxInt(u32), true, fd_dir);
}

pub fn closeFdRange(first: u32, last: u32, cloexec: bool, fd_dir: ?posix.fd_t) libcontainer.Error!void {
    // Linux CLOSE_RANGE_CLOEXEC is 1 << 2; Zig 0.16's packed flags differ.
    const result = linux.syscall3(.close_range, first, last, if (cloexec) @as(u32, 1 << 2) else 0);
    switch (linux.errno(result)) {
        .SUCCESS => return,
        .NOSYS, .PERM, .INVAL => {}, // Old kernel, unsupported flags, or outer filter.
        else => return checkResult(result),
    }
    const dir = try openPath(fd_dir orelse linux.AT.FDCWD, if (fd_dir != null) "." else "/proc/self/fd", .{ .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(dir);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(count) == .INTR) continue;
        try checkResult(count);
        if (count == 0) return;
        try closeDirectoryFdEntries(buffer[0..count], first, last, cloexec, dir);
    }
}

fn closeDirectoryFdEntries(entries: []const u8, first: u32, last: u32, cloexec: bool, dir: posix.fd_t) libcontainer.Error!void {
    var offset: usize = 0;
    while (offset < entries.len) {
        const entry: *align(1) const linux.dirent64 = @ptrCast(&entries[offset]);
        offset += entry.reclen;
        const name_ptr: [*]const u8 = &entry.name;
        const padded = name_ptr[0 .. entry.reclen - @offsetOf(linux.dirent64, "name")];
        const name = padded[0..std.mem.indexOfScalar(u8, padded, 0).?];
        const number = std.fmt.parseInt(u32, name, 10) catch continue;
        if (number < first or number > last or number == dir) continue;
        const fd: posix.fd_t = @intCast(number);
        if (!cloexec) {
            closeFd(fd);
            continue;
        }
        const flags = linux.fcntl(fd, linux.F.GETFD, 0);
        if (linux.errno(flags) == .BADF) continue;
        try checkResult(flags);
        try checkResult(linux.fcntl(fd, linux.F.SETFD, flags | linux.FD_CLOEXEC));
    }
}

/// Filter before fork so warnings and any stderr bookkeeping stay in the parent.
pub fn kernelCapabilities(configured: libcontainer.Capabilities) libcontainer.Error!libcontainer.Capabilities {
    var supported: u64 = 0;
    for (0..64) |cap| {
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        supported |= @as(u64, 1) << @intCast(cap);
    }
    var result = configured;
    var ignored: u64 = 0;
    inline for (std.meta.fields(libcontainer.Capabilities)) |field| {
        ignored |= @field(result, field.name) & ~supported;
        @field(result, field.name) &= supported;
    }
    for (0..64) |cap| {
        if (ignored & (@as(u64, 1) << @intCast(cap)) != 0)
            std.debug.print("igvano: warning: ignoring capability {d}, unsupported by this kernel\n", .{cap});
    }
    return result;
}

pub const CapabilityHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,
};

pub fn runProcess(configured: ?libcontainer.Process, executable: ?[*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, seccomp_program: ?seccomp.Program) !noreturn {
    // A process-less config can be created; it cannot be started.
    const process = configured orelse return error.InvalidProcess;
    // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
    if (process.no_new_privileges) {
        if (seccomp_program) |program| try installSeccomp(program);
    }
    try applyPersonality(process.personality);
    return execResolved(executable orelse return error.InvalidProcess, argv, envp);
}

// Runtime syscalls after successful filter installation:
// - NNP=false init/exec: setgroups, setgid, setuid, capset, prctl (credentials
//   and capabilities); faccessat2, statx (PATH lookup under the configured user).
//   On x86/arm these credential calls are setgroups32/setgid32/setuid32.
// - init: write/close (readiness), openat/close (FIFO), write (acknowledgement),
//   execve. NNP=true installs after the hooks and FIFO ack, leaving only execve.
// - exec: execve; NNP=true installs after process settings and PATH lookup.
// - NNP=false start hooks, when configured: memfd_create, fcntl (only with
//   closed stdio), write, lseek, clock_gettime, fork (clone on aarch64), dup2
//   (dup3 on aarch64), execve, wait4, nanosleep, close; kill on hook failure/
//   timeout, pread64 on hook failure. Error paths also write and exit_group.
// No descriptor sweep or rlimit syscall belongs after this point. FIFO opens
// use O_CLOEXEC; hook memfds and relocated fds use MFD_CLOEXEC/F_DUPFD_CLOEXEC,
// and only intentional hook stdio dup2/dup3 targets clear CLOEXEC.
/// The NOTIFY-capable form of installSeccomp. Like runc, report the listener
/// fd number on `report_fd` (write must never be notified, which the frontend
/// enforces), then wait for the runtime to copy it before closing ours.
/// Notified syscalls made meanwhile simply wait for the agent.
/// `rootless`: init of a non-root runtime that created the user namespace,
/// already dumpable by design. setuid to a non-root user clears dumpable,
/// and pidfd_getfd then fails the ptrace check, so restore it until the
/// ack. Other callers fail closed, as runc does.
pub fn installSeccompListener(program: seccomp.Program, report_fd: posix.fd_t, ack_fd: posix.fd_t, rootless: bool) libcontainer.Error!void {
    var listener: i32 = -1;
    const result = seccomp.installListener(program, &listener);
    if (result != .SUCCESS) return seccompFailed(result);
    defer closeFd(listener);
    defer closeFd(ack_fd);
    if (rootless) try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 1, 0, 0, 0));
    const response: CreateResponse = .{ .seccomp_fd = listener };
    if (!writeAll(report_fd, std.mem.asBytes(&response))) return error.CreateFailed;
    var byte: [1]u8 = undefined;
    if (!readAll(ack_fd, &byte) or byte[0] != 1) return error.CreateFailed;
    if (rootless) try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0));
}

/// Installs with a listener when the program has notify rules.
pub fn installSeccompFor(program: seccomp.Program, report_fd: posix.fd_t, ack_fd: ?posix.fd_t, rootless: bool) libcontainer.Error!void {
    if (program.flags & seccomp.filter_flag_new_listener == 0) return installSeccomp(program);
    return installSeccompListener(program, report_fd, ack_fd orelse return error.CreateFailed, rootless);
}

pub fn installSeccomp(program: seccomp.Program) libcontainer.Error!void {
    const result = seccomp.install(program);
    if (result != .SUCCESS) return seccompFailed(result);
}

fn seccompFailed(result: linux.E) libcontainer.Error {
    var errno_buffer: [16]u8 = undefined;
    const errno_name = std.enums.tagName(linux.E, result) orelse
        (std.fmt.bufPrint(&errno_buffer, "{d}", .{@intFromEnum(result)}) catch unreachable);
    reportDiagnostic("cannot install seccomp filter: E{s}", .{errno_name});
    return error.CreateFailed;
}

/// Runtime side of installSeccompListener: copy fd `target` out of `pid`
/// (pidfd_getfd, Linux 5.6+), let the process go on, then hand the copy to
/// the frontend, which sends it to the seccomp agent.
pub fn deliverSeccompListener(pid: i32, target: i32, ack_fd: posix.fd_t, callback: ?libcontainer.SeccompListenerCallback) libcontainer.Error!void {
    const pidfd = linux.pidfd_open(pid, 0);
    if (linux.errno(pidfd) != .SUCCESS) {
        reportDiagnostic("cannot open pidfd for seccomp listener of pid {d}: E{s}", .{ pid, @tagName(linux.errno(pidfd)) });
        return error.CreateFailed;
    }
    defer closeFd(@intCast(pidfd));
    const copied = linux.pidfd_getfd(@intCast(pidfd), target, 0);
    if (linux.errno(copied) != .SUCCESS) {
        reportDiagnostic("cannot copy seccomp listener fd {d} from pid {d}: E{s}", .{ target, pid, @tagName(linux.errno(copied)) });
        return error.CreateFailed;
    }
    const listener: posix.fd_t = @intCast(copied);
    defer closeFd(listener);
    if (!writeAll(ack_fd, &.{1})) return error.CreateFailed;
    const send = callback orelse {
        reportDiagnostic("seccomp notify filter installed without a listener callback", .{});
        return error.InvalidConfig;
    };
    try send.run(send.ptr, listener, pid);
}

pub fn applyOomScoreAdj(proc_dir: posix.fd_t, oom_score_adj: ?i32) libcontainer.Error!void {
    if (comptime builtin.os.tag == .linux) {
        // The runtime pins this procfs before joining namespaces; this write
        // precedes isolation, so it never uses the container's /proc.
        const value = oom_score_adj orelse return;
        var buffer: [12]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable;
        const fd = try openPath(proc_dir, "self/oom_score_adj", .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
        defer closeFd(fd);
        if (!writeAll(fd, text)) return error.CreateFailed;
    } else {
        return error.NotImplemented;
    }
}

pub const ProcessSettings = struct {
    uid: u32,
    gid: u32,
    additional_gids: []const u32,
    no_new_privileges: bool,
    capabilities: ?libcontainer.Capabilities,
    rlimits: []const libcontainer.Rlimit,
};

/// Runs before readiness, without allocating. Keep privileges until limits and
/// bounding drops finish, then retain permitted caps across the UID transition.
// For UID 0, exec recomputes permitted/effective as inheritable | bounding (as in runc).
pub fn applyProcess(process: libcontainer.Process, capabilities: ?libcontainer.Capabilities, rlimits: []const libcontainer.Rlimit) libcontainer.Error!void {
    return applyProcessSettings(.{
        .uid = process.uid,
        .gid = process.gid,
        .additional_gids = process.additional_gids,
        .no_new_privileges = process.no_new_privileges,
        .capabilities = capabilities,
        .rlimits = rlimits,
    });
}

const SchedAttr = extern struct {
    size: u32 = @sizeOf(SchedAttr),
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
};

/// Like runc, before seccomp and the credential change. `cpuset`:
/// the cgroup restricts CPUs, so sched_setattr's EPERM gets runc's message.
/// youki's setup_memory_policy.
pub fn applyMemoryPolicy(policy: ?libcontainer.MemoryPolicy) libcontainer.Error!void {
    if (policy) |value| {
        // No nodes: a NULL mask, which the kernel takes as empty.
        const mask: usize = if (value.maxnode == 0) 0 else @intFromPtr(&value.nodemask);
        const result = linux.syscall3(.set_mempolicy, @as(usize, @bitCast(@as(isize, value.mode))), mask, value.maxnode);
        checkResult(result) catch |err| {
            reportDiagnostic("set_mempolicy: {s}", .{@tagName(linux.errno(result))});
            return err;
        };
    }
}

/// runc's setupPersonality. Called after every seccomp filter is in place,
/// so the container's filter also governs personality(2).
pub fn applyPersonality(personality: ?u32) libcontainer.Error!void {
    if (personality) |value| {
        const result = linux.syscall1(.personality, value);
        checkResult(result) catch |err| {
            reportDiagnostic("set_personality: {s}", .{@tagName(linux.errno(result))});
            return err;
        };
    }
}

pub fn applySchedulerAndIOPriority(scheduler: ?libcontainer.Scheduler, io_priority: ?libcontainer.IOPriority, cpuset: bool) libcontainer.Error!void {
    if (scheduler) |value| {
        const attr: SchedAttr = .{ .policy = value.policy, .flags = value.flags, .nice = value.nice, .priority = value.priority, .runtime = value.runtime, .deadline = value.deadline, .period = value.period };
        const result = linux.syscall3(.sched_setattr, 0, @intFromPtr(&attr), 0);
        if (linux.errno(result) == .PERM and cpuset) {
            reportDiagnostic("process scheduler can't be used together with AllowedCPUs", .{});
            return error.PermissionDenied;
        }
        if (linux.errno(result) != .SUCCESS) {
            reportDiagnostic("error setting scheduler: E{s}", .{@tagName(linux.errno(result))});
            return checkResult(result);
        }
    }
    if (io_priority) |value| {
        // runc names this ioprioWhoPgrp, but 1 is IOPRIO_WHO_PROCESS: only
        // this process (and its children) change, never the caller's group.
        const ioprio_who_process = 1;
        const result = linux.syscall3(.ioprio_set, ioprio_who_process, 0, (@as(usize, value.class) << 13) | value.priority);
        if (linux.errno(result) != .SUCCESS) {
            reportDiagnostic("failed to set io priority: E{s}", .{@tagName(linux.errno(result))});
            return checkResult(result);
        }
    }
}

pub fn applyProcessSettings(process: ProcessSettings) libcontainer.Error!void {
    if (comptime builtin.os.tag == .linux) {
        try applyRlimits(process.rlimits);
        if (process.no_new_privileges)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
        if (process.capabilities) |caps| {
            try dropBoundingCapabilities(caps.bounding);
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
        }
        try fixStdioOwner(process.uid);
        // With a user namespace, additional_gids (like uid/gid) are namespace IDs.
        const groups = process.additional_gids;
        // Like runc, skip it only in a user namespace with setgroups "deny"
        // (rootless), where the kernel refuses it; otherwise fail closed.
        const result = linux.setgroups(groups.len, groups.ptr);
        if (!(linux.errno(result) == .PERM and groups.len == 0 and setgroupsDenied())) try checkResult(result);
        try checkResult(linux.setgid(process.gid));
        try checkResult(linux.setuid(process.uid));
        if (process.capabilities) |caps| try applyCapabilities(caps);
    } else {
        return error.NotImplemented;
    }
}

/// runc's fixStdioPermissions: stdio (a console, or pipes made by the
/// runtime) belongs to the process user, so it can use them. Only the
/// owner changes; /dev/null is left alone, and like runc only EINVAL,
/// EPERM and EROFS are ignored.
fn fixStdioOwner(uid: u32) libcontainer.Error!void {
    for (0..3) |fd| {
        var stat: linux.Statx = undefined;
        if (linux.errno(linux.statx(@intCast(fd), "", linux.AT.EMPTY_PATH, .{ .UID = true, .GID = true, .TYPE = true }, &stat)) != .SUCCESS) continue;
        if (stat.uid == uid) continue;
        if (stat.mode & linux.S.IFMT == linux.S.IFCHR and stat.rdev_major == 1 and stat.rdev_minor == 3) continue;
        const result = linux.fchown(@intCast(fd), uid, stat.gid);
        switch (linux.errno(result)) {
            .SUCCESS, .INVAL, .PERM, .ROFS => {},
            else => try checkResult(result),
        }
    }
}

fn setgroupsDenied() bool {
    const fd = openPath(linux.AT.FDCWD, "/proc/self/setgroups", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return false;
    defer closeFd(fd);
    var buffer: [16]u8 = undefined;
    const count = linux.read(fd, &buffer, buffer.len);
    if (linux.errno(count) != .SUCCESS) return false;
    return std.mem.eql(u8, std.mem.trim(u8, buffer[0..count], " \n"), "deny");
}

fn dropBoundingCapabilities(bounding: u64) libcontainer.Error!void {
    for (0..64) |cap| {
        // EINVAL marks the running kernel's last supported capability.
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        if (result != 0 and bounding & (@as(u64, 1) << @intCast(cap)) == 0)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0));
    }
}

fn applyCapabilities(caps: libcontainer.Capabilities) libcontainer.Error!void {
    // Linux's header uses a 32-bit pid, unlike Zig 0.16's usize field.
    const header: CapabilityHeader = .{};
    const data = [2]linux.cap_user_data_t{
        .{ .effective = @truncate(caps.effective), .permitted = @truncate(caps.permitted), .inheritable = @truncate(caps.inheritable) },
        .{ .effective = @truncate(caps.effective >> 32), .permitted = @truncate(caps.permitted >> 32), .inheritable = @truncate(caps.inheritable >> 32) },
    };
    try checkResult(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 0, 0, 0, 0));
    // Discard inherited ambient caps even when the configured set is empty.
    try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
    // Like runc, raise ambient caps one by one and only warn on failure
    // (an ambient cap must also be permitted and inheritable).
    for (0..64) |cap| {
        if (caps.ambient & (@as(u64, 1) << @intCast(cap)) == 0) continue;
        const result = linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_RAISE, cap, 0, 0);
        if (linux.errno(result) == .SUCCESS) continue;
        var buffer: [128]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "igvano: warning: can't raise ambient capability {s}: {s}\n", .{ capabilityName(cap), errnoText(linux.errno(result)) orelse @tagName(linux.errno(result)) }) catch continue;
        _ = writeAll(2, line);
    }
}

const capability_names = names: {
    var result: [linux.CAP.LAST_CAP + 1][]const u8 = @splat("CAP_UNKNOWN");
    for (std.meta.declarations(linux.CAP)) |decl| {
        if (!std.mem.eql(u8, decl.name, "LAST_CAP") and @TypeOf(@field(linux.CAP, decl.name)) == comptime_int)
            result[@field(linux.CAP, decl.name)] = "CAP_" ++ decl.name;
    }
    break :names result;
};

fn capabilityName(cap: usize) []const u8 {
    return if (cap < capability_names.len) capability_names[cap] else "CAP_UNKNOWN";
}

pub fn applyRlimits(rlimits: []const libcontainer.Rlimit) libcontainer.Error!void {
    for (rlimits) |limit| {
        const value: linux.rlimit = .{ .cur = limit.soft, .max = limit.hard };
        try checkResult(linux.setrlimit(limit.resource, &value));
    }
}

/// Go's exec.LookPath: a regular file, checked with the effective IDs and
/// capabilities (faccessat2 AT_EACCESS), so CAP_DAC_OVERRIDE counts. When
/// that call is missing or filtered, any execute bit will do.
fn isExecutable(path: [*:0]const u8) bool {
    // Zig 0.16 exposes statx rather than fstatat; follow symlinks and check type.
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true, .MODE = true }, &stat)) != .SUCCESS) return false;
    if (!stat.mask.TYPE or !linux.S.ISREG(stat.mode)) return false;
    const AT_EACCESS = 0x200;
    return switch (linux.errno(linux.syscall4(.faccessat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(path), linux.X_OK, AT_EACCESS))) {
        .SUCCESS => true,
        .NOSYS, .PERM => stat.mode & 0o111 != 0,
        else => false,
    };
}

pub fn resolveExecutable(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, buffer: []u8) error{ExecFailed}![*:0]const u8 {
    const executable = argv[0] orelse return error.ExecFailed;
    const name = std.mem.span(executable);
    errdefer reportDiagnostic("exec: \"{s}\": executable file not found in $PATH", .{name});
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        if (isExecutable(executable)) return executable;
        return error.ExecFailed;
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
    // Lookup happens inside the rootfs, without allocating after fork.
    var directories = std.mem.splitScalar(u8, path, ':');
    while (directories.next()) |directory| {
        const candidate = if (directory.len == 0) executable else (std.fmt.bufPrintZ(buffer, "{s}/{s}", .{ directory, name }) catch continue).ptr;
        if (isExecutable(candidate)) return candidate;
    }
    return error.ExecFailed;
}

pub fn execResolved(executable: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) error{ExecFailed}!noreturn {
    const err = linux.errno(linux.execve(executable, argv, envp));
    // runc's wording: "exec <args[0]>: <strerror>".
    var errno_buffer: [24]u8 = undefined;
    const text = errnoText(err) orelse if (std.enums.tagName(linux.E, err)) |name|
        std.fmt.bufPrint(&errno_buffer, "E{s}", .{name}) catch unreachable
    else
        std.fmt.bufPrint(&errno_buffer, "errno {d}", .{@intFromEnum(err)}) catch unreachable;
    reportDiagnostic("exec {s}: {s}", .{ std.mem.span(argv[0] orelse executable), text });
    return error.ExecFailed;
}

/// Go's syscall.Errno text for the errors execve commonly returns.
fn errnoText(err: linux.E) ?[]const u8 {
    return switch (err) {
        .NOENT => "no such file or directory",
        .ACCES => "permission denied",
        .NOEXEC => "exec format error",
        .PERM => "operation not permitted",
        .NOTDIR => "not a directory",
        .LOOP => "too many levels of symbolic links",
        .@"2BIG" => "argument list too long",
        .TXTBSY => "text file busy",
        .NOMEM => "cannot allocate memory",
        .ISDIR => "is a directory",
        .INVAL => "invalid argument",
        else => null,
    };
}

pub fn execProcess(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) error{ExecFailed}!noreturn {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = try resolveExecutable(argv, envp, &buffer);
    return execResolved(executable, argv, envp);
}

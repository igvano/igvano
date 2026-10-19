const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const oci = @import("../../oci.zig");
const seccomp = @import("../seccomp.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const writeAll = @import("syscall.zig").writeAll;
const openPath = @import("syscall.zig").openPath;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;

/// Mark inherited descriptors before installing seccomp. A pinned self/fd
/// directory allows the fallback even when the container has no /proc mount.
pub fn closeExecFrom(first: u32, fd_dir: ?posix.fd_t) Backend.Error!void {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    return closeFdRange(first, std.math.maxInt(u32), true, fd_dir);
}

pub fn closeFdRange(first: u32, last: u32, cloexec: bool, fd_dir: ?posix.fd_t) Backend.Error!void {
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

fn closeDirectoryFdEntries(entries: []const u8, first: u32, last: u32, cloexec: bool, dir: posix.fd_t) Backend.Error!void {
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
pub fn kernelCapabilities(configured: Backend.Capabilities) Backend.Error!Backend.Capabilities {
    var supported: u64 = 0;
    for (0..64) |cap| {
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        supported |= @as(u64, 1) << @intCast(cap);
    }
    var result = configured;
    var ignored: u64 = 0;
    inline for (std.meta.fields(Backend.Capabilities)) |field| {
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

pub fn runProcess(spec: *const oci.Spec, executable: ?[*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8, seccomp_program: ?seccomp.Program) !noreturn {
    // A process-less config can be created; it cannot be started.
    if (spec.process == null) return error.InvalidProcess;
    // With NNP=true, install after startContainer hooks (unfiltered); NNP=false hooks run filtered, intentionally.
    if (spec.process.?.noNewPrivileges) {
        if (seccomp_program) |program| try installSeccomp(program);
    }
    return execResolved(executable orelse return error.InvalidProcess, argv, envp);
}

// Runtime syscalls after successful filter installation:
// - NNP=false init/exec: setgroups, setgid, setuid, capset, prctl (credentials
//   and capabilities); faccessat, statx (PATH lookup under the configured user).
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
pub fn installSeccomp(program: seccomp.Program) Backend.Error!void {
    const result = seccomp.install(program);
    if (result != .SUCCESS) {
        var errno_buffer: [16]u8 = undefined;
        const errno_name = std.enums.tagName(linux.E, result) orelse
            (std.fmt.bufPrint(&errno_buffer, "{d}", .{@intFromEnum(result)}) catch unreachable);
        reportDiagnostic("cannot install seccomp filter: E{s}", .{errno_name});
        return error.CreateFailed;
    }
}

pub fn applyOomScoreAdj(proc_dir: posix.fd_t, oom_score_adj: ?i32) Backend.Error!void {
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
    capabilities: ?Backend.Capabilities,
    rlimits: []const Backend.Rlimit,
};

/// Runs before readiness, without allocating. Keep privileges until limits and
/// bounding drops finish, then retain permitted caps across the UID transition.
// For UID 0, exec recomputes permitted/effective as inheritable | bounding (as in runc).
pub fn applyProcess(process: oci.Spec.Process, capabilities: ?Backend.Capabilities, rlimits: []const Backend.Rlimit) Backend.Error!void {
    return applyProcessSettings(.{
        .uid = process.user.uid,
        .gid = process.user.gid,
        .additional_gids = process.user.additionalGids orelse &.{},
        .no_new_privileges = process.noNewPrivileges,
        .capabilities = capabilities,
        .rlimits = rlimits,
    });
}

pub fn applyProcessSettings(process: ProcessSettings) Backend.Error!void {
    if (comptime builtin.os.tag == .linux) {
        try applyRlimits(process.rlimits);
        if (process.no_new_privileges)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
        if (process.capabilities) |caps| {
            try dropBoundingCapabilities(caps.bounding);
            try checkResult(linux.prctl(@intFromEnum(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
        }
        // With a user namespace, additionalGids (like uid/gid) are namespace IDs.
        const groups = process.additional_gids;
        try checkResult(linux.setgroups(groups.len, groups.ptr));
        try checkResult(linux.setgid(process.gid));
        try checkResult(linux.setuid(process.uid));
        if (process.capabilities) |caps| try applyCapabilities(caps);
    } else {
        return error.NotImplemented;
    }
}

fn dropBoundingCapabilities(bounding: u64) Backend.Error!void {
    for (0..64) |cap| {
        // EINVAL marks the running kernel's last supported capability.
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        try checkResult(result);
        if (result != 0 and bounding & (@as(u64, 1) << @intCast(cap)) == 0)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0));
    }
}

fn applyCapabilities(caps: Backend.Capabilities) Backend.Error!void {
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
    for (0..64) |cap| {
        if (caps.ambient & (@as(u64, 1) << @intCast(cap)) != 0)
            try checkResult(linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_RAISE, cap, 0, 0));
    }
}

pub fn applyRlimits(rlimits: []const Backend.Rlimit) Backend.Error!void {
    for (rlimits) |limit| {
        const value: linux.rlimit = .{ .cur = limit.soft, .max = limit.hard };
        try checkResult(linux.setrlimit(limit.resource, &value));
    }
}

fn isExecutable(path: [*:0]const u8) bool {
    if (linux.errno(linux.faccessat(linux.AT.FDCWD, path, linux.X_OK, 0)) != .SUCCESS) return false;
    // Zig 0.16 exposes statx rather than fstatat; follow symlinks and check type.
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat)) != .SUCCESS) return false;
    return stat.mask.TYPE and linux.S.ISREG(stat.mode);
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
    // Linux's errno tags omit the E prefix used by runtime diagnostics.
    var errno_buffer: [16]u8 = undefined;
    const errno_name = std.enums.tagName(linux.E, err) orelse
        (std.fmt.bufPrint(&errno_buffer, "{d}", .{@intFromEnum(err)}) catch unreachable);
    reportDiagnostic("cannot execute process: E{s}", .{errno_name});
    return error.ExecFailed;
}

pub fn execProcess(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) error{ExecFailed}!noreturn {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const executable = try resolveExecutable(argv, envp, &buffer);
    return execResolved(executable, argv, envp);
}

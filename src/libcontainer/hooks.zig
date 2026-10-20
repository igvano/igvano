const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const reportDiagnostic = @import("linux.zig").reportDiagnostic;

/// Execution settings, already validated and translated by the frontend.
pub const Hook = struct {
    path: []const u8,
    args: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
    timeout_seconds: ?u64 = null,
};

pub const Prepared = struct {
    path: [:0]const u8,
    argv: [:null]const ?[*:0]const u8,
    envp: [:null]const ?[*:0]const u8,
    timeout_seconds: ?u64,
};

pub const Error = error{ HookFailed, HookTimeout, InvalidConfig, SystemResources, NotImplemented };

/// Use an arena: all strings and pointer arrays outlive fork and exec.
pub fn prepare(allocator: std.mem.Allocator, entries: []const Hook) ![]Prepared {
    const prepared = try allocator.alloc(Prepared, entries.len);
    for (entries, prepared) |entry, *hook| {
        if (!std.mem.startsWith(u8, entry.path, "/") or
            std.mem.indexOfScalar(u8, entry.path, 0) != null or
            entry.timeout_seconds == 0) return error.InvalidConfig;
        const path = try allocator.dupeZ(u8, entry.path);
        const args = if (entry.args.len == 0) &.{entry.path} else entry.args;
        const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);
        for (args, 0..) |arg, i| {
            if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidConfig;
            argv[i] = (try allocator.dupeZ(u8, arg)).ptr;
        }
        const envp = try allocator.allocSentinel(?[*:0]const u8, entry.env.len, null);
        for (entry.env, 0..) |env, i| {
            if (std.mem.indexOfScalar(u8, env, 0) != null) return error.InvalidConfig;
            envp[i] = (try allocator.dupeZ(u8, env)).ptr;
        }
        hook.* = .{ .path = path, .argv = argv, .envp = envp, .timeout_seconds = entry.timeout_seconds };
    }
    return prepared;
}

pub fn timeoutExpired(timeout_seconds: ?u64, elapsed_ns: u128) bool {
    const seconds = timeout_seconds orelse return false;
    return elapsed_ns >= @as(u128, seconds) * std.time.ns_per_s;
}

/// No allocator or std.Io calls after fork. Memfds supply stdin and capture
/// output without blocking the deadline on a full pipe or inheriting closed stdio.
pub fn run(entries: []const Prepared, state: []const u8) Error!void {
    return runHooks(entries, state, true);
}

/// Init has already swept inherited descriptors before seccomp. Every fd
/// created below is CLOEXEC except the hook child's intentional stdio copies.
/// NNP=false start hooks must avoid sweeping under the installed filter.
pub fn runWithCloexecFds(entries: []const Prepared, state: []const u8) Error!void {
    return runHooks(entries, state, false);
}

fn runHooks(entries: []const Prepared, state: []const u8, sweep: bool) Error!void {
    if (entries.len == 0) return;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    for (entries, 0..) |hook, index| {
        var reported = false;
        runOne(hook, state, index, &reported, sweep) catch |err| {
            // Only memfd setup can fail before runOne's diagnostic errdefer.
            if (!reported)
                reportDiagnostic("error running hook #{d}: {s}, stdout: , stderr: ", .{ index, @errorName(err) });
            return err;
        };
    }
}

fn monotonicNow() Error!u128 {
    var time: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &time)) != .SUCCESS) return error.HookFailed;
    return @as(u128, @intCast(time.sec)) * std.time.ns_per_s + @as(u128, @intCast(time.nsec));
}

fn createMemfd(name: [*:0]const u8) Error!std.posix.fd_t {
    const created = linux.memfd_create(name, linux.MFD.CLOEXEC);
    if (linux.errno(created) != .SUCCESS) return error.SystemResources;
    const fd: std.posix.fd_t = @intCast(created);
    if (fd <= 2) {
        // dup2(fd, fd) keeps CLOEXEC. Keep the source away from stdio even
        // when the runtime was launched with one of those descriptors closed.
        const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
        _ = linux.close(fd);
        if (linux.errno(moved) != .SUCCESS) return error.SystemResources;
        return @intCast(moved);
    }
    return fd;
}

fn capturedOutput(fd: std.posix.fd_t, buffer: []u8) []const u8 {
    while (true) {
        const result = linux.pread(fd, buffer.ptr, buffer.len, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return std.mem.trim(u8, buffer[0..result], " \t\r\n"),
            .INTR => continue,
            else => return "",
        }
    }
}

fn reportFailure(index: usize, err: Error, status: u32, output: std.posix.fd_t, errors: std.posix.fd_t) void {
    // Reserve room for both labels and the failure reason in the 512-byte detail.
    var stdout_buffer: [192]u8 = undefined;
    var stderr_buffer: [192]u8 = undefined;
    const stdout = capturedOutput(output, &stdout_buffer);
    const stderr = capturedOutput(errors, &stderr_buffer);
    var reason_buffer: [64]u8 = undefined;
    const reason = if (err == error.HookTimeout)
        "timeout"
    else if (linux.W.IFSIGNALED(status)) signal: {
        const sig = linux.W.TERMSIG(status);
        break :signal if (std.enums.tagName(linux.SIG, sig)) |name|
            std.fmt.bufPrint(&reason_buffer, "signal: {s}", .{name}) catch unreachable
        else
            std.fmt.bufPrint(&reason_buffer, "signal: {d}", .{@intFromEnum(sig)}) catch unreachable;
    } else if (status != 0 and linux.W.IFEXITED(status))
        std.fmt.bufPrint(&reason_buffer, "exit status {d}", .{linux.W.EXITSTATUS(status)}) catch unreachable
    else
        @errorName(err);
    reportDiagnostic("error running hook #{d}: {s}, stdout: {s}, stderr: {s}", .{ index, reason, stdout, stderr });
}

fn runOne(hook: Prepared, state: []const u8, index: usize, reported: *bool, sweep: bool) Error!void {
    const input = try createMemfd("igvano-hook-stdin");
    defer _ = linux.close(input);
    // ponytail: Captured hook output is unbounded, like runc's buffers; the
    // upgrade path is a size cap.
    const output = try createMemfd("igvano-hook-stdout");
    defer _ = linux.close(output);
    const errors = try createMemfd("igvano-hook-stderr");
    defer _ = linux.close(errors);
    var status: u32 = 0;
    errdefer |err| {
        reportFailure(index, err, status, output, errors);
        reported.* = true;
    }
    try writeHookState(input, state);
    const started = try monotonicNow();
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const pid: i32 = @intCast(forked);
    if (pid == 0) execHook(hook, input, output, errors, sweep);
    try waitHook(pid, hook.timeout_seconds, started, &status);
}

fn writeHookState(input: std.posix.fd_t, state: []const u8) Error!void {
    var offset: usize = 0;
    while (offset < state.len) {
        const result = linux.write(input, state[offset..].ptr, state.len - offset);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.HookFailed;
                offset += result;
            },
            .INTR => continue,
            else => return error.HookFailed,
        }
    }
    if (linux.errno(linux.lseek(input, 0, linux.SEEK.SET)) != .SUCCESS) return error.HookFailed;
}

fn execHook(hook: Prepared, input: std.posix.fd_t, output: std.posix.fd_t, errors: std.posix.fd_t, sweep: bool) noreturn {
    for ([_]std.posix.fd_t{ input, output, errors }, 0..) |fd, target|
        if (linux.errno(linux.dup2(fd, @intCast(target))) != .SUCCESS) linux.exit_group(1);
    if (sweep) @import("linux.zig").closeExecFrom(3, null) catch linux.exit_group(1);
    _ = linux.execve(hook.path, hook.argv.ptr, hook.envp.ptr);
    linux.exit_group(1);
}

fn waitHook(pid: i32, timeout_seconds: ?u64, started: u128, status: *u32) Error!void {
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        while (linux.errno(linux.waitpid(pid, status, 0)) == .INTR) {}
    };
    while (true) {
        const result = linux.waitpid(pid, status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => if (result != 0) {
                reaped = true;
                if (status.* != 0) return error.HookFailed;
                return;
            },
            .INTR => continue,
            .CHILD => {
                reaped = true;
                return error.HookFailed;
            },
            else => return error.HookFailed,
        }
        if (timeoutExpired(timeout_seconds, (try monotonicNow()) - started)) return error.HookTimeout;
        const delay: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        switch (linux.errno(linux.nanosleep(&delay, null))) {
            .SUCCESS, .INTR => {},
            else => return error.HookFailed,
        }
    }
}

test "hook timeout expires at its deadline and an omitted timeout never expires" {
    try std.testing.expect(!timeoutExpired(null, std.math.maxInt(u128)));
    try std.testing.expect(!timeoutExpired(1, 999_999_999));
    try std.testing.expect(timeoutExpired(1, 1_000_000_000));
    try std.testing.expect(timeoutExpired(1, 1_000_000_001));
    try std.testing.expect(!timeoutExpired(std.math.maxInt(u64), std.math.maxInt(u64)));
}

test "linux hooks close inherited fds at exec without changing caller flags" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const source = linux.open("/dev/null", .{}, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(source));
    defer _ = linux.close(@intCast(source));
    const copied = linux.fcntl(@intCast(source), linux.F.DUPFD, 100);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(copied));
    const fd: std.posix.fd_t = @intCast(copied);
    defer _ = linux.close(fd);
    try std.testing.expectEqual(@as(usize, 0), linux.fcntl(fd, linux.F.GETFD, 0));
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const command = try std.fmt.allocPrint(arena.allocator(), "test ! -e /proc/self/fd/{d}", .{fd});
    const entries = try prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", command },
        .timeout_seconds = 2,
    }});
    try run(entries, "{}\n");
    try std.testing.expectEqual(@as(usize, 0), linux.fcntl(fd, linux.F.GETFD, 0));
}

test "linux hook execution uses explicit argv environment and state stdin" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const entries = try prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "custom-argv0", "-c", "test \"$0\" = custom-argv0 && test \"$ONLY\" = hook && test -z \"${HOME+x}\" && IFS= read -r state && test \"$state\" = expected" },
        .env = &.{"ONLY=hook"},
        .timeout_seconds = 2,
    }});
    try run(entries, "expected\n");
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        _ = linux.close(0);
        run(entries, "expected\n") catch linux.exit_group(1);
        linux.exit_group(0);
    }
    var status: u32 = undefined;
    while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    try std.testing.expectEqual(@as(u32, 0), status);
    const defaults = try prepare(arena.allocator(), &.{.{ .path = "/bin/true" }});
    try run(defaults, "{}\n");
    const failing = try prepare(arena.allocator(), &.{
        .{ .path = "/bin/true" },
        .{ .path = "/bin/sh", .args = &.{ "sh", "-c", "exit 7" } },
    });
    try std.testing.expectError(error.HookFailed, run(failing, "{}\n"));
    var implementation: @import("linux.zig").LinuxBackend = .{};
    try std.testing.expect(std.mem.indexOf(u8, implementation.backend().diagnostic().?, "hook #1: exit status 7") != null);
    const missing = try prepare(arena.allocator(), &.{.{ .path = "/igvano-missing-hook" }});
    try std.testing.expectError(error.HookFailed, run(missing, "{}\n"));
}

test "linux hook timeout kills a hook that never reads large stdin" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const entries = try prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "printf timeout-out; printf timeout-err >&2; while :; do :; done" },
        .timeout_seconds = 1,
    }});
    const state = try arena.allocator().alloc(u8, 1 << 20);
    @memset(state, 'x');
    try std.testing.expectError(error.HookTimeout, run(entries, state));
    var implementation: @import("linux.zig").LinuxBackend = .{};
    const detail = implementation.backend().diagnostic() orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, detail, "timeout") != null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "stdout: timeout-out") != null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "stderr: timeout-err") != null);
}

test "linux hooks capture both output streams with closed runtime stdio" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const cases = [_]struct {
        command: []const u8,
        failure: ?Error,
        reason: []const u8 = "",
    }{
        .{ .command = "printf '  hook-out\\n'; printf ' hook-err\\n' >&2; exit 7", .failure = error.HookFailed, .reason = "exit status 7" },
        .{ .command = "printf hook-out; printf hook-err >&2; i=0; while test \"$i\" -lt 10000; do printf xxxxxxxxxx; printf xxxxxxxxxx >&2; i=$((i+1)); done; exit 1", .failure = error.HookFailed, .reason = "exit status 1" },
        .{ .command = "printf hook-out; printf hook-err >&2; kill -KILL $$", .failure = error.HookFailed, .reason = "signal: KILL" },
        .{ .command = "printf hook-out; printf hook-err >&2; kill -64 $$", .failure = error.HookFailed, .reason = "signal: 64" },
        .{ .command = "i=0; while test \"$i\" -lt 10000; do printf 'hook output'; i=$((i+1)); done", .failure = null },
    };
    for (cases) |case| {
        const entries = try prepare(arena.allocator(), &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", case.command },
            .timeout_seconds = 2,
        }});
        const forked = std.posix.system.fork();
        if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
        const pid: i32 = @intCast(forked);
        if (pid == 0) checkCapturedHookOutput(entries, case.failure, case.reason);
        var status: u32 = undefined;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
        try std.testing.expectEqual(@as(u32, 0), status);
    }
}

fn checkCapturedHookOutput(entries: []const Prepared, failure: ?Error, reason: []const u8) noreturn {
    _ = linux.close(1);
    if (failure != null) _ = linux.close(2);
    run(entries, "{}\n") catch |err| {
        const expected = failure orelse linux.exit_group(1);
        if (expected != err) linux.exit_group(1);
        var implementation: @import("linux.zig").LinuxBackend = .{};
        const detail = implementation.backend().diagnostic() orelse linux.exit_group(2);
        if (detail.len > 512 or
            std.mem.indexOf(u8, detail, "error running hook #0:") == null or
            std.mem.indexOf(u8, detail, reason) == null or
            std.mem.indexOf(u8, detail, "stdout: hook-out") == null or
            std.mem.indexOf(u8, detail, "stderr: hook-err") == null) linux.exit_group(3);
        linux.exit_group(0);
    };
    linux.exit_group(if (failure == null) 0 else 4);
}

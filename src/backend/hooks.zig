const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

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

/// No allocator or std.Io calls after fork. A memfd supplies stdin without
/// blocking the deadline when a hook does not read (or state exceeds pipe capacity).
pub fn run(entries: []const Prepared, state: []const u8) Error!void {
    if (entries.len == 0) return;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    for (entries) |hook| try runOne(hook, state);
}

fn monotonicNow() Error!u128 {
    var time: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &time)) != .SUCCESS) return error.HookFailed;
    return @as(u128, @intCast(time.sec)) * std.time.ns_per_s + @as(u128, @intCast(time.nsec));
}

fn runOne(hook: Prepared, state: []const u8) Error!void {
    const created = linux.memfd_create("igvano-hook", linux.MFD.CLOEXEC);
    if (linux.errno(created) != .SUCCESS) return error.SystemResources;
    var input: std.posix.fd_t = @intCast(created);
    if (input <= 2) {
        // dup2(fd, fd) keeps CLOEXEC. Keep the source away from stdio even
        // when the runtime was launched with one of those descriptors closed.
        const moved = linux.fcntl(input, linux.F.DUPFD_CLOEXEC, 3);
        _ = linux.close(input);
        if (linux.errno(moved) != .SUCCESS) return error.SystemResources;
        input = @intCast(moved);
    }
    defer _ = linux.close(input);
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
    const started = try monotonicNow();
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        if (linux.errno(linux.dup2(input, 0)) != .SUCCESS) linux.exit_group(1);
        // The kernel flag is 1 << 2 (Zig 0.16's packed wrapper differs).
        if (linux.errno(linux.syscall3(.close_range, 3, std.math.maxInt(u32), 1 << 2)) != .SUCCESS)
            linux.exit_group(1);
        _ = linux.execve(hook.path, hook.argv.ptr, hook.envp.ptr);
        linux.exit_group(1);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: u32 = undefined;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    };
    while (true) {
        var status: u32 = undefined;
        const result = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => if (result != 0) {
                reaped = true;
                if (status != 0) return error.HookFailed;
                return;
            },
            .INTR => continue,
            .CHILD => {
                reaped = true;
                return error.HookFailed;
            },
            else => return error.HookFailed,
        }
        if (timeoutExpired(hook.timeout_seconds, (try monotonicNow()) - started)) return error.HookTimeout;
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
    const failing = try prepare(arena.allocator(), &.{.{ .path = "/bin/sh", .args = &.{ "sh", "-c", "exit 7" } }});
    try std.testing.expectError(error.HookFailed, run(failing, "{}\n"));
    const missing = try prepare(arena.allocator(), &.{.{ .path = "/igvano-missing-hook" }});
    try std.testing.expectError(error.HookFailed, run(missing, "{}\n"));
}

test "linux hook timeout kills a hook that never reads large stdin" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const entries = try prepare(arena.allocator(), &.{.{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "while :; do :; done" },
        .timeout_seconds = 1,
    }});
    const state = try arena.allocator().alloc(u8, 1 << 20);
    @memset(state, 'x');
    try std.testing.expectError(error.HookTimeout, run(entries, state));
}

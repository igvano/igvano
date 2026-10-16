const std = @import("std");
const builtin = @import("builtin");

pub const Action = enum {
    kill_thread,
    kill_process,
    trap,
    errno,
    trace,
    log,
    allow,

    pub fn encode(self: Action, data: ?u16) u32 {
        return switch (self) {
            .kill_thread => 0,
            .kill_process => 0x80000000,
            .trap => 0x00030000,
            .errno => 0x00050000 | @as(u32, data orelse 1),
            .trace => 0x7ff00000 | @as(u32, data orelse 1),
            .log => 0x7ffc0000,
            .allow => 0x7fff0000,
        };
    }
};

pub const Arch = enum {
    x86_64,
    x86,
    aarch64,
    arm,

    pub fn audit(self: Arch) u32 {
        return switch (self) {
            .x86_64 => 0xc000003e,
            .x86 => 0x40000003,
            .aarch64 => 0xc00000b7,
            .arm => 0x40000028,
        };
    }

    pub fn native() ?Arch {
        return switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .x86 => .x86,
            .aarch64 => .aarch64,
            .arm => .arm,
            else => null,
        };
    }

    pub fn runnable(self: Arch, host: Arch) bool {
        return self == host or (host == .x86_64 and self == .x86) or
            (host == .aarch64 and self == .arm);
    }
};

pub const Op = enum { eq, ne, lt, le, gt, ge, masked_eq };
pub const Arg = struct { index: u32, value: u64, value_two: u64 = 0, op: Op };
pub const Rule = struct { arch: Arch, number: u32, action: Action, errno_ret: ?u16 = null, args: []const Arg = &.{} };
pub const Config = struct {
    default_action: Action,
    default_errno_ret: ?u16 = null,
    architectures: []const Arch,
    flags: u32 = 0,
    rules: []const Rule = &.{},
};
pub const Filter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 };
pub const Program = struct { filters: []const Filter, flags: u32 };
pub const Error = error{ InvalidConfig, FilterTooLarge, UnsupportedArchitecture } || std.mem.Allocator.Error;
pub const max_insns = 4096;

pub fn compile(allocator: std.mem.Allocator, config: Config, host: Arch) Error!Program {
    if (config.flags & ~@as(u32, 2 | 4 | 32) != 0) return error.InvalidConfig;
    for (config.rules) |rule| for (rule.args) |arg| {
        if (arg.index >= 6) return error.InvalidConfig;
    };
    var builder: Builder = .{ .allocator = allocator };
    defer builder.code.deinit(allocator);
    var failures: std.ArrayList(usize) = .empty;
    defer failures.deinit(allocator);
    var arches: [4]Arch = undefined;
    var targets: [4]usize = undefined;
    var count: usize = 0;
    try builder.emit(0x20, 4); // seccomp_data.arch
    for (config.architectures) |arch| {
        if (!arch.runnable(host)) continue;
        if (std.mem.indexOfScalar(Arch, arches[0..count], arch) != null) continue;
        arches[count] = arch;
        // A nearby conditional skips a 32-bit JA trampoline.
        try builder.emit(0x15, arch.audit());
        builder.code.items[builder.code.items.len - 1].jf = 1;
        targets[count] = try builder.jump();
        count += 1;
    }
    if (count == 0) return error.UnsupportedArchitecture;
    try builder.emit(0x06, Action.kill_process.encode(null));
    const default = config.default_action.encode(config.default_errno_ret);
    for (arches[0..count], targets[0..count]) |arch, target| {
        builder.patch(target);
        if (arch == .x86_64) {
            try builder.emit(0x20, 0);
            try builder.emit(0x35, 0x40000000);
            builder.code.items[builder.code.items.len - 1].jf = 1;
            try builder.emit(0x06, Action.kill_process.encode(null));
        }
        for (config.rules) |rule| {
            if (rule.arch != arch) continue;
            failures.clearRetainingCapacity();
            try builder.emit(0x20, 0); // Reload nr after argument loads.
            try builder.require(0x15, rule.number, true, &failures);
            for (rule.args) |arg| try builder.argument(arg, arch, &failures);
            try builder.emit(0x06, rule.action.encode(rule.errno_ret));
            for (failures.items) |failure| builder.patch(failure);
        }
        try builder.emit(0x06, default);
    }
    return .{ .filters = try builder.code.toOwnedSlice(allocator), .flags = config.flags };
}

const Builder = struct {
    allocator: std.mem.Allocator,
    code: std.ArrayList(Filter) = .empty,

    fn emit(self: *Builder, code: u16, k: u32) Error!void {
        if (self.code.items.len >= max_insns) return error.FilterTooLarge;
        try self.code.append(self.allocator, .{ .code = code, .k = k });
    }

    fn jump(self: *Builder) Error!usize {
        const index = self.code.items.len;
        try self.emit(0x05, 0);
        return index;
    }

    fn patch(self: *Builder, index: usize) void {
        self.code.items[index].k = @intCast(self.code.items.len - index - 1);
    }

    fn require(self: *Builder, code: u16, k: u32, want: bool, failures: *std.ArrayList(usize)) Error!void {
        try self.emit(code, k);
        self.code.items[self.code.items.len - 1].jt = if (want) 1 else 0;
        self.code.items[self.code.items.len - 1].jf = if (want) 0 else 1;
        try failures.append(self.allocator, try self.jump());
    }

    // True and false edges use JA, so neither depends on an 8-bit distance.
    fn branch(self: *Builder, code: u16, k: u32) Error![2]usize {
        try self.emit(code, k);
        self.code.items[self.code.items.len - 1].jf = 1;
        return .{ try self.jump(), try self.jump() };
    }

    fn argument(self: *Builder, arg: Arg, arch: Arch, failures: *std.ArrayList(usize)) Error!void {
        // All supported native/compat ABIs use little-endian seccomp_data.
        const low = 16 + arg.index * 8;
        const high = low + 4;
        const hi: u32 = @truncate(arg.value >> 32);
        const lo: u32 = @truncate(arg.value);
        if (arch == .x86 or arch == .arm) {
            // libseccomp truncates both operands for 32-bit ABIs.
            try self.emit(0x20, low);
            if (arg.op == .masked_eq) try self.emit(0x54, lo);
            try self.require(switch (arg.op) {
                .eq, .ne, .masked_eq => 0x15,
                .lt, .ge => 0x35,
                .le, .gt => 0x25,
            }, if (arg.op == .masked_eq) @truncate(arg.value_two) else lo, arg.op != .ne and arg.op != .lt and arg.op != .le, failures);
            return;
        }
        try self.emit(0x20, high);
        switch (arg.op) {
            .eq, .masked_eq => {
                if (arg.op == .masked_eq) try self.emit(0x54, hi);
                try self.require(0x15, if (arg.op == .eq) hi else @truncate(arg.value_two >> 32), true, failures);
                try self.emit(0x20, low);
                if (arg.op == .masked_eq) try self.emit(0x54, lo);
                try self.require(0x15, if (arg.op == .eq) lo else @truncate(arg.value_two), true, failures);
            },
            .ne => {
                const edge = try self.branch(0x15, hi);
                self.patch(edge[0]);
                try self.emit(0x20, low);
                try self.require(0x15, lo, false, failures);
                self.patch(edge[1]);
            },
            .lt, .le, .gt, .ge => {
                const greater = try self.branch(0x25, hi);
                const ascending = arg.op == .gt or arg.op == .ge;
                if (!ascending) try failures.append(self.allocator, greater[0]);
                // A smaller high word either succeeds (LT/LE) or fails (GT/GE).
                // Equality continues to the low-word comparison.
                self.patch(greater[1]);
                const equal = try self.branch(0x15, hi);
                if (ascending) try failures.append(self.allocator, equal[1]);
                self.patch(equal[0]);
                try self.emit(0x20, low);
                try self.require(switch (arg.op) {
                    .gt, .le => 0x25,
                    .ge, .lt => 0x35,
                    else => unreachable,
                }, lo, ascending, failures);
                if (ascending) self.patch(greater[0]) else self.patch(equal[1]);
            },
        }
    }
};

/// No allocation, privilege changes, or libc dependency. Return the kernel errno
/// so the caller can include it in the init diagnostic.
pub fn install(program: Program) std.os.linux.E {
    if (comptime builtin.os.tag != .linux) return .NOSYS;
    const linux = std.os.linux;
    const SockFprog = extern struct { len: u16, filter: [*]const Filter };
    const descriptor: SockFprog = .{ .len = @intCast(program.filters.len), .filter = program.filters.ptr };
    const result = linux.syscall3(.seccomp, 1, program.flags, @intFromPtr(&descriptor));
    if (linux.errno(result) == .NOSYS and program.flags == 0)
        return linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_SECCOMP), 2, @intFromPtr(&descriptor), 0, 0));
    return linux.errno(result);
}

const TestData = @import("../test/seccomp.zig").Data;
const interpret = @import("../test/seccomp.zig").interpret;

test "seccomp dispatch rejects foreign architectures and x32 and preserves default errno" {
    const program = try compile(std.testing.allocator, .{
        .default_action = .errno,
        .default_errno_ret = 13,
        .architectures = &.{ .x86_64, .x86, .arm },
        .rules = &.{
            .{ .arch = .x86_64, .number = 7, .action = .allow },
            .{ .arch = .x86, .number = 9, .action = .trap },
        },
    }, .x86_64);
    defer std.testing.allocator.free(program.filters);
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try interpret(program.filters, .{}));
    try std.testing.expectEqual(@as(u32, 0x00030000), try interpret(program.filters, .{ .arch = 0x40000003, .nr = 9 }));
    try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .arch = 0x40000028 }));
    try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .arch = 0 }));
    try std.testing.expectEqual(@as(u32, 0x0005000d), try interpret(program.filters, .{ .nr = 8 }));
    for ([_]u32{ 0x40000000, 0x40000007, 0xffffffff }) |number|
        try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .nr = number }));
}

test "seccomp x32 cannot bypass a denylist with an ALLOW default" {
    const program = try compile(std.testing.allocator, .{
        .default_action = .allow,
        .architectures = &.{.x86_64},
        .rules = &.{.{ .arch = .x86_64, .number = 83, .action = .errno }},
    }, .x86_64);
    defer std.testing.allocator.free(program.filters);
    try std.testing.expectEqual(@as(u32, 0x00050001), try interpret(program.filters, .{ .nr = 83 }));
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try interpret(program.filters, .{ .nr = 84 }));
    try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .nr = 0x40000000 + 83 }));
    try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .nr = 0x40000000 + 84 }));
}

test "seccomp unsigned 64-bit comparisons cross both word boundaries" {
    const values = [_]u64{ 0, 1, 0xfffffffe, 0xffffffff, 0x100000000, 0x100000001, 0x1ffffffff, 0x200000000, 0xffffffff00000000, 0xffffffffffffffff };
    for ([_]Op{ .eq, .ne, .lt, .le, .gt, .ge, .masked_eq }) |op| {
        for (values) |expected| {
            const program = try compile(std.testing.allocator, .{
                .default_action = .allow,
                .architectures = &.{.x86_64},
                .rules = &.{.{
                    .arch = .x86_64,
                    .number = 7,
                    .action = .errno,
                    .errno_ret = 42,
                    .args = &.{.{ .index = 5, .value = expected, .value_two = 0x100000001, .op = op }},
                }},
            }, .x86_64);
            defer std.testing.allocator.free(program.filters);
            for (values) |value| {
                const matches = switch (op) {
                    .eq => value == expected,
                    .ne => value != expected,
                    .lt => value < expected,
                    .le => value <= expected,
                    .gt => value > expected,
                    .ge => value >= expected,
                    .masked_eq => value & expected == 0x100000001,
                };
                var data: TestData = .{};
                data.args[5] = value;
                try std.testing.expectEqual(@as(u32, if (matches) 0x0005002a else 0x7fff0000), try interpret(program.filters, data));
            }
        }
    }
}

test "seccomp conditions are ANDed and alternative rules are ORed" {
    const program = try compile(std.testing.allocator, .{
        .default_action = .errno,
        .architectures = &.{.aarch64},
        .rules = &.{
            .{ .arch = .aarch64, .number = 7, .action = .allow, .args = &.{
                .{ .index = 0, .value = 0x100000000, .op = .eq },
                .{ .index = 1, .value = 0xff000000ff, .value_two = 0x100000002, .op = .masked_eq },
            } },
            .{ .arch = .aarch64, .number = 7, .action = .allow, .args = &.{.{ .index = 2, .value = 99, .op = .eq }} },
        },
    }, .aarch64);
    defer std.testing.allocator.free(program.filters);
    var data: TestData = .{ .arch = 0xc00000b7 };
    try std.testing.expectEqual(@as(u32, 0x00050001), try interpret(program.filters, data));
    data.args[0] = 0x100000000;
    data.args[1] = 0x101000002;
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try interpret(program.filters, data));
    data.args[0] = 0;
    try std.testing.expectEqual(@as(u32, 0x00050001), try interpret(program.filters, data));
    data.args[2] = 99;
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try interpret(program.filters, data));
}

test "seccomp compat comparisons truncate values and ignore argument high words" {
    for ([_]Arch{ .x86_64, .aarch64 }) |host| {
        const compat: Arch = if (host == .x86_64) .x86 else .arm;
        for ([_]Op{ .eq, .ne, .lt, .le, .gt, .ge, .masked_eq }) |op| {
            const program = try compile(std.testing.allocator, .{
                .default_action = .allow,
                .architectures = &.{ host, compat },
                .rules = &.{.{
                    .arch = compat,
                    .number = 7,
                    .action = .errno,
                    .errno_ret = 42,
                    .args = &.{.{ .index = 0, .value = 0xffffffffffffffff, .value_two = 0xffffffffffffffff, .op = op }},
                }},
            }, host);
            defer std.testing.allocator.free(program.filters);
            for ([_]u64{ 0, 0xfffffffe, 0xffffffff, 0xffffffffffffffff }) |value| {
                const low: u32 = @truncate(value);
                const matches = switch (op) {
                    .eq, .masked_eq, .ge => low == 0xffffffff,
                    .ne, .lt => low != 0xffffffff,
                    .le => true,
                    .gt => false,
                };
                var data: TestData = .{ .arch = compat.audit() };
                data.args[0] = value;
                try std.testing.expectEqual(@as(u32, if (matches) 0x0005002a else 0x7fff0000), try interpret(program.filters, data));
                data.arch = host.audit();
                try std.testing.expectEqual(@as(u32, 0x7fff0000), try interpret(program.filters, data));
            }
        }
    }
}

test "seccomp oversized filters and invalid argument indices fail before installation" {
    var rules: [1100]Rule = undefined;
    for (&rules, 0..) |*rule, number| rule.* = .{ .arch = .x86_64, .number = @intCast(number), .action = .allow };
    try std.testing.expectError(error.FilterTooLarge, compile(std.testing.allocator, .{
        .default_action = .errno,
        .architectures = &.{.x86_64},
        .rules = &rules,
    }, .x86_64));
    try std.testing.expectError(error.InvalidConfig, compile(std.testing.allocator, .{
        .default_action = .errno,
        .architectures = &.{.x86_64},
        .rules = &.{.{ .arch = .x86_64, .number = 7, .action = .allow, .args = &.{.{ .index = 6, .value = 0, .op = .eq }} }},
    }, .x86_64));
    // Fill the compat block so the native ABI's x32 guard crosses the limit.
    for (&rules) |*rule| rule.arch = .x86;
    try std.testing.expectError(error.FilterTooLarge, compile(std.testing.allocator, .{
        .default_action = .errno,
        .architectures = &.{ .x86, .x86_64 },
        .rules = rules[0..1022],
    }, .x86_64));
}

test "seccomp compiler frees partial code and jump fixups on allocation failure" {
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const program = try compile(allocator, .{
                .default_action = .errno,
                .flags = 2 | 4 | 32,
                .architectures = &.{ .x86_64, .x86 },
                .rules = &.{
                    .{ .arch = .x86_64, .number = 7, .action = .allow, .args = &.{ .{ .index = 1, .value = 0x100000000, .op = .ge }, .{ .index = 2, .value = 0xff, .value_two = 42, .op = .masked_eq } } },
                    .{ .arch = .x86, .number = 7, .action = .allow },
                },
            }, .x86_64);
            defer allocator.free(program.filters);
            try std.testing.expectEqual(@as(u32, 38), program.flags);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
}

test "linux seccomp ENOSYS falls back to prctl only when no flags are requested" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const arch = Arch.native() orelse return error.SkipZigTest;
    // An actual inherited filter simulates a kernel without seccomp(2).
    const no_seccomp = try compile(std.testing.allocator, .{
        .default_action = .allow,
        .architectures = &.{arch},
        .rules = &.{.{ .arch = arch, .number = @intFromEnum(linux.SYS.seccomp), .action = .errno, .errno_ret = @intFromEnum(linux.E.NOSYS) }},
    }, arch);
    defer std.testing.allocator.free(no_seccomp.filters);
    const filtered = try compile(std.testing.allocator, .{
        .default_action = .allow,
        .architectures = &.{arch},
        .rules = &.{.{ .arch = arch, .number = @intFromEnum(linux.SYS.getppid), .action = .errno }},
    }, arch);
    defer std.testing.allocator.free(filtered.filters);
    for ([_]u32{ 0, 2 }) |flags| {
        const result = linux.fork();
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(result));
        if (result == 0) {
            if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS)
                linux.exit_group(1);
            if (install(no_seccomp) != .SUCCESS) linux.exit_group(2);
            const error_code = install(.{ .filters = filtered.filters, .flags = flags });
            const expected: linux.E = if (flags == 0) .SUCCESS else .NOSYS;
            if (error_code != expected) linux.exit_group(3);
            const parent = linux.errno(linux.syscall0(.getppid));
            if (parent != (if (flags == 0) linux.E.PERM else linux.E.SUCCESS)) linux.exit_group(4);
            linux.exit_group(0);
        }
        var status: u32 = 0;
        const waited = linux.wait4(@intCast(result), &status, 0, null);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
        try std.testing.expectEqual(@as(u32, 0), status);
    }
}

test "seccomp actions preserve rule return data and default EPERM" {
    const cases = [_]struct { action: Action, data: ?u16 = null, expected: u32 }{
        .{ .action = .allow, .expected = 0x7fff0000 },
        .{ .action = .kill_thread, .expected = 0 },
        .{ .action = .kill_process, .expected = 0x80000000 },
        .{ .action = .trap, .expected = 0x00030000 },
        .{ .action = .errno, .expected = 0x00050001 },
        .{ .action = .errno, .data = 0, .expected = 0x00050000 },
        .{ .action = .errno, .data = 65535, .expected = 0x0005ffff },
        .{ .action = .trace, .expected = 0x7ff00001 },
        .{ .action = .trace, .data = 42, .expected = 0x7ff0002a },
        .{ .action = .log, .expected = 0x7ffc0000 },
    };
    for (cases) |case| {
        const program = try compile(std.testing.allocator, .{
            .default_action = case.action,
            .default_errno_ret = case.data,
            .architectures = &.{.x86_64},
            .rules = &.{.{ .arch = .x86_64, .number = 7, .action = case.action, .errno_ret = case.data }},
        }, .x86_64);
        defer std.testing.allocator.free(program.filters);
        for ([_]u32{ 7, 8 }) |nr|
            try std.testing.expectEqual(case.expected, try interpret(program.filters, .{ .nr = nr }));
        try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .nr = 0x40000000 }));
    }
}

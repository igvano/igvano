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
    x32,
    x86,
    aarch64,
    arm,

    pub fn audit(self: Arch) u32 {
        return switch (self) {
            .x86_64, .x32 => 0xc000003e,
            .x86 => 0x40000003,
            .aarch64 => 0xc00000b7,
            .arm => 0x40000028,
        };
    }

    pub fn native() ?Arch {
        return switch (builtin.cpu.arch) {
            .x86_64 => if (builtin.abi == .gnux32 or builtin.abi == .muslx32) .x32 else .x86_64,
            .x86 => .x86,
            .aarch64 => .aarch64,
            .arm => .arm,
            else => null,
        };
    }

    pub fn runnable(self: Arch, host: Arch) bool {
        return self == host or ((host == .x86_64 or host == .x32) and
            (self == .x86_64 or self == .x86 or self == .x32)) or
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
    var returns: std.ArrayList(ReturnJump) = .empty;
    defer returns.deinit(allocator);
    var arches: [5]Arch = undefined;
    var targets: [5]usize = undefined;
    var count: usize = 0;
    try builder.emit(0x20, 4); // seccomp_data.arch
    for (config.architectures) |arch| {
        if (!arch.runnable(host)) continue;
        if (std.mem.indexOfScalar(Arch, arches[0..count], arch) != null) continue;
        arches[count] = arch;
        targets[count] = try builder.archDispatch(arch);
        count += 1;
    }
    if (count == 0) return error.UnsupportedArchitecture;
    try builder.emit(0x06, Action.kill_process.encode(null));
    for (arches[0..count], targets[0..count]) |arch, target| {
        builder.patch(target);
        returns.clearRetainingCapacity();
        try builder.archRules(config, arch, &failures, &returns);
    }
    return .{ .filters = try builder.code.toOwnedSlice(allocator), .flags = config.flags };
}

const ReturnJump = struct {
    index: usize,
    action: u32,

    fn lessThan(_: void, a: ReturnJump, b: ReturnJump) bool {
        return a.action < b.action;
    }
};

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

    fn returnAction(self: *Builder, action: u32, returns: *std.ArrayList(ReturnJump)) Error!void {
        try returns.append(self.allocator, .{ .index = try self.jump(), .action = action });
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

    fn archDispatch(self: *Builder, arch: Arch) Error!usize {
        // A nearby conditional skips a 32-bit JA trampoline.
        try self.emit(0x15, arch.audit());
        self.code.items[self.code.items.len - 1].jf = if (arch == .x86_64 or arch == .x32) 3 else 1;
        if (arch == .x86_64 or arch == .x32) {
            // These ABIs share AUDIT_ARCH_X86_64; bit 30 selects x32.
            try self.emit(0x20, 0);
            try self.emit(0x45, 0x40000000);
            self.code.items[self.code.items.len - 1].jt = if (arch == .x86_64) 1 else 0;
            self.code.items[self.code.items.len - 1].jf = if (arch == .x32) 1 else 0;
        }
        const target = try self.jump();
        if (arch == .x86_64 or arch == .x32) try self.emit(0x20, 4);
        return target;
    }

    fn enosysStub(self: *Builder, config: Config, arch: Arch) Error!bool {
        // runc's patchbpf/enosys_linux.go: permissive defaults (including
        // TRACE, whose tracer handles future syscalls) do not get a stub.
        // Count every named rule, regardless of its action or conditions.
        switch (config.default_action) {
            .allow, .log, .trace => return false,
            else => {},
        }
        if (config.default_action.encode(config.default_errno_ret) == Action.errno.encode(38)) return false;
        var maximum: u32 = 0;
        for (config.rules) |rule| {
            if (rule.arch == arch) maximum = @max(maximum, rule.number);
        }
        // Like runc, an ABI with no positive syscall number has no stub.
        if (maximum == 0) return false;
        try self.emit(0x20, 0);
        try self.emit(0x25, maximum);
        self.code.items[self.code.items.len - 1].jf = 1;
        try self.emit(0x06, Action.errno.encode(38)); // Linux ENOSYS.
        return true;
    }

    fn archRules(self: *Builder, config: Config, arch: Arch, failures: *std.ArrayList(usize), returns: *std.ArrayList(ReturnJump)) Error!void {
        var nr_loaded = try self.enosysStub(config, arch);
        var rule_index: usize = 0;
        while (rule_index < config.rules.len) {
            const rule = config.rules[rule_index];
            rule_index += 1;
            if (rule.arch != arch) continue;
            failures.clearRetainingCapacity();
            if (!nr_loaded) {
                try self.emit(0x20, 0); // Reload nr after argument loads.
                nr_loaded = true;
            }
            const action = rule.action.encode(rule.errno_ret);
            if (rule.args.len == 0) {
                try self.ruleChain(rule, config.rules, &rule_index);
                try self.returnAction(action, returns);
                continue;
            }
            try self.require(0x15, rule.number, true, failures);
            for (rule.args) |arg| try self.argument(arg, arch, failures);
            nr_loaded = false;
            try self.returnAction(action, returns);
            for (failures.items) |failure| self.patch(failure);
        }
        try self.returnAction(config.default_action.encode(config.default_errno_ret), returns);
        try self.emitReturns(returns.items);
    }

    fn ruleChain(self: *Builder, rule: Rule, rules: []const Rule, rule_index: *usize) Error!void {
        // Preserve order: only merge consecutive unconditional rules
        // with identical return data within this ABI.
        const action = rule.action.encode(rule.errno_ret);
        const start = self.code.items.len;
        try self.emit(0x15, rule.number);
        var comparisons: usize = 1;
        while (rule_index.* < rules.len and comparisons < 256) {
            const next = rules[rule_index.*];
            if (next.arch != rule.arch) {
                rule_index.* += 1;
                continue;
            }
            if (next.args.len != 0 or next.action.encode(next.errno_ret) != action) break;
            try self.emit(0x15, next.number);
            comparisons += 1;
            rule_index.* += 1;
        }
        // A chain reaches a nearby JA to the shared action RET.
        // Split at 256 comparisons to keep every conditional jump u8.
        for (self.code.items[start..], 0..) |*instruction, i|
            instruction.jt = @intCast(comparisons - i - 1);
        self.code.items[self.code.items.len - 1].jf = 1;
    }

    fn emitReturns(self: *Builder, returns: []ReturnJump) Error!void {
        // Sorting only the return fixups leaves the rules' first-match order
        // intact and emits one RET for each distinct encoded action.
        std.mem.sort(ReturnJump, returns, {}, ReturnJump.lessThan);
        var index: usize = 0;
        while (index < returns.len) {
            const action = returns[index].action;
            while (index < returns.len and returns[index].action == action) : (index += 1)
                self.patch(returns[index].index);
            try self.emit(0x06, action);
        }
    }

    fn argument(self: *Builder, arg: Arg, arch: Arch, failures: *std.ArrayList(usize)) Error!void {
        // All supported native/compat ABIs use little-endian seccomp_data.
        const low = 16 + arg.index * 8;
        if (arch == .x86 or arch == .x32 or arch == .arm) {
            try self.argument32(arg, low, failures);
            return;
        }
        try self.emit(0x20, low + 4);
        switch (arg.op) {
            .eq, .masked_eq => try self.argumentEqual(arg, low, failures),
            .ne => try self.argumentNotEqual(arg, low, failures),
            .lt, .le, .gt, .ge => try self.argumentOrdered(arg, low, failures),
        }
    }

    fn argument32(self: *Builder, arg: Arg, low: u32, failures: *std.ArrayList(usize)) Error!void {
        // libseccomp truncates both operands for 32-bit ABIs.
        const lo: u32 = @truncate(arg.value);
        try self.emit(0x20, low);
        if (arg.op == .masked_eq) try self.emit(0x54, lo);
        try self.require(switch (arg.op) {
            .eq, .ne, .masked_eq => 0x15,
            .lt, .ge => 0x35,
            .le, .gt => 0x25,
        }, if (arg.op == .masked_eq) @truncate(arg.value_two) else lo, arg.op != .ne and arg.op != .lt and arg.op != .le, failures);
    }

    fn argumentEqual(self: *Builder, arg: Arg, low: u32, failures: *std.ArrayList(usize)) Error!void {
        const hi: u32 = @truncate(arg.value >> 32);
        const lo: u32 = @truncate(arg.value);
        if (arg.op == .masked_eq) try self.emit(0x54, hi);
        try self.require(0x15, if (arg.op == .eq) hi else @truncate(arg.value_two >> 32), true, failures);
        try self.emit(0x20, low);
        if (arg.op == .masked_eq) try self.emit(0x54, lo);
        try self.require(0x15, if (arg.op == .eq) lo else @truncate(arg.value_two), true, failures);
    }

    fn argumentNotEqual(self: *Builder, arg: Arg, low: u32, failures: *std.ArrayList(usize)) Error!void {
        const edge = try self.branch(0x15, @truncate(arg.value >> 32));
        self.patch(edge[0]);
        try self.emit(0x20, low);
        try self.require(0x15, @truncate(arg.value), false, failures);
        self.patch(edge[1]);
    }

    fn argumentOrdered(self: *Builder, arg: Arg, low: u32, failures: *std.ArrayList(usize)) Error!void {
        const greater = try self.branch(0x25, @truncate(arg.value >> 32));
        const ascending = arg.op == .gt or arg.op == .ge;
        if (!ascending) try failures.append(self.allocator, greater[0]);
        // A smaller high word either succeeds (LT/LE) or fails (GT/GE).
        // Equality continues to the low-word comparison.
        self.patch(greater[1]);
        const equal = try self.branch(0x15, @truncate(arg.value >> 32));
        if (ascending) try failures.append(self.allocator, equal[1]);
        self.patch(equal[0]);
        try self.emit(0x20, low);
        try self.require(switch (arg.op) {
            .gt, .le => 0x25,
            .ge, .lt => 0x35,
            else => unreachable,
        }, @truncate(arg.value), ascending, failures);
        if (ascending) self.patch(greater[0]) else self.patch(equal[1]);
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

test "seccomp unknown syscalls return ENOSYS above each ABI maximum" {
    for ([_]Arch{ .x86_64, .aarch64 }) |host| {
        const compat: Arch = if (host == .x86_64) .x86 else .arm;
        const program = try compile(std.testing.allocator, .{
            .default_action = .errno,
            .default_errno_ret = 13,
            .architectures = &.{ host, compat },
            .rules = &.{
                .{ .arch = host, .number = 10, .action = .allow },
                // Denied and conditional names also contribute to the maximum.
                .{ .arch = compat, .number = 20, .action = .trap, .args = &.{.{ .index = 0, .value = 1, .op = .eq }} },
            },
        }, host);
        defer std.testing.allocator.free(program.filters);
        for ([_]Arch{ host, compat }) |arch| {
            const maximum: u32 = if (arch == host) 10 else 20;
            try std.testing.expectEqual(@as(u32, 0x00050026), try interpret(program.filters, .{ .arch = arch.audit(), .nr = maximum + 1 }));
            try std.testing.expectEqual(@as(u32, 0x0005000d), try interpret(program.filters, .{ .arch = arch.audit(), .nr = maximum - 1 }));
        }
        try std.testing.expectEqual(@as(u32, 0x0005000d), try interpret(program.filters, .{ .arch = compat.audit(), .nr = 20 }));
        try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .arch = 0 }));
    }
}

test "seccomp ENOSYS stub follows runc default action conditions" {
    for ([_]Action{ .allow, .log, .trace, .errno, .trap, .kill_thread, .kill_process }) |action| {
        const program = try compile(std.testing.allocator, .{
            .default_action = action,
            .architectures = &.{.aarch64},
            .rules = &.{.{ .arch = .aarch64, .number = 10, .action = .allow }},
        }, .aarch64);
        defer std.testing.allocator.free(program.filters);
        const expected: u32 = switch (action) {
            .allow => 0x7fff0000,
            .log => 0x7ffc0000,
            .trace => 0x7ff00001,
            else => 0x00050026,
        };
        try std.testing.expectEqual(expected, try interpret(program.filters, .{ .arch = 0xc00000b7, .nr = 11 }));
        try std.testing.expectEqual(action.encode(null), try interpret(program.filters, .{ .arch = 0xc00000b7, .nr = 9 }));
    }
    // runc omits the stub when no positive syscall number is named.
    for ([_][]const Rule{ &.{}, &.{.{ .arch = .x86_64, .number = 0, .action = .allow }} }) |rules| {
        const program = try compile(std.testing.allocator, .{
            .default_action = .errno,
            .architectures = &.{ .x86_64, .x86 },
            .rules = rules,
        }, .x86_64);
        defer std.testing.allocator.free(program.filters);
        try std.testing.expectEqual(@as(u32, 0x00050001), try interpret(program.filters, .{ .nr = 1000 }));
        try std.testing.expectEqual(@as(u32, 0x00050001), try interpret(program.filters, .{ .arch = 0x40000003, .nr = 1000 }));
    }
}

test "seccomp default ENOSYS needs no extra ENOSYS stub" {
    const program = try compile(std.testing.allocator, .{
        .default_action = .errno,
        .default_errno_ret = 38,
        .architectures = &.{.aarch64},
        .rules = &.{.{ .arch = .aarch64, .number = 10, .action = .allow }},
    }, .aarch64);
    defer std.testing.allocator.free(program.filters);
    var enosys_returns: usize = 0;
    for (program.filters) |instruction| {
        if (instruction.code == 0x06 and instruction.k == 0x00050026) enosys_returns += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), enosys_returns);
    try std.testing.expectEqual(@as(u32, 0x00050026), try interpret(program.filters, .{ .arch = Arch.aarch64.audit(), .nr = 11 }));
}

test "seccomp optimized chains match ordered rules across every ABI and argument boundaries" {
    const arches = [_]Arch{ .x86_64, .x86, .x32, .aarch64, .arm };
    var rules: std.ArrayList(Rule) = .empty;
    defer rules.deinit(std.testing.allocator);
    for (arches) |arch| {
        const base: u32 = if (arch == .x32) 0x40000000 else 0;
        try rules.appendSlice(std.testing.allocator, &.{
            .{ .arch = arch, .number = base + 1, .action = .allow },
            .{ .arch = arch, .number = base + 3, .action = .errno, .errno_ret = 13, .args = &.{.{ .index = 0, .value = 0x100000001, .op = .eq }} },
            .{ .arch = arch, .number = base + 3, .action = .allow },
            .{ .arch = arch, .number = base + 4, .action = .trace, .errno_ret = 42, .args = &.{.{ .index = 0, .value = 0xff, .value_two = 2, .op = .masked_eq }} },
            .{ .arch = arch, .number = base + 5, .action = .errno, .errno_ret = 0 },
            .{ .arch = arch, .number = base + 4, .action = .errno, .errno_ret = 42 },
            .{ .arch = arch, .number = base + 5, .action = .trap },
        });
        inline for ([_]Op{ .ne, .lt, .le, .gt, .ge }, 0..) |op, index| {
            try rules.append(std.testing.allocator, .{
                .arch = arch,
                .number = base + 6 + @as(u32, @intCast(index)),
                .action = .trap,
                .args = &.{.{ .index = 0, .value = 0x100000001, .op = op }},
            });
            try rules.append(std.testing.allocator, .{
                .arch = arch,
                .number = base + 6 + @as(u32, @intCast(index)),
                .action = .errno,
                .errno_ret = 7,
            });
        }
    }
    // More than 256 consecutive comparisons, with foreign-ABI rules interleaved.
    for (20..340) |number| for (arches) |arch| {
        const base: u32 = if (arch == .x32) 0x40000000 else 0;
        try rules.append(std.testing.allocator, .{ .arch = arch, .number = base + @as(u32, @intCast(number)), .action = .allow });
    };
    for (arches) |arch| {
        const base: u32 = if (arch == .x32) 0x40000000 else 0;
        try rules.appendSlice(std.testing.allocator, &.{
            .{ .arch = arch, .number = base + 100, .action = .kill_thread },
            .{ .arch = arch, .number = base + 400, .action = .errno, .errno_ret = 13, .args = &.{
                .{ .index = 0, .value = 0x100000001, .op = .ne },
                .{ .index = 1, .value = 1, .op = .eq },
            } },
            .{ .arch = arch, .number = base + 401, .action = .trace, .errno_ret = 0 },
            .{ .arch = arch, .number = base + 400, .action = .allow },
        });
    }
    for ([_]Arch{ .x86_64, .aarch64 }) |host| {
        const config: Config = .{ .default_action = .errno, .architectures = &arches, .rules = rules.items };
        const program = try compile(std.testing.allocator, config, host);
        defer std.testing.allocator.free(program.filters);
        for (arches) |arch| {
            if (!arch.runnable(host)) continue;
            try expectOptimizedMatches(config, program, arch);
        }
    }
}

fn expectOptimizedMatches(config: Config, program: Program, arch: Arch) !void {
    const testing = @import("../test/seccomp.zig");
    const values = [_]u64{ 0, 1, 2, 0xffffffff, 0x100000000, 0x100000001, 0x100000002, 0xffffffffffffffff };
    const base: u32 = if (arch == .x32) 0x40000000 else 0;
    for (values) |value| for ([_]u64{ 0, 1 }) |second| {
        var data: TestData = .{ .arch = arch.audit(), .args = .{ value, second, 0, 0, 0, 0 } };
        for (0..412) |number| {
            data.nr = base + @as(u32, @intCast(number));
            try std.testing.expectEqual(testing.evaluate(config, arch, data), try interpret(program.filters, data));
        }
    };
}

test "seccomp x32 and amd64 have independent ENOSYS boundaries" {
    const x32: Arch = .x32;
    const program = try compile(std.testing.allocator, .{
        .default_action = .errno,
        .default_errno_ret = 13,
        .architectures = &.{ x32, .x86_64, .x86 },
        .rules = &.{
            .{ .arch = .x86_64, .number = 10, .action = .allow },
            .{ .arch = x32, .number = 0x40000000 + 20, .action = .allow },
            .{ .arch = .x86, .number = 30, .action = .allow },
        },
    }, .x86_64);
    defer std.testing.allocator.free(program.filters);
    const cases = [_]struct { number: u32, expected: u32 }{
        .{ .number = 9, .expected = 0x0005000d },
        .{ .number = 10, .expected = 0x7fff0000 },
        .{ .number = 11, .expected = 0x00050026 },
        .{ .number = 0x40000000 + 19, .expected = 0x0005000d },
        .{ .number = 0x40000000 + 20, .expected = 0x7fff0000 },
        .{ .number = 0x40000000 + 21, .expected = 0x00050026 },
    };
    for (cases) |case|
        try std.testing.expectEqual(case.expected, try interpret(program.filters, .{ .nr = case.number }));
    try std.testing.expectEqual(@as(u32, 0x0005000d), try interpret(program.filters, .{ .arch = 0x40000003, .nr = 29 }));
    try std.testing.expectEqual(@as(u32, 0x00050026), try interpret(program.filters, .{ .arch = 0x40000003, .nr = 31 }));
}

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
    try std.testing.expectEqual(@as(u32, 0x0005000d), try interpret(program.filters, .{ .nr = 6 }));
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
    var rules: [max_insns]Rule = undefined;
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
    // Architecture dispatch and the ENOSYS stub count towards the same limit.
    for (&rules) |*rule| rule.arch = .x86;
    try std.testing.expectError(error.FilterTooLarge, compile(std.testing.allocator, .{
        .default_action = .errno,
        .architectures = &.{ .x86, .x86_64 },
        .rules = &rules,
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
        for ([_]u32{ 6, 7 }) |nr|
            try std.testing.expectEqual(case.expected, try interpret(program.filters, .{ .nr = nr }));
        try std.testing.expectEqual(@as(u32, 0x80000000), try interpret(program.filters, .{ .nr = 0x40000000 }));
    }
}

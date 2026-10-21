const std = @import("std");
const builtin = @import("builtin");
const Rule = @import("root.zig").Resources.DeviceRule;
const devices = @import("devices.zig");

/// Linux struct bpf_insn. Register nibbles follow the target's byte order.
pub const Insn = extern struct {
    code: u8,
    regs: u8 = 0,
    off: i16 = 0,
    imm: i32 = 0,

    fn init(code: u8, dst: u4, src: u4, off: i16, imm: i32) Insn {
        return .{
            .code = code,
            .regs = if (builtin.cpu.arch.endian() == .little)
                @as(u8, dst) | (@as(u8, src) << 4)
            else
                @as(u8, src) | (@as(u8, dst) << 4),
            .off = off,
            .imm = imm,
        };
    }
};

const op = struct {
    const ldx_w = 0x61;
    const and_imm = 0x54;
    const rsh_imm = 0x74;
    const mov_imm = 0xb4;
    const mov_reg = 0xbc;
    const jeq_imm = 0x15;
    const jne_imm = 0x55;
    const jne_reg = 0x5d;
    const exit = 0x95;
};

fn deviceNumber(number: ?i64) error{InvalidConfig}!?u32 {
    const value = number orelse return null;
    if (value == -1) return null;
    if (value < 0 or value > std.math.maxInt(u32)) return error.InvalidConfig;
    return @intCast(value);
}

pub fn isAllowAll(rules: []const Rule) bool {
    if (rules.len != 1) return false;
    const rule = rules[0];
    return rule.allow and rule.kind == .all and
        (deviceNumber(rule.major) catch return false) == null and
        (deviceNumber(rule.minor) catch return false) == null and
        (devices.accessMask(rule.access) catch return false) == 7;
}

/// The caller owns the instructions. As in runc, compile only normalized
/// exceptions, with the emulator's mode determining the final decision.
pub fn compile(allocator: std.mem.Allocator, configured: []const Rule) devices.Error![]Insn {
    var emu = try devices.Emulator.init(allocator, configured);
    defer emu.deinit(allocator);
    return compileEmulator(allocator, emu);
}

pub fn compileEmulator(allocator: std.mem.Allocator, emu: devices.Emulator) devices.Error![]Insn {
    const rules = try emu.rules(allocator);
    defer allocator.free(rules);
    var insns: std.ArrayList(Insn) = .empty;
    defer insns.deinit(allocator);
    try insns.appendSlice(allocator, &.{
        Insn.init(op.ldx_w, 2, 1, 0, 0),
        Insn.init(op.and_imm, 2, 0, 0, 0xffff),
        Insn.init(op.ldx_w, 3, 1, 0, 0),
        Insn.init(op.rsh_imm, 3, 0, 0, 16),
        Insn.init(op.ldx_w, 4, 1, 4, 0),
        Insn.init(op.ldx_w, 5, 1, 8, 0),
    });
    for (rules) |rule| {
        if (rule.kind == .all) continue;
        try appendRule(allocator, &insns, rule);
    }
    try insns.appendSlice(allocator, &.{
        Insn.init(op.mov_imm, 0, 0, 0, @intFromBool(emu.default_allow)),
        Insn.init(op.exit, 0, 0, 0, 0),
    });
    return insns.toOwnedSlice(allocator);
}

fn appendRule(allocator: std.mem.Allocator, insns: *std.ArrayList(Insn), rule: Rule) devices.Error!void {
    const start = insns.items.len;
    const mask = try devices.accessMask(rule.access);
    const major = try deviceNumber(rule.major);
    const minor = try deviceNumber(rule.minor);
    try insns.append(allocator, Insn.init(op.jne_imm, 2, 0, 0, if (rule.kind == .block) 1 else 2));
    if (mask != 7) {
        // Allows require every requested bit; a deny exception blocks overlap.
        try insns.appendSlice(allocator, &.{
            Insn.init(op.mov_reg, 6, 3, 0, 0),
            Insn.init(op.and_imm, 6, 0, 0, @intCast(mask)),
            Insn.init(if (rule.allow) op.jne_reg else op.jeq_imm, 6, if (rule.allow) 3 else 0, 0, 0),
        });
    }
    if (major) |number| try appendNumber(allocator, insns, 4, number);
    if (minor) |number| try appendNumber(allocator, insns, 5, number);
    try insns.appendSlice(allocator, &.{
        Insn.init(op.mov_imm, 0, 0, 0, @intFromBool(rule.allow)),
        Insn.init(op.exit, 0, 0, 0, 0),
    });
    patchRuleJumps(insns.items, start);
}

fn patchRuleJumps(insns: []Insn, start: usize) void {
    for (insns[start..], start..) |*insn, index| {
        if (insn.code == op.jeq_imm or insn.code == op.jne_imm or insn.code == op.jne_reg)
            insn.off = @intCast(insns.len - index - 1);
    }
}

fn appendNumber(allocator: std.mem.Allocator, insns: *std.ArrayList(Insn), reg: u4, number: u32) std.mem.Allocator.Error!void {
    if (number <= std.math.maxInt(i32)) {
        try insns.append(allocator, Insn.init(op.jne_imm, reg, 0, 0, @intCast(number)));
    } else {
        // JMP immediates sign-extend to 64 bits. MOV32 zero-extends instead,
        // so unsigned device numbers also work without requiring JMP32.
        try insns.appendSlice(allocator, &.{
            Insn.init(op.mov_imm, 6, 0, 0, @bitCast(number)),
            Insn.init(op.jne_reg, reg, 6, 0, 0),
        });
    }
}

/// Test-only interpreter for the small instruction set used by this compiler.
fn evaluate(insns: []const Insn, context: [3]u32) !bool {
    var regs: [11]u64 = @splat(0);
    var pc: usize = 0;
    while (pc < insns.len) {
        const insn = insns[pc];
        const dst = if (builtin.cpu.arch.endian() == .little) insn.regs & 15 else insn.regs >> 4;
        const src = if (builtin.cpu.arch.endian() == .little) insn.regs >> 4 else insn.regs & 15;
        const imm: u32 = @bitCast(insn.imm);
        const jump_imm: u64 = @bitCast(@as(i64, insn.imm));
        var jump = false;
        switch (insn.code) {
            0x61 => regs[dst] = try loadContext(context, src, insn.off),
            0x54 => regs[dst] = @as(u32, @truncate(regs[dst])) & imm,
            0x74 => regs[dst] = @as(u32, @truncate(regs[dst])) >> @as(u5, @intCast(imm)),
            0xb4 => regs[dst] = imm,
            0xbc => regs[dst] = @as(u32, @truncate(regs[src])),
            0x15 => jump = regs[dst] == jump_imm,
            0x55 => jump = regs[dst] != jump_imm,
            0x5d => jump = regs[dst] != regs[src],
            0x95 => return regs[0] == 1,
            else => return error.InvalidInstruction,
        }
        try std.testing.expect(insn.off >= 0);
        pc += 1 + if (jump) @as(usize, @intCast(insn.off)) else 0;
    }
    return error.MissingExit;
}

fn loadContext(context: [3]u32, src: u8, offset: i16) !u32 {
    try std.testing.expectEqual(@as(u8, 1), src);
    try std.testing.expect(offset >= 0 and @mod(offset, 4) == 0 and offset <= 8);
    return context[@intCast(@divTrunc(offset, 4))];
}

fn expectDecision(rules: []const Rule, kind: u32, major: u32, minor: u32, access: u32, allowed: bool) !void {
    const insns = try compile(std.testing.allocator, rules);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(allowed, try evaluate(insns, .{ (access << 16) | kind, major, minor }));
}

test "device filter assembler encodes Linux instruction fields in target byte order" {
    const insn = Insn.init(0x61, 2, 1, 0x1234, 0x12345678);
    const expected: [8]u8 = if (builtin.cpu.arch.endian() == .little)
        .{ 0x61, 0x12, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12 }
    else
        .{ 0x61, 0x21, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78 };
    try std.testing.expectEqualSlices(u8, &expected, std.mem.asBytes(&insn));
}

test "device filter interpreter rejects opcodes the compiler does not emit" {
    for ([_]u8{ 0x1d, 0x05 }) |code|
        try std.testing.expectError(error.InvalidInstruction, evaluate(&.{
            Insn.init(code, 0, 0, 0, 0),
            Insn.init(op.exit, 0, 0, 0, 0),
        }, .{ 0, 0, 0 }));
}

test "device filter defaults to deny and permits only matching types and numbers" {
    try expectDecision(&.{}, 2, 1, 3, 2, false);
    const rules = [_]Rule{.{ .allow = true, .kind = .char, .major = 1, .minor = 3 }};
    try expectDecision(&rules, 2, 1, 3, 7, true);
    try expectDecision(&rules, 1, 1, 3, 2, false);
    try expectDecision(&rules, 2, 2, 3, 2, false);
    try expectDecision(&rules, 2, 1, 5, 2, false);
    try expectDecision(&.{.{ .allow = true, .kind = .block, .major = 8 }}, 1, 8, 0, 6, true);
    try expectDecision(&.{.{ .allow = true, .kind = .block, .major = 8 }}, 2, 8, 0, 6, false);
}

test "device filter supports both wildcard spellings and all device types" {
    for ([_]u32{ 1, 2 }) |kind| {
        try expectDecision(&.{.{ .allow = true }}, kind, 123, 456, 7, true);
        try expectDecision(&.{.{ .allow = true, .major = -1, .minor = -1 }}, kind, 123, 456, 7, true);
        try expectDecision(&.{.{ .allow = true, .minor = 3 }}, kind, 123, 3, 7, true);
        try expectDecision(&.{.{ .allow = true, .minor = 3 }}, kind, 123, 4, 7, true);
        try expectDecision(&.{.{ .allow = true, .major = 1 }}, kind, 1, 456, 7, true);
        try expectDecision(&.{.{ .allow = true, .major = 1 }}, kind, 2, 456, 7, true);
        const device_kind: @FieldType(Rule, "kind") = if (kind == 1) .block else .char;
        try expectDecision(&.{.{ .allow = true, .kind = device_kind, .minor = 3 }}, kind, 123, 3, 7, true);
        try expectDecision(&.{.{ .allow = true, .kind = device_kind, .minor = 3 }}, kind, 123, 4, 7, false);
        try expectDecision(&.{.{ .allow = true, .kind = device_kind, .major = 1 }}, kind, 1, 456, 7, true);
        try expectDecision(&.{.{ .allow = true, .kind = device_kind, .major = 1 }}, kind, 2, 456, 7, false);
    }
}

test "v2 device filter rejects holes in wildcard allows like v1" {
    for ([_]?i64{ null, -1 }) |wildcard| {
        const rules = [_]Rule{
            .{ .allow = true, .kind = .char, .major = 10, .minor = wildcard },
            .{ .allow = false, .kind = .char, .major = 10, .minor = 237 },
        };
        try std.testing.expectError(error.CannotPunchHole, compile(std.testing.allocator, &rules));
    }
}

test "device filter allow rules match access subsets rather than any overlapping permission" {
    const cases = [_]struct { access: []const u8, allowed: [7]bool }{
        .{ .access = "m", .allowed = .{ true, false, false, false, false, false, false } },
        .{ .access = "r", .allowed = .{ false, true, false, false, false, false, false } },
        .{ .access = "w", .allowed = .{ false, false, false, true, false, false, false } },
        .{ .access = "rw", .allowed = .{ false, true, false, true, false, true, false } },
        .{ .access = "mr", .allowed = .{ true, true, true, false, false, false, false } },
        .{ .access = "wm", .allowed = .{ true, false, false, true, true, false, false } },
        .{ .access = "mwr", .allowed = .{ true, true, true, true, true, true, true } },
    };
    for (cases) |case| {
        for (case.allowed, 1..) |allowed, access|
            try expectDecision(&.{.{ .allow = true, .kind = .char, .access = case.access }}, 2, 1, 3, @intCast(access), allowed);
    }
}

test "device filter enforces normalized deny and allow exceptions" {
    const denylist = [_]Rule{
        .{ .allow = true },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 3, .access = "w" },
    };
    try expectDecision(&denylist, 2, 1, 3, 4, false);
    try expectDecision(&denylist, 2, 1, 3, 2, true);
    try expectDecision(&denylist, 2, 1, 3, 6, false);
    try expectDecision(&denylist, 1, 1, 3, 4, true);
    const allowlist = [_]Rule{
        .{ .allow = false },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 3 },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 5 },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5, .access = "r" },
    };
    try expectDecision(&allowlist, 2, 1, 3, 7, true);
    try expectDecision(&allowlist, 2, 1, 5, 2, true);
    try expectDecision(&allowlist, 2, 1, 5, 4, false);
    try expectDecision(&allowlist, 2, 1, 5, 6, false);
    try expectDecision(&allowlist, 1, 1, 3, 7, false);
    try expectDecision(&.{ .{ .allow = true, .kind = .char }, .{ .allow = false } }, 2, 1, 3, 7, false);
}

test "device filter denies overlapping access after a default-deny allow rule" {
    const rules = [_]Rule{
        .{ .allow = false },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5 },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 5, .access = "w" },
    };
    for ([_]bool{ true, true, true, false, false, false, false }, 1..) |allowed, access|
        try expectDecision(&rules, 2, 1, 5, @intCast(access), allowed);
}

test "device filter compares the full unsigned device number" {
    const rules = [_]Rule{.{ .allow = true, .kind = .char, .major = 0xffffffff, .minor = 0x80000000 }};
    try expectDecision(&rules, 2, 0xffffffff, 0x80000000, 7, true);
    try expectDecision(&rules, 2, 0x7fffffff, 0x80000000, 7, false);
    try expectDecision(&rules, 2, 0xffffffff, 0, 7, false);
}

test "device filter merges split permissions and leaves concrete allows after wildcard denies" {
    const merged = [_]Rule{
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5, .access = "r" },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5, .access = "w" },
    };
    try expectDecision(&merged, 2, 1, 5, 6, true);
    try expectDecision(&merged, 2, 1, 5, 7, false);
    const broader_deny = [_]Rule{
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5 },
        .{ .allow = false, .kind = .char, .major = 1, .access = "rw" },
    };
    try expectDecision(&broader_deny, 2, 1, 5, 7, true);
    try expectDecision(&broader_deny, 2, 1, 6, 7, false);
}

test "device filter rejects invalid access and device numbers even in shadowed rules" {
    for ([_]Rule{
        .{ .allow = true, .access = "" },
        .{ .allow = true, .access = "rx" },
        .{ .allow = true, .major = -2 },
        .{ .allow = true, .minor = -2 },
        .{ .allow = true, .major = 0x100000000 },
        .{ .allow = true, .minor = 0x100000000 },
    }) |rule|
        try std.testing.expectError(error.InvalidConfig, compile(std.testing.allocator, &.{ rule, .{ .allow = true } }));
}

test "device filter skips BPF only for a single unrestricted allow rule" {
    try std.testing.expect(isAllowAll(&.{.{ .allow = true }}));
    try std.testing.expect(isAllowAll(&.{.{ .allow = true, .major = -1, .minor = -1, .access = "mwr" }}));
    try std.testing.expect(!isAllowAll(&.{}));
    try std.testing.expect(!isAllowAll(&.{.{ .allow = false }}));
    try std.testing.expect(!isAllowAll(&.{.{ .allow = true, .kind = .char }}));
    try std.testing.expect(!isAllowAll(&.{.{ .allow = true, .major = 1 }}));
    try std.testing.expect(!isAllowAll(&.{.{ .allow = true, .access = "rw" }}));
    try std.testing.expect(!isAllowAll(&.{ .{ .allow = true }, .{ .allow = false } }));
}

test "device filter frees allocations on every compiler allocation failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const insns = try compile(allocator, &.{
                .{ .allow = false },
                .{ .allow = true, .kind = .char, .major = 1, .minor = 3, .access = "rw" },
                .{ .allow = true, .major = 0xffffffff },
            });
            defer allocator.free(insns);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

const std = @import("std");
const builtin = @import("builtin");

pub const Data = extern struct {
    nr: u32 = 7,
    arch: u32 = 0xc000003e,
    ip: u64 = 0,
    args: [6]u64 = @splat(0),
};

// A deliberately small interpreter, independent of the compiler's branch logic.
pub fn interpret(filters: anytype, data: Data) !u32 {
    var pc: usize = 0;
    var accumulator: u32 = 0;
    const bytes = std.mem.asBytes(&data);
    while (pc < filters.len) {
        const instruction = filters[pc];
        pc += 1;
        switch (instruction.code) {
            0x20 => {
                if (instruction.k % 4 != 0 or instruction.k > bytes.len - 4) return error.InvalidLoad;
                accumulator = std.mem.readInt(u32, bytes[instruction.k..][0..4], builtin.cpu.arch.endian());
            },
            0x05 => pc += instruction.k,
            0x15, 0x25, 0x35, 0x45 => {
                const matched = switch (instruction.code) {
                    0x15 => accumulator == instruction.k,
                    0x25 => accumulator > instruction.k,
                    0x35 => accumulator >= instruction.k,
                    0x45 => accumulator & instruction.k != 0,
                    else => unreachable,
                };
                pc += if (matched) instruction.jt else instruction.jf;
            },
            0x54 => accumulator &= instruction.k,
            0x06 => return instruction.k,
            else => return error.InvalidInstruction,
        }
    }
    return error.InvalidJump;
}

/// Evaluate the rules in order, independently of the BPF compiler.
pub fn evaluate(config: anytype, arch: anytype, data: Data) u32 {
    var maximum: u32 = 0;
    rules: for (config.rules) |rule| {
        if (rule.arch != arch) continue;
        maximum = @max(maximum, rule.number);
        if (rule.number != data.nr) continue;
        for (rule.args) |arg| {
            var value = data.args[arg.index];
            var expected = arg.value;
            var expected_two = arg.value_two;
            if (arch == .x86 or arch == .x32 or arch == .arm) {
                value = @as(u32, @truncate(value));
                expected = @as(u32, @truncate(expected));
                expected_two = @as(u32, @truncate(expected_two));
            }
            const matches = switch (arg.op) {
                .eq => value == expected,
                .ne => value != expected,
                .lt => value < expected,
                .le => value <= expected,
                .gt => value > expected,
                .ge => value >= expected,
                .masked_eq => value & expected == expected_two,
            };
            if (!matches) continue :rules;
        }
        return rule.action.encode(rule.errno_ret);
    }
    switch (config.default_action) {
        .allow, .log, .trace => {},
        else => if (maximum != 0 and data.nr > maximum) return 0x00050026,
    }
    return config.default_action.encode(config.default_errno_ret);
}

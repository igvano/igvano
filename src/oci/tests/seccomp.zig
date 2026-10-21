const std = @import("std");
const libcontainer = @import("libcontainer");
const Spec = @import("../spec.zig").Spec;
const prepareSeccomp = @import("../seccomp.zig").prepareSeccomp;
const freeSeccomp = @import("../seccomp.zig").freeSeccomp;

test "seccomp Docker default profile stays below 2500 instructions and exercises long jumps" {
    const seccomp = libcontainer.seccomp;
    const testing = @import("libcontainer").testing.seccomp;
    const parsed = try std.json.parseFromSlice(Spec.Seccomp, std.testing.allocator, @embedFile("../../libcontainer/testdata/docker-default.json"), .{});
    defer parsed.deinit();
    const config = (try prepareSeccomp(std.testing.allocator, parsed.value)).?;
    defer freeSeccomp(std.testing.allocator, config);
    for ([_]seccomp.Arch{ .x86_64, .aarch64 }) |host| {
        const program = try seccomp.compile(std.testing.allocator, config, host);
        defer std.testing.allocator.free(program.filters);
        std.debug.print("Docker seccomp {s}: {d} instructions\n", .{ @tagName(host), program.filters.len });
        try std.testing.expect(program.filters.len <= 2500);
        var long_jump = false;
        for (program.filters) |instruction| {
            if (instruction.code == 0x05 and instruction.k > 255) long_jump = true;
        }
        try std.testing.expect(long_jump);
        const numbers = if (host == .x86_64) [_]u32{ 0, 257, 59, 436, 332, 135, 250 } else [_]u32{ 63, 56, 221, 436, 291, 92, 219 };
        // Includes the syscalls needed between the early installation and exec:
        // read, openat, execve, close_range, statx, personality, keyctl.
        for (numbers[0..5]) |nr|
            try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, .{ .nr = nr, .arch = host.audit() }));
        try std.testing.expectEqual(@as(u32, 0x00050001), try testing.interpret(program.filters, .{ .nr = numbers[6], .arch = host.audit() }));
        var personality: testing.Data = .{ .nr = numbers[5], .arch = host.audit() };
        try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, personality));
        personality.args[0] = 1;
        try std.testing.expectEqual(@as(u32, 0x00050001), try testing.interpret(program.filters, personality));
        // The compat block's architecture dispatch uses the long JA.
        const compat: seccomp.Arch = if (host == .x86_64) .x86 else .arm;
        try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, .{ .nr = 3, .arch = compat.audit() }));
        for (config.architectures) |arch| {
            if (!arch.runnable(host)) continue;
            const base: u32 = if (arch == .x32) 0x40000000 else 0;
            var maximum: u32 = base;
            for (config.rules) |rule| {
                if (rule.arch == arch) maximum = @max(maximum, rule.number);
            }
            var data: testing.Data = .{ .arch = arch.audit() };
            for (0..maximum - base + 11) |number| {
                data.nr = base + @as(u32, @intCast(number));
                try std.testing.expectEqual(testing.evaluate(config, arch, data), try testing.interpret(program.filters, data));
            }
        }
    }
}

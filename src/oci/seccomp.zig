const std = @import("std");
const libcontainer = @import("libcontainer");
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const Spec = @import("spec.zig").Spec;

pub fn prepareSeccomp(allocator: std.mem.Allocator, configured: ?Spec.Seccomp) !?libcontainer.seccomp.Config {
    const config = configured orelse return null;
    const seccomp = libcontainer.seccomp;
    // Like runc: a listener path without notify rules is ignored.
    const default_action = try seccompAction(config.defaultAction);
    if (default_action == .notify) return seccompInvalid("SCMP_ACT_NOTIFY cannot be used as default action", .{});
    try validateSeccompNotify(config);
    if (config.defaultErrnoRet != null and default_action != .errno and default_action != .trace)
        return seccompInvalid("seccomp defaultErrnoRet is not supported by {s}", .{config.defaultAction});
    const default_errno = try seccompErrno(config.defaultErrnoRet);
    const flags = try seccompFlags(config.flags);
    var arches: std.ArrayList(seccomp.Arch) = .empty;
    defer arches.deinit(allocator);
    try appendSeccompArches(allocator, &arches, config.architectures);
    var rules: std.ArrayList(seccomp.Rule) = .empty;
    defer rules.deinit(allocator);
    errdefer for (rules.items) |rule| allocator.free(rule.args);
    var args: std.ArrayList(seccomp.Arg) = .empty;
    defer args.deinit(allocator);
    for (config.syscalls orelse &.{}) |syscall| {
        try appendSeccompSyscall(allocator, &rules, &args, arches.items, syscall);
    }
    const owned_arches = try arches.toOwnedSlice(allocator);
    errdefer allocator.free(owned_arches);
    return .{
        .default_action = default_action,
        .default_errno_ret = default_errno,
        .architectures = owned_arches,
        .flags = flags,
        .rules = try rules.toOwnedSlice(allocator),
    };
}

fn seccompFlags(configured: ?[]const []const u8) !u32 {
    var flags: u32 = 0;
    for (configured orelse &.{}) |flag|
        flags |= seccomp_flags.get(flag) orelse
            return seccompInvalid("unsupported seccomp flag: {s}", .{flag});
    return flags;
}

fn appendSeccompArches(allocator: std.mem.Allocator, arches: *std.ArrayList(libcontainer.seccomp.Arch), configured: ?[]const []const u8) !void {
    const seccomp = libcontainer.seccomp;
    // Like seccomp_init, retain the native ABI when additional ABIs are named.
    try arches.append(allocator, seccomp.Arch.native() orelse
        return seccompInvalid("seccomp is unsupported on this architecture", .{}));
    for (configured orelse &.{}) |name| {
        // Known but unimplemented ABIs are ignored.
        const arch = (seccomp_arches.get(name) orelse
            return seccompInvalid("unknown seccomp architecture: {s}", .{name})) orelse continue;
        if (std.mem.indexOfScalar(seccomp.Arch, arches.items, arch) == null)
            try arches.append(allocator, arch);
    }
}

fn appendSeccompSyscall(allocator: std.mem.Allocator, rules: *std.ArrayList(libcontainer.seccomp.Rule), args: *std.ArrayList(libcontainer.seccomp.Arg), arches: []const libcontainer.seccomp.Arch, syscall: Spec.Seccomp.Syscall) !void {
    const action = try seccompAction(syscall.action);
    if (syscall.errnoRet != null and action != .errno and action != .trace)
        return seccompInvalid("seccomp errnoRet is not supported by {s}", .{syscall.action});
    const errno_ret = try seccompErrno(syscall.errnoRet);
    const repeated_index = try prepareSeccompArgs(allocator, args, syscall.args);
    try appendSeccompRules(allocator, rules, arches, syscall.names, action, errno_ret, args.items, repeated_index);
}

fn prepareSeccompArgs(allocator: std.mem.Allocator, args: *std.ArrayList(libcontainer.seccomp.Arg), configured: ?[]const Spec.Seccomp.Arg) !bool {
    args.clearRetainingCapacity();
    var indices: [6]bool = @splat(false);
    var repeated_index = false;
    for (configured orelse &.{}) |arg| {
        if (arg.index >= 6) return seccompInvalid("seccomp argument index must be less than 6", .{});
        repeated_index = repeated_index or indices[arg.index];
        indices[arg.index] = true;
        try args.append(allocator, .{
            .index = arg.index,
            .value = arg.value,
            .value_two = arg.valueTwo,
            .op = seccomp_ops.get(arg.op) orelse
                return seccompInvalid("unknown seccomp operator: {s}", .{arg.op}),
        });
    }
    return repeated_index;
}

fn appendSeccompRules(allocator: std.mem.Allocator, rules: *std.ArrayList(libcontainer.seccomp.Rule), arches: []const libcontainer.seccomp.Arch, names: []const []const u8, action: libcontainer.seccomp.Action, errno_ret: ?u16, args: []const libcontainer.seccomp.Arg, repeated_index: bool) !void {
    const seccomp = libcontainer.seccomp;
    for (arches) |arch| for (names) |name| {
        const number = seccompSyscall(arch, name) orelse continue;
        // runc/libseccomp split every condition into an OR rule if any index repeats.
        for (0..if (repeated_index) args.len else 1) |i| {
            const conditions = if (repeated_index) args[i..][0..1] else args;
            const owned_args = try allocator.dupe(seccomp.Arg, conditions);
            errdefer allocator.free(owned_args);
            try rules.append(allocator, .{ .arch = arch, .number = number, .action = action, .errno_ret = errno_ret, .args = owned_args });
        }
    };
}

pub fn freeSeccomp(allocator: std.mem.Allocator, config: ?libcontainer.seccomp.Config) void {
    const value = config orelse return;
    for (value.rules) |rule| allocator.free(rule.args);
    allocator.free(value.rules);
    allocator.free(value.architectures);
}

fn seccompInvalid(comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
    return invalidConfig("linux.seccomp: " ++ fmt, args);
}

/// True when any rule sends syscalls to the seccomp agent at listenerPath.
pub fn seccompNotifies(config: Spec.Seccomp) bool {
    for (config.syscalls orelse &.{}) |syscall| {
        if (std.mem.eql(u8, syscall.action, "SCMP_ACT_NOTIFY")) return true;
    }
    return false;
}

fn validateSeccompNotify(config: Spec.Seccomp) error{InvalidConfig}!void {
    if (!seccompNotifies(config)) return;
    if ((config.listenerPath orelse @as([]const u8, "")).len == 0)
        return seccompInvalid("SCMP_ACT_NOTIFY requires listenerPath", .{});
    for (config.syscalls orelse &.{}) |syscall| {
        if (!std.mem.eql(u8, syscall.action, "SCMP_ACT_NOTIFY")) continue;
        // The runtime reports the listener fd to its parent with write.
        for (syscall.names) |name| if (std.mem.eql(u8, name, "write"))
            return seccompInvalid("SCMP_ACT_NOTIFY cannot be used for the write syscall", .{});
    }
}

fn seccompAction(name: []const u8) error{InvalidConfig}!libcontainer.seccomp.Action {
    return seccomp_actions.get(name) orelse seccompInvalid("unknown seccomp action: {s}", .{name});
}

fn seccompErrno(value: ?u32) error{InvalidConfig}!?u16 {
    const number = value orelse return null;
    if (number > std.math.maxInt(u16))
        return seccompInvalid("seccomp return data must fit in 16 bits", .{});
    return @intCast(number);
}

pub const seccomp_actions = std.StaticStringMap(libcontainer.seccomp.Action).initComptime(.{
    .{ "SCMP_ACT_KILL", .kill_thread },          .{ "SCMP_ACT_KILL_THREAD", .kill_thread },
    .{ "SCMP_ACT_KILL_PROCESS", .kill_process }, .{ "SCMP_ACT_TRAP", .trap },
    .{ "SCMP_ACT_ERRNO", .errno },               .{ "SCMP_ACT_TRACE", .trace },
    .{ "SCMP_ACT_LOG", .log },                   .{ "SCMP_ACT_ALLOW", .allow },
    .{ "SCMP_ACT_NOTIFY", .notify },
});

pub const seccomp_arches = std.StaticStringMap(?libcontainer.seccomp.Arch).initComptime(.{
    .{ "SCMP_ARCH_NATIVE", libcontainer.seccomp.Arch.native() },
    .{ "SCMP_ARCH_X86_64", .x86_64 },
    .{ "SCMP_ARCH_X86", .x86 },
    .{ "SCMP_ARCH_AARCH64", .aarch64 },
    .{ "SCMP_ARCH_ARM", .arm },
    .{ "SCMP_ARCH_X32", .x32 },
    .{ "SCMP_ARCH_MIPS", null },
    .{ "SCMP_ARCH_MIPS64", null },
    .{ "SCMP_ARCH_MIPS64N32", null },
    .{ "SCMP_ARCH_MIPSEL", null },
    .{ "SCMP_ARCH_MIPSEL64", null },
    .{ "SCMP_ARCH_MIPSEL64N32", null },
    .{ "SCMP_ARCH_PPC", null },
    .{ "SCMP_ARCH_PPC64", null },
    .{ "SCMP_ARCH_PPC64LE", null },
    .{ "SCMP_ARCH_S390", null },
    .{ "SCMP_ARCH_S390X", null },
    .{ "SCMP_ARCH_PARISC", null },
    .{ "SCMP_ARCH_PARISC64", null },
    .{ "SCMP_ARCH_RISCV64", null },
    .{ "SCMP_ARCH_LOONGARCH64", null },
    .{ "SCMP_ARCH_M68K", null },
    .{ "SCMP_ARCH_SH", null },
    .{ "SCMP_ARCH_SHEB", null },
});

pub const seccomp_ops = std.StaticStringMap(libcontainer.seccomp.Op).initComptime(.{
    .{ "SCMP_CMP_EQ", .eq },               .{ "SCMP_CMP_NE", .ne }, .{ "SCMP_CMP_LT", .lt },
    .{ "SCMP_CMP_LE", .le },               .{ "SCMP_CMP_GT", .gt }, .{ "SCMP_CMP_GE", .ge },
    .{ "SCMP_CMP_MASKED_EQ", .masked_eq },
});

pub const seccomp_flags = std.StaticStringMap(u32).initComptime(.{
    .{ "SECCOMP_FILTER_FLAG_LOG", 2 },
    .{ "SECCOMP_FILTER_FLAG_SPEC_ALLOW", 4 },
    // ponytail: accepted but not set; needs Linux 5.19 and changes only how
    // a notified task reacts to non-fatal signals.
    .{ "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV", 0 },
    // Like runc, init/exec are single-threaded at installation.
    .{ "SECCOMP_FILTER_FLAG_TSYNC", 0 },
});

fn syscallMap(comptime Syscalls: type, comptime aliases: []const struct { []const u8, []const u8 }) std.StaticStringMap(u32) {
    @setEvalBranchQuota(200000);
    const fields = @typeInfo(Syscalls).@"enum".fields;
    var entries: [fields.len + aliases.len]struct { []const u8, u32 } = undefined;
    var len: usize = 0;
    for (fields) |field| {
        // Aliased enum spellings are not syscall names on this ABI.
        for (aliases) |alias| {
            if (std.mem.eql(u8, field.name, alias[1])) break;
        } else {
            entries[len] = .{ field.name, @intCast(field.value) };
            len += 1;
        }
    }
    for (aliases) |alias| {
        entries[len] = .{ alias[0], @intCast(@intFromEnum(@field(Syscalls, alias[1]))) };
        len += 1;
    }
    return .initComptime(entries[0..len]);
}

// OCI/libseccomp name -> Zig enum spelling, scoped to each ABI.
const seccomp_syscalls_x64 = syscallMap(std.os.linux.syscalls.X64, &.{
    .{ "newfstatat", "fstatat64" },
    .{ "_sysctl", "sysctl" },
});

const seccomp_syscalls_x32 = syscallMap(std.os.linux.syscalls.X32, &.{
    .{ "newfstatat", "fstatat64" },
});

const seccomp_syscalls_x86 = syscallMap(std.os.linux.syscalls.X86, &.{
    .{ "_llseek", "llseek" },
    .{ "_newselect", "newselect" },
    .{ "_sysctl", "sysctl" },
});

const seccomp_syscalls_arm64 = syscallMap(std.os.linux.syscalls.Arm64, &.{
    .{ "newfstatat", "fstatat64" },
});

const seccomp_syscalls_arm = syscallMap(std.os.linux.syscalls.Arm, &.{
    .{ "_llseek", "llseek" },
    .{ "_newselect", "newselect" },
    .{ "_sysctl", "sysctl" },
    .{ "arm_fadvise64_64", "fadvise64_64" },
    .{ "arm_sync_file_range", "sync_file_range" },
    .{ "sync_file_range2", "sync_file_range" },
});

fn seccompSyscall(arch: libcontainer.seccomp.Arch, name: []const u8) ?u32 {
    return switch (arch) {
        .x86_64 => seccomp_syscalls_x64.get(name),
        .x32 => seccomp_syscalls_x32.get(name),
        .x86 => seccomp_syscalls_x86.get(name),
        .aarch64 => seccomp_syscalls_arm64.get(name),
        .arm => seccomp_syscalls_arm.get(name),
    };
}

test "seccomp syscall lookup uses ABI-specific OCI names" {
    const cases = [_]struct { arch: libcontainer.seccomp.Arch, name: []const u8, number: ?u32 }{
        .{ .arch = .x86_64, .name = "newfstatat", .number = 262 },
        .{ .arch = .x32, .name = "newfstatat", .number = 0x40000000 + 262 },
        .{ .arch = .x32, .name = "execve", .number = 0x40000000 + 520 },
        .{ .arch = .aarch64, .name = "newfstatat", .number = 79 },
        .{ .arch = .x86, .name = "_llseek", .number = 140 },
        .{ .arch = .arm, .name = "_llseek", .number = 140 },
        .{ .arch = .x86, .name = "_newselect", .number = 142 },
        .{ .arch = .arm, .name = "_newselect", .number = 142 },
        .{ .arch = .x86_64, .name = "_sysctl", .number = 156 },
        .{ .arch = .x86, .name = "_sysctl", .number = 149 },
        .{ .arch = .arm, .name = "_sysctl", .number = 149 },
        .{ .arch = .arm, .name = "arm_fadvise64_64", .number = 270 },
        .{ .arch = .arm, .name = "arm_sync_file_range", .number = 341 },
        .{ .arch = .arm, .name = "sync_file_range2", .number = 341 },
        .{ .arch = .x86, .name = "fstatat64", .number = 300 },
        .{ .arch = .arm, .name = "fstatat64", .number = 327 },
        .{ .arch = .x86, .name = "fadvise64_64", .number = 272 },
        .{ .arch = .x86_64, .name = "sync_file_range", .number = 277 },
        .{ .arch = .aarch64, .name = "sync_file_range", .number = 84 },
        .{ .arch = .x86_64, .name = "fstatat64", .number = null },
        .{ .arch = .aarch64, .name = "fstatat64", .number = null },
        .{ .arch = .x86, .name = "newfstatat", .number = null },
        .{ .arch = .arm, .name = "newfstatat", .number = null },
        .{ .arch = .x86, .name = "llseek", .number = null },
        .{ .arch = .arm, .name = "llseek", .number = null },
        .{ .arch = .x86, .name = "newselect", .number = null },
        .{ .arch = .arm, .name = "newselect", .number = null },
        .{ .arch = .x86_64, .name = "sysctl", .number = null },
        .{ .arch = .x86, .name = "sysctl", .number = null },
        .{ .arch = .arm, .name = "sysctl", .number = null },
        .{ .arch = .arm, .name = "fadvise64_64", .number = null },
        .{ .arch = .arm, .name = "sync_file_range", .number = null },
    };
    for (cases) |case|
        try std.testing.expectEqual(case.number, seccompSyscall(case.arch, case.name));
    for ([_]libcontainer.seccomp.Arch{ .x86_64, .x32, .x86, .aarch64, .arm }) |arch|
        try std.testing.expectEqual(@as(?u32, null), seccompSyscall(arch, "riscv_hwprobe"));
}

test "seccomp translation resolves syscall numbers per ABI and skips unknown names" {
    const parsed = try std.json.parseFromSlice(Spec.Seccomp, std.testing.allocator,
        \\{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":13,
        \\ "architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],
        \\ "flags":["SECCOMP_FILTER_FLAG_LOG","SECCOMP_FILTER_FLAG_SPEC_ALLOW","SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV","SECCOMP_FILTER_FLAG_TSYNC"],
        \\ "syscalls":[{"names":["mkdir","not_a_syscall"],"action":"SCMP_ACT_ALLOW",
        \\ "args":[{"index":0,"value":4294967296,"valueTwo":1,"op":"SCMP_CMP_MASKED_EQ"}]}]}
    , .{});
    defer parsed.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const translated = (try prepareSeccomp(arena.allocator(), parsed.value)).?;
    try std.testing.expectEqual(@as(u32, 6), translated.flags);
    try std.testing.expectEqual(@as(u32, 0x0005000d), translated.default_action.encode(translated.default_errno_ret));
    var found_x64 = false;
    var found_x86 = false;
    for (translated.rules) |rule| {
        try std.testing.expectEqual(@as(u64, 4294967296), rule.args[0].value);
        try std.testing.expectEqual(@as(u64, 1), rule.args[0].value_two);
        try std.testing.expectEqual(libcontainer.seccomp.Op.masked_eq, rule.args[0].op);
        switch (rule.arch) {
            .x86_64 => {
                try std.testing.expectEqual(@as(u32, 83), rule.number);
                found_x64 = true;
            },
            .x86 => {
                try std.testing.expectEqual(@as(u32, 39), rule.number);
                found_x86 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_x64 and found_x86);
    try std.testing.expectEqual(@as(?u32, 34), seccompSyscall(.aarch64, "mkdirat"));
    try std.testing.expectEqual(@as(?u32, 323), seccompSyscall(.arm, "mkdirat"));
}

test "seccomp rejects unsupported or unknown schema values even for unknown syscalls" {
    const cases = [_]Spec.Seccomp{
        .{ .defaultAction = "unknown" },
        .{ .defaultAction = "SCMP_ACT_NOTIFY" },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .architectures = &.{"SCMP_ARCH_UNKNOWN"} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .flags = &.{"SECCOMP_FILTER_FLAG_NEW_LISTENER"} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .flags = &.{"unknown"} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .defaultErrnoRet = 5 },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .defaultErrnoRet = 65536 },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .syscalls = &.{.{ .names = &.{"unknown"}, .action = "SCMP_ACT_KILL", .errnoRet = 1 }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .syscalls = &.{.{ .names = &.{"unknown"}, .action = "unknown" }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .syscalls = &.{.{ .names = &.{"unknown"}, .action = "SCMP_ACT_NOTIFY" }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .listenerPath = "", .syscalls = &.{.{ .names = &.{"mkdir"}, .action = "SCMP_ACT_NOTIFY" }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .listenerPath = "/l", .syscalls = &.{.{ .names = &.{ "mkdir", "write" }, .action = "SCMP_ACT_NOTIFY" }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .syscalls = &.{.{ .names = &.{"unknown"}, .action = "SCMP_ACT_ALLOW", .args = &.{.{ .index = 0, .value = 0, .op = "unknown" }} }} },
        .{ .defaultAction = "SCMP_ACT_ALLOW", .syscalls = &.{.{ .names = &.{"mkdir"}, .action = "SCMP_ACT_ERRNO", .args = &.{.{ .index = 6, .value = 0, .op = "SCMP_CMP_EQ" }} }} },
    };
    for (cases) |config| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expectError(error.InvalidConfig, prepareSeccomp(arena.allocator(), config));
    }
    try std.testing.expect((try prepareSeccomp(std.testing.allocator, null)) == null);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expect((try prepareSeccomp(arena.allocator(), .{ .defaultAction = "SCMP_ACT_ALLOW" })).?.architectures.len == 1);
    // A listener path alone is ignored; notify rules with one are accepted.
    _ = try prepareSeccomp(arena.allocator(), .{ .defaultAction = "SCMP_ACT_ALLOW", .listenerPath = "/listener" });
    const notify = (try prepareSeccomp(arena.allocator(), .{ .defaultAction = "SCMP_ACT_ALLOW", .listenerPath = "/l", .syscalls = &.{.{ .names = &.{"mkdir"}, .action = "SCMP_ACT_NOTIFY" }} })).?;
    try std.testing.expectEqual(libcontainer.seccomp.Action.notify, notify.rules[0].action);
    try std.testing.expect((try prepareSeccomp(arena.allocator(), .{
        .defaultAction = "SCMP_ACT_ALLOW",
        .architectures = &.{"SCMP_ARCH_NATIVE"},
    })).?.architectures.len == 1);
    try std.testing.expect((try prepareSeccomp(arena.allocator(), .{
        .defaultAction = "SCMP_ACT_ALLOW",
        .architectures = &.{"SCMP_ARCH_X32"},
    })).?.architectures.len == if (libcontainer.seccomp.Arch.native() == .x32) @as(usize, 1) else 2);
}

test "seccomp repeated argument indices deny personality alternatives" {
    const seccomp = libcontainer.seccomp;
    const testing = @import("libcontainer").testing.seccomp;
    // A repeated index makes every condition an alternative, including index 1.
    // Distinct indices in the second syscall still form a conjunction.
    const config = (try prepareSeccomp(std.testing.allocator, .{
        .defaultAction = "SCMP_ACT_ALLOW",
        .architectures = &.{ "SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM" },
        .syscalls = &.{
            .{ .names = &.{"personality"}, .action = "SCMP_ACT_ERRNO", .errnoRet = 42, .args = &.{
                .{ .index = 0, .value = 8, .op = "SCMP_CMP_EQ" },
                .{ .index = 0, .value = 0x40000, .op = "SCMP_CMP_EQ" },
                .{ .index = 1, .value = 99, .op = "SCMP_CMP_EQ" },
            } },
            .{ .names = &.{"mkdirat"}, .action = "SCMP_ACT_ERRNO", .errnoRet = 13, .args = &.{
                .{ .index = 0, .value = 8, .op = "SCMP_CMP_EQ" },
                .{ .index = 1, .value = 99, .op = "SCMP_CMP_EQ" },
            } },
        },
    })).?;
    defer freeSeccomp(std.testing.allocator, config);
    for ([_]seccomp.Arch{ .x86_64, .aarch64 }) |host| {
        const program = try seccomp.compile(std.testing.allocator, config, host);
        defer std.testing.allocator.free(program.filters);
        for ([_]seccomp.Arch{ host, if (host == .x86_64) .x86 else .arm }) |arch| {
            var data: testing.Data = .{ .arch = arch.audit(), .nr = seccompSyscall(arch, "personality").? };
            for ([_]u64{ 8, 0x40000 }) |value| {
                data.args[0] = value;
                try std.testing.expectEqual(@as(u32, 0x0005002a), try testing.interpret(program.filters, data));
            }
            data.args[0] = 0;
            try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, data));
            data.args[1] = 99;
            try std.testing.expectEqual(@as(u32, 0x0005002a), try testing.interpret(program.filters, data));
            data.nr = seccompSyscall(arch, "mkdirat").?;
            try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, data));
            data.args[0] = 8;
            try std.testing.expectEqual(@as(u32, 0x0005000d), try testing.interpret(program.filters, data));
            data.args[1] = 0;
            try std.testing.expectEqual(@as(u32, 0x7fff0000), try testing.interpret(program.filters, data));
        }
    }
}

test "seccomp accepts all spec architecture names and ignores unimplemented ABIs" {
    const names = [_][]const u8{
        "SCMP_ARCH_X86",     "SCMP_ARCH_X86_64",   "SCMP_ARCH_X32",         "SCMP_ARCH_ARM",
        "SCMP_ARCH_AARCH64", "SCMP_ARCH_MIPS",     "SCMP_ARCH_MIPS64",      "SCMP_ARCH_MIPS64N32",
        "SCMP_ARCH_MIPSEL",  "SCMP_ARCH_MIPSEL64", "SCMP_ARCH_MIPSEL64N32", "SCMP_ARCH_PPC",
        "SCMP_ARCH_PPC64",   "SCMP_ARCH_PPC64LE",  "SCMP_ARCH_S390",        "SCMP_ARCH_S390X",
        "SCMP_ARCH_PARISC",  "SCMP_ARCH_PARISC64", "SCMP_ARCH_RISCV64",     "SCMP_ARCH_LOONGARCH64",
        "SCMP_ARCH_M68K",    "SCMP_ARCH_SH",       "SCMP_ARCH_SHEB",        "SCMP_ARCH_NATIVE",
    };
    for (names) |name| {
        const config = (try prepareSeccomp(std.testing.allocator, .{
            .defaultAction = "SCMP_ACT_ALLOW",
            .architectures = &.{name},
            .syscalls = &.{.{ .names = &.{"personality"}, .action = "SCMP_ACT_ERRNO" }},
        })).?;
        defer freeSeccomp(std.testing.allocator, config);
        const native = libcontainer.seccomp.Arch.native().?;
        const program = try libcontainer.seccomp.compile(std.testing.allocator, config, native);
        defer std.testing.allocator.free(program.filters);
        if (std.mem.eql(u8, name, "SCMP_ARCH_NATIVE") or
            (!std.mem.eql(u8, name, "SCMP_ARCH_X86") and !std.mem.eql(u8, name, "SCMP_ARCH_X86_64") and
                !std.mem.eql(u8, name, "SCMP_ARCH_X32") and
                !std.mem.eql(u8, name, "SCMP_ARCH_ARM") and !std.mem.eql(u8, name, "SCMP_ARCH_AARCH64")))
            try std.testing.expectEqualSlices(libcontainer.seccomp.Arch, &.{native}, config.architectures);
    }
}

test "seccomp translation cleans up partial rules on allocation failure" {
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const config = try prepareSeccomp(allocator, .{
                .defaultAction = "SCMP_ACT_ERRNO",
                .architectures = &.{ "SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_ARM", "SCMP_ARCH_AARCH64" },
                .syscalls = &.{.{
                    .names = &.{ "mkdirat", "personality", "unknown" },
                    .action = "SCMP_ACT_ALLOW",
                    .args = &.{
                        .{ .index = 0, .value = 0, .op = "SCMP_CMP_EQ" },
                        .{ .index = 0, .value = 8, .op = "SCMP_CMP_EQ" },
                        .{ .index = 1, .value = 0x100000000, .op = "SCMP_CMP_LT" },
                    },
                }},
            });
            defer freeSeccomp(allocator, config);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
}

const std = @import("std");
const libcontainer = @import("libcontainer");
const invalidConfig = @import("diagnostic.zig").invalidConfig;
const Spec = @import("spec.zig").Spec;
const requireCreate = @import("validate.zig").requireCreate;

/// A joined IPC/network/UTS namespace must differ from the runtime's namespace.
fn sysctlNamespace(config: Spec.Linux, kind: @FieldType(Spec.Namespace, "type")) bool {
    for (config.namespaces orelse &.{}) |namespace| {
        if (namespace.type != kind) continue;
        const path = namespace.joinPath() orelse return true;
        if (comptime @import("builtin").os.tag == .linux) {
            const linux = std.os.linux;
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const target = std.fmt.bufPrintZ(&buffer, "{s}", .{path}) catch return false;
            var own: linux.Statx = undefined;
            var joined: linux.Statx = undefined;
            const own_path: [*:0]const u8 = switch (kind) {
                .ipc => "/proc/self/ns/ipc",
                .uts => "/proc/self/ns/uts",
                else => "/proc/self/ns/net",
            };
            if (linux.errno(linux.statx(linux.AT.FDCWD, own_path, 0, .{ .INO = true }, &own)) != .SUCCESS or
                linux.errno(linux.statx(linux.AT.FDCWD, target, 0, .{ .INO = true }, &joined)) != .SUCCESS or
                !own.mask.INO or !joined.mask.INO) return false;
            return own.dev_major != joined.dev_major or own.dev_minor != joined.dev_minor or own.ino != joined.ino;
        }
        return false;
    }
    return false;
}

pub fn validateSysctls(config: Spec.Linux) error{InvalidConfig}!void {
    const configured = config.sysctl orelse return;
    var entries = configured.map.iterator();
    while (entries.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        const allowed = allowed: {
            if (key.len == 0 or std.mem.indexOfAny(u8, key, "/\x00") != null or
                std.mem.indexOf(u8, key, "..") != null or
                std.mem.indexOfAny(u8, value, "\x00\n") != null) break :allowed false;
            if (std.mem.startsWith(u8, key, "net.")) break :allowed sysctlNamespace(config, .network);
            if (std.mem.eql(u8, key, "kernel.domainname") or std.mem.eql(u8, key, "kernel.hostname"))
                break :allowed sysctlNamespace(config, .uts);
            if (std.mem.startsWith(u8, key, "fs.mqueue.")) break :allowed sysctlNamespace(config, .ipc);
            for ([_][]const u8{
                "kernel.msgmax", "kernel.msgmnb", "kernel.msgmni", "kernel.sem",
                "kernel.shmall", "kernel.shmmax", "kernel.shmmni", "kernel.shm_rmid_forced",
            }) |ipc_key| {
                if (std.mem.eql(u8, key, ipc_key)) break :allowed sysctlNamespace(config, .ipc);
            }
            break :allowed false;
        };
        if (!allowed) {
            return invalidConfig("linux.sysctl.{s}: invalid setting or required namespace is not isolated", .{key});
        }
    }
}

/// The frontend validated namespace ownership; libcontainer receives only writes.
pub fn prepareSysctls(allocator: std.mem.Allocator, config: Spec.Linux) ![]libcontainer.Sysctl {
    const configured = config.sysctl orelse return allocator.alloc(libcontainer.Sysctl, 0);
    const entries = try allocator.alloc(libcontainer.Sysctl, configured.map.count());
    var iterator = configured.map.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1)
        entries[index] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
    return entries;
}

test "OCI sysctls parse and translate borrowed keys and values" {
    const parsed = try std.json.parseFromSlice(Spec.Linux, std.testing.allocator,
        \\{"namespaces":[{"type":"network"}],"sysctl":{"net.ipv4.ip_forward":"1"}}
    , .{});
    defer parsed.deinit();
    try validateSysctls(parsed.value);
    const settings = try prepareSysctls(std.testing.allocator, parsed.value);
    defer std.testing.allocator.free(settings);
    try std.testing.expectEqual(@as(usize, 1), settings.len);
    try std.testing.expectEqualStrings("net.ipv4.ip_forward", settings[0].key);
    try std.testing.expectEqualStrings("1", settings[0].value);
}

test "OCI sysctl validation requires the matching namespace" {
    const cases = [_]struct { key: []const u8, kind: @FieldType(Spec.Namespace, "type") }{
        .{ .key = "kernel.msgmax", .kind = .ipc },
        .{ .key = "kernel.msgmnb", .kind = .ipc },
        .{ .key = "kernel.msgmni", .kind = .ipc },
        .{ .key = "kernel.sem", .kind = .ipc },
        .{ .key = "kernel.shmall", .kind = .ipc },
        .{ .key = "kernel.shmmax", .kind = .ipc },
        .{ .key = "kernel.shmmni", .kind = .ipc },
        .{ .key = "kernel.shm_rmid_forced", .kind = .ipc },
        .{ .key = "fs.mqueue.msg_max", .kind = .ipc },
        .{ .key = "net.ipv4.ip_forward", .kind = .network },
        .{ .key = "kernel.hostname", .kind = .uts },
        .{ .key = "kernel.domainname", .kind = .uts },
    };
    for (cases) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, "1");
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{ .sysctl = sysctl }));
        for ([_]@FieldType(Spec.Namespace, "type"){ .ipc, .network, .uts, .mount }) |kind| {
            const config: Spec.Linux = .{ .sysctl = sysctl, .namespaces = &.{.{ .type = kind }} };
            if (kind == case.kind) {
                try validateSysctls(config);
            } else {
                try std.testing.expectError(error.InvalidConfig, validateSysctls(config));
            }
        }
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{
            .sysctl = sysctl,
            .namespaces = &.{.{ .type = case.kind, .path = "/proc/self/ns/missing" }},
        }));
    }
}

test "OCI sysctls reject host settings traversal and invalid values" {
    for ([_]struct { key: []const u8, value: []const u8 = "1" }{
        .{ .key = "vm.swappiness" },
        .{ .key = "kernel.core_pattern" },
        .{ .key = "fs.file-max" },
        .{ .key = "" },
        .{ .key = "net/ipv4/ip_forward" },
        .{ .key = "net..ipv4.ip_forward" },
        .{ .key = "net.ipv4.ip_forward\x00" },
        .{ .key = "net.ipv4.ip_forward", .value = "1\x00" },
        .{ .key = "net.ipv4.ip_forward", .value = "1\n" },
    }) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, case.value);
        const config: Spec.Linux = .{ .sysctl = sysctl, .namespaces = &.{ .{ .type = .ipc }, .{ .type = .network }, .{ .type = .uts } } };
        try std.testing.expectError(error.InvalidConfig, validateSysctls(config));
        try std.testing.expectError(error.InvalidConfig, requireCreate(.{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" }, .linux = config }));
    }
}

test "OCI IPC network and UTS sysctls reject joining the runtime namespace" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { key: []const u8, kind: @FieldType(Spec.Namespace, "type"), path: []const u8 }{
        .{ .key = "kernel.msgmax", .kind = .ipc, .path = "/proc/self/ns/ipc" },
        .{ .key = "net.ipv4.ip_forward", .kind = .network, .path = "/proc/self/ns/net" },
        .{ .key = "net.ipv4.ip_forward", .kind = .network, .path = "/proc/thread-self/ns/net" },
        .{ .key = "kernel.hostname", .kind = .uts, .path = "/proc/self/ns/uts" },
        .{ .key = "kernel.hostname", .kind = .uts, .path = "/proc/thread-self/ns/uts" },
        .{ .key = "kernel.domainname", .kind = .uts, .path = "/proc/self/ns/uts" },
        .{ .key = "kernel.domainname", .kind = .uts, .path = "/proc/thread-self/ns/uts" },
    }) |case| {
        var sysctl: std.json.ArrayHashMap([]const u8) = .{};
        defer sysctl.deinit(std.testing.allocator);
        try sysctl.map.put(std.testing.allocator, case.key, "1");
        try std.testing.expectError(error.InvalidConfig, validateSysctls(.{
            .sysctl = sysctl,
            .namespaces = &.{.{ .type = case.kind, .path = case.path }},
        }));
    }
}

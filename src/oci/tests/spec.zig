const std = @import("std");
const loadSpec = @import("../spec.zig").loadSpec;

test "loadSpec parses a runc-style config and tolerates unknown fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "config.json",
        .data =
        \\{
        \\  "ociVersion": "1.0.2",
        \\  "root": {"path": "rootfs", "readonly": true},
        \\  "process": {
        \\    "terminal": true,
        \\    "user": {"uid": 1000, "gid": 1001, "additionalGids": [1002]},
        \\    "args": ["/bin/sh", "-c", "echo hello"],
        \\    "env": ["PATH=/usr/bin:/bin", "TERM=xterm"],
        \\    "cwd": "/",
        \\    "capabilities": {"bounding": ["CAP_CHOWN"]},
        \\    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        \\    "noNewPrivileges": true
        \\  },
        \\  "hostname": "example",
        \\  "mounts": [{
        \\    "destination": "/proc",
        \\    "type": "proc",
        \\    "source": "proc",
        \\    "options": ["nosuid", "noexec", "nodev"]
        \\  }],
        \\  "linux": {
        \\    "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "uts"}],
        \\    "resources": {"devices": [{"allow": false, "access": "rwm"}]},
        \\    "maskedPaths": ["/proc/kcore"]
        \\  },
        \\  "annotations": {"org.example.description": "hello"}
        \\}
        ,
    });

    const bundle = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(bundle);
    const parsed = try loadSpec(std.testing.allocator, std.testing.io, bundle);
    defer parsed.deinit();
    const spec = parsed.value;
    try std.testing.expectEqualStrings("1.0.2", spec.ociVersion);
    try std.testing.expectEqualStrings("rootfs", spec.root.path);
    try std.testing.expect(spec.root.readonly);
    const process = spec.process.?;
    try std.testing.expectEqual(@as(usize, 3), process.args.len);
    try std.testing.expectEqualStrings("/bin/sh", process.args[0]);
    try std.testing.expectEqualStrings("-c", process.args[1]);
    try std.testing.expectEqualStrings("echo hello", process.args[2]);
    try std.testing.expectEqual(@as(usize, 2), process.env.?.len);
    try std.testing.expectEqualStrings("PATH=/usr/bin:/bin", process.env.?[0]);
    try std.testing.expectEqualStrings("TERM=xterm", process.env.?[1]);
    try std.testing.expectEqualStrings("/", process.cwd);
    try std.testing.expectEqual(@as(?bool, true), process.terminal);
    try std.testing.expect(process.noNewPrivileges);
    try std.testing.expectEqual(@as(u32, 1000), process.user.uid);
    try std.testing.expectEqual(@as(u32, 1001), process.user.gid);
    try std.testing.expectEqualStrings("example", spec.hostname.?);
    try std.testing.expectEqual(@as(usize, 1), spec.mounts.?.len);
    const mount = spec.mounts.?[0];
    try std.testing.expectEqualStrings("/proc", mount.destination);
    try std.testing.expectEqualStrings("proc", mount.type.?);
    try std.testing.expectEqualStrings("proc", mount.source.?);
    try std.testing.expectEqual(@as(usize, 3), mount.options.?.len);
    try std.testing.expectEqualStrings("nosuid", mount.options.?[0]);
    try std.testing.expectEqualStrings("noexec", mount.options.?[1]);
    try std.testing.expectEqualStrings("nodev", mount.options.?[2]);
    const namespaces = spec.linux.?.namespaces.?;
    try std.testing.expectEqual(@as(usize, 3), namespaces.len);
    try std.testing.expectEqual(.pid, namespaces[0].type);
    try std.testing.expectEqual(.mount, namespaces[1].type);
    try std.testing.expectEqual(.uts, namespaces[2].type);
    try std.testing.expect(namespaces[0].path == null);
    try std.testing.expectEqualStrings("hello", spec.annotations.?.map.get("org.example.description").?);
}

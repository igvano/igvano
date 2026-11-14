const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const diagnostics = @import("../diagnostic.zig");
const checkResult = @import("../syscall.zig").checkResult;
const closeFd = @import("../syscall.zig").closeFd;
const openPath = @import("../syscall.zig").openPath;
const Write = @import("../cgroup_v2.zig").Write;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const removeCreatedCgroup = @import("../cgroup.zig").removeCreatedCgroup;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const removeCgroupChildren = @import("../cgroup.zig").removeCgroupChildren;
const removeV1Cgroup = @import("../cgroup_v1.zig").removeV1Cgroup;

test "linux cgroup creation reuses parents but rejects existing leaves" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign");
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_][]const u8{ "foreign", "parent/foreign" }) |path| {
        const result = walkCgroup(root, path, true, &.{});
        if (result) |fd| {
            if (fd) |opened| closeFd(opened);
        } else |_| {}
        try std.testing.expectError(error.CreateFailed, result);
        const existing = (try walkCgroup(root, path, false, &.{})).?;
        closeFd(existing);
    }
    const owned = (try walkCgroup(root, "parent/owned", true, &.{})).?;
    closeFd(owned);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "parent/owned", false, &.{}));
}

test "linux cgroup creation enables requested controllers and ordinary lookups leave them alone" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "parent", .default_dir);
    for ([_][]const u8{ "cgroup.controllers", "parent/cgroup.controllers" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "pids rdma misc\n" });
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const owned = (try walkCgroup(root, "parent/owned", true, &.{
        .{ .name = "pids.max", .value = "5" },
        .{ .name = "rdma.max", .value = "mlx5_0 hca_handle=1" },
        .{ .name = "misc.max", .value = "sev 1" },
        .{ .name = "cgroup.max.depth", .value = "8" },
    })).?;
    closeFd(owned);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+pids +rdma +misc ", enabled);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "sentinel" });
    }
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned/cgroup.subtree_control", .{}));
    // Lookup must not even need the controller files.
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.procs");
    const existing = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    closeFd(existing);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const unchanged = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256));
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings("sentinel", unchanged);
    }
    try tmp.dir.deleteFile(std.testing.io, "cgroup.subtree_control");
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.subtree_control");
    const without_controls = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    closeFd(without_controls);
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "missing", false, &.{}));
}

test "linux cgroup activation never follows subtree control symlinks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.controllers", .data = "pids\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "sentinel" });
    try tmp.dir.symLink(std.testing.io, "outside", "cgroup.subtree_control", .{});
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try std.testing.expectError(error.CgroupWriteFailed, walkCgroup(root, "owned", true, &.{.{ .name = "pids.max", .value = "5" }}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned", .{}));
    const unchanged = try tmp.dir.readFileAlloc(std.testing.io, "outside", std.testing.allocator, .limited(256));
    defer std.testing.allocator.free(unchanged);
    try std.testing.expectEqualStrings("sentinel", unchanged);
}

test "linux cgroup activation refuses populated non-root parents even for threaded controllers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "parent", .default_dir);
    for ([_][]const u8{ "cgroup.controllers", "parent/cgroup.controllers" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "pids cpu\n" });
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "1\n" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    for ([_]Write{ .{ .name = "pids.max", .value = "5" }, .{ .name = "cpu.weight", .value = "20" } }) |write| {
        for ([_]bool{ true, false }) |create| {
            try std.testing.expectError(error.CgroupWriteFailed, walkCgroup(root, "parent/x", create, &.{write}));
            try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "has processes") != null);
            const unchanged = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.subtree_control", std.testing.allocator, .limited(64));
            defer std.testing.allocator.free(unchanged);
            try std.testing.expectEqualStrings("", unchanged);
            const kind = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.type", std.testing.allocator, .limited(64));
            defer std.testing.allocator.free(kind);
            try std.testing.expectEqualStrings("domain\n", kind);
            try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/x", .{}));
        }
    }
    // The real hierarchy root has no cgroup.type and is exempt even when populated.
    try tmp.dir.deleteFile(std.testing.io, "parent/cgroup.type");
    const owned = (try walkCgroup(root, "parent/x", true, &.{.{ .name = "pids.max", .value = "5" }})).?;
    closeFd(owned);
    const enabled = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.subtree_control", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(enabled);
    // The requested controller, then (best effort) all available ones.
    try std.testing.expectEqualStrings("+pids +cpu", enabled);
    const procs = try tmp.dir.readFileAlloc(std.testing.io, "parent/cgroup.procs", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(procs);
    try std.testing.expectEqualStrings("1\n", procs);
}

test "linux cgroup update walk enables only ancestors without creating missing directories" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned");
    for ([_][]const u8{ "cgroup.controllers", "parent/cgroup.controllers" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "memory\n" });
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/cgroup.procs", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.type", .data = "domain\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.procs", .data = "1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "parent/owned/cgroup.subtree_control", .data = "sentinel" });
    const root = try openPath(tmp.dir.handle, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const writes: []const Write = &.{.{ .name = "memory.max", .value = "64" }};
    const owned = (try walkCgroup(root, "parent/owned", false, writes)).?;
    closeFd(owned);
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+memory ", enabled);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    }
    const leaf = try tmp.dir.readFileAlloc(std.testing.io, "parent/owned/cgroup.subtree_control", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(leaf);
    try std.testing.expectEqualStrings("sentinel", leaf);
    try std.testing.expectEqual(@as(?posix.fd_t, null), try walkCgroup(root, "parent/missing/child", false, writes));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/missing", .{}));
    for ([_][]const u8{ "cgroup.subtree_control", "parent/cgroup.subtree_control" }) |path| {
        const enabled = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64));
        defer std.testing.allocator.free(enabled);
        try std.testing.expectEqualStrings("+memory ", enabled);
    }
}

test "linux cgroup removal deletes nested children and preserves sibling cgroups" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/other");
    try tmp.dir.createDirPath(std.testing.io, "parent/foreign/keep");
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try removeCgroup(root, "parent/owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "parent/foreign/keep", .{});
    try removeCgroup(root, "parent/owned");
    try removeCgroup(root, "missing/container");
}

test "linux create cleanup preserves a replacement cgroup at the same path" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/owned");
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const original = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    defer closeFd(original);
    try tmp.dir.deleteDir(std.testing.io, "parent/owned");
    try removeCreatedCgroup(root, "parent/owned", original);

    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    try removeCreatedCgroup(root, "parent/owned", original);
    _ = try tmp.dir.statFile(std.testing.io, "parent/owned/child/grandchild", .{});

    const replacement = (try walkCgroup(root, "parent/owned", false, &.{})).?;
    defer closeFd(replacement);
    try removeCreatedCgroup(root, "parent/owned", replacement);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "parent/owned", .{}));
}

test "linux child cgroup cleanup leaves control files and symlinks untouched" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "owned/child/grandchild");
    try tmp.dir.createDirPath(std.testing.io, "outside/keep");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "owned/cgroup.events", .data = "populated 0\n" });
    try tmp.dir.symLink(std.testing.io, "../outside", "owned/escape", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    const owned = (try walkCgroup(root, "owned", false, &.{})).?;
    defer closeFd(owned);
    try removeCgroupChildren(owned, "owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned/child", .{}));
    _ = try tmp.dir.statFile(std.testing.io, "owned/cgroup.events", .{});
    _ = try tmp.dir.statFile(std.testing.io, "owned/escape", .{});
    _ = try tmp.dir.statFile(std.testing.io, "outside/keep", .{});
}

test "linux busy child cleanup reports the full descendant path" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    defer diagnostics.last_diagnostic_len = 0;
    try tmp.dir.createDirPath(std.testing.io, "parent/owned/child/grandchild");
    // Unlike cgroupfs, a regular control file keeps the directory nonempty.
    for ([_][]const u8{ "parent/owned/cgroup.procs", "parent/owned/child/cgroup.procs", "parent/owned/child/grandchild/cgroup.procs" }) |path|
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = "" });
    try std.testing.expectError(error.CgroupDeleteFailed, removeCgroup(tmp.dir.handle, "parent/owned"));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "parent/owned/child/grandchild") != null);
    const owned = (try walkCgroup(tmp.dir.handle, "parent/owned", false, &.{})).?;
    defer closeFd(owned);
    try std.testing.expectError(error.CgroupDeleteFailed, removeV1Cgroup(tmp.dir.handle, "/", "parent/owned", owned, null, null));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "parent/owned/child/grandchild") != null);
}

test "linux cleanup does not reject descendants longer than the diagnostic buffer" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "owned", .default_dir);
    var parent = try openPath(tmp.dir.handle, "owned", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(parent);
    var name_buffer: [256]u8 = @splat('x');
    name_buffer[255] = 0;
    const name = name_buffer[0..255 :0];
    for (0..20) |_| {
        try checkResult(linux.mkdirat(parent, name, 0o755));
        const child = try openPath(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        closeFd(parent);
        parent = child;
    }
    try removeCgroup(tmp.dir.handle, "owned");
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "owned", .{}));
}

test "linux cgroup-only writes do not require cgroup.controllers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "parent/leaf");
    const leaf = (try walkCgroup(tmp.dir.handle, "parent/leaf", false, &.{.{ .name = "cgroup.freeze", .value = "1" }})).?;
    defer closeFd(leaf);
}

test "linux controller buffer overflow reports a cgroup failure" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.controllers", .data = "cpu " ** 2300 });
    try std.testing.expectError(error.CgroupWriteFailed, walkCgroup(tmp.dir.handle, "leaf", false, &.{.{ .name = "cpu.max", .value = "max 100000" }}));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "8 KiB") != null);
}

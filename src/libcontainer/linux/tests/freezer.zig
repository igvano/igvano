const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const diagnostics = @import("../diagnostic.zig");
const checkResult = @import("../syscall.zig").checkResult;
const closeFd = @import("../syscall.zig").closeFd;
const openPath = @import("../syscall.zig").openPath;
const killV2Members = @import("../cgroup_v2.zig").killV2Members;
const CgroupMode = @import("../cgroup.zig").CgroupMode;
const readCgroupFile = @import("../cgroup.zig").readCgroupFile;
const killV1Members = @import("../cgroup_v1.zig").killV1Members;
const cgroupFrozen = @import("../freezer.zig").cgroupFrozen;
const waitFrozen = @import("../freezer.zig").waitFrozen;
const setCgroupFrozen = @import("../freezer.zig").setCgroupFrozen;

test "linux explicit freeze timeout cancels the request and retains its diagnostic" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    for ([_]CgroupMode{ .unified, .legacy }) |mode| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const name: [:0]const u8 = if (mode == .unified) "cgroup.freeze" else "freezer.state";
        const thawed: []const u8 = if (mode == .unified) "0" else "THAWED";
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = thawed });
        // Exhaust the polling budget immediately to exercise timeout cleanup
        // without needing an unfreezable process or a real cgroup hierarchy.
        try std.testing.expectError(error.CgroupWriteFailed, setCgroupFrozen(tmp.dir.handle, mode, true, "igvano/pause-test", 0));
        const state = try readCgroupFile(std.testing.allocator, tmp.dir.handle, name);
        defer std.testing.allocator.free(state);
        try std.testing.expectEqualStrings(thawed, state);
        const diagnostic = diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len];
        try std.testing.expect(std.mem.indexOf(u8, diagnostic, "igvano/pause-test") != null);
        try std.testing.expect(std.mem.indexOf(u8, diagnostic, "did not reach freezer state") != null);
    }
}

test "linux v2 freezer status follows the local request while completion follows events" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { request: []const u8, events: []const u8, frozen: bool, completed: bool }{
        .{ .request = "1\n", .events = "populated 1\nfrozen 0\n", .frozen = true, .completed = false },
        .{ .request = "0\n", .events = "populated 1\nfrozen 1\n", .frozen = false, .completed = true },
    }) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.freeze", .data = case.request });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = case.events });
        try std.testing.expectEqual(case.frozen, try cgroupFrozen(tmp.dir.handle, .unified));
        try std.testing.expect(try waitFrozen(tmp.dir.handle, .unified, case.completed, 1));
        try std.testing.expect(!try waitFrozen(tmp.dir.handle, .unified, case.frozen, 1));
    }
}

test "linux v2 kill all retains a pending user freeze request" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.freeze", .data = "1" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.events", .data = "populated 0\nfrozen 0\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cgroup.procs", .data = "" });
    for ([_]i32{ 0, 9, 15 }) |signal| {
        try killV2Members(tmp.dir.handle, signal, "/", "igvano/pending-pause-test");
        const state = try readCgroupFile(std.testing.allocator, tmp.dir.handle, "cgroup.freeze");
        defer std.testing.allocator.free(state);
        try std.testing.expectEqualStrings("1", state);
    }
}

test "linux v1 failed freeze retains its diagnostic and real cgroup path after thaw fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    defer diagnostics.last_diagnostic_len = 0;
    // /dev/full makes both writes fail with values named in the diagnostic.
    checkResult(linux.mknodat(tmp.dir.handle, "freezer.state", linux.S.IFCHR | 0o600, 0x107)) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    const probe = openPath(tmp.dir.handle, "freezer.state", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    closeFd(probe);
    try std.testing.expectError(error.CgroupWriteFailed, killV1Members(tmp.dir.handle, tmp.dir.handle, 9, "/", "igvano/freeze-test", null));
    const diagnostic = diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len];
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "igvano/freeze-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "FROZEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "THAWED") == null);
}

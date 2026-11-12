const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const diagnostics = @import("../diagnostic.zig");
const PreparedMount = @import("../mount.zig").PreparedMount;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const writeAll = @import("../syscall.zig").writeAll;
const readAll = @import("../syscall.zig").readAll;
const openPath = @import("../syscall.zig").openPath;
const CreateResponse = @import("../diagnostic.zig").CreateResponse;
const console = @import("../console.zig").console;
const sendMountSources = @import("../mount_sources.zig").sendMountSources;
const receiveMountSources = @import("../mount_sources.zig").receiveMountSources;

test "linux mount source helper EOF retains a specific diagnostic" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    const namespace = try openPath(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    for (0..3) |stage| {
        const sockets = try console.socketpair();
        const child = try forkProcess();
        if (child == 0) {
            closeFd(sockets[0]);
            const fd = console.receiveFd(sockets[1]) catch linux.exit_group(1);
            closeFd(fd);
            if (stage != 0) {
                // Read init's request first, as the real helper does.
                var request: [1]u8 = undefined;
                if (!readAll(sockets[1], &request)) linux.exit_group(2);
                const response: CreateResponse = .{};
                if (!writeAll(sockets[1], std.mem.asBytes(&response))) linux.exit_group(2);
            }
            if (stage == 2) {
                // Die after sending rights but before completing their payload.
                var rights: console.Rights = .{
                    .header = .{ .len = console.rights_len, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS },
                    .fd = namespace,
                };
                const data = "p";
                const iov = [_]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
                const message: linux.msghdr_const = .{
                    .name = null,
                    .namelen = 0,
                    .iov = &iov,
                    .iovlen = 1,
                    .control = &rights,
                    .controllen = @sizeOf(console.Rights),
                    .flags = 0,
                };
                checkResult(linux.sendmsg(sockets[1], &message, linux.MSG.NOSIGNAL)) catch linux.exit_group(3);
            }
            linux.exit_group(0);
        }
        closeFd(sockets[1]);
        defer closeFd(sockets[0]);
        defer _ = waitChild(child) catch {};
        var mounts = [_]PreparedMount{.{
            .destination = "/data",
            .source = "/unused",
            .type = null,
            .flags = linux.MS.BIND,
            .propagation = 0,
            .data = "",
        }};
        try std.testing.expectError(error.CreateFailed, receiveMountSources(&mounts, sockets[0], namespace));
        try std.testing.expectEqualStrings("mount source helper exited unexpectedly", diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
    }
}

test "linux mount source helper rejects directory and final symlinks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer diagnostics.last_diagnostic_len = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "source", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/item", .data = "unchanged" });
    try tmp.dir.symLink(std.testing.io, "source", "alias", .{});
    try tmp.dir.symLink(std.testing.io, "source/item", "link", .{});
    const sockets = try console.socketpair();
    defer for (sockets) |fd| closeFd(fd);
    for ([_][]const u8{ "alias/item", "link" }) |suffix| {
        const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, suffix }, 0);
        defer std.testing.allocator.free(path);
        const mounts = [_]PreparedMount{.{
            .destination = "/data",
            .source = path,
            .type = null,
            .flags = linux.MS.BIND,
            .propagation = 0,
            .data = "",
        }};
        diagnostics.last_diagnostic_len = 0;
        // Each source waits for init's request byte.
        try std.testing.expect(writeAll(sockets[1], &.{1}));
        try std.testing.expectError(error.CreateFailed, sendMountSources(&mounts, sockets[0], false));
        const diagnostic = try std.fmt.allocPrint(std.testing.allocator, "bind source {s} contains a symlink; symlinks are not allowed when joining a mount namespace", .{path});
        defer std.testing.allocator.free(diagnostic);
        try std.testing.expectEqualStrings(diagnostic, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len]);
        // Ordinary sources opened by the runtime still follow symlinks.
        const ordinary = try openPath(linux.AT.FDCWD, path, .{ .PATH = true, .CLOEXEC = true });
        closeFd(ordinary);
        // So does the helper in init's own private mount namespace.
        try std.testing.expect(writeAll(sockets[1], &.{1}));
        try sendMountSources(&mounts, sockets[0], true);
        var response: CreateResponse = .{};
        try std.testing.expect(readAll(sockets[1], std.mem.asBytes(&response)));
        try std.testing.expect(response.failureError() == null);
        closeFd(try console.receiveFd(sockets[1]));
    }
}

test "linux mount source helper opens each source only when init asks" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/late", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(path);
    const sockets = try console.socketpair();
    defer closeFd(sockets[0]);
    var peer_open = true;
    defer if (peer_open) closeFd(sockets[1]);
    const mounts = [_]PreparedMount{.{ .destination = "/data", .source = path, .type = null, .flags = linux.MS.BIND, .propagation = 0, .data = "" }};
    // The source appears only after the helper started, like a source made by an earlier mount.
    try tmp.dir.createDir(std.testing.io, "late", .default_dir);
    try std.testing.expect(writeAll(sockets[1], &.{1}));
    try sendMountSources(&mounts, sockets[0], true);
    var response: CreateResponse = .{};
    try std.testing.expect(readAll(sockets[1], std.mem.asBytes(&response)));
    closeFd(try console.receiveFd(sockets[1]));
    // Without a request (init stopped), the helper returns without opening anything.
    closeFd(sockets[1]);
    peer_open = false;
    try sendMountSources(&mounts, sockets[0], true);
}

const std = @import("std");
const builtin = @import("builtin");
const libcontainer = @import("libcontainer");

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2) {
        std.debug.print("usage: libcontainer-consumer <rootfs>\n", .{});
        return 1;
    }
    const rootfs = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[1], allocator);
    const id = if (comptime builtin.os.tag == .linux)
        try std.fmt.allocPrint(allocator, "igvano-consumer-{d}", .{std.os.linux.getpid()})
    else
        "igvano-consumer";
    const directory = try std.fmt.allocPrintSentinel(allocator, "/tmp/{s}", .{id}, 0);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{directory}, 0);
    try prepareFifo(init.io, directory, fifo);
    defer if (comptime builtin.os.tag == .linux) {
        std.Io.Dir.cwd().deleteFile(init.io, fifo) catch {};
        std.Io.Dir.cwd().deleteDir(init.io, directory) catch {};
    };

    const process: libcontainer.Process = .{ .args = &.{"/bin/sh"}, .cwd = "/", .uid = 0, .gid = 0 };
    const options: libcontainer.CreateOptions = .{
        .allocator = allocator,
        .id = id,
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .process = process,
        .namespaces = &.{ .{ .kind = .mount }, .{ .kind = .pid } },
        .cgroup_path = id,
    };
    var instance = libcontainer.linux.Container.create(options) catch |err| {
        std.debug.print("create: {s}\n", .{libcontainer.linux.diagnostic() orelse @errorName(err)});
        return 1;
    };
    defer instance.deinit(allocator);
    const container = instance.container();
    defer container.delete() catch |err| {
        std.debug.print("delete: {s}\n", .{libcontainer.linux.diagnostic() orelse @errorName(err)});
    };
    defer container.kill(@intFromEnum(std.os.linux.SIG.KILL)) catch |err| {
        std.debug.print("kill: {s}\n", .{libcontainer.linux.diagnostic() orelse @errorName(err)});
    };
    std.debug.print("PID: {d}\n", .{instance.state.pid});
    return 0;
}

fn prepareFifo(io: std.Io, directory: [:0]const u8, fifo: [:0]const u8) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    if (linux.errno(linux.mkdir(directory, 0o700)) != .SUCCESS)
        return error.CreateDirectoryFailed;
    errdefer std.Io.Dir.cwd().deleteDir(io, directory) catch {};
    if (linux.errno(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.CreateFifoFailed;
}

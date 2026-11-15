const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const attached = @import("../attached.zig");
const Config = @import("args.zig").Config;
const ContainerOverride = @import("state.zig").ContainerOverride;
const createContainerFor = @import("create.zig").createContainerFor;
const startContainer = @import("start.zig").startContainer;
const diagnostics = @import("diagnostic.zig");
const deleteContainer = @import("delete.zig").deleteContainer;
const reserveStdio = @import("exec.zig").reserveStdio;
const enableExecSubreaper = @import("exec.zig").enableExecSubreaper;
const restoreExecSubreaper = @import("exec.zig").restoreExecSubreaper;
const notify = @import("notify.zig");

/// runc run: create and start. With --detach it returns after start, like
/// create + start. Otherwise it adopts the init as a subreaper, forwards
/// signals and stdio (or a local PTY), returns the init's exit status, and
/// deletes the container unless --keep.
pub fn runContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !u8 {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    if (config.detach) {
        _ = try createContainerFor(allocator, io, injected, config, null);
        errdefer if (!config.keep) removeContainer(allocator, io, injected, config, true);
        try startContainer(allocator, io, injected, config);
        return 0;
    }
    const linux = std.os.linux;
    // runc refuses a console socket unless it detaches; the foreground PTY is local.
    if (config.console_socket != null)
        return oci.validationError(error.UnexpectedConsoleSocket, "--console-socket: requires --detach", .{});
    try reserveStdio();
    const was_subreaper = try enableExecSubreaper();
    defer restoreExecSubreaper(was_subreaper);
    var signals = try attached.Signals.init();
    defer signals.deinit();
    var controller: ?std.posix.fd_t = null;
    defer if (controller) |fd| {
        _ = linux.close(fd);
    };
    const pid = try createContainerFor(allocator, io, injected, config, &controller);
    // Before start: output written earlier would already carry "\r\n".
    if (controller) |fd| attached.clearOnlcr(fd, 1);
    var reaped = false;
    errdefer {
        if (!reaped) {
            _ = linux.kill(pid, .KILL);
            var status: u32 = undefined;
            while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
        }
        // Like runc, --keep keeps the state even when run fails after create.
        if (!config.keep) removeContainer(allocator, io, injected, config, true);
    }
    // runc relays READY= with its own PID as MAINPID while it stays attached.
    var relay = if (config.notify_socket) |host| try notify.Relay.bind(config.root, config.id, host) else null;
    errdefer if (relay) |value| value.deinit();
    try startContainer(allocator, io, injected, config);
    // The thread owns the socket from here and closes it once init is gone.
    if (relay) |value| {
        (try std.Thread.spawn(.{}, relayReady, .{ value, pid })).detach();
        relay = null;
    }
    const status = try attached.wait(pid, &reaped, &signals, controller, 0, 1);
    if (!config.keep) removeContainer(allocator, io, injected, config, false);
    return status;
}

fn relayReady(relay: notify.Relay, pid: i32) void {
    defer relay.deinit();
    relay.run(pid, std.os.linux.getpid()) catch |err|
        std.debug.print("igvano: warning: cannot relay sd_notify READY: {s}\n", .{@errorName(err)});
}

fn removeContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, force: bool) void {
    // Keep the failure's detail for the error report.
    const saved: diagnostics.SavedDetail = .save();
    defer saved.restore();
    var delete = config;
    delete.subcommand = .delete;
    delete.force = force;
    deleteContainer(allocator, io, injected, delete) catch |err|
        std.debug.print("igvano: warning: cannot delete container '{s}' after run: {s}\n", .{ config.id, @errorName(err) });
}

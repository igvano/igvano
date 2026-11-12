const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const attached = @import("../attached.zig");
const Config = @import("args.zig").Config;
const ContainerOverride = @import("state.zig").ContainerOverride;
const createContainerFor = @import("create.zig").createContainerFor;
const startContainer = @import("start.zig").startContainer;
const deleteContainer = @import("delete.zig").deleteContainer;
const reserveStdio = @import("exec.zig").reserveStdio;
const enableExecSubreaper = @import("exec.zig").enableExecSubreaper;
const restoreExecSubreaper = @import("exec.zig").restoreExecSubreaper;

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
    try startContainer(allocator, io, injected, config);
    const status = try attached.wait(pid, &reaped, &signals, controller, 0, 1);
    if (!config.keep) removeContainer(allocator, io, injected, config, false);
    return status;
}

fn removeContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config, force: bool) void {
    var delete = config;
    delete.subcommand = .delete;
    delete.force = force;
    deleteContainer(allocator, io, injected, delete) catch |err|
        std.debug.print("igvano: warning: cannot delete container '{s}' after run: {s}\n", .{ config.id, @errorName(err) });
}

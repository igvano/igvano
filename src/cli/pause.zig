const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("state.zig").ContainerInstance;
const containerResult = @import("diagnostic.zig").containerResult;
const ContainerOverride = @import("state.zig").ContainerOverride;
const bindContainer = @import("state.zig").bindContainer;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const readLiveState = @import("state.zig").readLiveState;

pub fn pauseContainer(allocator: std.mem.Allocator, io: std.Io, injected: ?ContainerOverride, config: Config) !void {
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const locked = if (lock) |file| try lockContainer(file, false) else true;
    if (locked) {
        if (lock) |file| try requireLinkedLock(io, file);
    } else {
        std.debug.print("igvano: warning: container '{s}' is busy; changing freezer state without the lock\n", .{config.id});
    }
    const state = try readLiveState(allocator, io, injected, config, locked);
    defer state.deinit();
    var instance: ContainerInstance = undefined;
    const container = if (state.container_state) |value| bindContainer(&instance, injected, value) else null;
    if (config.subcommand == .pause) {
        try oci.requirePause(state.parsed.value.status);
        try containerResult(container.?, container.?.freeze());
    } else {
        try oci.requireResume(state.parsed.value.status);
        try containerResult(container.?, container.?.thaw());
    }
}

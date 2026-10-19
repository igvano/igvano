const std = @import("std");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const backendResult = @import("diagnostic.zig").backendResult;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const readLiveState = @import("state.zig").readLiveState;

pub fn pauseContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const locked = if (lock) |file| try lockContainer(file, false) else true;
    if (locked) {
        if (lock) |file| try requireLinkedLock(io, file);
    } else {
        std.debug.print("igvano: warning: container '{s}' is busy; changing freezer state without the lock\n", .{config.id});
    }
    const state = try readLiveState(allocator, io, backend, config, locked);
    defer state.deinit();
    if (config.subcommand == .pause) {
        try oci.requirePause(state.parsed.value.status);
        try backendResult(backend, backend.freeze(state.handle.?));
    } else {
        try oci.requireResume(state.parsed.value.status);
        try backendResult(backend, backend.thaw(state.handle.?));
    }
}

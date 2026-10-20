const std = @import("std");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Backend = libcontainer.Backend;
const Config = @import("args.zig").Config;
const openContainerLock = @import("state.zig").openContainerLock;
const lockContainer = @import("state.zig").lockContainer;
const requireLinkedLock = @import("state.zig").requireLinkedLock;
const readLiveState = @import("state.zig").readLiveState;

pub fn stateContainer(allocator: std.mem.Allocator, io: std.Io, backend: Backend, config: Config) !void {
    const lock = try openContainerLock(allocator, config, false);
    defer if (lock) |file| file.close(io);
    const persist_recovery = if (lock) |file| try lockContainer(file, false) else true;
    if (persist_recovery) {
        if (lock) |file| try requireLinkedLock(io, file);
    }
    const state = try readLiveState(allocator, io, backend, config, persist_recovery);
    defer state.deinit();
    const json = try oci.stateJson(allocator, state.parsed.value);
    defer allocator.free(json);
    try std.Io.File.stdout().writeStreamingAll(io, json);
}

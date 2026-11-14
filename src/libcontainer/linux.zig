const std = @import("std");
const libcontainer = @import("root.zig");

pub const console = @import("linux/console.zig").console;
pub const apparmorEnabled = @import("linux/procfs.zig").apparmorEnabled;
pub const systemdCgroupMatches = @import("linux/systemd.zig").systemdCgroupMatches;

/// Borrowed thread-local failure detail; copy immediately before another operation.
pub fn diagnostic() ?[]const u8 {
    return @import("linux/diagnostic.zig").diagnostic();
}

pub const Container = struct {
    state: libcontainer.State,
    owned: bool = false,

    /// Creates an instance owning state.starttime; all other state fields borrow options.
    /// Call deinit with options.allocator when the instance is no longer needed.
    pub fn create(options: libcontainer.CreateOptions) libcontainer.Error!Container {
        return .{ .state = try @import("linux/create.zig").create(options), .owned = true };
    }

    /// Borrows state; deinit is a no-op on loaded instances.
    pub fn load(state: libcontainer.State) Container {
        return .{ .state = state };
    }

    /// Takes ownership of state.starttime; all other fields remain borrowed.
    /// Call deinit with the allocator that allocated starttime.
    pub fn adopt(state: libcontainer.State) Container {
        return .{ .state = state, .owned = true };
    }

    /// Frees starttime owned by created or adopted instances, using the same allocator.
    /// Does nothing for loaded instances.
    pub fn deinit(self: *Container, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.state.starttime);
    }

    /// Borrows this instance as an interface; keep it alive at a stable address.
    pub fn container(self: *Container) libcontainer.Container {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: libcontainer.Container.VTable = .{
        .exec = exec,
        .alive = alive,
        .kill = kill,
        .killAll = killAll,
        .update = update,
        .pids = pids,
        .stats = stats,
        .freeze = freeze,
        .thaw = thaw,
        .frozen = frozen,
        .delete = delete,
        .diagnostic = containerDiagnostic,
    };

    fn exec(ptr: *anyopaque, options: libcontainer.ExecOptions) libcontainer.Error!i32 {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/exec.zig").exec(self.state, options);
    }

    fn alive(ptr: *anyopaque) libcontainer.Error!bool {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/proc.zig").alive(self.state);
    }

    fn kill(ptr: *anyopaque, signal: i32) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/proc.zig").kill(self.state, signal);
    }

    fn killAll(ptr: *anyopaque, signal: i32) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").killAll(self.state, signal);
    }

    fn update(ptr: *anyopaque, resources: libcontainer.Resources) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").update(self.state, resources);
    }

    fn pids(ptr: *anyopaque, allocator: std.mem.Allocator) libcontainer.Error![]i32 {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").pids(self.state, allocator);
    }

    fn stats(ptr: *anyopaque, allocator: std.mem.Allocator) libcontainer.Error!libcontainer.Stats {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/stats.zig").stats(self.state, allocator);
    }

    fn freeze(ptr: *anyopaque) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").freeze(self.state);
    }

    fn thaw(ptr: *anyopaque) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").thaw(self.state);
    }

    fn frozen(ptr: *anyopaque) libcontainer.Error!bool {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").frozen(self.state);
    }

    fn delete(ptr: *anyopaque) libcontainer.Error!void {
        const self: *Container = @ptrCast(@alignCast(ptr));
        return @import("linux/cgroup_ops.zig").delete(self.state);
    }

    fn containerDiagnostic(_: *anyopaque) ?[]const u8 {
        return diagnostic();
    }
};

test {
    _ = @import("devicefilter.zig");
    _ = @import("devices.zig");
    _ = @import("linux/netdev.zig");
    _ = @import("dbus.zig");
    _ = @import("linux/cgroup.zig");
    _ = @import("linux/cgroup_ops.zig");
    _ = @import("linux/cgroup_v1.zig");
    _ = @import("linux/cgroup_v2.zig");
    _ = @import("linux/console.zig");
    _ = @import("linux/copyup.zig");
    _ = @import("linux/create.zig");
    _ = @import("linux/device_nodes.zig");
    _ = @import("linux/devices.zig");
    _ = @import("linux/diagnostic.zig");
    _ = @import("linux/exec.zig");
    _ = @import("linux/stats.zig");
    _ = @import("linux/freezer.zig");
    _ = @import("linux/mount.zig");
    _ = @import("linux/mount_sources.zig");
    _ = @import("linux/mountinfo.zig");
    _ = @import("linux/namespaces.zig");
    _ = @import("linux/proc.zig");
    _ = @import("linux/process.zig");
    _ = @import("linux/procfs.zig");
    _ = @import("linux/rootfs.zig");
    _ = @import("linux/syscall.zig");
    _ = @import("linux/systemd.zig");
    _ = @import("linux/tests/cgroups_v1.zig");
    _ = @import("linux/tests/cgroups_v2.zig");
    _ = @import("linux/tests/console.zig");
    _ = @import("linux/tests/devices.zig");
    _ = @import("linux/tests/diagnostic.zig");
    _ = @import("linux/tests/freezer.zig");
    _ = @import("linux/tests/helpers.zig");
    _ = @import("linux/tests/idmapped_mounts.zig");
    _ = @import("linux/tests/inherited_mounts.zig");
    _ = @import("linux/tests/lifecycle.zig");
    _ = @import("linux/tests/mount_sources.zig");
    _ = @import("linux/tests/mounts.zig");
    _ = @import("linux/tests/namespaces.zig");
    _ = @import("linux/tests/process.zig");
    _ = @import("linux/tests/procfs.zig");
    _ = @import("linux/tests/rootfs.zig");
    _ = @import("linux/tests/signaling.zig");
}

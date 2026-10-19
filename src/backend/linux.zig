const std = @import("std");
const Backend = @import("../backend.zig").Backend;
const Resources = Backend.Resources;

pub const reportDiagnostic = @import("linux/diagnostic.zig").reportDiagnostic;
pub const lockedMountFlags = @import("linux/mount.zig").lockedMountFlags;
pub const cgroupMountType = @import("linux/mount.zig").cgroupMountType;
pub const namespaceFlags = @import("linux/namespaces.zig").namespaceFlags;
pub const closeExecFrom = @import("linux/process.zig").closeExecFrom;
pub const console = @import("linux/console.zig").console;
pub const apparmorEnabled = @import("linux/procfs.zig").apparmorEnabled;
pub const systemdCgroupMatches = @import("linux/systemd.zig").systemdCgroupMatches;

pub const LinuxBackend = struct {
    pub fn backend(self: *LinuxBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .create = create,
        .exec = exec,
        .alive = alive,
        .kill = kill,
        .killAll = killAll,
        .update = update,
        .pids = pids,
        .freeze = freeze,
        .thaw = thaw,
        .frozen = frozen,
        .delete = delete,
        .diagnostic = diagnostic,
    };

    fn diagnostic(ptr: *anyopaque) ?[]const u8 {
        return @import("linux/diagnostic.zig").diagnostic(ptr);
    }

    fn exec(ptr: *anyopaque, handle: Backend.Handle, options: Backend.ExecOptions) Backend.Error!i32 {
        return @import("linux/exec.zig").exec(ptr, handle, options);
    }

    fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
        return @import("linux/create.zig").create(ptr, options);
    }

    fn alive(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        return @import("linux/proc.zig").alive(ptr, handle);
    }

    fn kill(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        return @import("linux/proc.zig").kill(ptr, handle, signal);
    }

    fn killAll(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
        return @import("linux/cgroup_ops.zig").killAll(ptr, handle, signal);
    }

    fn update(ptr: *anyopaque, handle: Backend.Handle, resources: Resources) Backend.Error!void {
        return @import("linux/cgroup_ops.zig").update(ptr, handle, resources);
    }

    fn pids(ptr: *anyopaque, handle: Backend.Handle, allocator: std.mem.Allocator) Backend.Error![]i32 {
        return @import("linux/cgroup_ops.zig").pids(ptr, handle, allocator);
    }

    fn freeze(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        return @import("linux/cgroup_ops.zig").freeze(ptr, handle);
    }

    fn thaw(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        return @import("linux/cgroup_ops.zig").thaw(ptr, handle);
    }

    fn frozen(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
        return @import("linux/cgroup_ops.zig").frozen(ptr, handle);
    }

    fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
        return @import("linux/cgroup_ops.zig").delete(ptr, handle);
    }
};

test {
    _ = @import("devicefilter.zig");
    _ = @import("devices.zig");
    _ = @import("dbus.zig");
    _ = @import("linux/cgroup.zig");
    _ = @import("linux/cgroup_ops.zig");
    _ = @import("linux/cgroup_v1.zig");
    _ = @import("linux/cgroup_v2.zig");
    _ = @import("linux/console.zig");
    _ = @import("linux/create.zig");
    _ = @import("linux/device_nodes.zig");
    _ = @import("linux/devices.zig");
    _ = @import("linux/diagnostic.zig");
    _ = @import("linux/exec.zig");
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

const Backend = @import("root.zig").Backend;

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
        .create = @import("linux/create.zig").create,
        .exec = @import("linux/exec.zig").exec,
        .alive = @import("linux/proc.zig").alive,
        .kill = @import("linux/proc.zig").kill,
        .killAll = @import("linux/cgroup_ops.zig").killAll,
        .update = @import("linux/cgroup_ops.zig").update,
        .pids = @import("linux/cgroup_ops.zig").pids,
        .freeze = @import("linux/cgroup_ops.zig").freeze,
        .thaw = @import("linux/cgroup_ops.zig").thaw,
        .frozen = @import("linux/cgroup_ops.zig").frozen,
        .delete = @import("linux/cgroup_ops.zig").delete,
        .diagnostic = @import("linux/diagnostic.zig").diagnostic,
    };
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

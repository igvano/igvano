const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const Resources = Backend.Resources;
const diagnostics = @import("diagnostic.zig");
const v2DeviceRules = @import("devices.zig").v2DeviceRules;
const applyV2DeviceFilter = @import("devices.zig").applyV2DeviceFilter;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;
const v2Writes = @import("cgroup_v2.zig").v2Writes;
const freeWrites = @import("cgroup_v2.zig").freeWrites;
const v2IgnoredFields = @import("cgroup_v2.zig").v2IgnoredFields;
const v2MountRoot = @import("cgroup_v2.zig").v2MountRoot;
const killV2Members = @import("cgroup_v2.zig").killV2Members;
const walkCgroup = @import("cgroup_v2.zig").walkCgroup;
const validateCgroupPath = @import("cgroup.zig").validateCgroupPath;
const openCgroupRoot = @import("cgroup.zig").openCgroupRoot;
const readCgroupFile = @import("cgroup.zig").readCgroupFile;
const collectCgroupPids = @import("cgroup.zig").collectCgroupPids;
const writeCgroupFile = @import("cgroup.zig").writeCgroupFile;
const cgroupPopulated = @import("cgroup.zig").cgroupPopulated;
const removeCgroup = @import("cgroup.zig").removeCgroup;
const freeV1Writes = @import("cgroup_v1.zig").freeV1Writes;
const v1Writes = @import("cgroup_v1.zig").v1Writes;
const freeV1Hierarchies = @import("cgroup_v1.zig").freeV1Hierarchies;
const openV1Hierarchies = @import("cgroup_v1.zig").openV1Hierarchies;
const walkV1Cgroup = @import("cgroup_v1.zig").walkV1Cgroup;
const applyV1Writes = @import("cgroup_v1.zig").applyV1Writes;
const killV1Members = @import("cgroup_v1.zig").killV1Members;
const removeV1Cgroups = @import("cgroup_v1.zig").removeV1Cgroups;
const readMountinfo = @import("mountinfo.zig").readMountinfo;
const bootId = @import("rootfs.zig").bootId;
const detachRootfs = @import("rootfs.zig").detachRootfs;
const openFreezerCgroup = @import("freezer.zig").openFreezerCgroup;
const cgroupFrozen = @import("freezer.zig").cgroupFrozen;
const setFrozen = @import("freezer.zig").setFrozen;
const alive = @import("proc.zig").alive;
const kill = @import("proc.zig").kill;
const setSystemdResources = @import("systemd.zig").setSystemdResources;
const stopSystemdScope = @import("systemd.zig").stopSystemdScope;

pub fn killAll(ptr: *anyopaque, handle: Backend.Handle, signal: i32) Backend.Error!void {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        if (signal < 0 or signal >= linux.NSIG) return error.KillFailed;
        const path = handle.cgroup_path orelse {
            kill(ptr, handle, signal) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => return err,
            };
            return;
        };
        try validateCgroupPath(path);
        const allocator = std.heap.page_allocator;
        const root = try openCgroupRoot();
        defer closeFd(root.fd);
        if (root.mode == .legacy) {
            const hierarchies = try openV1Hierarchies(allocator, handle.systemd);
            defer freeV1Hierarchies(allocator, hierarchies);
            var members: ?posix.fd_t = null;
            var member_controller: ?[]const u8 = null;
            var member_mount_root: []const u8 = "/";
            var freezer: ?posix.fd_t = null;
            for (hierarchies) |*hierarchy| {
                hierarchy.leaf = try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false);
                if (hierarchy.leaf) |fd| {
                    if (members == null) {
                        members = fd;
                        member_controller = hierarchy.controllers[0];
                        member_mount_root = hierarchy.mount_root;
                    }
                    if (hierarchy.has("freezer")) {
                        freezer = fd;
                        members = fd;
                        member_controller = "freezer";
                        member_mount_root = hierarchy.mount_root;
                    }
                }
            }
            if (members) |fd| try killV1Members(fd, freezer, signal, member_mount_root, path, member_controller);
            return;
        }
        const cgroup = (try walkCgroup(root.fd, path, false, &.{})) orelse return;
        defer closeFd(cgroup);
        if (signal == @intFromEnum(linux.SIG.KILL)) {
            while (true) {
                const opened = linux.openat(cgroup, "cgroup.kill", .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
                switch (linux.errno(opened)) {
                    .SUCCESS => {
                        closeFd(@intCast(opened));
                        try writeCgroupFile(cgroup, "cgroup.kill", "1", path);
                        return;
                    },
                    .NOENT => break,
                    .INTR => continue,
                    else => try checkResult(opened),
                }
            }
        }
        const mountinfo = readMountinfo(allocator) catch |err| {
            if (err == error.OutOfMemory) return err;
            reportDiagnostic("cannot kill all members of cgroup '{s}': cannot read /proc/self/mountinfo: {s}", .{ path, @errorName(err) });
            return error.KillFailed;
        };
        defer allocator.free(mountinfo);
        const mount_root = v2MountRoot(allocator, mountinfo) catch |err| {
            if (err == error.OutOfMemory) return err;
            reportDiagnostic("cannot kill all members of cgroup '{s}': cannot determine cgroup v2 mount root from /proc/self/mountinfo: {s}", .{ path, @errorName(err) });
            return error.KillFailed;
        };
        defer allocator.free(mount_root);
        try killV2Members(cgroup, signal, mount_root, path);
    } else {
        return error.NotImplemented;
    }
}

pub fn update(_: *anyopaque, handle: Backend.Handle, resources: Resources) Backend.Error!void {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const path = handle.cgroup_path orelse {
        reportDiagnostic("container '{s}' has no cgroup to update", .{handle.id});
        return error.Unsupported;
    };
    try validateCgroupPath(path);
    const allocator = std.heap.page_allocator;
    const root = try openCgroupRoot();
    defer closeFd(root.fd);
    if (root.mode == .legacy) {
        if (resources.unified.len != 0) {
            reportDiagnostic("unified resources require cgroup v2", .{});
            return error.InvalidConfig;
        }
        const writes = try v1Writes(allocator, resources);
        defer freeV1Writes(allocator, writes);
        const hierarchies = try openV1Hierarchies(allocator, handle.systemd);
        defer freeV1Hierarchies(allocator, hierarchies);
        for (hierarchies) |*hierarchy|
            hierarchy.leaf = (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false)) orelse return error.ProcessNotFound;
        var requested = resources;
        var device_rules: []const Resources.DeviceRule = &.{};
        defer allocator.free(device_rules);
        if (handle.systemd and resources.devices.len != 0) {
            device_rules = try v2DeviceRules(allocator, resources.devices, handle.device_nodes);
        }
        if (handle.systemd) if (requested.cpu) |cpu| {
            if ((cpu.quota != null or cpu.period != null) and (cpu.quota == null or cpu.period == null)) {
                for (hierarchies) |hierarchy| {
                    if (!hierarchy.has("cpu")) continue;
                    if (cpu.quota == null) {
                        const value = try readCgroupFile(allocator, hierarchy.leaf.?, "cpu.cfs_quota_us");
                        defer allocator.free(value);
                        requested.cpu.?.quota = std.fmt.parseInt(i64, std.mem.trim(u8, value, " \t\n"), 10) catch return error.CgroupWriteFailed;
                    }
                    if (cpu.period == null) {
                        const value = try readCgroupFile(allocator, hierarchy.leaf.?, "cpu.cfs_period_us");
                        defer allocator.free(value);
                        requested.cpu.?.period = std.fmt.parseInt(u64, std.mem.trim(u8, value, " \t\n"), 10) catch return error.CgroupWriteFailed;
                    }
                    break;
                }
            }
        };
        try setSystemdResources(allocator, handle, requested, .legacy, false, device_rules);
        try applyV1Writes(allocator, hierarchies, writes, resources, if (resources.devices.len != 0) handle.device_nodes else null, path, false);
    } else {
        var requested = resources;
        var inferred_memory_limit = false;
        if (requested.memory) |memory| {
            if (memory.limit == null and (memory.swap orelse 0) > 0) {
                const existing = (try walkCgroup(root.fd, path, false, &.{.{ .name = "memory.max", .value = "" }})) orelse return error.ProcessNotFound;
                defer closeFd(existing);
                const current = try readCgroupFile(allocator, existing, "memory.max");
                defer allocator.free(current);
                const value = std.mem.trim(u8, current, " \t\n");
                requested.memory.?.limit = if (std.mem.eql(u8, value, "max"))
                    -1
                else
                    std.fmt.parseInt(i64, value, 10) catch return error.CgroupWriteFailed;
                inferred_memory_limit = true;
            }
        }
        var writes = try v2Writes(allocator, requested);
        defer freeWrites(allocator, writes);
        const ignored_fields = try v2IgnoredFields(allocator, resources);
        defer allocator.free(ignored_fields);
        if (ignored_fields.len != 0)
            std.debug.print("igvano: warning: cgroup v2 has no equivalent for: {s}; ignoring\n", .{ignored_fields});
        const cgroup = (try walkCgroup(root.fd, path, false, writes)) orelse return error.ProcessNotFound;
        defer closeFd(cgroup);
        if (requested.cpu) |cpu| {
            if ((cpu.quota != null or cpu.period != null) and (cpu.quota == null or cpu.period == null)) {
                // cpu.max combines two fields; preserve the omitted half.
                const current = try readCgroupFile(allocator, cgroup, "cpu.max");
                defer allocator.free(current);
                var fields = std.mem.tokenizeAny(u8, current, " \t\n");
                const quota = fields.next() orelse return error.CgroupWriteFailed;
                const period = fields.next() orelse return error.CgroupWriteFailed;
                if (cpu.quota == null) requested.cpu.?.quota = if (std.mem.eql(u8, quota, "max"))
                    -1
                else
                    std.fmt.parseInt(i64, quota, 10) catch return error.CgroupWriteFailed;
                if (cpu.period == null)
                    requested.cpu.?.period = std.fmt.parseInt(u64, period, 10) catch return error.CgroupWriteFailed;
                const completed = try v2Writes(allocator, requested);
                freeWrites(allocator, writes);
                writes = completed;
            }
        }
        var omit_inferred_memory_limit = inferred_memory_limit;
        for (resources.unified) |entry| {
            if (std.mem.eql(u8, entry.key, "memory.max")) {
                omit_inferred_memory_limit = false;
                break;
            }
        }
        try setSystemdResources(allocator, handle, requested, .unified, omit_inferred_memory_limit, &.{});
        for (writes) |write| {
            // The current limit was needed only to convert total swap.
            if (inferred_memory_limit and std.mem.eql(u8, write.name, "memory.max")) {
                inferred_memory_limit = false;
                continue;
            }
            try writeCgroupFile(cgroup, write.name, write.value, path);
        }
        if (resources.devices.len != 0) {
            const rules = try v2DeviceRules(allocator, resources.devices, handle.device_nodes);
            defer allocator.free(rules);
            try applyV2DeviceFilter(allocator, cgroup, rules, path, true);
        }
    }
}

pub fn pids(ptr: *anyopaque, handle: Backend.Handle, allocator: std.mem.Allocator) Backend.Error![]i32 {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const path = handle.cgroup_path orelse {
        return allocator.dupe(i32, if (try alive(ptr, handle)) &.{handle.pid} else &.{});
    };
    try validateCgroupPath(path);
    var result: std.ArrayList(i32) = .empty;
    errdefer result.deinit(allocator);
    const root = try openCgroupRoot();
    defer closeFd(root.fd);
    const members = if (root.mode == .legacy) members: {
        const hierarchies = try openV1Hierarchies(allocator, handle.systemd);
        defer freeV1Hierarchies(allocator, hierarchies);
        for ([_]?[]const u8{ "freezer", "pids", null }) |controller| {
            for (hierarchies) |hierarchy| {
                if (controller) |name| {
                    if (!hierarchy.has(name)) continue;
                }
                if (try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false)) |fd|
                    break :members fd;
            }
        }
        break :members null;
    } else try walkCgroup(root.fd, path, false, &.{});
    if (members) |fd| {
        defer closeFd(fd);
        try collectCgroupPids(allocator, fd, &result);
    }
    return result.toOwnedSlice(allocator);
}

pub fn freeze(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
    return setFrozen(handle, true);
}

pub fn thaw(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
    return setFrozen(handle, false);
}

pub fn frozen(_: *anyopaque, handle: Backend.Handle) Backend.Error!bool {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const cgroup = (try openFreezerCgroup(handle)) orelse return false;
    defer closeFd(cgroup.fd);
    return cgroupFrozen(cgroup.fd, cgroup.mode);
}

pub fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
    diagnostics.last_diagnostic_len = 0;
    if (comptime builtin.os.tag == .linux) {
        if (handle.cgroup_path) |path| cgroup_cleanup: {
            try validateCgroupPath(path);
            if (handle.systemd) {
                // Namespace init ignores the scope's default SIGTERM. Drain
                // members first, as fs deletion does, so StopUnit completes
                // within the job deadline even when descendants remain.
                try killAll(ptr, handle, @intFromEnum(linux.SIG.KILL));
                try stopSystemdScope(std.heap.page_allocator, std.fs.path.basename(path));
            }
            const root = try openCgroupRoot();
            defer closeFd(root.fd);
            if (root.mode == .legacy) {
                const allocator = std.heap.page_allocator;
                const hierarchies = try openV1Hierarchies(allocator, handle.systemd or handle.systemd_cleanup);
                defer freeV1Hierarchies(allocator, hierarchies);
                for (hierarchies) |*hierarchy| {
                    hierarchy.leaf = try walkV1Cgroup(allocator, hierarchy.root.?, hierarchy.mount_root, path, false, false);
                }
                try removeV1Cgroups(hierarchies, path);
                break :cgroup_cleanup;
            }
            const cgroup = (try walkCgroup(root.fd, path, false, &.{})) orelse break :cgroup_cleanup;
            defer closeFd(cgroup);
            // kill targets init only. delete terminates any remaining descendants.
            if (try cgroupPopulated(cgroup))
                try writeCgroupFile(cgroup, "cgroup.kill", "1", path);
            try removeCgroup(root.fd, path);
        }
        // Cgroup removal waits for all members to exit before mounts detach.
        if (handle.rootfs_mount) |path| {
            // Old state has no ownership identity, so preserve its mounts.
            if (handle.rootfs_mount_id) |id| {
                const created_boot = handle.rootfs_mount_boot_id orelse return;
                const current_boot = try bootId();
                if (std.mem.eql(u8, &created_boot, &current_boot))
                    try detachRootfs(path, .{ .created = id });
            }
        }
    } else {
        return error.NotImplemented;
    }
}

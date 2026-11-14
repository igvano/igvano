const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const mountDestination = @import("mount.zig").mountDestination;
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const fdPath = @import("syscall.zig").fdPath;
const RootfsStep = @import("rootfs.zig").RootfsStep;

pub const PreparedDevice = struct {
    path: [:0]const u8,
    mode: u32,
    dev: u32,
    uid: u32 = 0,
    gid: u32 = 0,
};

pub fn validateDeviceNode(fd: posix.fd_t, device: PreparedDevice) libcontainer.Error!void {
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (!stat.mask.TYPE) return error.CreateFailed;
    const kind = device.mode & linux.S.IFMT;
    if (stat.mode & linux.S.IFMT != kind) return error.InvalidPath;
    if (kind == linux.S.IFCHR or kind == linux.S.IFBLK) {
        // Decode the Linux device number passed to mknodat.
        const major = (device.dev >> 8) & 0xfff;
        const minor = (device.dev & 0xff) | ((device.dev >> 12) & 0xfff00);
        if (stat.rdev_major != major or stat.rdev_minor != minor) return error.InvalidPath;
    }
}

pub fn createDevice(root_fd: posix.fd_t, device: PreparedDevice, private_mount_namespace: bool, step: *RootfsStep) libcontainer.Error!void {
    if (comptime builtin.os.tag == .linux) {
        step.* = .{ .operation = "prepare device parent", .path = device.path };
        const parent = std.fs.path.dirname(device.path) orelse return error.InvalidPath;
        const dir = try mountDestination(root_fd, parent, false, true);
        defer closeFd(dir);
        var name_buffer: [256]u8 = undefined;
        const name = std.fmt.bufPrintZ(&name_buffer, "{s}", .{std.fs.path.basename(device.path)}) catch return error.InvalidPath;
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
        step.operation = "mknod";
        const created = linux.mknodat(dir, name, device.mode, device.dev);
        switch (linux.errno(created)) {
            .SUCCESS => {
                // Pin the new node for metadata updates, even if the name changes.
                step.operation = "open device";
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                step.operation = "validate device";
                try validateDeviceNode(node, device);
                step.operation = "chown device";
                try checkResult(linux.fchownat(node, "", device.uid, device.gid, linux.AT.EMPTY_PATH));
                var buffer: [64]u8 = undefined;
                step.operation = "chmod device";
                try checkResult(linux.fchmodat(linux.AT.FDCWD, fdPath(&buffer, node), device.mode & 0o7777));
            },
            // A configured mount may already supply this device. Preserve it
            // only when its type and device number match the requested node.
            .EXIST => {
                // Deliberately keep existing metadata: this node may come
                // from a bind mount, and rewriting it would change the host.
                step.operation = "open existing device";
                const node = try openPath(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true });
                defer closeFd(node);
                step.operation = "validate existing device";
                try validateDeviceNode(node, device);
            },
            .PERM => {
                // mknod is forbidden in user namespaces. Like runc, retry an
                // EPERM as a bind, including when the runtime inherited a user ns.
                step.operation = "open device bind source";
                const source = try openPath(linux.AT.FDCWD, device.path, .{ .PATH = true, .CLOEXEC = true });
                defer closeFd(source);
                step.operation = "validate device bind source";
                try validateDeviceNode(source, device);
                step.operation = "prepare device bind destination";
                const target = try mountDestination(root_fd, device.path, true, true);
                defer closeFd(target);
                var source_buffer: [64]u8 = undefined;
                var target_buffer: [64]u8 = undefined;
                step.operation = "bind device";
                try checkResult(linux.mount(fdPath(&source_buffer, source), fdPath(&target_buffer, target), null, linux.MS.BIND, 0));
                if (!private_mount_namespace) {
                    step.operation = "device private propagation";
                    const mounted = try mountDestination(root_fd, device.path, true, false);
                    defer closeFd(mounted);
                    try checkResult(linux.mount(null, fdPath(&target_buffer, mounted), null, linux.MS.PRIVATE | linux.MS.REC, 0));
                }
                // Like runc, bind fallback inherits host metadata; changing it
                // here would chmod/chown the host device as well.
            },
            else => try checkResult(created),
        }
    } else {
        return error.NotImplemented;
    }
}

pub fn setupDevices(root_fd: posix.fd_t, devices: []const PreparedDevice, symlinks: []const libcontainer.Symlink, private_mount_namespace: bool, step: *RootfsStep) libcontainer.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (devices) |device| {
            // Like runc, /dev/ptmx is always the pts/ptmx symlink, even when
            // listed: a host node there would bypass the container's devpts.
            if (std.mem.eql(u8, device.path, "/dev/ptmx")) continue;
            try createDevice(root_fd, device, private_mount_namespace, step);
        }
        try setupSymlinks(root_fd, symlinks, step);
    } else {
        return error.NotImplemented;
    }
}

pub fn setupSymlinks(root_fd: posix.fd_t, symlinks: []const libcontainer.Symlink, step: *RootfsStep) libcontainer.Error!void {
    if (comptime builtin.os.tag == .linux) {
        for (symlinks) |link| {
            step.* = .{ .operation = "prepare symlink parent", .path = link.path };
            if (!std.mem.startsWith(u8, link.path, "/")) return error.InvalidPath;
            const parent = std.fs.path.dirname(link.path) orelse return error.InvalidPath;
            const dir = try mountDestination(root_fd, parent, false, true);
            defer closeFd(dir);
            var buffer: [256]u8 = undefined;
            const name = std.fmt.bufPrintZ(&buffer, "{s}", .{std.fs.path.basename(link.path)}) catch return error.InvalidPath;
            // Like runc's setupPtmx, replace whatever the rootfs has there:
            // a host node would bypass the container's devpts.
            if (std.mem.eql(u8, link.path, "/dev/ptmx")) {
                step.operation = "remove existing ptmx";
                const removed = linux.unlinkat(dir, name, 0);
                if (linux.errno(removed) != .NOENT) try checkResult(removed);
            }
            step.operation = "symlink";
            const result = linux.symlinkat(link.target, dir, name);
            switch (linux.errno(result)) {
                .SUCCESS, .EXIST => {},
                else => try checkResult(result),
            }
        }
    } else {
        return error.NotImplemented;
    }
}

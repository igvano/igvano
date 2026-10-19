const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Backend = @import("../../../backend.zig").Backend;
const Resources = Backend.Resources;
const oci = @import("../../../oci.zig");
const seccomp = @import("../../seccomp.zig");
const diagnostics = @import("../diagnostic.zig");
const v2DeviceRules = @import("../devices.zig").v2DeviceRules;
const runningInUserNamespace = @import("../devices.zig").runningInUserNamespace;
const queryDevicePrograms = @import("../devices.zig").queryDevicePrograms;
const applyV2DeviceFilter = @import("../devices.zig").applyV2DeviceFilter;
const deviceEmulator = @import("../devices.zig").deviceEmulator;
const checkResult = @import("../syscall.zig").checkResult;
const forkProcess = @import("../syscall.zig").forkProcess;
const closeFd = @import("../syscall.zig").closeFd;
const waitChild = @import("../syscall.zig").waitChild;
const readAll = @import("../syscall.zig").readAll;
const openPath = @import("../syscall.zig").openPath;
const walkCgroup = @import("../cgroup_v2.zig").walkCgroup;
const openCgroupRoot = @import("../cgroup.zig").openCgroupRoot;
const removeCgroup = @import("../cgroup.zig").removeCgroup;
const freeV1Writes = @import("../cgroup_v1.zig").freeV1Writes;
const v1Writes = @import("../cgroup_v1.zig").v1Writes;
const v1DeviceNumber = @import("../cgroup_v1.zig").v1DeviceNumber;
const V1Hierarchy = @import("../cgroup_v1.zig").V1Hierarchy;
const applyV1Writes = @import("../cgroup_v1.zig").applyV1Writes;
const RootfsStep = @import("../rootfs.zig").RootfsStep;
const checkV2TestDevices = @import("helpers.zig").checkV2TestDevices;
const checkV2TestDefaultDevices = @import("helpers.zig").checkV2TestDefaultDevices;
const requireTestMountNamespace = @import("helpers.zig").requireTestMountNamespace;
const PreparedDevice = @import("../device_nodes.zig").PreparedDevice;
const validateDeviceNode = @import("../device_nodes.zig").validateDeviceNode;
const createDevice = @import("../device_nodes.zig").createDevice;
const LinuxBackend = @import("../../linux.zig").LinuxBackend;

test "linux v2 device filter loads a large rule set without overflowing the verifier log" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(root.fd);
    if (root.mode != .unified) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "igvano-v2-many-devices-{d}", .{linux.getpid()});
    defer allocator.free(path);
    const cgroup = (walkCgroup(root.fd, path, true, &.{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    }).?;
    defer closeFd(cgroup);
    defer removeCgroup(root.fd, path) catch {};
    var rules: [200]Resources.DeviceRule = undefined;
    for (&rules, 0..) |*rule, minor|
        rule.* = .{ .allow = true, .kind = .char, .major = 1, .minor = @intCast(minor), .access = "rw" };
    try applyV2DeviceFilter(allocator, cgroup, &rules, path, false);
    const ids = try queryDevicePrograms(allocator, cgroup, path);
    defer allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 1), ids.len);
}

test "linux v1 device updates verify readback after writing only the transition" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (runningInUserNamespace()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    defer diagnostics.last_diagnostic_len = 0;
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "devices.list",
        .data =
        \\c *:* m
        \\b *:* m
        \\c 1:3 rwm
        \\c 1:5 rwm
        \\c 1:7 rwm
        \\c 1:8 rwm
        \\c 1:9 rwm
        \\c 5:0 rwm
        \\c 5:2 rwm
        \\c 136:* rwm
        \\c 10:200 rwm
        \\c 10:237 r
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "devices.allow", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "devices.deny", .data = "untouched" });
    const resources: Resources = .{ .devices = &.{
        .{ .allow = true, .kind = .char, .major = 10, .minor = 237, .access = "rw" },
    } };
    const writes = try v1Writes(std.testing.allocator, resources);
    defer freeV1Writes(std.testing.allocator, writes);
    const hierarchies: []const V1Hierarchy = &.{.{
        .mountpoint = "/test/devices",
        .mount_root = "/",
        .controllers = &.{"devices"},
        .leaf = tmp.dir.handle,
    }};
    // Regular files do not apply the transition to devices.list.
    try std.testing.expectError(error.CgroupWriteFailed, applyV1Writes(std.testing.allocator, hierarchies, writes, resources, null, "test", false));
    try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "devices.list does not match") != null);
    const allowed = try tmp.dir.readFileAlloc(std.testing.io, "devices.allow", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(allowed);
    try std.testing.expectEqualStrings("c 10:237 w", allowed);
    const denied = try tmp.dir.readFileAlloc(std.testing.io, "devices.deny", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(denied);
    try std.testing.expectEqualStrings("untouched", denied);
    const configured = try v2DeviceRules(std.testing.allocator, resources.devices, &.{});
    defer std.testing.allocator.free(configured);
    var target = try deviceEmulator(std.testing.allocator, configured);
    defer target.deinit(std.testing.allocator);
    const rules = try target.rules(std.testing.allocator);
    defer std.testing.allocator.free(rules);
    var expected: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer expected.deinit();
    for (rules) |rule| {
        var major: [24]u8 = undefined;
        var minor: [24]u8 = undefined;
        try expected.writer.print("{c} {s}:{s} {s}\n", .{
            @as(u8, if (rule.kind == .char) 'c' else 'b'),
            if (rule.major) |n| try v1DeviceNumber(&major, n) else "*",
            if (rule.minor) |n| try v1DeviceNumber(&minor, n) else "*",
            rule.access,
        });
    }
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "devices.list", .data = expected.written() });
    try applyV1Writes(std.testing.allocator, hierarchies, writes, resources, null, "test", false);
}

test "linux v1 container allowlist opens dev null while a denied device fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .legacy) return error.SkipZigTest;
    try requireTestMountNamespace();
    // Confirm the probe device works before testing the cgroup denial.
    const probe = openPath(linux.AT.FDCWD, "/dev/loop-control", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return error.SkipZigTest;
    closeFd(probe);
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/dev");
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrint(allocator, "{s}/rootfs", .{absolute});
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const denied = try std.fmt.allocPrintSentinel(allocator, "{s}/dev/denied", .{rootfs}, 0);
    defer allocator.free(denied);
    try checkResult(linux.mknod(denied, linux.S.IFCHR | 0o600, (10 << 8) | 237));
    const path = try std.fmt.allocPrint(allocator, "igvano-v1-devices-{d}", .{linux.getpid()});
    defer allocator.free(path);
    const devices = try oci.prepareDevices(allocator, null);
    defer oci.freeDevices(allocator, devices);
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = "v1-devices",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = path,
        .devices = devices,
        .mounts = &.{
            .{ .destination = "/bin", .source = "/bin", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
            .{ .destination = "/lib", .source = "/lib", .type = null, .flags = linux.MS.BIND | linux.MS.RDONLY, .propagation = 0, .data = "" },
        },
        .resources = .{ .devices = &.{.{ .allow = false }} },
        .start_hooks = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "exec 3< /dev/null || exit 1; if (exec 4< /dev/denied) 2>/dev/null; then exit 2; fi; exit 0" },
            .timeout_seconds = 2,
        }},
    });
    defer allocator.free(handle.starttime);
    defer backend.delete(handle) catch {};
    try std.testing.expect(try backend.alive(handle));
    const reader = try openPath(linux.AT.FDCWD, fifo, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(reader);
    var byte: [1]u8 = undefined;
    try std.testing.expect(readAll(reader, &byte));
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
    // Delete must rediscover hierarchies even when the saved init PID is gone.
    try backend.delete(.{ .id = handle.id, .pid = 0, .starttime = "", .cgroup_path = path });
    try std.testing.expect(!try backend.alive(handle));
}

test "linux v2 container device filter preserves defaults and replaces unlisted device policy on update" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    defer closeFd(root.fd);
    if (root.mode != .unified) return error.SkipZigTest;
    try requireTestMountNamespace();
    const device_probe = openPath(linux.AT.FDCWD, "/dev/loop-control", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) catch return error.SkipZigTest;
    closeFd(device_probe);
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "igvano-v2-devices-{d}", .{linux.getpid()});
    defer allocator.free(path);
    // Probe delegation before create; filter failures must fail the test.
    const probe = (walkCgroup(root.fd, path, true, &.{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    }).?;
    closeFd(probe);
    try removeCgroup(root.fd, path);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "rootfs/dev");
    const base = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, allocator);
    defer allocator.free(absolute);
    const rootfs = try std.fmt.allocPrint(allocator, "{s}/rootfs", .{absolute});
    defer allocator.free(rootfs);
    const fifo = try std.fmt.allocPrintSentinel(allocator, "{s}/exec.fifo", .{absolute}, 0);
    defer allocator.free(fifo);
    try checkResult(linux.mknod(fifo, linux.S.IFIFO | 0o600, 0));
    const rules = [_]Resources.DeviceRule{
        .{ .allow = false },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 3 },
        .{ .allow = true, .kind = .char, .major = 10, .minor = 237 },
    };
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
    };
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    var original_memlock: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.MEMLOCK, &original_memlock));
    const limited_memlock: linux.rlimit = .{ .cur = @min(original_memlock.cur, 64 * 1024), .max = original_memlock.max };
    try checkResult(linux.setrlimit(.MEMLOCK, &limited_memlock));
    defer _ = linux.setrlimit(.MEMLOCK, &original_memlock);
    const handle = try backend.create(.{
        .allocator = allocator,
        .id = "v2-devices",
        .rootfs = rootfs,
        .exec_fifo = fifo,
        .spec = &spec,
        .cgroup_path = path,
        .devices = &.{.{ .path = "/dev/null", .kind = .character, .major = 1, .minor = 3 }},
        .mounts = &.{
            .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .flags = linux.MS.NOSUID, .propagation = 0, .data = "mode=755" },
            .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .flags = linux.MS.NOSUID | linux.MS.NOEXEC, .propagation = 0, .data = "newinstance,ptmxmode=666,mode=620" },
        },
        .device_symlinks = &.{.{ .path = "/dev/ptmx", .target = "pts/ptmx" }},
        .resources = .{ .devices = rules[0..2] },
    });
    defer allocator.free(handle.starttime);
    defer {
        backend.kill(handle, 9) catch {};
        backend.delete(handle) catch {};
    }
    var inherited_memlock: linux.rlimit = undefined;
    try checkResult(linux.prlimit(handle.pid, .MEMLOCK, null, &inherited_memlock));
    try std.testing.expectEqual(limited_memlock.cur, inherited_memlock.cur);
    try std.testing.expectEqual(limited_memlock.max, inherited_memlock.max);
    const cgroup = (try walkCgroup(root.fd, path, false, &.{})).?;
    defer closeFd(cgroup);
    var buffer: [64]u8 = undefined;
    const ns_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/ns/mnt", .{handle.pid});
    const namespace = try openPath(linux.AT.FDCWD, ns_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(namespace);
    const root_path = try std.fmt.bufPrintZ(&buffer, "/proc/{d}/root", .{handle.pid});
    const init_root = try openPath(linux.AT.FDCWD, root_path, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(init_root);
    try checkV2TestDevices(cgroup, namespace, init_root, false);
    try checkV2TestDefaultDevices(cgroup, namespace, init_root);
    try backend.update(handle, .{});
    try checkV2TestDevices(cgroup, namespace, init_root, false);
    try backend.update(handle, .{ .devices = &rules });
    try checkV2TestDevices(cgroup, namespace, init_root, true);
    try backend.update(handle, .{ .devices = &rules });
    try checkV2TestDevices(cgroup, namespace, init_root, true);
    try backend.update(handle, .{ .devices = &.{.{ .allow = false }} });
    try checkV2TestDevices(cgroup, namespace, init_root, false);
    try checkV2TestDefaultDevices(cgroup, namespace, init_root);
    // An unrestricted update must also replace the old restrictive program.
    try backend.update(handle, .{ .devices = &.{.{ .allow = true }} });
    const ids = try queryDevicePrograms(allocator, cgroup, path);
    defer allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 1), ids.len);
    var actual_memlock: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.MEMLOCK, &actual_memlock));
    try std.testing.expectEqual(limited_memlock.cur, actual_memlock.cur);
    try std.testing.expectEqual(limited_memlock.max, actual_memlock.max);
}

test "linux v2 device filter skips forbidden bpf only for full-access allows in the initial user namespace" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var stat: linux.Statx = undefined;
    try checkResult(linux.statx(linux.AT.FDCWD, "/proc/self/ns/user", 0, .{ .INO = true }, &stat));
    if (!stat.mask.INO or stat.ino != 0xeffffffd) return error.SkipZigTest;
    const root = openCgroupRoot() catch return error.SkipZigTest;
    closeFd(root.fd);
    if (root.mode != .unified) return error.SkipZigTest;
    const pid = try forkProcess();
    if (pid == 0) {
        const filters = [_]seccomp.Filter{
            .{ .code = 0x20, .k = 0 }, // seccomp_data.nr
            .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.bpf) },
            .{ .code = 0x06, .k = 0x00050001 }, // EPERM
            .{ .code = 0x06, .k = 0x7fff0000 }, // ALLOW
        };
        var original: linux.rlimit = undefined;
        checkResult(linux.getrlimit(.MEMLOCK, &original)) catch linux.exit_group(6);
        const limited: linux.rlimit = .{ .cur = 0, .max = original.max };
        checkResult(linux.setrlimit(.MEMLOCK, &limited)) catch linux.exit_group(7);
        checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(1);
        if (seccomp.install(.{ .filters = &filters, .flags = 0 }) != .SUCCESS) linux.exit_group(2);
        const allocator = std.heap.page_allocator;
        for ([_]struct { rules: []const Resources.DeviceRule, skip: bool }{
            .{ .rules = &.{}, .skip = true },
            .{ .rules = &.{.{ .allow = true }}, .skip = true },
            .{ .rules = &.{.{ .allow = false }}, .skip = false },
            .{ .rules = &.{.{ .allow = true, .kind = .char }}, .skip = true },
            .{ .rules = &.{ .{ .allow = true }, .{ .allow = true } }, .skip = true },
            .{ .rules = &.{.{ .allow = true, .kind = .char, .access = "r" }}, .skip = false },
            .{ .rules = &.{
                .{ .allow = true, .kind = .char, .access = "r" },
                .{ .allow = true, .kind = .char, .access = "wm" },
            }, .skip = false },
        }) |case| {
            if (applyV2DeviceFilter(allocator, -1, case.rules, "bpf-forbidden-test", false)) |_| {
                if (!case.skip) linux.exit_group(5);
            } else |err| {
                if (case.skip or err != error.CgroupWriteFailed or
                    std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "BPF_PROG_LOAD") == null or
                    std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "PERM") == null)
                    linux.exit_group(4);
            }
            var actual: linux.rlimit = undefined;
            checkResult(linux.getrlimit(.MEMLOCK, &actual)) catch linux.exit_group(8);
            if (actual.cur != limited.cur or actual.max != limited.max) linux.exit_group(9);
        }
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u32, 0), try waitChild(pid));
}

test "linux v2 device filter skips load errors in a user namespace for every policy" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]linux.E{ .PERM, .ACCES, .INVAL }) |bpf_error| {
        const pid = try forkProcess();
        if (pid == 0) {
            const unshared = linux.errno(linux.unshare(linux.CLONE.NEWUSER));
            if (unshared == .PERM) linux.exit_group(77);
            if (unshared != .SUCCESS) linux.exit_group(1);
            const filters = [_]seccomp.Filter{
                .{ .code = 0x20, .k = 0 },
                .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.bpf) },
                .{ .code = 0x06, .k = 0x00050000 | @as(u32, @intFromEnum(bpf_error)) },
                .{ .code = 0x06, .k = 0x7fff0000 },
            };
            checkResult(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch linux.exit_group(2);
            if (seccomp.install(.{ .filters = &filters, .flags = 0 }) != .SUCCESS) linux.exit_group(3);
            const allocator = std.heap.page_allocator;
            var original: linux.rlimit = undefined;
            checkResult(linux.getrlimit(.MEMLOCK, &original)) catch linux.exit_group(4);
            for ([_][]const Resources.DeviceRule{
                &.{},
                &.{.{ .allow = true, .kind = .char, .major = 1, .minor = 3 }},
                &.{ .{ .allow = true, .access = "r" }, .{ .allow = true, .access = "w" } },
                &.{.{ .allow = false }},
                &.{ .{ .allow = false }, .{ .allow = true } },
            }) |rules| {
                applyV2DeviceFilter(allocator, -1, rules, "rootless-device-test", false) catch linux.exit_group(5);
                if (std.mem.indexOf(u8, diagnostics.last_diagnostic[0..diagnostics.last_diagnostic_len], "warning:") == null)
                    linux.exit_group(6);
            }
            const implicit = v2DeviceRules(allocator, &.{}, &.{}) catch linux.exit_group(7);
            applyV2DeviceFilter(allocator, -1, implicit, "rootless-implicit-devices", false) catch linux.exit_group(8);
            allocator.free(implicit);
            var actual: linux.rlimit = undefined;
            checkResult(linux.getrlimit(.MEMLOCK, &actual)) catch linux.exit_group(9);
            if (actual.cur != original.cur or actual.max != original.max) linux.exit_group(10);
            linux.exit_group(0);
        }
        const status = try waitChild(pid);
        if (status == 77 << 8) return error.SkipZigTest;
        try std.testing.expectEqual(@as(u32, 0), status);
    }
}

test "linux device creation rejects mismatched existing nodes and preserves matching FIFOs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "file", .data = "" });
    try tmp.dir.createDir(std.testing.io, "directory", .default_dir);
    try tmp.dir.symLink(std.testing.io, "pipe", "link", .{});
    const base = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer std.testing.allocator.free(base);
    const root = try openPath(linux.AT.FDCWD, base, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true });
    defer closeFd(root);
    try checkResult(linux.mknodat(root, "pipe", linux.S.IFIFO | 0o600, 0));
    const before = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    var step: RootfsStep = .{};
    for ([_][:0]const u8{ "/file", "/directory", "/link" }) |path| {
        try std.testing.expectError(error.InvalidPath, createDevice(root, .{
            .path = path,
            .mode = linux.S.IFIFO | 0o666,
            .dev = 0,
        }, true, &step));
    }
    try createDevice(root, .{ .path = "/pipe", .mode = linux.S.IFIFO | 0o666, .dev = 0 }, true, &step);
    const stat = try tmp.dir.statFile(std.testing.io, "pipe", .{});
    try std.testing.expectEqual(before.permissions.toMode(), stat.permissions.toMode());
}

test "linux device validation rejects mismatched types and device numbers" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const source = try openPath(linux.AT.FDCWD, "/dev/null", .{ .PATH = true, .CLOEXEC = true });
    defer closeFd(source);
    try validateDeviceNode(source, .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x103 });
    for ([_]PreparedDevice{
        .{ .path = "/dev/null", .mode = linux.S.IFBLK | 0o666, .dev = 0x103 },
        .{ .path = "/dev/null", .mode = linux.S.IFIFO | 0o666, .dev = 0 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x203 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x105 },
        .{ .path = "/dev/null", .mode = linux.S.IFCHR | 0o666, .dev = 0x100103 },
    }) |device| {
        try std.testing.expectError(error.InvalidPath, validateDeviceNode(source, device));
    }
}

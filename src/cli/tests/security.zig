const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const diagnostics = @import("../diagnostic.zig");
const Config = @import("../args.zig").Config;
const createContainer = @import("../create.zig").createContainer;
const startContainer = @import("../start.zig").startContainer;
const execContainer = @import("../exec.zig").execContainer;
const waitExec = @import("../exec.zig").waitExec;
const deleteContainer = @import("../delete.zig").deleteContainer;
const runIsolatedSecurityTest = @import("helpers.zig").runIsolatedSecurityTest;

test "linux seccomp create exec and start enforce filters with and without noNewPrivileges" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    // An inherited NNP bit cannot be cleared for the false case.
    if (linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 0)
        return error.SkipZigTest;
    if (linux.errno(linux.access("/sys/fs/cgroup/cgroup.controllers", linux.F_OK)) == .SUCCESS and
        linux.errno(linux.access("/sys/fs/cgroup", linux.W_OK)) != .SUCCESS)
        return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.SystemResources;
    const child: i32 = @intCast(forked);
    if (child == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) linux.exit_group(77);
        if (linux.errno(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) != .SUCCESS)
            linux.exit_group(1);
        testSeccompLifecycle(absolute) catch |err| {
            std.debug.print("seccomp lifecycle test: {s}\n", .{@errorName(err)});
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }
    const status = try waitExec(child);
    if (status == 77) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), status);
}

fn testSeccompLifecycle(base: []const u8) !void {
    const linux = std.os.linux;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const probe_path = std.testing.environ.getPosix("IGVANO_SECCOMP_PROBE") orelse return error.MissingSeccompProbe;
    const probe = try cwd.realPathFileAlloc(io, probe_path, allocator);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)));
    const docker = try std.json.parseFromSlice(oci.Spec.Seccomp, allocator, @embedFile("../../backend/testdata/docker-default.json"), .{});
    // runtime-tools generate uses an ERRNO allowlist and leaves NNP unset.
    // This older-style fixture has 314 names, including statx, but no
    // close_range, faccessat2 or landlock syscalls to raise the native maximum.
    const runtime_tools = try std.json.parseFromSlice(oci.Spec.Seccomp, allocator, @embedFile("../../backend/testdata/runtime-tools-default.json"), .{});
    const restricted: oci.Spec.Seccomp = .{
        .defaultAction = "SCMP_ACT_ALLOW",
        .syscalls = &.{
            .{ .names = &.{ "mkdir", "mkdirat" }, .action = "SCMP_ACT_ERRNO", .errnoRet = 1 },
            .{ .names = &.{"personality"}, .action = "SCMP_ACT_ERRNO", .args = &.{.{ .index = 0, .value = 0, .op = "SCMP_CMP_NE" }} },
        },
    };
    for ([_]oci.Spec.Seccomp{ restricted, docker.value, runtime_tools.value }, 0..) |profile, profile_index| {
        for ([_]bool{ false, true }) |nnp| {
            const id = try std.fmt.allocPrint(allocator, "seccomp-{d}-{s}", .{ profile_index, if (nnp) "true" else "false" });
            const bundle = try std.fs.path.join(allocator, &.{ base, id });
            const rootfs = try std.fs.path.join(allocator, &.{ bundle, "rootfs" });
            const root = try std.fs.path.join(allocator, &.{ base, "state" });
            try cwd.createDirPath(io, try std.fs.path.join(allocator, &.{ rootfs, "tmp" }));
            const cgroup = try std.fmt.allocPrint(allocator, "igvano-seccomp-{d}-{s}", .{ linux.getpid(), id });
            const nnp_arg: []const u8 = if (nnp) "true" else "false";
            var mounts: std.ArrayList(oci.Spec.Mount) = .empty;
            try mounts.appendSlice(allocator, &.{
                .{ .destination = "/probe", .source = probe, .type = "bind", .options = &.{ "bind", "ro" } },
                .{ .destination = "/proc", .source = "proc", .type = "proc" },
            });
            if (profile_index == 2) {
                for ([_][]const u8{ "/bin", "/usr", "/lib", "/lib64" }) |path| {
                    if (linux.errno(linux.access(try allocator.dupeZ(u8, path), linux.F_OK)) == .SUCCESS)
                        try mounts.append(allocator, .{ .destination = path, .source = path, .type = "bind", .options = &.{ "rbind", "ro" } });
                }
            }
            const spec: oci.Spec = .{
                .ociVersion = "1.0.2",
                .root = .{ .path = "rootfs" },
                .process = .{
                    .args = if (profile_index == 2) &.{"/bin/true"} else &.{ "probe", nnp_arg, if (profile_index == 0) "restricted" else "docker" },
                    .env = &.{"PATH=/"},
                    .cwd = "/",
                    .noNewPrivileges = nnp,
                    .user = .{ .uid = 0, .gid = 0 },
                    // Installing the false case after this drop would fail.
                    .capabilities = .{},
                },
                .mounts = mounts.items,
                .linux = .{ .cgroupsPath = cgroup, .namespaces = &.{ .{ .type = .mount }, .{ .type = .pid } }, .seccomp = profile },
                .hooks = if (profile_index != 1) .{ .startContainer = &.{.{
                    .path = "/probe",
                    .args = &.{ "/probe", nnp_arg, if (profile_index == 0) "hook" else "runtime-tools-hook" },
                    .timeout = 2,
                }} } else null,
            };
            try cwd.writeFile(io, .{
                .sub_path = try std.fs.path.join(allocator, &.{ bundle, "config.json" }),
                .data = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false }),
            });
            var implementation: backend_module.LinuxBackend = .{};
            const backend = implementation.backend();
            var config: Config = .{ .root = root, .id = id, .subcommand = .create, .bundle = bundle };
            try createContainer(allocator, io, backend, config);
            defer {
                config.subcommand = .delete;
                config.force = true;
                deleteContainer(allocator, io, backend, config) catch {};
            }
            const saved = try oci.loadState(allocator, io, root, id);
            const pid = saved.value.pid.?;
            var reaped = false;
            defer if (!reaped) {
                _ = linux.kill(pid, .KILL);
                _ = waitExec(pid) catch {};
            };
            // Exec must enforce the saved policy even before init is started,
            // both with inherited process settings and an explicit --process.
            config.subcommand = .exec;
            config.exec_args = spec.process.?.args;
            try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
            if (profile_index == 2) {
                config.exec_args = &.{ "/probe", nnp_arg, "runtime-tools" };
                try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
                config.exec_args = spec.process.?.args;
            }
            config.process_file = try std.fs.path.join(allocator, &.{ bundle, "process.json" });
            try cwd.writeFile(io, .{
                .sub_path = config.process_file.?,
                .data = try std.json.Stringify.valueAlloc(allocator, spec.process.?, .{ .emit_null_optional_fields = false }),
            });
            try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
            config.subcommand = .start;
            try startContainer(allocator, io, backend, config);
            const status = try waitExec(pid);
            reaped = true;
            try std.testing.expectEqual(@as(u8, 0), status);
        }
    }
}

test "linux AppArmor confines init and exec with inherited and explicit profiles" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (!backend_module.apparmorEnabled()) return error.SkipZigTest;
    if (std.os.linux.prctl(@intFromEnum(std.os.linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 0)
        return error.SkipZigTest;
    try runIsolatedSecurityTest(testAppArmorLifecycle);
}

test "linux rshared and rslave binds propagate mounts after container start" {
    try runIsolatedSecurityTest(testPropagationLifecycle);
}

fn testAppArmorLifecycle(base: []const u8) !void {
    const linux = std.os.linux;
    const parser = parser: {
        for ([_][:0]const u8{ "/usr/sbin/apparmor_parser", "/sbin/apparmor_parser", "/usr/bin/apparmor_parser" }) |path| {
            if (linux.errno(linux.access(path, linux.X_OK)) == .SUCCESS) break :parser path;
        }
        return error.SkipZigTest;
    };
    var threaded: std.Io.Threaded = .init_single_threaded;
    // process.run allocates spawn buffers through the I/O implementation.
    threaded.allocator = std.heap.page_allocator;
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const probe_path = std.testing.environ.getPosix("IGVANO_SECCOMP_PROBE") orelse return error.MissingSeccompProbe;
    const probe = try cwd.realPathFileAlloc(io, probe_path, allocator);
    const profile = try std.fmt.allocPrint(allocator, "igvano-deny-write-{d}", .{linux.getpid()});
    const override = try std.fmt.allocPrint(allocator, "{s}-exec", .{profile});
    const profile_path = try std.fs.path.join(allocator, &.{ base, "apparmor-profile" });
    var policy: std.Io.Writer.Allocating = .init(allocator);
    defer policy.deinit();
    // Permit runtime liveness, signaling and procfs reads, as cri-tools' base
    // abstraction does; the profile's deliberate restriction is the write.
    for ([_][]const u8{ profile, override }) |name|
        try policy.writer.print("profile {s} flags=(attach_disconnected,mediate_deleted) {{\n  file,\n  signal (receive) peer=unconfined,\n  ptrace (readby) peer=unconfined,\n  deny /tmp/denied w,\n}}\n", .{name});
    try cwd.writeFile(io, .{ .sub_path = profile_path, .data = policy.written() });
    const loaded = try std.process.run(allocator, io, .{ .argv = &.{ parser, "-r", profile_path } });
    if (loaded.term != .exited or loaded.term.exited != 0) {
        std.debug.print("apparmor_parser: {s}\n", .{loaded.stderr});
        return error.ProfileLoadFailed;
    }
    defer {
        const removed = std.process.run(allocator, io, .{ .argv = &.{ parser, "-R", profile_path } }) catch null;
        if (removed) |result| {
            if (result.term != .exited or result.term.exited != 0)
                std.debug.print("apparmor_parser cleanup: {s}\n", .{result.stderr});
        }
    }
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)));
    for ([_]bool{ false, true }) |nnp| {
        const id: []const u8 = if (nnp) "apparmor-nnp" else "apparmor";
        const bundle = try std.fs.path.join(allocator, &.{ base, id });
        const rootfs = try std.fs.path.join(allocator, &.{ bundle, "rootfs" });
        const root = try std.fs.path.join(allocator, &.{ base, "state" });
        try cwd.createDirPath(io, try std.fs.path.join(allocator, &.{ rootfs, "tmp" }));
        // Pre-create a writable file so failure cannot be mistaken for a missing parent.
        try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(allocator, &.{ rootfs, "tmp/denied" }), .data = "" });
        const nnp_arg: []const u8 = if (nnp) "true" else "false";
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .process = .{
                .args = &.{ "/probe", nnp_arg, "apparmor", profile },
                .cwd = "/",
                .noNewPrivileges = nnp,
                .apparmorProfile = profile,
                .user = .{ .uid = 0, .gid = 0 },
                .capabilities = .{},
            },
            .mounts = &.{
                .{ .destination = "/probe", .source = probe, .type = "bind", .options = &.{ "bind", "ro" } },
                .{ .destination = "/proc", .source = "proc", .type = "proc" },
            },
            .linux = .{
                .cgroupsPath = try std.fmt.allocPrint(allocator, "igvano-{d}-{s}", .{ linux.getpid(), id }),
                .namespaces = &.{ .{ .type = .mount }, .{ .type = .pid } },
                .seccomp = .{ .defaultAction = "SCMP_ACT_ALLOW" },
            },
        };
        try cwd.writeFile(io, .{
            .sub_path = try std.fs.path.join(allocator, &.{ bundle, "config.json" }),
            .data = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false }),
        });
        var implementation: backend_module.LinuxBackend = .{};
        const backend = implementation.backend();
        var config: Config = .{ .root = root, .id = id, .subcommand = .create, .bundle = bundle };
        try createContainer(allocator, io, backend, config);
        defer {
            config.subcommand = .delete;
            config.force = true;
            deleteContainer(allocator, io, backend, config) catch {};
        }
        const saved = try oci.loadState(allocator, io, root, id);
        const pid = saved.value.pid.?;
        var reaped = false;
        defer if (!reaped) {
            _ = linux.kill(pid, .KILL);
            _ = waitExec(pid) catch {};
        };
        config.subcommand = .exec;
        config.exec_args = spec.process.?.args;
        try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
        config.process_file = try std.fs.path.join(allocator, &.{ bundle, "process.json" });
        // --process without a profile must still use the container's profile.
        var process = spec.process.?;
        for ([_]?[]const u8{ null, "", override }) |name| {
            process.apparmorProfile = name;
            process.args = &.{ "/probe", nnp_arg, "apparmor", if (name == null or name.?.len == 0) profile else override };
            try cwd.writeFile(io, .{
                .sub_path = config.process_file.?,
                .data = try std.json.Stringify.valueAlloc(allocator, process, .{ .emit_null_optional_fields = false }),
            });
            try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
        }
        process.apparmorProfile = try std.fmt.allocPrint(allocator, "{s}-not-loaded", .{profile});
        try cwd.writeFile(io, .{
            .sub_path = config.process_file.?,
            .data = try std.json.Stringify.valueAlloc(allocator, process, .{ .emit_null_optional_fields = false }),
        });
        try std.testing.expectError(error.CreateFailed, execContainer(allocator, io, backend, config));
        try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_backend_detail.?, "profile not loaded") != null);
        config.subcommand = .start;
        try startContainer(allocator, io, backend, config);
        const status = try waitExec(pid);
        reaped = true;
        try std.testing.expectEqual(@as(u8, 0), status);
    }
}

fn testPropagationLifecycle(base: []const u8) !void {
    const linux = std.os.linux;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const probe_path = std.testing.environ.getPosix("IGVANO_SECCOMP_PROBE") orelse return error.MissingSeccompProbe;
    const probe = try cwd.realPathFileAlloc(io, probe_path, allocator);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)));
    const cases = [_]struct {
        id: ?[]const u8 = null,
        root: oci.Spec.Propagation,
        mount: ?oci.Spec.Propagation,
        userns: bool = false,
    }{
        .{ .root = .rshared, .mount = .rshared },
        .{ .root = .rslave, .mount = .rslave },
        .{ .root = .shared, .mount = .rshared },
        .{ .root = .slave, .mount = .rslave },
        .{ .root = .private, .mount = .rshared },
        .{ .id = "userns-rslave-rslave", .root = .rslave, .mount = .rslave, .userns = true },
        .{ .id = "userns-private-rshared", .root = .private, .mount = .rshared, .userns = true },
        .{ .id = "userns-rslave-default", .root = .rslave, .mount = null, .userns = true },
    };
    for (cases) |case| {
        const id = case.id orelse @tagName(case.root);
        const bundle = try std.fs.path.join(allocator, &.{ base, id });
        const bundle_z = try allocator.dupeZ(u8, bundle);
        const rootfs = try std.fs.path.join(allocator, &.{ bundle, "rootfs" });
        const root = try std.fs.path.join(allocator, &.{ base, "state" });
        const source = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}/source", .{ base, id }, 0);
        const host_mount = try std.fmt.allocPrintSentinel(allocator, "{s}/from-host", .{source}, 0);
        const container_mount = try std.fmt.allocPrintSentinel(allocator, "{s}/from-container", .{source}, 0);
        const host_data = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}/host-data", .{ base, id }, 0);
        for ([_][]const u8{ rootfs, host_mount, container_mount, host_data }) |path| try cwd.createDirPath(io, path);
        if (case.userns) {
            const rootfs_z = try allocator.dupeZ(u8, rootfs);
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chown(rootfs_z, 100000, 200000)));
        }
        try cwd.writeFile(io, .{
            .sub_path = try std.fs.path.join(allocator, &.{ host_data, "flag" }),
            .data = "host",
        });
        // A shared containing mount exercises runc's parent-mount isolation,
        // including plain propagation flags that leave submount peers intact.
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(bundle_z, bundle_z, null, linux.MS.BIND, 0)));
        defer _ = linux.umount2(bundle_z, linux.MNT.DETACH);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(null, bundle_z, null, linux.MS.SHARED, 0)));
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(source, source, null, linux.MS.BIND | linux.MS.REC, 0)));
        defer _ = linux.umount2(source, linux.MNT.DETACH);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(null, source, null, linux.MS.SHARED | linux.MS.REC, 0)));
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .process = .{
                .args = &.{ "/probe", "true", "propagation-init" },
                .cwd = "/",
                .noNewPrivileges = true,
                .user = .{ .uid = 0, .gid = 0 },
            },
            .mounts = &.{
                .{ .destination = "/probe", .source = probe, .type = "bind", .options = &.{ "bind", "ro" } },
                .{ .destination = "/proc", .source = "proc", .type = "proc" },
                .{ .destination = "/volume", .source = source, .type = "bind", .options = if (case.mount) |propagation| &.{ "rbind", @tagName(propagation) } else &.{"rbind"} },
            },
            .linux = .{
                .rootfsPropagation = case.root,
                .cgroupsPath = try std.fmt.allocPrint(allocator, "igvano-propagation-{d}-{s}", .{ linux.getpid(), id }),
                .namespaces = if (case.userns) &.{ .{ .type = .mount }, .{ .type = .pid }, .{ .type = .user } } else &.{ .{ .type = .mount }, .{ .type = .pid } },
                .uidMappings = if (case.userns) &.{.{ .containerID = 0, .hostID = 100000, .size = 65536 }} else null,
                .gidMappings = if (case.userns) &.{.{ .containerID = 0, .hostID = 200000, .size = 65536 }} else null,
            },
        };
        try cwd.writeFile(io, .{
            .sub_path = try std.fs.path.join(allocator, &.{ bundle, "config.json" }),
            .data = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false }),
        });
        var implementation: backend_module.LinuxBackend = .{};
        const backend = implementation.backend();
        var config: Config = .{ .root = root, .id = id, .subcommand = .create, .bundle = bundle };
        try createContainer(allocator, io, backend, config);
        defer {
            config.subcommand = .delete;
            config.force = true;
            deleteContainer(allocator, io, backend, config) catch {};
        }
        const saved = try oci.loadState(allocator, io, root, id);
        const pid = saved.value.pid.?;
        defer {
            _ = linux.kill(pid, .KILL);
            _ = waitExec(pid) catch {};
        }
        config.subcommand = .start;
        try startContainer(allocator, io, backend, config);
        // The source was already bound into the running container.
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(host_data, host_mount, null, linux.MS.BIND, 0)));
        defer _ = linux.umount2(host_mount, linux.MNT.DETACH);
        config.subcommand = .exec;
        config.exec_args = &.{ "/probe", "true", "propagation-host" };
        try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
        config.exec_args = &.{ "/probe", "true", "propagation-container" };
        try std.testing.expectEqual(@as(u8, 0), try execContainer(allocator, io, backend, config));
        const flag = try std.fmt.allocPrintSentinel(allocator, "{s}/flag", .{container_mount}, 0);
        if (case.userns) {
            // The container's user namespace is downstream of the host.
            try std.testing.expectEqual(linux.E.NOENT, linux.errno(linux.access(flag, linux.F_OK)));
        } else {
            try std.testing.expectEqual(if (case.mount == .rshared) linux.E.SUCCESS else linux.E.NOENT, linux.errno(linux.access(flag, linux.F_OK)));
            if (case.mount == .rshared)
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.umount2(container_mount, linux.MNT.DETACH)));
        }
    }
}

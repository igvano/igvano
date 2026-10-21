const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const ContainerInstance = @import("../state.zig").ContainerInstance;
const attached = @import("../../attached.zig");
const diagnostics = @import("../diagnostic.zig");
const Config = @import("../args.zig").Config;
const parseArgs = @import("../args.zig").parseArgs;
const updateContainer = @import("../update.zig").updateContainer;
const containerState = @import("../state.zig").containerState;
const readLiveState = @import("../state.zig").readLiveState;
const createContainer = @import("../create.zig").createContainer;
const startContainer = @import("../start.zig").startContainer;
const execContainer = @import("../exec.zig").execContainer;
const waitExec = @import("../exec.zig").waitExec;
const killContainer = @import("../kill.zig").killContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const psContainer = @import("../ps.zig").psContainer;
const pauseContainer = @import("../pause.zig").pauseContainer;
const readTestCgroup = @import("helpers.zig").readTestCgroup;
const execTestCommand = @import("helpers.zig").execTestCommand;
const testPtyPair = @import("helpers.zig").testPtyPair;
const waitTestExec = @import("helpers.zig").waitTestExec;
const LockTestContainer = @import("helpers.zig").LockTestContainer;
const LockTestProcess = @import("helpers.zig").LockTestProcess;

test "attached exec catches signals inside backend exec while detached exec has no handler" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        var detached = false;

        fn exec(_: *anyopaque, _: libcontainer.ExecOptions) libcontainer.Error!i32 {
            for ([_]linux.SIG{ .TERM, .HUP }) |signal| {
                var action: linux.Sigaction = undefined;
                if (linux.errno(linux.sigaction(signal, null, &action)) != .SUCCESS)
                    return error.ExecFailed;
                if ((action.handler.handler == linux.SIG.DFL) != detached)
                    return error.InvalidProcess;
                // Delivered before container.exec returns; the attached frontend
                // must already supervise signals even on the failure path.
                if (!detached) _ = linux.kill(@intCast(linux.getpid()), signal);
            }
            return error.ExecFailed;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(root);
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try oci.saveState(allocator, std.testing.io, root, .{ .id = "example", .status = .running, .pid = 1234, .bundle = "/unused" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "example" });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "process.json",
        .data =
        \\{"args":["true"],"cwd":"/","user":{"uid":0,"gid":0}}
        ,
    });
    const process_file = try std.fs.path.join(allocator, &.{ root, "process.json" });
    defer allocator.free(process_file);
    for ([_]bool{ false, true }) |detached| {
        const forked = std.posix.system.fork();
        if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
        const pid: i32 = @intCast(forked);
        if (pid == 0) {
            TestContainer.detached = detached;
            const action: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.DFL }, .mask = linux.sigemptyset(), .flags = 0 };
            for ([_]linux.SIG{ .TERM, .HUP }) |signal| _ = linux.sigaction(signal, &action, null);
            var threaded: std.Io.Threaded = .init_single_threaded;
            var implementation: LockTestContainer = .{};
            var vtable = LockTestContainer.vtable;
            vtable.exec = TestContainer.exec;
            const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &vtable };
            const config: Config = .{ .root = root, .id = "example", .subcommand = .exec, .process_file = process_file, .detach = detached };
            _ = execContainer(std.heap.page_allocator, threaded.io(), overrideContainer(&implementation, container), config) catch |err|
                linux.exit_group(if (err == error.ExecFailed) 0 else 1);
            linux.exit_group(2);
        }
        try std.testing.expectEqual(@as(u8, 0), try waitExec(pid));
    }
}

test "linux exec update ps pause resume and forced delete obey the live container lifecycle" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    if (linux.geteuid() != 0 or linux.errno(linux.access("/bin/sh", linux.X_OK)) != .SUCCESS)
        return error.SkipZigTest;
    // On v1 the tmpfs hierarchy root may be readonly while controller mounts
    // beneath it are writable. Only v2 requires writes directly to this root.
    if (linux.errno(linux.access("/sys/fs/cgroup/cgroup.controllers", linux.F_OK)) == .SUCCESS and
        linux.errno(linux.access("/sys/fs/cgroup", linux.W_OK)) != .SUCCESS)
        return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const child: i32 = @intCast(forked);
    if (child == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) linux.exit_group(77);
        if (linux.errno(linux.mount(null, "/", null, linux.MS.PRIVATE | linux.MS.REC, 0)) != .SUCCESS)
            linux.exit_group(1);
        testExecLifecycle(absolute) catch |err| {
            std.debug.print("exec lifecycle test: {s}\n", .{@errorName(err)});
            if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }
    const status = try waitExec(child);
    if (status == 77) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), status);
}

fn testExecLifecycle(base: []const u8) !void {
    const linux = std.os.linux;
    var threaded: std.Io.Threaded = .init_single_threaded;
    // Spawning host ps needs storage for its argv, even without I/O workers.
    threaded.allocator = std.heap.page_allocator;
    const io = threaded.io();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const bundle = try std.fs.path.join(allocator, &.{ base, "bundle" });
    const rootfs = try std.fs.path.join(allocator, &.{ bundle, "rootfs" });
    try cwd.createDirPath(io, rootfs);
    const root = try std.fs.path.join(allocator, &.{ base, "state" });
    const cgroup = try std.fmt.allocPrint(allocator, "igvano-exec-test-{d}", .{linux.getpid()});
    var mounts: std.ArrayList(oci.Spec.Mount) = .empty;
    for ([_][]const u8{ "/bin", "/sbin", "/usr", "/lib", "/lib64" }) |path| {
        const path_z = try allocator.dupeZ(u8, path);
        if (linux.errno(linux.access(path_z, linux.F_OK)) == .SUCCESS)
            try mounts.append(allocator, .{ .destination = path, .source = path, .type = "bind", .options = &.{ "rbind", "ro" } });
    }
    try mounts.append(allocator, .{ .destination = "/dev", .source = "tmpfs", .type = "tmpfs", .options = &.{ "nosuid", "mode=755" } });
    try mounts.append(allocator, .{ .destination = "/dev/pts", .source = "devpts", .type = "devpts", .options = &.{ "nosuid", "noexec", "newinstance", "ptmxmode=666", "mode=620" } });
    try mounts.append(allocator, .{ .destination = "/proc", .source = "proc", .type = "proc" });
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "rootfs" },
        .process = .{ .args = &.{ "sleep", "120" }, .env = &.{"PATH=/bin:/usr/bin"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
        .linux = .{ .cgroupsPath = cgroup, .namespaces = &.{ .{ .type = .mount }, .{ .type = .pid }, .{ .type = .cgroup } } },
        .mounts = mounts.items,
    };
    const config_path = try std.fs.path.join(allocator, &.{ bundle, "config.json" });
    try cwd.writeFile(io, .{ .sub_path = config_path, .data = try std.json.Stringify.valueAlloc(allocator, spec, .{ .emit_null_optional_fields = false }) });
    // Stand in for the shim, so detached children and init can be reaped.
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)) != .SUCCESS)
        return error.SubreaperFailed;

    const container = null;
    var config: Config = .{ .root = root, .id = "example", .subcommand = .create, .bundle = bundle };
    try createContainer(allocator, io, null, config);
    defer {
        config.subcommand = .delete;
        config.force = true;
        deleteContainer(allocator, io, null, config) catch {};
    }
    const saved = try oci.loadState(allocator, io, root, config.id);
    const init_pid = saved.value.pid.?;
    const init_handle = try containerState(allocator, io, root, saved.value, false);
    var init_reaped = false;
    defer if (!init_reaped) {
        _ = linux.kill(init_pid, .KILL);
        if ((frozen: {
            var instance = ContainerInstance.load(init_handle);
            break :frozen instance.container().frozen();
        }) catch false) (thaw: {
            var instance = ContainerInstance.load(init_handle);
            break :thaw instance.container().thaw();
        }) catch {};
        _ = waitExec(init_pid) catch {};
    };
    const ps = try parseArgs(&.{ "igvano", "--root", root, "ps", "--format", "json", "example" });
    const ps_path = try std.fs.path.join(allocator, &.{ base, "pids.json" });
    {
        const file = try cwd.createFile(io, ps_path, .{});
        defer file.close(io);
        try psContainer(allocator, io, null, ps, file);
        const json = try cwd.readFileAlloc(io, ps_path, allocator, .limited(4096));
        const pids = try std.json.parseFromSlice([]i32, allocator, json, .{});
        defer pids.deinit();
        try std.testing.expect(std.mem.indexOfScalar(i32, pids.value, init_pid) != null);
    }
    // An externally frozen init must also override its saved created status.
    try (freeze: {
        var instance = ContainerInstance.load(init_handle);
        break :freeze instance.container().freeze();
    });
    {
        const state = try readLiveState(allocator, io, null, config, false);
        defer state.deinit();
        try std.testing.expectEqual(oci.Status.paused, state.parsed.value.status);
        try std.testing.expectError(error.InvalidStatus, startContainer(allocator, io, null, config));
    }
    try (thaw: {
        var instance = ContainerInstance.load(init_handle);
        break :thaw instance.container().thaw();
    });
    const created_command = try parseArgs(&.{ "igvano", "--root", root, "exec", "example", "sh", "-c", "exit 23" });
    try std.testing.expectEqual(@as(u8, 23), try execTestCommand(created_command, null));
    config.subcommand = .start;
    try startContainer(allocator, io, null, config);
    try testUpdateResources(allocator, io, container, root, cgroup, base);
    try testAttachedExec(allocator, io, root);
    // The saved config, rather than the now-missing bundle config, supplies exec defaults.
    try cwd.deleteFile(io, config_path);
    {
        // CLOEXEC alone still lets cwd escape through an inherited host directory.
        var host_dir = try cwd.openDir(io, base, .{});
        defer host_dir.close(io);
        const leaked_cwd = try std.fmt.allocPrint(allocator, "/proc/self/fd/{d}", .{host_dir.handle});
        const escaping = try parseArgs(&.{ "igvano", "--root", root, "exec", "--cwd", leaked_cwd, "example", "true" });
        try std.testing.expectError(error.CreateFailed, execContainer(allocator, io, null, escaping));
        try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_container_detail.?, "cannot change exec cwd") != null);
    }
    var capture: [2]std.posix.fd_t = undefined;
    if (std.posix.errno(std.posix.system.pipe2(&capture, .{ .CLOEXEC = true })) != .SUCCESS)
        return error.SystemResources;
    defer _ = linux.close(capture[0]);
    var capture_writer: ?std.posix.fd_t = capture[1];
    defer if (capture_writer) |fd| {
        _ = linux.close(fd);
    };
    const command = try parseArgs(&.{
        "igvano",                                                                                                                    "--root", root, "exec", "example", "sh", "-c",
        "echo $$; cat /proc/self/cgroup; readlink /proc/self/ns/pid; test \"$(cat /proc/self/cgroup)\" = \"$(cat /proc/1/cgroup)\"",
    });
    // exec must also work while a different command owns the container lock.
    const lock_path = try std.fs.path.join(allocator, &.{ root, config.id, oci.lock_file_name });
    {
        var holder = try LockTestProcess.hold(lock_path);
        defer holder.deinit();
        try std.testing.expectEqual(@as(u8, 0), try execTestCommand(command, capture[1]));
    }
    _ = linux.close(capture[1]);
    capture_writer = null;
    var output: [4096]u8 = undefined;
    var used: usize = 0;
    while (used < output.len) {
        const read = linux.read(capture[0], output[used..].ptr, output.len - used);
        if (linux.errno(read) == .INTR) continue;
        if (linux.errno(read) != .SUCCESS) return error.ReadFailed;
        if (read == 0) break;
        used += read;
    }
    const first_newline = std.mem.indexOfScalar(u8, output[0..used], '\n') orelse return error.InvalidProcess;
    try std.testing.expect(try std.fmt.parseInt(u32, output[0..first_newline], 10) > 1);
    const ns_path = try std.fmt.allocPrint(allocator, "/proc/{d}/ns/pid", .{init_pid});
    var ns: [64]u8 = undefined;
    const ns_len = try cwd.readLink(io, ns_path, &ns);
    const ns_line = try std.fmt.allocPrint(allocator, "{s}\n", .{ns[0..ns_len]});
    try std.testing.expect(std.mem.endsWith(u8, output[0..used], ns_line));
    try std.testing.expect(std.mem.indexOf(u8, output[first_newline + 1 .. used], ":/\n") != null);
    const pid_file = try std.fs.path.join(allocator, &.{ base, "exec.pid" });
    for ([_]struct { script: []const u8, status: u8 }{
        .{ .script = "exit 0", .status = 0 },
        .{ .script = "exit 23", .status = 23 },
        .{ .script = "kill -TERM $$", .status = 143 },
    }) |case| {
        const exiting = try parseArgs(&.{ "igvano", "--root", root, "exec", "example", "sh", "-c", case.script });
        try std.testing.expectEqual(case.status, try execTestCommand(exiting, null));
        const detached_exiting = try parseArgs(&.{ "igvano", "--root", root, "exec", "--detach", "--pid-file", pid_file, "example", "sh", "-c", case.script });
        try std.testing.expectEqual(@as(u8, 0), try execTestCommand(detached_exiting, null));
        const detached_pid_text = try cwd.readFileAlloc(io, pid_file, allocator, .limited(32));
        const detached_pid = try std.fmt.parseInt(i32, detached_pid_text, 10);
        try std.testing.expectEqual(case.status, try waitExec(detached_pid));
    }
    {
        const ignored: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
        var previous: linux.Sigaction = undefined;
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sigaction(.PIPE, &ignored, &previous)));
        defer _ = linux.sigaction(.PIPE, &previous, null);
        const ignored_pipe = try parseArgs(&.{
            "igvano",                                                                                                                                 "--root", root, "exec", "--detach", "--pid-file", pid_file, "example", "sh", "-c",
            "while read key value rest; do case \"$key\" in SigIgn:) test $((0x$value & 4096)) -ne 0; exit;; esac; done < /proc/self/status; exit 1",
        });
        try std.testing.expectEqual(@as(u8, 0), try execTestCommand(ignored_pipe, null));
        const ignored_pid_text = try cwd.readFileAlloc(io, pid_file, allocator, .limited(32));
        try std.testing.expectEqual(@as(u8, 0), try waitExec(try std.fmt.parseInt(i32, ignored_pid_text, 10)));
    }
    const invalid = try parseArgs(&.{ "igvano", "--root", root, "exec", "example", "/igvano-missing-exec" });
    try std.testing.expectError(error.CreateFailed, execContainer(allocator, io, null, invalid));
    try std.testing.expectEqualStrings("exec: \"/igvano-missing-exec\": executable file not found in $PATH", diagnostics.last_container_detail.?);
    const process_file = try std.fs.path.join(allocator, &.{ base, "process.json" });
    try cwd.writeFile(io, .{
        .sub_path = process_file,
        .data = "{\"args\":[\"sleep\",\"120\"],\"env\":[\"PATH=/bin:/usr/bin\"],\"cwd\":\"/\",\"user\":{\"uid\":0,\"gid\":0}}",
    });
    const detached = try parseArgs(&.{ "igvano", "--root", root, "exec", "--process", process_file, "--detach", "--pid-file", pid_file, "example" });
    try std.testing.expectEqual(@as(u8, 0), try execTestCommand(detached, null));
    const pid_text = try cwd.readFileAlloc(io, pid_file, allocator, .limited(32));
    const exec_pid = try std.fmt.parseInt(i32, pid_text, 10);
    var exec_reaped = false;
    defer if (!exec_reaped) {
        _ = linux.kill(exec_pid, .KILL);
        _ = waitExec(exec_pid) catch {};
    };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(exec_pid, @enumFromInt(0))));
    const init_cgroup_path = try std.fmt.allocPrint(allocator, "/proc/{d}/cgroup", .{init_pid});
    const exec_cgroup_path = try std.fmt.allocPrint(allocator, "/proc/{d}/cgroup", .{exec_pid});
    const init_cgroup = try cwd.readFileAlloc(io, init_cgroup_path, allocator, .limited(4096));
    const exec_cgroup = try cwd.readFileAlloc(io, exec_cgroup_path, allocator, .limited(4096));
    try std.testing.expectEqualStrings(init_cgroup, exec_cgroup);
    _ = linux.kill(exec_pid, .KILL);
    _ = try waitExec(exec_pid);
    exec_reaped = true;

    const pause = try parseArgs(&.{ "igvano", "--root", root, "pause", "example" });
    const resume_config = try parseArgs(&.{ "igvano", "--root", root, "resume", "example" });
    try std.testing.expectError(error.InvalidStatus, pauseContainer(allocator, io, null, resume_config));
    try pauseContainer(allocator, io, null, pause);
    {
        const paused = try readLiveState(allocator, io, null, pause, false);
        defer paused.deinit();
        try std.testing.expectEqual(oci.Status.paused, paused.parsed.value.status);
        try std.testing.expect(try (frozen: {
            var instance = ContainerInstance.load(paused.container_state.?);
            break :frozen instance.container().frozen();
        }));
        try testUpdateResources(allocator, io, container, root, cgroup, base);
        try std.testing.expect(try (frozen: {
            var instance = ContainerInstance.load(paused.container_state.?);
            break :frozen instance.container().frozen();
        }));
        try std.testing.expectError(error.InvalidStatus, pauseContainer(allocator, io, null, pause));
        try std.testing.expectError(error.InvalidStatus, startContainer(allocator, io, null, config));
        try std.testing.expectError(error.InvalidStatus, execContainer(allocator, io, null, command));
        try std.testing.expectError(error.InvalidStatus, deleteContainer(allocator, io, null, config));
        const file = try cwd.createFile(io, ps_path, .{});
        defer file.close(io);
        try psContainer(allocator, io, null, ps, file);
        const paused_json = try cwd.readFileAlloc(io, ps_path, allocator, .limited(4096));
        const paused_pids = try std.json.parseFromSlice([]i32, allocator, paused_json, .{});
        defer paused_pids.deinit();
        try std.testing.expect(std.mem.indexOfScalar(i32, paused_pids.value, init_pid) != null);
        const signal_all = try parseArgs(&.{ "igvano", "--root", root, "kill", "--all", "example", "15" });
        try killContainer(allocator, io, null, signal_all);
        try std.testing.expect(try (frozen: {
            var instance = ContainerInstance.load(paused.container_state.?);
            break :frozen instance.container().frozen();
        }));
    }
    // PID namespace init ignores a default SIGTERM, so it stays running after thaw.
    try pauseContainer(allocator, io, null, resume_config);
    {
        const running = try readLiveState(allocator, io, null, config, false);
        defer running.deinit();
        try std.testing.expectEqual(oci.Status.running, running.parsed.value.status);
        try std.testing.expect(!try (frozen: {
            var instance = ContainerInstance.load(running.container_state.?);
            break :frozen instance.container().frozen();
        }));
        const file = try cwd.createFile(io, ps_path, .{});
        defer file.close(io);
        const table = try parseArgs(&.{ "igvano", "--root", root, "ps", "example", "-ef" });
        try psContainer(allocator, io, null, table, file);
        const text = try cwd.readFileAlloc(io, ps_path, allocator, .limited(4096));
        try std.testing.expect(std.mem.startsWith(u8, text, "UID"));
        try std.testing.expect(std.mem.indexOf(u8, text, try std.fmt.allocPrint(allocator, "{d}", .{init_pid})) != null);
        const custom = try parseArgs(&.{ "igvano", "--root", root, "ps", "example", "-o", "pid,comm", "-e" });
        const custom_file = try cwd.createFile(io, ps_path, .{});
        defer custom_file.close(io);
        try psContainer(allocator, io, null, custom, custom_file);
        const custom_text = try cwd.readFileAlloc(io, ps_path, allocator, .limited(4096));
        try std.testing.expect(std.mem.indexOf(u8, custom_text, "PID") != null);
        try std.testing.expect(std.mem.indexOf(u8, custom_text, "sleep") != null);
    }
    try pauseContainer(allocator, io, null, pause);
    config.subcommand = .delete;
    config.force = true;
    const deleting = std.Io.Clock.awake.now(io);
    try deleteContainer(allocator, io, null, config);
    try std.testing.expect(deleting.untilNow(io, .awake).nanoseconds < std.Io.Duration.fromSeconds(5).nanoseconds);
    _ = try waitExec(init_pid);
    init_reaped = true;
    try std.testing.expectError(error.FileNotFound, oci.loadState(allocator, io, root, config.id));
    // Each mode's own membership file disappears when all cgroup hierarchies are removed.
    var lines = std.mem.tokenizeScalar(u8, init_cgroup, '\n');
    while (lines.next()) |line| {
        const first = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidState;
        const second = std.mem.indexOfScalarPos(u8, line, first + 1, ':') orelse return error.InvalidState;
        const controllers = line[first + 1 .. second];
        if (std.mem.startsWith(u8, controllers, "name=")) continue;
        const hierarchy = if (controllers.len == 0) "/sys/fs/cgroup" else try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/{s}", .{controllers});
        const members_path = try std.fmt.allocPrint(allocator, "{s}/{s}/cgroup.procs", .{ hierarchy, cgroup });
        try std.testing.expectError(error.FileNotFound, cwd.openFile(io, members_path, .{}));
    }
    try std.testing.expectError(error.FileNotFound, execContainer(allocator, io, null, command));
}

fn testUpdateResources(allocator: std.mem.Allocator, io: std.Io, container: ?@import("../state.zig").ContainerOverride, root: []const u8, cgroup: []const u8, base: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const unified = std.os.linux.errno(std.os.linux.access("/sys/fs/cgroup/cgroup.controllers", std.os.linux.F_OK)) == .SUCCESS;
    const memory_path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{
        @as([]const u8, if (unified) "/sys/fs/cgroup" else "/sys/fs/cgroup/memory"),
        cgroup,
        @as([]const u8, if (unified) "memory.max" else "memory.limit_in_bytes"),
    });
    const pids_path = try std.fmt.allocPrint(allocator, "{s}/{s}/pids.max", .{
        @as([]const u8, if (unified) "/sys/fs/cgroup" else "/sys/fs/cgroup/pids"), cgroup,
    });
    const resource_file = try std.fs.path.join(allocator, &.{ base, "resources.json" });
    const update = try parseArgs(&.{ "igvano", "--root", root, "update", "--resources", resource_file, "example" });
    try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"memory\":{\"limit\":33554432},\"pids\":{\"limit\":50}}" });
    if (unified and std.os.linux.errno(std.os.linux.access("/sys/fs/cgroup/cgroup.type", std.os.linux.F_OK)) == .SUCCESS) {
        const procs = try readTestCgroup(allocator, io, "/sys/fs/cgroup/cgroup.procs");
        if (std.mem.trim(u8, procs, " \t\n").len != 0) {
            const controllers = try readTestCgroup(allocator, io, "/sys/fs/cgroup/cgroup.subtree_control");
            const kind = try readTestCgroup(allocator, io, "/sys/fs/cgroup/cgroup.type");
            try std.testing.expectError(error.CgroupWriteFailed, updateContainer(allocator, io, container, update));
            try std.testing.expect(std.mem.indexOf(u8, diagnostics.last_container_detail orelse return error.TestUnexpectedResult, "has processes") != null);
            try std.testing.expectEqualStrings(controllers, try readTestCgroup(allocator, io, "/sys/fs/cgroup/cgroup.subtree_control"));
            try std.testing.expectEqualStrings(kind, try readTestCgroup(allocator, io, "/sys/fs/cgroup/cgroup.type"));
            return;
        }
    }
    try updateContainer(allocator, io, container, update);
    try std.testing.expectEqualStrings("33554432", std.mem.trim(u8, try readTestCgroup(allocator, io, memory_path), " \t\n"));
    const memory_flag = try parseArgs(&.{ "igvano", "--root", root, "update", "--memory", "64m", "example" });
    try updateContainer(allocator, io, container, memory_flag);
    const memory = try readTestCgroup(allocator, io, memory_path);
    try std.testing.expectEqualStrings("67108864", std.mem.trim(u8, memory, " \t\n"));
    const pids = try readTestCgroup(allocator, io, pids_path);
    try std.testing.expectEqualStrings("50", std.mem.trim(u8, pids, " \t\n"));

    try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"cpu\":{\"shares\":512}}" });
    try updateContainer(allocator, io, container, update);
    const unchanged = try readTestCgroup(allocator, io, memory_path);
    try std.testing.expectEqualStrings(memory, unchanged);
    const unchanged_pids = try readTestCgroup(allocator, io, pids_path);
    try std.testing.expectEqualStrings(pids, unchanged_pids);
    const cpu_path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{
        @as([]const u8, if (unified) "/sys/fs/cgroup" else "/sys/fs/cgroup/cpu"),
        cgroup,
        @as([]const u8, if (unified) "cpu.weight" else "cpu.shares"),
    });
    const shares = try readTestCgroup(allocator, io, cpu_path);
    try std.testing.expectEqualStrings(if (unified) "20" else "512", std.mem.trim(u8, shares, " \t\n"));
    if (unified) {
        const max_path = try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/{s}/cpu.max", .{cgroup});
        try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"cpu\":{\"quota\":50000,\"period\":200000}}" });
        try updateContainer(allocator, io, container, update);
        try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"cpu\":{\"quota\":25000}}" });
        try updateContainer(allocator, io, container, update);
        const max = try readTestCgroup(allocator, io, max_path);
        try std.testing.expectEqualStrings("25000 200000", std.mem.trim(u8, max, " \t\n"));
        try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"memory\":{\"swap\":134217728}}" });
        try updateContainer(allocator, io, container, update);
        const swap_path = try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/{s}/memory.swap.max", .{cgroup});
        const swap = try readTestCgroup(allocator, io, swap_path);
        try std.testing.expectEqualStrings("67108864", std.mem.trim(u8, swap, " \t\n"));
        try std.testing.expectEqualStrings(memory, try readTestCgroup(allocator, io, memory_path));
    }
    try cwd.writeFile(io, .{ .sub_path = resource_file, .data = "{\"cpu\":{\"shares\":512}}" });
    // Model the shim's stdin request in a child so the test retains its stdin.
    const input = try cwd.openFile(io, resource_file, .{});
    defer input.close(io);
    const linux = std.os.linux;
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const child: i32 = @intCast(forked);
    if (child == 0) {
        if (linux.errno(linux.dup2(input.handle, 0)) != .SUCCESS) linux.exit_group(1);
        var threaded: std.Io.Threaded = .init_single_threaded;
        var stdin_update = update;
        stdin_update.resources_file = "-";
        updateContainer(std.heap.page_allocator, threaded.io(), container, stdin_update) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    try std.testing.expectEqual(@as(u8, 0), try waitExec(child));
    try std.testing.expectEqualStrings(memory, try readTestCgroup(allocator, io, memory_path));
}

fn testAttachedExec(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    const linux = std.os.linux;
    var capture: [2]std.posix.fd_t = undefined;
    if (linux.errno(linux.pipe2(&capture, .{ .CLOEXEC = true })) != .SUCCESS) return error.SystemResources;
    defer for (capture) |fd| {
        _ = linux.close(fd);
    };
    // wait is interruptible, so the TERM trap need not wait for sleep to finish.
    const command = try parseArgs(&.{ "igvano", "--root", root, "exec", "example", "sh", "-c", "trap 'exit 42' TERM; echo ready; sleep 100 & wait" });
    const runner = std.posix.system.fork();
    if (std.posix.errno(runner) != .SUCCESS) return error.SystemResources;
    const runner_pid: i32 = @intCast(runner);
    if (runner_pid == 0) {
        if (linux.errno(linux.dup2(capture[1], 1)) != .SUCCESS) linux.exit_group(1);
        var threaded: std.Io.Threaded = .init_single_threaded;

        const status = execContainer(std.heap.page_allocator, threaded.io(), null, command) catch linux.exit_group(1);
        linux.exit_group(status);
    }
    var runner_reaped = false;
    defer if (!runner_reaped) {
        _ = linux.kill(runner_pid, .KILL);
        _ = waitExec(runner_pid) catch {};
    };
    var poll = [_]linux.pollfd{.{ .fd = capture[0], .events = linux.POLL.IN, .revents = 0 }};
    var ready: [6]u8 = undefined;
    var ready_used: usize = 0;
    while (ready_used < ready.len) {
        try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll, 5000));
        const count = linux.read(capture[0], ready[ready_used..].ptr, ready.len - ready_used);
        switch (linux.errno(count)) {
            .SUCCESS => if (count == 0) return error.ReadFailed else {
                ready_used += count;
            },
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
    try std.testing.expectEqualStrings("ready\n", &ready);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(runner_pid, .TERM)));
    try std.testing.expectEqual(@as(u8, 42), try waitTestExec(io, runner_pid));
    runner_reaped = true;

    const terminal = try testPtyPair();
    defer for (terminal) |fd| {
        _ = linux.close(fd);
    };
    const original = try std.posix.tcgetattr(terminal[1]);
    const original_flags = linux.fcntl(terminal[1], linux.F.GETFL, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(original_flags));
    var size: std.posix.winsize = .{ .row = 24, .col = 80, .xpixel = 0, .ypixel = 0 };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.ioctl(terminal[1], linux.T.IOCSWINSZ, @intFromPtr(&size))));
    const tty_command = try parseArgs(&.{ "igvano", "--root", root, "exec", "-t", "example", "sh", "-c", "tty; read first; stty size; echo initial; read answer; stty size; echo answer=$answer" });
    const tty_runner = std.posix.system.fork();
    if (std.posix.errno(tty_runner) != .SUCCESS) return error.SystemResources;
    const tty_pid: i32 = @intCast(tty_runner);
    if (tty_pid == 0) {
        _ = linux.close(terminal[0]);
        if (linux.errno(linux.dup2(terminal[1], 0)) != .SUCCESS or linux.errno(linux.dup2(terminal[1], 1)) != .SUCCESS) linux.exit_group(1);
        var threaded: std.Io.Threaded = .init_single_threaded;

        const status = execContainer(std.heap.page_allocator, threaded.io(), null, tty_command) catch linux.exit_group(1);
        linux.exit_group(status);
    }
    var tty_reaped = false;
    defer if (!tty_reaped) {
        _ = linux.kill(tty_pid, .KILL);
        _ = waitExec(tty_pid) catch {};
    };
    try std.testing.expectEqual(@as(usize, 6), linux.write(terminal[0], "start\n", 6));
    var output: [4096]u8 = undefined;
    var used: usize = 0;
    var resized = false;
    while (std.mem.indexOf(u8, output[0..used], "answer=hello") == null) {
        poll[0].fd = terminal[0];
        try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll, 5000));
        const count = linux.read(terminal[0], output[used..].ptr, output.len - used);
        if (linux.errno(count) != .SUCCESS or count == 0) return error.ReadFailed;
        used += count;
        if (used == output.len) return error.StreamTooLong;
        if (!resized and std.mem.indexOf(u8, output[0..used], "initial") != null) {
            try std.testing.expectEqual(original_flags, linux.fcntl(terminal[1], linux.F.GETFL, 0));
            size.row = 40;
            size.col = 100;
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.ioctl(terminal[1], linux.T.IOCSWINSZ, @intFromPtr(&size))));
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(tty_pid, .WINCH)));
            try std.testing.expectEqual(@as(usize, 6), linux.write(terminal[0], "hello\n", 6));
            resized = true;
        }
    }
    try std.testing.expect(std.mem.indexOf(u8, output[0..used], "/dev/pts/") != null);
    try std.testing.expect(std.mem.indexOf(u8, output[0..used], "24 80") != null);
    try std.testing.expect(std.mem.indexOf(u8, output[0..used], "40 100") != null);
    try std.testing.expectEqual(@as(u8, 0), try waitTestExec(io, tty_pid));
    tty_reaped = true;
    const restored = try std.posix.tcgetattr(terminal[1]);
    try std.testing.expectEqual(original.lflag, restored.lflag);
    try std.testing.expectEqual(original.iflag, restored.iflag);
    try std.testing.expectEqual(original.oflag, restored.oflag);
    const closed_stdin = try parseArgs(&.{ "igvano", "--root", root, "exec", "-t", "example", "true" });
    const closed_runner = std.posix.system.fork();
    if (std.posix.errno(closed_runner) != .SUCCESS) return error.SystemResources;
    const closed_pid: i32 = @intCast(closed_runner);
    if (closed_pid == 0) {
        for ([_]std.posix.fd_t{ 0, 1, 2 }) |fd| _ = linux.close(fd);
        var threaded: std.Io.Threaded = .init_single_threaded;

        const status = execContainer(std.heap.page_allocator, threaded.io(), null, closed_stdin) catch linux.exit_group(1);
        linux.exit_group(status);
    }
    try std.testing.expectEqual(@as(u8, 0), try waitExec(closed_pid));

    const detached = try parseArgs(&.{ "igvano", "--root", root, "exec", "--detach", "-t", "example", "tty" });
    try std.testing.expectError(error.MissingConsoleSocket, execContainer(allocator, io, null, detached));
}

test "attached wait drains buffered output after PTY hangup" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const terminal = try testPtyPair();
    defer _ = linux.close(terminal[0]);
    var replica: ?std.posix.fd_t = terminal[1];
    defer if (replica) |fd| {
        _ = linux.close(fd);
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const output = try tmp.dir.createFile(std.testing.io, "output", .{});
    defer output.close(std.testing.io);
    var signals = try attached.Signals.init();
    defer signals.deinit();
    const expected = [_]u8{'x'} ** 6000;
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        if (linux.write(terminal[1], &expected, expected.len) != expected.len) linux.exit_group(1);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitExec(pid) catch {};
    };
    _ = linux.close(replica.?);
    replica = null;
    // Ensure all output and the hangup are queued before supervision starts.
    var info: linux.siginfo_t = undefined;
    while (true) {
        switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT, null))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    try std.testing.expectEqual(@as(u8, 0), try attached.wait(pid, &reaped, &signals, terminal[0], -1, output.handle));
    try std.testing.expect(reaped);
    const actual = try tmp.dir.readFileAlloc(std.testing.io, "output", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(&expected, actual);
}

test "attached wait reports reaping even when output draining fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const terminal = try testPtyPair();
    defer _ = linux.close(terminal[0]);
    var replica: ?std.posix.fd_t = terminal[1];
    defer if (replica) |fd| {
        _ = linux.close(fd);
    };
    var output: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&output, .{ .CLOEXEC = true })));
    defer _ = linux.close(output[1]);
    var reader: ?std.posix.fd_t = output[0];
    defer if (reader) |fd| {
        _ = linux.close(fd);
    };
    var signals = try attached.Signals.init();
    defer signals.deinit();
    const forked = std.posix.system.fork();
    if (std.posix.errno(forked) != .SUCCESS) return error.SystemResources;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        if (linux.write(terminal[1], "ready\n", 6) != 6) linux.exit_group(1);
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        _ = waitExec(pid) catch {};
    };
    _ = linux.close(replica.?);
    replica = null;
    // Leave an exited zombie for attached.wait to collect before it drains the
    // PTY into a pipe without a reader, which deterministically produces EPIPE.
    var info: linux.siginfo_t = undefined;
    while (true) {
        switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT, null))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    _ = linux.close(reader.?);
    reader = null;
    try std.testing.expectError(error.ConsoleWriteFailed, attached.wait(pid, &reaped, &signals, terminal[0], -1, output[1]));
    try std.testing.expect(reaped);
}

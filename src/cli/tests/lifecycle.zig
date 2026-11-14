const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Subcommand = @import("../args.zig").Subcommand;
const Config = @import("../args.zig").Config;
const parseArgs = @import("../args.zig").parseArgs;
const readLiveState = @import("../state.zig").readLiveState;
const createContainer = @import("../create.zig").createContainer;
const makeExecFifo = @import("../create.zig").makeExecFifo;
const startContainer = @import("../start.zig").startContainer;
const killContainer = @import("../kill.zig").killContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const saveTestStarttime = @import("helpers.zig").saveTestStarttime;

test "linux lifecycle waits for exec FIFO EOF and persists running then stopped" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
        ,
    });
    const relative = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(relative);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, relative, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const fifo = try std.fs.path.join(std.testing.allocator, &.{ root, "example", oci.exec_fifo_name });
    defer std.testing.allocator.free(fifo);
    const fifo_z = try std.testing.allocator.dupeZ(u8, fifo);
    defer std.testing.allocator.free(fifo_z);
    const poststart_input = try std.fs.path.join(std.testing.allocator, &.{ root, "poststart-input" });
    defer std.testing.allocator.free(poststart_input);
    try makeExecFifo(std.testing.allocator, fifo);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        // Model an init waiting for the frontend's start handshake, without chroot.
        const opened = linux.open(fifo_z, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) linux.exit_group(1);
        const fd: posix.fd_t = @intCast(opened);
        if (posix.system.write(fd, &[_]u8{1}, 1) != 1) linux.exit_group(1);
        const argv = [_:null]?[*:0]const u8{ "/bin/sleep", "60" };
        const envp = [_:null]?[*:0]const u8{};
        _ = linux.execve("/bin/sleep", &argv, &envp);
        _ = linux.write(fd, &.{0}, 1);
        linux.exit_group(1);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        _ = posix.system.waitpid(pid, &status, 0);
    };
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = pid,
        .bundle = bundle,
    });
    try saveTestStarttime(root, pid);

    const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
    try killContainer(std.testing.allocator, std.testing.io, null, .{ .root = root, .subcommand = .kill, .id = "example", .signal = "0" });
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststart-source", .{root});
    defer std.testing.allocator.free(output_env);
    const input_env = try std.fmt.allocPrint(std.testing.allocator, "INPUT={s}", .{poststart_input});
    defer std.testing.allocator.free(input_env);
    const saved_hooks: oci.Spec.Hooks = .{
        .poststart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "/bin/cat > \"$INPUT\" && printf saved > \"$OUT\"" },
            .env = &.{ output_env, input_env },
        }},
    };
    const hook_json = try std.json.Stringify.valueAlloc(std.testing.allocator, saved_hooks, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(hook_json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = hook_json });
    // A replaced bundle must not change the hooks captured at create.
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}},"hooks":{"prestart":[{"path":"/igvano-missing-hook"}],"poststart":[{"path":"/igvano-missing-hook"}]}}
        ,
    });
    try startContainer(std.testing.allocator, std.testing.io, null, config);
    const input = try tmp.dir.readFileAlloc(std.testing.io, "poststart-input", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(input);
    const hook_state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
    defer hook_state.deinit();
    try std.testing.expectEqual(oci.Status.running, hook_state.value.status);
    try std.testing.expectEqual(@as(?i32, pid), hook_state.value.pid);
    const hook_output = try tmp.dir.readFileAlloc(std.testing.io, "poststart-source", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(hook_output);
    try std.testing.expectEqualStrings("saved", hook_output);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{}));
    const running = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer running.deinit();
    try std.testing.expectEqual(oci.Status.running, running.value.status);
    try std.testing.expectError(error.InvalidStatus, startContainer(std.testing.allocator, std.testing.io, null, config));
    try std.testing.expectError(error.InvalidStatus, deleteContainer(std.testing.allocator, std.testing.io, null, config));
    try killContainer(std.testing.allocator, std.testing.io, null, .{ .root = root, .subcommand = .kill, .id = "example", .signal = "SIGKILL" });
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    reaped = true;
    const stopped = try readLiveState(std.testing.allocator, std.testing.io, null, config, true);
    defer stopped.deinit();
    try std.testing.expectEqual(oci.Status.stopped, stopped.parsed.value.status);
    const persisted = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer persisted.deinit();
    try std.testing.expectEqual(oci.Status.stopped, persisted.value.status);
    try std.testing.expectError(error.ContainerNotRunning, killContainer(std.testing.allocator, std.testing.io, null, config));
    try deleteContainer(std.testing.allocator, std.testing.io, null, config);
    try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
}

test "linux kill all succeeds on stopped containers while plain kill fails" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const relative = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(relative);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, relative, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const forked = posix.system.fork();
    if (posix.errno(forked) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        const delay: linux.timespec = .{ .sec = 60, .nsec = 0 };
        while (true) _ = linux.nanosleep(&delay, null);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        _ = posix.system.waitpid(pid, &status, 0);
    };
    try saveTestStarttime(root, pid);
    _ = linux.kill(pid, .KILL);
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    reaped = true;

    const all = try parseArgs(&.{ "igvano", "--root", root, "kill", "--all", "example", "9" });
    const plain = try parseArgs(&.{ "igvano", "--root", root, "kill", "example", "9" });
    for ([_]oci.Status{ .created, .running, .stopped }) |saved_status| {
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .pid = pid,
            .status = saved_status,
            .bundle = "/unused",
        });
        try killContainer(std.testing.allocator, std.testing.io, null, all);
        try std.testing.expectError(error.ContainerNotRunning, killContainer(std.testing.allocator, std.testing.io, null, plain));
    }
}

test "start uses saved process presence after bundle config changes" {
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return true;
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque) libcontainer.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const start_result: ?anyerror = if (builtin.os.tag == .linux) null else error.NotImplemented;
    const cases = [_]struct { process: ?[]const u8, json: []const u8, failure: ?anyerror }{
        .{ .process = "true\n", .json = "garbage", .failure = start_result },
        .{ .process = " \ttrue\r\n", .json = "garbage", .failure = start_result },
        .{ .process = "true\n", .json = "{}", .failure = start_result },
        .{ .process = "true\n", .json = "{\"ociVersion\":\"1.0.2\",\"root\":{\"path\":\"/\"}}", .failure = start_result },
        .{ .process = "false\n", .json = "{\"ociVersion\":\"1.0.2\",\"root\":{\"path\":\"/\"},\"process\":{\"args\":[\"/bin/sh\"],\"cwd\":\"/\",\"user\":{\"uid\":0,\"gid\":0}}}", .failure = error.MissingProcess },
        .{ .process = "false\n", .json = "garbage", .failure = error.MissingProcess },
        .{ .process = " \tfalse\r\n", .json = "garbage", .failure = error.MissingProcess },
        .{ .process = "garbage\n", .json = "garbage", .failure = error.InvalidState },
        .{ .process = "", .json = "garbage", .failure = error.InvalidState },
        .{ .process = "x" ** 33, .json = "garbage", .failure = error.InvalidState },
        .{ .process = null, .json = "garbage", .failure = start_result },
    };
    var implementation: TestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
    for (cases) |case| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        defer tmp.dir.deleteTree(std.testing.io, "example") catch {};
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = case.json });
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .created,
            .pid = 1234,
            .bundle = bundle,
        });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
        if (case.process) |value|
            try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/process", .data = value });
        // A buffered acknowledgement exercises start without a real init process.
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        if (case.failure) |failure| {
            try std.testing.expectError(failure, startContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config));
        } else {
            try startContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
            const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer state.deinit();
            try std.testing.expectEqual(oci.Status.running, state.value.status);
        }
    }
}

test "linux start preserves process presence captured at create" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(_: *anyopaque, options: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            if (options.on_create) |callback| try callback.run(callback.ptr, .{
                .id = options.id,
                .pid = 1234,
                .starttime = "12345",
            });
            return .{ .id = options.id, .pid = 1234, .starttime = try options.allocator.dupe(u8, "12345") };
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return true;
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque) libcontainer.Error!void {
            return error.NotImplemented;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: TestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    for ([_]bool{ false, true }) |has_process| {
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "." },
            .linux = .{ .namespaces = &.{.{ .type = .mount }} },
            .process = if (has_process) .{ .args = &.{"/bin/sh"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } } else null,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        try createContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{
            .root = root,
            .subcommand = .create,
            .id = "example",
            .bundle = bundle,
        });
        defer tmp.dir.deleteTree(std.testing.io, "example") catch {};
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = "bundle/config.json",
            .data = if (has_process) "garbage" else
                \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
            ,
        });
        try tmp.dir.deleteFile(std.testing.io, "example/exec.fifo");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const config: Config = .{ .root = root, .subcommand = .start, .id = "example" };
        if (has_process) {
            try startContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
            const state = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer state.deinit();
            try std.testing.expectEqual(oci.Status.running, state.value.status);
        } else {
            try std.testing.expectError(error.MissingProcess, startContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config));
        }
    }
}

test "linux state kill and delete refresh stale creating created and running states" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const posix = std.posix;
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) linux.exit_group(0);
    var child_status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &child_status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);

    for ([_]oci.Status{ .creating, .created, .running, .paused }) |status| {
        for ([_]Subcommand{ .state, .kill, .delete }) |subcommand| {
            try tmp.dir.createDirPath(std.testing.io, "example");
            try oci.saveState(std.testing.allocator, std.testing.io, root, .{
                .id = "example",
                .status = status,
                .pid = pid,
                .bundle = "/bundle",
            });
            try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
            const config: Config = .{ .root = root, .subcommand = subcommand, .id = "example" };
            switch (subcommand) {
                .state => {
                    const state = try readLiveState(std.testing.allocator, std.testing.io, null, config, true);
                    defer state.deinit();
                    try std.testing.expectEqual(oci.Status.stopped, state.parsed.value.status);
                },
                .kill => try std.testing.expectError(error.ContainerNotRunning, killContainer(std.testing.allocator, std.testing.io, null, config)),
                .delete => {
                    try deleteContainer(std.testing.allocator, std.testing.io, null, config);
                    try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
                    continue;
                },
                else => unreachable,
            }
            const persisted = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer persisted.deinit();
            try std.testing.expectEqual(oci.Status.stopped, persisted.value.status);
        }
    }
}

test "creating state without a process identity becomes stopped and deletable" {
    defer oci.clearDiagnostic();
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque) libcontainer.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const handle = self.state;
            return std.mem.eql(u8, handle.starttime, "alive");
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque) libcontainer.Error!void {}
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    var implementation: TestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &TestContainer.vtable };
    for ([_]?i32{ null, 1234 }) |pid| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .creating,
            .pid = pid,
            .bundle = "/bundle",
        });
        const config: Config = .{ .root = root, .id = "example", .subcommand = .delete };
        const state = try readLiveState(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config, true);
        defer state.deinit();
        try std.testing.expectEqual(oci.Status.stopped, state.parsed.value.status);
        try std.testing.expect(oci.diagnostic() == null);
        try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    }
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .creating,
        .pid = 1234,
        .bundle = "/bundle",
    });
    const state = try readLiveState(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{
        .root = root,
        .id = "example",
        .subcommand = .state,
    }, true);
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.creating, state.parsed.value.status);
}

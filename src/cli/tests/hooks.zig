const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Backend = libcontainer.Backend;
const readLiveState = @import("../state.zig").readLiveState;
const createContainer = @import("../create.zig").createContainer;
const CreateContext = @import("../create.zig").CreateContext;
const makeExecFifo = @import("../create.zig").makeExecFifo;
const startContainer = @import("../start.zig").startContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const saveTestStarttime = @import("helpers.zig").saveTestStarttime;

test "linux create callback runs only createRuntime with creating state" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const state_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "example" });
    defer std.testing.allocator.free(state_dir);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/order", .{root});
    defer std.testing.allocator.free(output_env);
    var state: oci.State = .{ .id = "example", .status = .creating, .bundle = "/bundle" };
    var context: CreateContext = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .root = root,
        .state_dir = state_dir,
        .state = &state,
        .hooks = .{
            .prestart = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "printf prestart >> \"$OUT\"" },
                .env = &.{output_env},
                .timeout = 2,
            }},
            .createRuntime = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"creating\"'*'\"pid\":1234'*) printf createRuntime >> \"$OUT\";; *) exit 1;; esac" },
                .env = &.{output_env},
                .timeout = 2,
            }},
        },
    };
    try CreateContext.run(&context, .{ .id = "example", .pid = 1234, .starttime = "12345" });
    const order = try tmp.dir.readFileAlloc(std.testing.io, "order", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(order);
    try std.testing.expectEqualStrings("createRuntime", order);
    const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer saved.deinit();
    try std.testing.expectEqual(oci.Status.creating, saved.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), saved.value.pid);
}

test "linux failed create runs poststop after removing runtime state" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        killed: bool = false,
        deleted: bool = false,
        fail_create: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        fn create(ptr: *anyopaque, options: Backend.CreateOptions) Backend.Error!Backend.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.fail_create) return error.HookFailed;
            const handle: Backend.Handle = .{ .id = options.id, .pid = 1234, .starttime = "12345" };
            if (options.on_create) |callback| callback.run(callback.ptr, handle) catch |err| {
                // A backend owns cleanup when its parent callback aborts create.
                try kill(ptr, handle, 9);
                try delete(ptr, handle);
                return err;
            };
            return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return true;
        }
        fn kill(ptr: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = true;
        }
        fn delete(ptr: *anyopaque, _: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop-input", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    const hook: oci.Spec.Hook = .{
        .path = "/bin/sh",
        .args = &.{ "sh", "-c", "test \"$ONLY\" = hook || exit 0; IFS= read -r state; case \"$state\" in *'\"status\":\"creating\"'*'\"pid\":1234'*) exit 7;; esac" },
        .env = &.{"ONLY=hook"},
        .timeout = 2,
    };
    const spec: oci.Spec = .{
        .ociVersion = "1.0.2",
        .root = .{ .path = "." },
        .linux = .{ .namespaces = &.{.{ .type = .mount }} },
        .hooks = .{
            .createRuntime = &.{hook},
            .poststop = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
                .env = &.{ output_env, state_env },
                .timeout = 2,
            }},
        },
    };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ base, "bundle" });
    defer std.testing.allocator.free(bundle);
    for ([_]bool{ false, true }) |fail_create| {
        var implementation: TestBackend = .{ .fail_create = fail_create };
        try std.testing.expectError(error.HookFailed, createContainer(std.testing.allocator, std.testing.io, .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        }, .{ .root = base, .subcommand = .create, .id = "example", .bundle = bundle }));
        try std.testing.expectEqual(!fail_create, implementation.killed and implementation.deleted);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
        const input = try tmp.dir.readFileAlloc(std.testing.io, "poststop-input", std.testing.allocator, .limited(4096));
        defer std.testing.allocator.free(input);
        const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
        defer state.deinit();
        try std.testing.expectEqual(oci.Status.stopped, state.value.status);
        try std.testing.expectEqualStrings("example", state.value.id);
        try std.testing.expectEqual(@as(?i32, if (fail_create) null else 1234), state.value.pid);
        try tmp.dir.deleteFile(std.testing.io, "poststop-input");
    }
}

test "linux poststop runs after stopped-container deletion despite a missing bundle and earlier hook failure" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestBackend = struct {
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            return false;
        }
        fn kill(_: *anyopaque, _: Backend.Handle, _: i32) Backend.Error!void {
            return error.NotImplemented;
        }
        fn delete(_: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            if (handle.pid != 1234) return error.InvalidProcess;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/hook-state", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    const configured: oci.Spec.Hooks = .{ .poststop = &.{
        .{ .path = "/igvano-missing-hook" },
        .{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
            .env = &.{ output_env, state_env },
            .timeout = 2,
        },
    } };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .pid = 1234,
        .status = .stopped,
        .bundle = "/igvano-missing-bundle",
    });
    var implementation: TestBackend = .{};
    try deleteContainer(std.testing.allocator, std.testing.io, .{
        .ptr = &implementation,
        .vtable = &TestBackend.vtable,
    }, .{ .root = root, .id = "example", .subcommand = .delete });
    const input = try tmp.dir.readFileAlloc(std.testing.io, "hook-state", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(input);
    const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.stopped, state.value.status);
    try std.testing.expectEqualStrings("example", state.value.id);
    try std.testing.expectEqual(@as(?i32, 1234), state.value.pid);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "linux prestart receives created state before init unblocks and poststart runs" {
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
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const fifo = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/example/exec.fifo", .{root}, 0);
    defer std.testing.allocator.free(fifo);
    try makeExecFifo(std.testing.allocator, fifo);
    const output = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/order", .{root}, 0);
    defer std.testing.allocator.free(output);
    const result = posix.system.fork();
    if (posix.errno(result) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(result);
    if (pid == 0) {
        // Opening the write end models init's block before executing the program.
        const fd = linux.open(fifo, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) linux.exit_group(1);
        const order = linux.open(output, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(order) != .SUCCESS) linux.exit_group(2);
        if (linux.errno(linux.write(@intCast(order), " init", 5)) != .SUCCESS) linux.exit_group(3);
        if (linux.errno(linux.write(@intCast(fd), &.{1}, 1)) != .SUCCESS) linux.exit_group(4);
        const argv = [_:null]?[*:0]const u8{"/bin/true"};
        const envp = [_:null]?[*:0]const u8{};
        _ = linux.execve("/bin/true", &argv, &envp);
        _ = linux.write(@intCast(fd), &.{0}, 1);
        linux.exit_group(5);
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
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}", .{output});
    defer std.testing.allocator.free(output_env);
    const pid_env = try std.fmt.allocPrint(std.testing.allocator, "PID={d}", .{pid});
    defer std.testing.allocator.free(pid_env);
    const configured: oci.Spec.Hooks = .{
        .prestart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"created\"'*'\"pid\":'\"$PID\"*) test ! -e \"$OUT\" && printf prestart > \"$OUT\";; *) exit 1;; esac" },
            .env = &.{ output_env, pid_env },
            .timeout = 2,
        }},
        .poststart = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "IFS= read -r state; case \"$state\" in *'\"status\":\"running\"'*'\"pid\":'\"$PID\"*) printf ' poststart' >> \"$OUT\";; *) exit 1;; esac" },
            .env = &.{ output_env, pid_env },
            .timeout = 2,
        }},
    };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
    defer std.testing.allocator.free(json);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
    var implementation: libcontainer.LinuxBackend = .{};
    try startContainer(std.testing.allocator, std.testing.io, implementation.backend(), .{
        .root = root,
        .id = "example",
        .subcommand = .start,
    });
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    reaped = true;
    try std.testing.expectEqual(@as(@TypeOf(status), 0), status);
    const order = try tmp.dir.readFileAlloc(std.testing.io, "order", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(order);
    try std.testing.expectEqualStrings("prestart init poststart", order);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{}));
}

test "prestart failure kills init and destroys runtime state" {
    const TestBackend = struct {
        checks: usize = 0,
        killed: bool = false,
        signal: ?i32 = null,
        deleted: bool = false,
        const vtable: Backend.VTable = .{ .create = create, .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        fn create(_: *anyopaque, _: Backend.CreateOptions) Backend.Error!Backend.Handle {
            return error.NotImplemented;
        }
        fn alive(ptr: *anyopaque, _: Backend.Handle) Backend.Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.checks += 1;
            return !self.killed;
        }
        fn kill(ptr: *anyopaque, _: Backend.Handle, signal: i32) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = true;
            self.signal = signal;
            // A cleanup error must not replace the hook failure.
            return error.KillFailed;
        }
        fn delete(ptr: *anyopaque, handle: Backend.Handle) Backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.killed or handle.pid != 1234 or
                !std.mem.eql(u8, handle.cgroup_path orelse return error.InvalidPath, "custom/persisted"))
                return error.CgroupDeleteFailed;
            self.deleted = true;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"process":{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop-state", .{root});
    defer std.testing.allocator.free(output_env);
    const state_env = try std.fmt.allocPrint(std.testing.allocator, "STATE_DIR={s}/example", .{root});
    defer std.testing.allocator.free(state_env);
    for ([_]struct { json: []const u8, failure: anyerror }{
        .{ .json = "{\"prestart\":[{\"path\":\"relative-hook\"}]}", .failure = error.InvalidConfig },
        .{ .json = "{\"prestart\":[{\"path\":\"/igvano-missing-hook\"}]}", .failure = if (builtin.os.tag == .linux) error.HookFailed else error.NotImplemented },
    }) |case| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = .created,
            .pid = 1234,
            .bundle = bundle,
        });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "12345" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/cgroup", .data = "custom/persisted" });
        // A buffered acknowledgement makes an accidental start succeed on Linux.
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const hooks = try std.json.parseFromSlice(oci.Spec.Hooks, std.testing.allocator, case.json, .{});
        defer hooks.deinit();
        var configured = hooks.value;
        configured.poststop = &.{.{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
            .env = &.{ output_env, state_env },
            .timeout = 2,
        }};
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, configured, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/hooks.json", .data = json });
        var implementation: TestBackend = .{};
        const backend: Backend = .{
            .ptr = &implementation,
            .vtable = &TestBackend.vtable,
        };
        try std.testing.expectError(case.failure, startContainer(std.testing.allocator, std.testing.io, backend, .{
            .root = root,
            .id = "example",
            .subcommand = .start,
        }));
        try std.testing.expect(implementation.killed);
        try std.testing.expectEqual(@as(?i32, 9), implementation.signal);
        try std.testing.expect(implementation.deleted);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
        try std.testing.expectError(error.FileNotFound, readLiveState(std.testing.allocator, std.testing.io, backend, .{
            .root = root,
            .id = "example",
            .subcommand = .state,
        }, true));
        if (comptime builtin.os.tag == .linux) {
            const input = try tmp.dir.readFileAlloc(std.testing.io, "poststop-state", std.testing.allocator, .limited(4096));
            defer std.testing.allocator.free(input);
            const stopped = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
            defer stopped.deinit();
            try std.testing.expectEqual(oci.Status.stopped, stopped.value.status);
            try std.testing.expectEqual(@as(?i32, 1234), stopped.value.pid);
            try tmp.dir.deleteFile(std.testing.io, "poststop-state");
        }
    }
}

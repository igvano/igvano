const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const readLiveState = @import("../state.zig").readLiveState;
const createContainer = @import("../create.zig").createContainer;
const CreateContext = @import("../create.zig").CreateContext;
const makeExecFifo = @import("../create.zig").makeExecFifo;
const startContainer = @import("../start.zig").startContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const saveTestStarttime = @import("helpers.zig").saveTestStarttime;

test "linux create callback runs prestart then createRuntime with creating state" {
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
    try std.testing.expectEqualStrings("prestartcreateRuntime", order);
    const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer saved.deinit();
    try std.testing.expectEqual(oci.Status.creating, saved.value.status);
    try std.testing.expectEqual(@as(?i32, 1234), saved.value.pid);
}

test "linux failed create runs poststop after removing runtime state" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        killed: bool = false,
        deleted: bool = false,
        fail_create: bool = false,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(ptr: *anyopaque, options: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.fail_create) return error.HookFailed;
            const handle: libcontainer.State = .{ .id = options.id, .pid = 1234, .starttime = "12345" };
            if (options.on_create) |callback| callback.run(callback.ptr, handle) catch |err| {
                // A container owns cleanup when its parent callback aborts create.
                try kill(ptr, 9);
                try delete(ptr);
                return err;
            };
            return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return true;
        }
        fn kill(ptr: *anyopaque, _: i32) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.killed = true;
        }
        fn delete(ptr: *anyopaque) libcontainer.Error!void {
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
        var implementation: TestContainer = .{ .fail_create = fail_create };
        try std.testing.expectError(error.HookFailed, createContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, .{
            .ptr = &implementation,
            .vtable = &TestContainer.vtable,
        }), .{ .root = base, .subcommand = .create, .id = "example", .bundle = bundle }));
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

test "linux poststop runs after stopped-container deletion despite a missing bundle, and a failure fails delete" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        const vtable: libcontainer.Container.VTable = .{ .alive = alive, .kill = kill, .killAll = kill, .delete = delete };
        pub fn create(_: *anyopaque, _: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            return error.NotImplemented;
        }
        fn alive(_: *anyopaque) libcontainer.Error!bool {
            return false;
        }
        fn kill(_: *anyopaque, _: i32) libcontainer.Error!void {
            return error.NotImplemented;
        }
        fn delete(ptr: *anyopaque) libcontainer.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const handle = self.state;
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
        .{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "test ! -e \"$STATE_DIR\" && /bin/cat > \"$OUT\"" },
            .env = &.{ output_env, state_env },
            .timeout = 2,
        },
        .{ .path = "/igvano-missing-hook" },
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
    var implementation: TestContainer = .{};
    // Like runc: state is gone, the failing poststop hook fails delete.
    try std.testing.expectError(error.HookFailed, deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, .{
        .ptr = &implementation,
        .vtable = &TestContainer.vtable,
    }), .{ .root = root, .id = "example", .subcommand = .delete }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    const input = try tmp.dir.readFileAlloc(std.testing.io, "hook-state", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(input);
    const state = try std.json.parseFromSlice(oci.State, std.testing.allocator, input, .{});
    defer state.deinit();
    try std.testing.expectEqual(oci.Status.stopped, state.value.status);
    try std.testing.expectEqualStrings("example", state.value.id);
    try std.testing.expectEqual(@as(?i32, 1234), state.value.pid);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "linux start unblocks init and then runs poststart with running state" {
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

    try startContainer(std.testing.allocator, std.testing.io, null, .{
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
    try std.testing.expectEqualStrings(" init poststart", order);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "example/exec.fifo", .{}));
}

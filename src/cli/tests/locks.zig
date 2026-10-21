const std = @import("std");
const overrideContainer = @import("helpers.zig").overrideContainer;
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const Subcommand = @import("../args.zig").Subcommand;
const Config = @import("../args.zig").Config;
const openContainerLock = @import("../state.zig").openContainerLock;
const deleteStateDirectory = @import("../state.zig").deleteStateDirectory;
const readLiveState = @import("../state.zig").readLiveState;
const createContainer = @import("../create.zig").createContainer;
const CreateContext = @import("../create.zig").CreateContext;
const killContainer = @import("../kill.zig").killContainer;
const deleteContainer = @import("../delete.zig").deleteContainer;
const destroyContainer = @import("../delete.zig").destroyContainer;
const LockTestContainer = @import("helpers.zig").LockTestContainer;
const LockTestProcess = @import("helpers.zig").LockTestProcess;
const saveTestStarttime = @import("helpers.zig").saveTestStarttime;

test "linux held lock lets state report stopped without persisting recovery" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "dead" });
    for ([_]oci.Status{ .creating, .created, .running }) |status| {
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = status,
            .pid = if (status == .creating) null else 1234,
            .bundle = "/bundle",
        });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        const config: Config = .{ .root = root, .id = "example", .subcommand = .state };
        var command = try LockTestProcess.command(config, null);
        defer command.deinit();
        var output: [4096]u8 = undefined;
        var len: usize = 0;
        while (true) {
            try std.testing.expect(try command.readable(2000));
            const count = try std.posix.read(command.fd, output[len..]);
            if (count == 0) break;
            len += count;
        }
        try command.wait();
        try std.testing.expect(len > 1 and output[len - 1] == 1);
        const reported = try std.json.parseFromSlice(oci.State, std.testing.allocator, output[0 .. len - 1], .{});
        defer reported.deinit();
        try std.testing.expectEqual(oci.Status.stopped, reported.value.status);
        const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer saved.deinit();
        try std.testing.expectEqual(status, saved.value.status);
        try holder.release();
        try holder.wait();
        var unlocked = try LockTestProcess.command(config, null);
        defer unlocked.deinit();
        // State output is small enough to fit in the socket before wait.
        try unlocked.wait();
        const recovered = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer recovered.deinit();
        try std.testing.expectEqual(oci.Status.stopped, recovered.value.status);
    }
}

test "linux start and ordinary delete wait for a held container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    for ([_]Subcommand{ .start, .delete }) |subcommand| {
        try tmp.dir.createDirPath(std.testing.io, "example");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        const status: oci.Status = if (subcommand == .delete) .stopped else .created;
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = status,
            .pid = 1234,
            .bundle = "/bundle",
        });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        var command = try LockTestProcess.command(.{ .root = root, .id = "example", .subcommand = subcommand }, null);
        defer command.deinit();
        try command.waitForLockFd(path);
        try std.testing.expect(!try command.readable(100));
        try holder.release();
        try holder.wait();
        try command.expectByte();
        try command.wait();
        if (subcommand == .delete) {
            try std.testing.expectError(error.FileNotFound, oci.loadState(std.testing.allocator, std.testing.io, root, "example"));
        } else {
            const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
            defer saved.deinit();
            try std.testing.expectEqual(if (subcommand == .start) oci.Status.running else status, saved.value.status);
        }
    }
}

test "linux kill delivers a signal while another process holds the container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .running,
        .pid = holder.pid,
        .bundle = "/bundle",
    });
    try saveTestStarttime(root, holder.pid);
    const watchdog = try std.Thread.spawn(.{}, LockTestProcess.releaseAfterTimeout, .{holder});
    defer watchdog.join();

    // Recovery operations run in the parent; busy warnings must not print after fork.
    try killContainer(std.testing.allocator, std.testing.io, null, .{
        .root = root,
        .id = "example",
        .subcommand = .kill,
        .signal = "SIGTERM",
    });
    var status: u32 = undefined;
    while (true) {
        switch (std.os.linux.errno(std.os.linux.waitpid(holder.pid, &status, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    holder.pid = 0;
    try std.testing.expectEqual(@as(u32, 15), status);
}

test "linux forced delete removes state while another process holds the container lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestIo = struct {
        fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_path: []const u8, new_dir: std.Io.Dir, new_path: []const u8) std.Io.Dir.RenameError!void {
            // Recovery must not persist stale state while the lock is busy.
            if (std.mem.eql(u8, std.fs.path.basename(new_path), oci.state_file_name)) return error.AccessDenied;
            return std.testing.io.vtable.dirRename(userdata, old_dir, old_path, new_dir, new_path);
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "dead" });
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .running,
        .pid = 1234,
        .bundle = "/bundle",
    });
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    const watchdog = try std.Thread.spawn(.{}, LockTestProcess.releaseAfterTimeout, .{holder});
    defer watchdog.join();
    var vtable = std.testing.io.vtable.*;
    vtable.dirRename = TestIo.rename;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var implementation: LockTestContainer = .{};
    try deleteContainer(std.testing.allocator, io, overrideContainer(&implementation, .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable }), .{
        .root = root,
        .id = "example",
        .subcommand = .delete,
        .force = true,
    });
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    try std.testing.expect(!try holder.readable(0));
    try holder.release();
    try holder.wait();
}

test "linux lock waiters reject deleted containers even when the id is recreated" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(base);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    for ([_]Subcommand{ .start, .delete }) |subcommand| {
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        var holder = try LockTestProcess.hold(path);
        defer holder.deinit();
        var command = try LockTestProcess.command(.{ .root = root, .id = "example", .subcommand = subcommand }, error.FileNotFound);
        defer command.deinit();
        try command.waitForLockFd(path);
        try tmp.dir.deleteTree(std.testing.io, "example");
        try tmp.dir.createDir(std.testing.io, "example", .default_dir);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        try oci.saveState(std.testing.allocator, std.testing.io, root, .{
            .id = "example",
            .status = if (subcommand == .delete) .stopped else .created,
            .pid = 1234,
            .bundle = "/bundle",
        });
        try holder.release();
        try holder.wait();
        try command.expectByte();
        try command.wait();
        try tmp.dir.deleteTree(std.testing.io, "example");
    }
}

test "linux busy owners preserve a recreated id after forced delete" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]struct { subcommand: Subcommand, fail: bool, failure: anyerror }{
        .{ .subcommand = .create, .fail = true, .failure = error.CreateFailed },
        .{ .subcommand = .create, .fail = false, .failure = error.FileNotFound },
        .{ .subcommand = .start, .fail = true, .failure = error.HookFailed },
        .{ .subcommand = .start, .fail = false, .failure = error.FileNotFound },
    }) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
        try tmp.dir.createDir(std.testing.io, "replacement", .default_dir);
        const base = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
        defer std.testing.allocator.free(base);
        const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, base, std.testing.allocator);
        defer std.testing.allocator.free(root);
        const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
        defer std.testing.allocator.free(bundle);
        const replacement = try std.fs.path.join(std.testing.allocator, &.{ root, "replacement" });
        defer std.testing.allocator.free(replacement);
        const ready_env = try std.fmt.allocPrint(std.testing.allocator, "READY={s}/ready", .{root});
        defer std.testing.allocator.free(ready_env);
        const resume_env = try std.fmt.allocPrint(std.testing.allocator, "RESUME={s}/resume", .{root});
        defer std.testing.allocator.free(resume_env);
        const output_env = try std.fmt.allocPrint(std.testing.allocator, "OUT={s}/poststop", .{root});
        defer std.testing.allocator.free(output_env);
        const hook: oci.Spec.Hook = .{
            .path = "/bin/sh",
            .args = &.{ "sh", "-c", "printf ready > \"$READY\"; while test ! -e \"$RESUME\"; do /bin/sleep 0.01; done; exit \"$FAIL\"" },
            .env = &.{ ready_env, resume_env, if (case.subcommand == .start and case.fail) "FAIL=7" else "FAIL=0" },
            .timeout = 5,
        };
        const hooks: oci.Spec.Hooks = .{
            .createRuntime = if (case.subcommand == .create) &.{hook} else null,
            .prestart = if (case.subcommand == .start) &.{hook} else null,
            .poststop = &.{.{
                .path = "/bin/sh",
                .args = &.{ "sh", "-c", "printf x >> \"$OUT\"" },
                .env = &.{output_env},
                .timeout = 2,
            }},
        };
        const spec: oci.Spec = .{
            .ociVersion = "1.0.2",
            .root = .{ .path = "/" },
            .process = .{ .args = &.{"/bin/true"}, .cwd = "/", .user = .{ .uid = 0, .gid = 0 } },
            .linux = .{ .namespaces = &.{.{ .type = .mount }} },
            .hooks = hooks,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bundle/config.json", .data = json });
        var replacement_spec = spec;
        replacement_spec.hooks = null;
        const replacement_json = try std.json.Stringify.valueAlloc(std.testing.allocator, replacement_spec, .{ .emit_null_optional_fields = false });
        defer std.testing.allocator.free(replacement_json);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "replacement/config.json", .data = replacement_json });
        var implementation: LockTestContainer = .{ .create_pid = 1234 };
        const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable };
        const config: Config = .{ .root = root, .id = "example", .subcommand = case.subcommand, .bundle = bundle };
        if (case.subcommand == .start)
            try createContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{ .root = root, .id = "example", .subcommand = .create, .bundle = bundle });
        implementation.fail_create = case.fail;
        var owner = try LockTestProcess.commandWithContainer(config, case.failure, overrideContainer(&implementation, container));
        defer owner.deinit();
        const started = std.Io.Clock.awake.now(std.testing.io);
        while (true) {
            if (tmp.dir.statFile(std.testing.io, "ready", .{})) |_| break else |err| {
                if (err != error.FileNotFound) return err;
            }
            if (started.untilNow(std.testing.io, .awake).nanoseconds >= std.Io.Duration.fromSeconds(2).nanoseconds)
                return error.HookWaitTimeout;
            try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
        }
        try deleteContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{ .root = root, .id = "example", .subcommand = .delete, .force = true });
        implementation = .{ .create_pid = 5678 };
        try createContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), .{ .root = root, .id = "example", .subcommand = .create, .bundle = replacement });
        // A stale starter would consume the replacement's acknowledgement and overwrite its state.
        try tmp.dir.deleteFile(std.testing.io, "example/exec.fifo");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/exec.fifo", .data = "\x01" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "resume", .data = "" });
        try owner.expectByte();
        try owner.wait();
        const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
        defer saved.deinit();
        try std.testing.expectEqual(oci.Status.created, saved.value.status);
        try std.testing.expectEqual(@as(?i32, 5678), saved.value.pid);
        try std.testing.expectEqualStrings(replacement, saved.value.bundle);
        const poststop = try tmp.dir.readFileAlloc(std.testing.io, "poststop", std.testing.allocator, .limited(32));
        defer std.testing.allocator.free(poststop);
        try std.testing.expectEqualStrings("x", poststop);
        const fifo = try tmp.dir.readFileAlloc(std.testing.io, "example/exec.fifo", std.testing.allocator, .limited(32));
        defer std.testing.allocator.free(fifo);
        try std.testing.expectEqualStrings("\x01", fifo);
    }
}

test "unlinked owner lock prevents create callback writes and destruction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    var lock: ?std.Io.File = try tmp.dir.createFile(std.testing.io, "example/lock", .{ .read = true });
    defer if (lock) |file| file.close(std.testing.io);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const state_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "example" });
    defer std.testing.allocator.free(state_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .creating,
        .pid = 1234,
        .bundle = "/old",
    });
    var implementation: LockTestContainer = .{};
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable };
    const config: Config = .{ .root = root, .id = "example", .subcommand = .start };
    var state = try readLiveState(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config, false);
    defer state.deinit();
    try deleteStateDirectory(std.testing.io, state_dir);
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "replacement" });
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = 5678,
        .bundle = "/new",
    });
    var context: CreateContext = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .root = root,
        .state_dir = state_dir,
        .state = &state.parsed.value,
        .hooks = .{},
        .lock = lock,
    };
    try std.testing.expectError(error.FileNotFound, context.ready(state.container_state.?));
    try std.testing.expectError(error.FileNotFound, destroyContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config, &state, &lock, null));
    const saved = try oci.loadState(std.testing.allocator, std.testing.io, root, "example");
    defer saved.deinit();
    try std.testing.expectEqual(oci.Status.created, saved.value.status);
    try std.testing.expectEqual(@as(?i32, 5678), saved.value.pid);
    const starttime = try tmp.dir.readFileAlloc(std.testing.io, "example/starttime", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(starttime);
    try std.testing.expectEqualStrings("replacement", starttime);
}

test "state directory cleanup falls back to deleteTree when opening fails" {
    const TestIo = struct {
        fn openDir(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!std.Io.Dir {
            if (!options.iterate and std.mem.endsWith(u8, path, "/example")) return error.AccessDenied;
            return std.testing.io.vtable.dirOpenDir(userdata, dir, path, options);
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/state.json", .data = "{}" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "" });
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "example" });
    defer std.testing.allocator.free(path);
    var vtable = std.testing.io.vtable.*;
    vtable.dirOpenDir = TestIo.openDir;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try deleteStateDirectory(io, path);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
    try deleteStateDirectory(std.testing.io, path);
}

test "linux create never reuses an existing lock file" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/lock", .data = "existing lock" });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.PathAlreadyExists, openContainerLock(std.testing.allocator, .{
        .root = root,
        .id = "example",
        .subcommand = .create,
    }, true));
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "example/lock", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("existing lock", contents);
}

test "linux early create failure removes state while holding the lock" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestIo = struct {
        var checked = false;
        var held = false;
        var state_removed = false;

        fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_path: []const u8, new_dir: std.Io.Dir, new_path: []const u8) std.Io.Dir.RenameError!void {
            // Fail after creating state.json, but before container setup begins.
            if (std.mem.eql(u8, std.fs.path.basename(new_path), oci.hooks_file_name)) return error.AccessDenied;
            return std.testing.io.vtable.dirRename(userdata, old_dir, old_path, new_dir, new_path);
        }

        fn openDir(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!std.Io.Dir {
            const opened = try std.testing.io.vtable.dirOpenDir(userdata, dir, path, options);
            errdefer opened.close(std.testing.io);
            if (options.iterate and std.mem.endsWith(u8, path, "/example")) {
                checked = true;
                var buffer: [std.fs.max_path_bytes]u8 = undefined;
                const lock_path = std.fmt.bufPrint(&buffer, "{s}/lock", .{path}) catch return error.Unexpected;
                held = LockTestProcess.isHeld(lock_path) catch return error.Unexpected;
                if (opened.statFile(std.testing.io, oci.state_file_name, .{})) |_| {
                    state_removed = false;
                } else |err| {
                    state_removed = err == error.FileNotFound;
                }
            }
            return opened;
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}]},"hooks":{}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var vtable = std.testing.io.vtable.*;
    vtable.dirRename = TestIo.rename;
    vtable.dirOpenDir = TestIo.openDir;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var implementation: LockTestContainer = .{};
    try std.testing.expectError(error.AccessDenied, createContainer(std.testing.allocator, io, overrideContainer(&implementation, .{
        .ptr = &implementation,
        .vtable = &LockTestContainer.vtable,
    }), .{ .root = root, .id = "example", .subcommand = .create, .bundle = bundle }));
    try std.testing.expect(TestIo.checked);
    try std.testing.expect(TestIo.held);
    try std.testing.expect(TestIo.state_removed);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir(std.testing.io, "example", .{}));
}

test "linux create holds a private lock until backend setup finishes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const TestContainer = struct {
        state: libcontainer.State = undefined,
        const vtable: libcontainer.Container.VTable = .{ .alive = LockTestContainer.alive, .kill = LockTestContainer.kill, .killAll = LockTestContainer.kill, .delete = LockTestContainer.delete };
        pub fn create(_: *anyopaque, options: libcontainer.CreateOptions) libcontainer.Error!libcontainer.State {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const path = std.fmt.bufPrintZ(&buffer, "{s}/lock", .{std.fs.path.dirname(options.exec_fifo).?}) catch return error.InvalidPath;
            if (!(LockTestProcess.isHeld(path) catch return error.CreateFailed)) return error.CreateFailed;
            const handle: libcontainer.State = .{ .id = options.id, .pid = 1234, .starttime = "alive" };
            if (options.on_create) |callback| try callback.run(callback.ptr, handle);
            return .{ .id = options.id, .pid = handle.pid, .starttime = try options.allocator.dupe(u8, handle.starttime) };
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "bundle", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bundle/config.json",
        .data =
        \\{"ociVersion":"1.0.2","root":{"path":"/"},"linux":{"namespaces":[{"type":"mount"}]}}
        ,
    });
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const bundle = try std.fs.path.join(std.testing.allocator, &.{ root, "bundle" });
    defer std.testing.allocator.free(bundle);
    var implementation: TestContainer = .{};
    try createContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, .{ .ptr = &implementation, .vtable = &TestContainer.vtable }), .{
        .root = root,
        .id = "example",
        .subcommand = .create,
        .bundle = bundle,
    });
    const stat = try tmp.dir.statFile(std.testing.io, "example/lock", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "example", "lock" });
    defer std.testing.allocator.free(path);
    var holder = try LockTestProcess.hold(path);
    defer holder.deinit();
    try holder.release();
    try holder.wait();
}

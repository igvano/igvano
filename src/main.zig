const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const backend_module = @import("igvano").backend;
const Backend = backend_module.Backend;
const diagnostics = @import("cli/diagnostic.zig");
const backendResult = @import("cli/diagnostic.zig").backendResult;
const Subcommand = @import("cli/args.zig").Subcommand;
const Config = @import("cli/args.zig").Config;
const parseArgsWithLog = @import("cli/args.zig").parseArgsWithLog;
const LogFormat = @import("cli/log.zig").LogFormat;
const appendErrorLog = @import("cli/log.zig").appendErrorLog;
const updateContainer = @import("cli/update.zig").updateContainer;
const createContainer = @import("cli/create.zig").createContainer;
const startContainer = @import("cli/start.zig").startContainer;
const execContainer = @import("cli/exec.zig").execContainer;
const killContainer = @import("cli/kill.zig").killContainer;
const deleteContainer = @import("cli/delete.zig").deleteContainer;
const psContainer = @import("cli/ps.zig").psContainer;
const pauseContainer = @import("cli/pause.zig").pauseContainer;
const stateContainer = @import("cli/state_cmd.zig").stateContainer;
const features = @import("cli/features.zig").features;
pub const default_root = @import("cli/args.zig").default_root;

pub fn main(init: std.process.Init) !u8 {
    oci.clearDiagnostic();
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var log: ?[]const u8 = null;
    var log_format: LogFormat = .text;
    const config = parseArgsWithLog(args, &log, &log_format) catch |err| {
        const message = switch (err) {
            error.MissingRoot => "missing value for --root",
            error.MissingLog => "missing value for --log",
            error.MissingLogFormat => "missing value for --log-format",
            error.InvalidLogFormat => "invalid --log-format; expected text or json",
            error.MissingSubcommand => "missing subcommand",
            error.UnknownOption => "unknown option",
            error.UnknownSubcommand => "unknown subcommand",
            error.MissingId => "missing container id",
            error.MissingBundle => "missing value for --bundle",
            error.MissingPidFile => "missing value for --pid-file",
            error.MissingConsoleSocket => "missing value for --console-socket",
            error.MissingProcessFile => "missing value for --process",
            error.MissingResources => "update requires --resources <file|-> or resource flags",
            error.MissingResourceValue => "missing value for resource flag",
            error.InvalidResourceValue => "invalid resource flag value",
            error.MissingCommand => "exec requires a command or --process",
            error.MissingCwd => "missing value for --cwd",
            error.MissingEnv => "missing value for --env",
            error.MissingUser => "missing value for --user",
            error.InvalidUser => "invalid --user; expected UID[:GID]",
            error.InvalidBoolean => "invalid boolean; expected true or false",
            error.MissingFormat => "missing value for --format",
            error.InvalidFormat => "invalid --format; expected table or json",
            error.InvalidProcess => "invalid process environment; expected K=V",
            error.UnexpectedArgument => "unexpected argument; global flags must precede the subcommand",
            error.InvalidId => "invalid container id",
        };
        var buffer: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "igvano: {s}", .{oci.diagnosticFor(err) orelse message}) catch unreachable;
        emitError(allocator, init.io, log, log_format, line, null, null);
        std.debug.print(@import("cli/args.zig").usage, .{});
        return 1;
    };
    var implementation: backend_module.LinuxBackend = .{};
    const backend = implementation.backend();
    diagnostics.last_backend_detail = null;
    if (config.subcommand == .exec) {
        return execContainer(allocator, init.io, backend, config) catch |err| {
            reportError(allocator, init.io, diagnostics.last_backend_detail, config, err);
            return 1;
        };
    }
    const result = switch (config.subcommand) {
        .features => features(allocator, init.io),
        .state => stateContainer(allocator, init.io, backend, config),
        .create => createContainer(allocator, init.io, backend, config),
        .start => startContainer(allocator, init.io, backend, config),
        .kill => killContainer(allocator, init.io, backend, config),
        .update => updateContainer(allocator, init.io, backend, config),
        .ps => psContainer(allocator, init.io, backend, config, std.Io.File.stdout()),
        .pause, .@"resume" => pauseContainer(allocator, init.io, backend, config),
        .delete => deleteContainer(allocator, init.io, backend, config),
        .exec => unreachable,
    };
    result catch |err| {
        reportError(allocator, init.io, diagnostics.last_backend_detail, config, err);
        return 1;
    };
    return 0;
}

fn reportError(allocator: std.mem.Allocator, io: std.Io, diagnostic: ?[]const u8, config: Config, err: anyerror) void {
    const message = (if (err == error.FileNotFound)
        std.fmt.allocPrint(allocator, "igvano: container '{s}' or a required file does not exist", .{config.id})
    else if (err == error.ContainerExists)
        std.fmt.allocPrint(allocator, "igvano: container '{s}' already exists", .{config.id})
    else if (err == error.StartTimeout)
        std.fmt.allocPrint(allocator, "igvano: start for '{s}' timed out waiting for init readiness", .{config.id})
    else if (err == error.MissingConsoleSocket)
        allocator.dupe(u8, "igvano: terminal=true requires --console-socket")
    else if (err == error.UnexpectedConsoleSocket)
        allocator.dupe(u8, "igvano: --console-socket requires terminal=true")
    else if (config.subcommand == .start and err == error.ProcessNotFound)
        std.fmt.allocPrint(allocator, "igvano: init for '{s}' is no longer alive; start failed", .{config.id})
    else if (config.subcommand == .kill and (err == error.ContainerNotRunning or err == error.ProcessNotFound))
        std.fmt.allocPrint(allocator, "igvano: kill for '{s}' failed: {s}", .{
            config.id,
            @as([]const u8, if (err == error.ContainerNotRunning) "container not running" else "no such process"),
        })
    else
        std.fmt.allocPrint(allocator, "igvano: {s} for '{s}' failed: {s}", .{ @tagName(config.subcommand), config.id, @errorName(err) })) catch {
        std.debug.print("igvano: {s} for '{s}' failed: {s}\n", .{ @tagName(config.subcommand), config.id, @errorName(err) });
        return;
    };
    defer allocator.free(message);
    const frontend_detail = if (diagnostic == null) oci.diagnosticFor(err) else null;
    emitError(allocator, io, config.log, config.log_format, message, frontend_detail, diagnostic orelse frontend_detail);
}

fn emitError(allocator: std.mem.Allocator, io: std.Io, log: ?[]const u8, log_format: LogFormat, message: []const u8, stderr_detail: ?[]const u8, log_detail: ?[]const u8) void {
    if (stderr_detail) |detail|
        std.debug.print("{s}: {s}\n", .{ message, detail })
    else
        std.debug.print("{s}\n", .{message});
    if (log) |path| {
        const detailed = if (log_detail) |detail|
            std.fmt.allocPrint(allocator, "{s}: {s}", .{ message, detail }) catch null
        else
            null;
        defer if (detailed) |bytes| allocator.free(bytes);
        appendErrorLog(allocator, io, path, log_format, detailed orelse message) catch |err| {
            std.debug.print("igvano: warning: cannot write log '{s}': {s}\n", .{ path, @errorName(err) });
        };
    }
}

comptime {
    if (builtin.is_test) {
        _ = @import("cli/args.zig");
        _ = @import("cli/create.zig");
        _ = @import("cli/delete.zig");
        _ = @import("cli/diagnostic.zig");
        _ = @import("cli/exec.zig");
        _ = @import("cli/features.zig");
        _ = @import("cli/hooks.zig");
        _ = @import("cli/kill.zig");
        _ = @import("cli/log.zig");
        _ = @import("cli/pause.zig");
        _ = @import("cli/process.zig");
        _ = @import("cli/ps.zig");
        _ = @import("cli/start.zig");
        _ = @import("cli/state.zig");
        _ = @import("cli/state_cmd.zig");
        _ = @import("cli/tests/create.zig");
        _ = @import("cli/tests/delete.zig");
        _ = @import("cli/tests/exec.zig");
        _ = @import("cli/tests/helpers.zig");
        _ = @import("cli/tests/hooks.zig");
        _ = @import("cli/tests/lifecycle.zig");
        _ = @import("cli/tests/locks.zig");
        _ = @import("cli/tests/security.zig");
        _ = @import("cli/tests/start.zig");
        _ = @import("cli/tests/systemd.zig");
        _ = @import("cli/update.zig");
    }
}

test "dispatch recognizes lifecycle subcommands and rejects unknown commands" {
    try std.testing.expectEqual(@as(?Subcommand, .state), std.meta.stringToEnum(Subcommand, "state"));
    try std.testing.expectEqual(@as(?Subcommand, .create), std.meta.stringToEnum(Subcommand, "create"));
    try std.testing.expectEqual(@as(?Subcommand, .start), std.meta.stringToEnum(Subcommand, "start"));
    try std.testing.expectEqual(@as(?Subcommand, .kill), std.meta.stringToEnum(Subcommand, "kill"));
    try std.testing.expectEqual(@as(?Subcommand, .delete), std.meta.stringToEnum(Subcommand, "delete"));
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "unknown") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "STATE") == null);
    try std.testing.expect(std.meta.stringToEnum(Subcommand, "starting") == null);
}

test "reportError includes backend diagnostic in the JSON log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, "runtime.log" });
    defer std.testing.allocator.free(path);
    const config: Config = .{ .root = "/unused", .subcommand = .create, .id = "example", .log = path, .log_format = .json };
    reportError(std.testing.allocator, std.testing.io, null, config, error.Unsupported);
    reportError(std.testing.allocator, std.testing.io, "mounting cgroup v1 hierarchies inside the container is not implemented yet", config, error.Unsupported);
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    for ([_][]const u8{
        "igvano: create for 'example' failed: Unsupported",
        "igvano: create for 'example' failed: Unsupported: mounting cgroup v1 hierarchies inside the container is not implemented yet",
    }) |expected| {
        const parsed = try std.json.parseFromSlice(struct { level: []const u8, msg: []const u8 }, std.testing.allocator, lines.next().?, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        try std.testing.expectEqualStrings("error", parsed.value.level);
        try std.testing.expectEqualStrings(expected, parsed.value.msg);
    }
    try std.testing.expect(lines.next() == null);
}

test "reportError includes frontend validation detail in text and JSON logs" {
    defer oci.clearDiagnostic();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_]LogFormat{ .text, .json }) |format| {
        oci.clearDiagnostic();
        const path = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path, @tagName(format) });
        defer std.testing.allocator.free(path);
        const config: Config = .{ .root = "/unused", .subcommand = .create, .id = "example", .log = path, .log_format = format };
        oci.requireCreate(.{
            .ociVersion = "1.0.2",
            .root = .{ .path = "rootfs" },
            .mounts = &.{.{ .destination = "../outside" }},
        }) catch |err| {
            try std.testing.expectEqual(error.InvalidConfig, err);
            reportError(std.testing.allocator, std.testing.io, null, config, err);
        };
        const bytes = try tmp.dir.readFileAlloc(std.testing.io, @tagName(format), std.testing.allocator, .limited(4096));
        defer std.testing.allocator.free(bytes);
        try std.testing.expect(std.mem.indexOf(u8, bytes, "mounts[0]: container path: must be absolute and NUL-free") != null);
    }
}

test "kill errors use shim-compatible messages in the log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try tmp.dir.createDir(io, "example", .default_dir);
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(root);
    const log = try std.fs.path.join(allocator, &.{ root, "runtime.log" });
    defer allocator.free(log);
    try oci.saveState(allocator, io, root, .{ .id = "example", .status = .stopped, .bundle = "/unused" });
    var implementation: backend_module.LinuxBackend = .{};
    const config: Config = .{ .root = root, .subcommand = .kill, .id = "example", .log = log, .log_format = .json };
    killContainer(allocator, io, implementation.backend(), config) catch |err|
        reportError(allocator, io, null, config, err);
    reportError(allocator, io, null, config, error.ProcessNotFound);
    const bytes = try tmp.dir.readFileAlloc(io, "runtime.log", allocator, .limited(4096));
    defer allocator.free(bytes);
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    for ([_][]const u8{ "container not running", "no such process" }) |expected| {
        const parsed = try std.json.parseFromSlice(struct { msg: []const u8 }, allocator, lines.next().?, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        try std.testing.expect(std.mem.indexOf(u8, parsed.value.msg, expected) != null);
    }
    try std.testing.expect(lines.next() == null);
}

test "backend error detail survives cleanup overwriting the borrowed buffer" {
    const LockTestBackend = @import("cli/tests/helpers.zig").LockTestBackend;
    diagnostics.last_backend_detail = null;
    defer diagnostics.last_backend_detail = null;
    var detail = "original create failure".*;
    var implementation: LockTestBackend = .{ .detail = &detail };
    const backend: Backend = .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable };
    const spec: oci.Spec = .{ .ociVersion = "1.0.2", .root = .{ .path = "rootfs" } };
    try std.testing.expectError(error.NotImplemented, backendResult(backend, backend.create(.{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/bundle/rootfs",
        .exec_fifo = "/runtime/example/exec.fifo",
        .spec = &spec,
    })));
    const handle: Backend.Handle = .{ .id = "example", .pid = 1234, .starttime = "alive" };
    @memset(&detail, 'x');
    backend.kill(handle, 9) catch {};
    backend.delete(handle) catch {};
    try std.testing.expectEqualStrings("original create failure", diagnostics.last_backend_detail.?);
    try backendResult(backend, backend.delete(handle));
    try std.testing.expect(diagnostics.last_backend_detail == null);
}

test "frontend failure after successful liveness does not log stale backend detail" {
    const LockTestBackend = @import("cli/tests/helpers.zig").LockTestBackend;
    diagnostics.last_backend_detail = null;
    defer diagnostics.last_backend_detail = null;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "example", .default_dir);
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "runtime.log" });
    defer std.testing.allocator.free(path);
    try oci.saveState(std.testing.allocator, std.testing.io, root, .{
        .id = "example",
        .status = .created,
        .pid = 1234,
        .bundle = "/bundle",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/starttime", .data = "alive" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "example/process", .data = "false\n" });
    var implementation: LockTestBackend = .{ .detail = "stale backend failure" };
    const backend: Backend = .{ .ptr = &implementation, .vtable = &LockTestBackend.vtable };
    const config: Config = .{ .root = root, .subcommand = .start, .id = "example", .log = path };
    startContainer(std.testing.allocator, std.testing.io, backend, config) catch |err| {
        try std.testing.expectEqual(error.MissingProcess, err);
        reportError(std.testing.allocator, std.testing.io, diagnostics.last_backend_detail, config, err);
    };
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("igvano: start for 'example' failed: MissingProcess: start: container has no process\n", bytes);
}

test "error reporting prints frontend detail once and keeps backend detail only in the log" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "runtime.log" });
    defer std.testing.allocator.free(path);
    const config: Config = .{ .root = root, .subcommand = .create, .id = "example", .log = path };
    var capture: [2]std.posix.fd_t = undefined;
    if (std.posix.errno(std.posix.system.pipe(&capture)) != .SUCCESS) return error.SystemResources;
    defer for (capture) |fd| (std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } }).close(std.testing.io);
    const saved = std.posix.system.dup(2);
    if (std.posix.errno(saved) != .SUCCESS) return error.SystemResources;
    const saved_fd: std.posix.fd_t = @intCast(saved);
    defer (std.Io.File{ .handle = saved_fd, .flags = .{ .nonblocking = false } }).close(std.testing.io);
    if (std.posix.errno(std.posix.system.dup2(capture[1], 2)) != .SUCCESS) return error.SystemResources;
    {
        defer _ = std.posix.system.dup2(saved_fd, 2);
        reportError(std.testing.allocator, std.testing.io, "backend detail already printed", config, error.Unsupported);
        oci.recordDiagnostic(error.InvalidConfig, "frontend detail", .{});
        defer oci.clearDiagnostic();
        reportError(std.testing.allocator, std.testing.io, null, config, error.InvalidConfig);
    }
    var bytes: [512]u8 = undefined;
    const read = std.posix.system.read(capture[0], &bytes, bytes.len);
    if (std.posix.errno(read) != .SUCCESS) return error.ReadFailed;
    const count: usize = @intCast(read);
    try std.testing.expectEqualStrings(
        "igvano: create for 'example' failed: Unsupported\n" ++
            "igvano: create for 'example' failed: InvalidConfig: frontend detail\n",
        bytes[0..count],
    );
    const log = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(log);
    try std.testing.expect(std.mem.indexOf(u8, log, "Unsupported: backend detail already printed") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "InvalidConfig: frontend detail") != null);
}

const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");
const diagnostics = @import("cli/diagnostic.zig");
const containerResult = @import("cli/diagnostic.zig").containerResult;
const Subcommand = @import("cli/args.zig").Subcommand;
const Config = @import("cli/args.zig").Config;
const parseArgsWithLog = @import("cli/args.zig").parseArgsWithLog;
const ParseArgsError = @typeInfo(@typeInfo(@TypeOf(parseArgsWithLog)).@"fn".return_type.?).error_union.error_set;
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
const writeSpec = @import("cli/spec.zig").writeSpec;
const runContainer = @import("cli/run.zig").runContainer;
const listContainers = @import("cli/list.zig").listContainers;
const eventsContainer = @import("cli/events.zig").eventsContainer;
pub const default_root = @import("cli/args.zig").default_root;

pub fn main(init: std.process.Init) !u8 {
    oci.clearDiagnostic();
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (try helpOrVersion(init.io, args)) |status| return status;

    var log: ?[]const u8 = null;
    var log_format: LogFormat = .text;
    var config = parseArgsWithLog(args, &log, &log_format) catch |err| {
        const message = argumentErrorMessage(err);
        var buffer: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "igvano: {s}", .{oci.diagnosticFor(err) orelse message}) catch unreachable;
        emitError(allocator, init.io, log, log_format, line, null, null);
        std.debug.print(@import("cli/args.zig").usage, .{});
        return 1;
    };
    diagnostics.last_container_detail = null;
    if (setupConfig(allocator, init, &config)) |status| return status;
    return dispatchCommand(allocator, init.io, config) catch |err| {
        reportError(allocator, init.io, diagnostics.last_container_detail, config, err);
        // Like runc, a failed exec exits 255 so callers can tell it from the
        // process's own status.
        return if (config.subcommand == .exec) 255 else 1;
    };
}

fn helpOrVersion(io: std.Io, args: []const []const u8) !?u8 {
    var out_buffer: [8192]u8 = undefined;
    var err_buffer: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    var errors: std.Io.Writer = .fixed(&err_buffer);
    const status = try @import("cli/help.zig").handle(args, &out, &errors) orelse return null;
    try std.Io.File.stdout().writeStreamingAll(io, out.buffered());
    try std.Io.File.stderr().writeStreamingAll(io, errors.buffered());
    return status;
}

/// Process-wide setup after parsing; a status means exit with it.
fn setupConfig(allocator: std.mem.Allocator, init: std.process.Init, config: *Config) ?u8 {
    config.path_env = init.minimal.environ.getPosix("PATH");
    // Before igvano opens any fd of its own, which could take a free slot.
    if (config.subcommand == .exec) for (3..3 + @as(usize, config.preserve_fds)) |fd| {
        if (std.os.linux.errno(std.os.linux.fcntl(@intCast(fd), std.os.linux.F.GETFD, 0)) != .SUCCESS) {
            std.debug.print("igvano: --preserve-fds: fd {d} is not open\n", .{fd});
            return 255;
        }
    };
    if (config.root.ptr == default_root.ptr) {
        const root = xdgRoot(allocator, init.minimal.environ.getPosix("XDG_RUNTIME_DIR")) catch |err| {
            std.debug.print("igvano: the path in $XDG_RUNTIME_DIR must be writable by the user: {s}\n", .{@errorName(err)});
            return 1;
        };
        if (root) |value| config.root = value;
    }
    if (config.debug) config.debug_log = @import("cli/log.zig").openDebugLog(config.log, config.log_format) catch |err| {
        std.debug.print("igvano: cannot open log '{s}': {s}\n", .{ config.log orelse "", @errorName(err) });
        return 1;
    };
    return null;
}

/// Like runc, a non-root runtime keeps state in $XDG_RUNTIME_DIR/igvano,
/// sticky so XDG cleanup leaves it alone. Root keeps /run/igvano.
// ponytail: runc also honors XDG for root in a user namespace unless
// USER=root; add that when a nested runtime needs it.
fn xdgRoot(allocator: std.mem.Allocator, xdg: ?[]const u8) !?[]const u8 {
    if (comptime builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    const dir = xdg orelse return null;
    if (dir.len == 0 or linux.geteuid() == 0) return null;
    const root = try std.fs.path.joinZ(allocator, &.{ dir, "igvano" });
    switch (linux.errno(linux.mkdir(root, 0o700))) {
        .SUCCESS, .EXIST => {},
        else => return error.InvalidRoot,
    }
    if (linux.errno(linux.chmod(root, 0o1700)) != .SUCCESS) return error.InvalidRoot;
    return root;
}

fn argumentErrorMessage(err: ParseArgsError) []const u8 {
    const messages = std.StaticStringMap([]const u8).initComptime(.{
        .{ "MissingRoot", "missing value for --root" },
        .{ "MissingLog", "missing value for --log" },
        .{ "MissingLogFormat", "missing value for --log-format" },
        .{ "InvalidLogFormat", "invalid --log-format; expected text or json" },
        .{ "MissingSubcommand", "missing subcommand" },
        .{ "UnknownOption", "unknown option" },
        .{ "UnknownSubcommand", "unknown subcommand" },
        .{ "MissingId", "missing container id" },
        .{ "MissingBundle", "missing value for --bundle" },
        .{ "MissingPidFile", "missing value for --pid-file" },
        .{ "MissingConsoleSocket", "missing value for --console-socket" },
        .{ "MissingPidfdSocket", "missing value for --pidfd-socket" },
        .{ "MissingProcessFile", "missing value for --process" },
        .{ "MissingResources", "update requires --resources <file|-> or resource flags" },
        .{ "MissingResourceValue", "missing value for resource flag" },
        .{ "InvalidResourceValue", "invalid resource flag value" },
        .{ "MissingCommand", "exec requires a command or --process" },
        .{ "MissingCwd", "missing value for --cwd" },
        .{ "MissingEnv", "missing value for --env" },
        .{ "MissingUser", "missing value for --user" },
        .{ "InvalidUser", "invalid --user; expected UID[:GID]" },
        .{ "InvalidBoolean", "invalid boolean; expected true or false" },
        .{ "MissingFormat", "missing value for --format" },
        .{ "MissingInterval", "missing value for --interval" },
        .{ "MissingExecValue", "missing value for an exec option" },
        .{ "InvalidExecValue", "invalid value for an exec option" },
        .{ "InvalidDuration", "invalid --interval; expected a positive duration such as 5s" },
        .{ "InvalidFormat", "invalid --format; expected table or json" },
        .{ "InvalidProcess", "invalid process environment; expected K=V" },
        .{ "UnexpectedArgument", "unexpected argument; global flags must precede the subcommand" },
        .{ "InvalidId", "invalid container id" },
    });
    comptime {
        @setEvalBranchQuota(4000);
        for (@typeInfo(ParseArgsError).error_set.?) |parse_error| {
            if (messages.get(parse_error.name) == null)
                @compileError("missing argument error message for " ++ parse_error.name);
        }
    }
    return messages.get(@errorName(err)).?;
}

fn dispatchCommand(allocator: std.mem.Allocator, io: std.Io, config: Config) !u8 {
    switch (config.subcommand) {
        .features => try features(allocator, io),
        .state => try stateContainer(allocator, io, null, config),
        .create => try createContainer(allocator, io, null, config),
        .start => try startContainer(allocator, io, null, config),
        .exec => return execContainer(allocator, io, null, config),
        .kill => try killContainer(allocator, io, null, config),
        .update => try updateContainer(allocator, io, null, config),
        .ps => try psContainer(allocator, io, null, config, std.Io.File.stdout()),
        .pause, .@"resume" => try pauseContainer(allocator, io, null, config),
        .delete => try deleteContainer(allocator, io, null, config),
        .spec => try writeSpec(allocator, io, config),
        .run => return runContainer(allocator, io, null, config),
        .list => try listContainers(allocator, io, null, config),
        .events => try eventsContainer(allocator, io, null, config),
    }
    return 0;
}

fn reportError(allocator: std.mem.Allocator, io: std.Io, diagnostic: ?[]const u8, config: Config, err: anyerror) void {
    const message = errorMessage(allocator, config, err) catch {
        std.debug.print("igvano: {s} for '{s}' failed: {s}\n", .{ @tagName(config.subcommand), config.id, @errorName(err) });
        return;
    };
    defer allocator.free(message);
    const detail = diagnostic orelse oci.diagnosticFor(err);
    // Like runc run, the process's own exec error is printed alone.
    if (err == error.ProcessExecFailed) if (detail) |text| return emitError(allocator, io, config.log, config.log_format, text, null, null);
    emitError(allocator, io, config.log, config.log_format, message, detail, detail);
}

fn errorMessage(allocator: std.mem.Allocator, config: Config, err: anyerror) ![]u8 {
    return if (err == error.FileNotFound)
        std.fmt.allocPrint(allocator, "igvano: container '{s}' or a required file does not exist", .{config.id})
    else if (err == error.ContainerExists)
        std.fmt.allocPrint(allocator, "igvano: container '{s}' already exists", .{config.id})
    else if (err == error.StartTimeout)
        std.fmt.allocPrint(allocator, "igvano: start for '{s}' timed out waiting for init readiness", .{config.id})
    else if (err == error.MissingConsoleSocket)
        allocator.dupe(u8, "igvano: terminal=true requires --console-socket")
    else if (err == error.UnexpectedConsoleSocket)
        allocator.dupe(u8, "igvano: --console-socket requires terminal=true")
    else
        commandErrorMessage(allocator, config, err);
}

fn commandErrorMessage(allocator: std.mem.Allocator, config: Config, err: anyerror) ![]u8 {
    return if (config.subcommand == .start and err == error.ProcessNotFound)
        std.fmt.allocPrint(allocator, "igvano: init for '{s}' is no longer alive; start failed", .{config.id})
    else if (config.subcommand == .kill and (err == error.ContainerNotRunning or err == error.ProcessNotFound))
        std.fmt.allocPrint(allocator, "igvano: kill for '{s}' failed: {s}", .{
            config.id,
            @as([]const u8, if (err == error.ContainerNotRunning) "container not running" else "no such process"),
        })
    else
        std.fmt.allocPrint(allocator, "igvano: {s} for '{s}' failed: {s}", .{ @tagName(config.subcommand), config.id, @errorName(err) });
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
        _ = @import("cli/events.zig");
        _ = @import("cli/exec.zig");
        _ = @import("cli/features.zig");
        _ = @import("cli/help.zig");
        _ = @import("cli/hooks.zig");
        _ = @import("cli/kill.zig");
        _ = @import("cli/list.zig");
        _ = @import("cli/log.zig");
        _ = @import("cli/pause.zig");
        _ = @import("cli/process.zig");
        _ = @import("cli/ps.zig");
        _ = @import("cli/run.zig");
        _ = @import("cli/seccomp_agent.zig");
        _ = @import("cli/spec.zig");
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
    const config: Config = .{ .root = root, .subcommand = .kill, .id = "example", .log = log, .log_format = .json };
    killContainer(allocator, io, null, config) catch |err|
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
    const overrideContainer = @import("cli/tests/helpers.zig").overrideContainer;
    const LockTestContainer = @import("cli/tests/helpers.zig").LockTestContainer;
    const createDiagnostic = @import("cli/state.zig").createDiagnostic;
    diagnostics.last_container_detail = null;
    defer diagnostics.last_container_detail = null;
    var detail = "original create failure".*;
    var implementation: LockTestContainer = .{ .detail = &detail };
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable };
    const created = LockTestContainer.create(&implementation, .{
        .allocator = std.testing.allocator,
        .id = "example",
        .rootfs = "/bundle/rootfs",
        .exec_fifo = "/runtime/example/exec.fifo",
    });
    const message = createDiagnostic(overrideContainer(&implementation, container));
    try std.testing.expectError(error.NotImplemented, diagnostics.resultWithDetail(message, created));
    const handle: libcontainer.State = .{ .id = "example", .pid = 1234, .starttime = "alive" };
    implementation.state = handle;
    @memset(&detail, 'x');
    container.kill(9) catch {};
    container.delete() catch {};
    try std.testing.expectEqualStrings("original create failure", diagnostics.last_container_detail.?);
    try containerResult(container, container.delete());
    try std.testing.expect(diagnostics.last_container_detail == null);
}

test "frontend failure after successful liveness does not log stale backend detail" {
    const overrideContainer = @import("cli/tests/helpers.zig").overrideContainer;
    const LockTestContainer = @import("cli/tests/helpers.zig").LockTestContainer;
    diagnostics.last_container_detail = null;
    defer diagnostics.last_container_detail = null;
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
    var implementation: LockTestContainer = .{ .detail = "stale container failure" };
    const container: libcontainer.Container = .{ .ptr = &implementation, .vtable = &LockTestContainer.vtable };
    const config: Config = .{ .root = root, .subcommand = .start, .id = "example", .log = path };
    startContainer(std.testing.allocator, std.testing.io, overrideContainer(&implementation, container), config) catch |err| {
        try std.testing.expectEqual(error.MissingProcess, err);
        reportError(std.testing.allocator, std.testing.io, diagnostics.last_container_detail, config, err);
    };
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("igvano: start for 'example' failed: MissingProcess: start: container has no process\n", bytes);
}

test "error reporting prints backend and frontend detail once, on stderr and in the log" {
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
        reportError(std.testing.allocator, std.testing.io, "container detail", config, error.Unsupported);
        oci.recordDiagnostic(error.InvalidConfig, "frontend detail", .{});
        defer oci.clearDiagnostic();
        reportError(std.testing.allocator, std.testing.io, null, config, error.InvalidConfig);
    }
    var bytes: [512]u8 = undefined;
    const read = std.posix.system.read(capture[0], &bytes, bytes.len);
    if (std.posix.errno(read) != .SUCCESS) return error.ReadFailed;
    const count: usize = @intCast(read);
    try std.testing.expectEqualStrings(
        "igvano: create for 'example' failed: Unsupported: container detail\n" ++
            "igvano: create for 'example' failed: InvalidConfig: frontend detail\n",
        bytes[0..count],
    );
    const log = try tmp.dir.readFileAlloc(std.testing.io, "runtime.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(log);
    try std.testing.expect(std.mem.indexOf(u8, log, "Unsupported: container detail") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "InvalidConfig: frontend detail") != null);
}

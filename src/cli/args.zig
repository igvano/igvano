const std = @import("std");
const oci = @import("igvano").oci;
const LogFormat = @import("log.zig").LogFormat;
const parseUpdateArgs = @import("update.zig").parseUpdateArgs;
const features = @import("features.zig").features;

pub const default_root = "/run/igvano";

pub const Subcommand = enum {
    features,
    state,
    create,
    start,
    exec,
    kill,
    update,
    ps,
    pause,
    @"resume",
    delete,
};

const PsFormat = enum { table, json };

const ExecUser = struct {
    uid: u32,
    gid: ?u32,
};

pub const Config = struct {
    root: []const u8,
    subcommand: Subcommand,
    id: []const u8,
    log: ?[]const u8 = null,
    log_format: LogFormat = .text,
    bundle: ?[]const u8 = null,
    pid_file: ?[]const u8 = null,
    console_socket: ?[]const u8 = null,
    signal: ?[]const u8 = null,
    systemd: bool = false,
    force: bool = false,
    all: bool = false,
    ps_format: PsFormat = .table,
    ps_args: []const []const u8 = &.{},
    process_file: ?[]const u8 = null,
    resources_file: ?[]const u8 = null,
    resource_flags: oci.Spec.Resources = .{},
    detach: bool = false,
    tty: ?bool = null,
    exec_cwd: ?[]const u8 = null,
    exec_user: ?ExecUser = null,
    /// Borrowed option tokens, scanned again to collect repeated --env values.
    exec_flags: []const []const u8 = &.{},
    exec_args: []const []const u8 = &.{},
};

pub fn parseArgs(args: []const []const u8) !Config {
    var log: ?[]const u8 = null;
    var log_format: LogFormat = .text;
    return parseArgsWithLog(args, &log, &log_format);
}

// Keep the settings already parsed available when a later argument fails.
pub fn parseArgsWithLog(args: []const []const u8, log: *?[]const u8, log_format: *LogFormat) !Config {
    var root: []const u8 = default_root;
    var systemd = false;
    var index: usize = 1;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) {
        if (std.mem.eql(u8, args[index], "--root")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) return oci.validationError(error.MissingRoot, "--root: missing value", .{});
            root = args[index];
        } else if (std.mem.startsWith(u8, args[index], "--root=")) {
            root = args[index]["--root=".len..];
            if (root.len == 0) return oci.validationError(error.MissingRoot, "--root: missing value", .{});
        } else if (std.mem.eql(u8, args[index], "--log")) {
            index += 1;
            if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                return oci.validationError(error.MissingLog, "--log: missing value", .{});
            log.* = args[index];
        } else if (std.mem.startsWith(u8, args[index], "--log=")) {
            const value = args[index]["--log=".len..];
            if (value.len == 0) return oci.validationError(error.MissingLog, "--log: missing value", .{});
            log.* = value;
        } else if (std.mem.eql(u8, args[index], "--log-format") or std.mem.startsWith(u8, args[index], "--log-format=")) {
            const value = if (std.mem.eql(u8, args[index], "--log-format")) value: {
                index += 1;
                if (index >= args.len or std.mem.startsWith(u8, args[index], "--")) return oci.validationError(error.MissingLogFormat, "--log-format: missing value", .{});
                break :value args[index];
            } else args[index]["--log-format=".len..];
            if (value.len == 0) return oci.validationError(error.MissingLogFormat, "--log-format: missing value", .{});
            log_format.* = std.meta.stringToEnum(LogFormat, value) orelse return oci.validationError(error.InvalidLogFormat, "--log-format: expected text or json", .{});
        } else if (std.mem.eql(u8, args[index], "--debug")) {
            // Accepted for compatibility with runc callers.
        } else if (std.mem.eql(u8, args[index], "--systemd-cgroup")) {
            systemd = true;
        } else {
            return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index]});
        }
        index += 1;
    }
    if (index >= args.len) return oci.validationError(error.MissingSubcommand, "missing subcommand", .{});
    const subcommand = std.meta.stringToEnum(Subcommand, args[index]) orelse
        return oci.validationError(error.UnknownSubcommand, "unknown subcommand '{s}'", .{args[index]});
    index += 1;
    if (subcommand == .features) {
        if (index != args.len) return oci.validationError(error.UnexpectedArgument, "unexpected argument; global flags must precede the subcommand", .{});
        return .{
            .root = root,
            .subcommand = subcommand,
            .id = "",
            .systemd = systemd,
            .log = log.*,
            .log_format = log_format.*,
        };
    }

    var bundle: ?[]const u8 = null;
    var pid_file: ?[]const u8 = null;
    var console_socket: ?[]const u8 = null;
    var force = false;
    var all = false;
    var ps_format: PsFormat = .table;
    var process_file: ?[]const u8 = null;
    var resources_file: ?[]const u8 = null;
    var resource_flags: oci.Spec.Resources = .{};
    var detach = false;
    var tty: ?bool = null;
    var exec_cwd: ?[]const u8 = null;
    var exec_user: ?ExecUser = null;
    const flags_start = index;
    if (subcommand == .exec) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            const flag = args[index];
            if (std.mem.eql(u8, flag, "--detach") or std.mem.eql(u8, flag, "-d") or std.mem.startsWith(u8, flag, "--detach=")) {
                detach = try boolOption(flag);
            } else if (std.mem.eql(u8, flag, "--tty") or std.mem.eql(u8, flag, "-t") or std.mem.startsWith(u8, flag, "--tty=")) {
                tty = try boolOption(flag);
            } else if (std.mem.eql(u8, flag, "--process") or std.mem.startsWith(u8, flag, "--process=")) {
                process_file = try optionValue(args, &index, error.MissingProcessFile);
            } else if (std.mem.eql(u8, flag, "--pid-file") or std.mem.startsWith(u8, flag, "--pid-file=")) {
                pid_file = try optionValue(args, &index, error.MissingPidFile);
            } else if (std.mem.eql(u8, flag, "--console-socket") or std.mem.startsWith(u8, flag, "--console-socket=")) {
                console_socket = try optionValue(args, &index, error.MissingConsoleSocket);
            } else if (std.mem.eql(u8, flag, "--cwd") or std.mem.startsWith(u8, flag, "--cwd=")) {
                exec_cwd = try optionValue(args, &index, error.MissingCwd);
            } else if (std.mem.eql(u8, flag, "--user") or std.mem.startsWith(u8, flag, "--user=")) {
                exec_user = try parseUser(try optionValue(args, &index, error.MissingUser));
            } else if (std.mem.eql(u8, flag, "--env") or std.mem.startsWith(u8, flag, "--env=")) {
                try oci.validateEnv(try optionValue(args, &index, error.MissingEnv));
            } else return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index]});
        }
    }
    if (subcommand == .create) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            if (std.mem.eql(u8, args[index], "--bundle")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return oci.validationError(error.MissingBundle, "--bundle: missing value", .{});
                bundle = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--bundle=")) {
                bundle = args[index]["--bundle=".len..];
                if (bundle.?.len == 0) return oci.validationError(error.MissingBundle, "--bundle: missing value", .{});
            } else if (std.mem.eql(u8, args[index], "--pid-file")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return oci.validationError(error.MissingPidFile, "--pid-file: missing value", .{});
                pid_file = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--pid-file=")) {
                pid_file = args[index]["--pid-file=".len..];
                if (pid_file.?.len == 0) return oci.validationError(error.MissingPidFile, "--pid-file: missing value", .{});
            } else if (std.mem.eql(u8, args[index], "--console-socket")) {
                index += 1;
                if (index >= args.len or args[index].len == 0 or std.mem.startsWith(u8, args[index], "--"))
                    return oci.validationError(error.MissingConsoleSocket, "--console-socket: missing value", .{});
                console_socket = args[index];
            } else if (std.mem.startsWith(u8, args[index], "--console-socket=")) {
                console_socket = args[index]["--console-socket=".len..];
                if (console_socket.?.len == 0) return oci.validationError(error.MissingConsoleSocket, "--console-socket: missing value", .{});
            } else {
                return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index]});
            }
        }
        if (bundle == null) bundle = ".";
    } else if (subcommand == .update) {
        const parsed_update = try parseUpdateArgs(args, index);
        index = parsed_update.index;
        resources_file = parsed_update.resources_file;
        resource_flags = parsed_update.resource_flags;
    } else if (subcommand == .delete) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            if (!std.mem.eql(u8, args[index], "--force")) return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index]});
            force = true;
        }
    } else if (subcommand == .ps) {
        while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
            const flag = args[index];
            if (!std.mem.eql(u8, flag, "--format") and !std.mem.startsWith(u8, flag, "--format="))
                return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index]});
            ps_format = std.meta.stringToEnum(PsFormat, try optionValue(args, &index, error.MissingFormat)) orelse
                return oci.validationError(error.InvalidFormat, "--format: expected table or json", .{});
        }
    } else if (subcommand == .kill) {
        while (index < args.len and (std.mem.eql(u8, args[index], "--all") or
            std.mem.eql(u8, args[index], "-a"))) : (index += 1)
        {
            all = true;
        }
    }
    if (index >= args.len) return oci.validationError(error.MissingId, "container id: required", .{});
    const remaining = args.len - index;
    if (subcommand == .exec) {
        if (process_file != null and remaining != 1) return oci.validationError(error.UnexpectedArgument, "exec: --process cannot be combined with command arguments", .{});
        if (process_file == null and remaining == 1) return oci.validationError(error.MissingCommand, "exec: requires a command or --process", .{});
    } else if (subcommand != .ps and remaining != 1 and !(subcommand == .kill and remaining == 2)) return oci.validationError(error.UnexpectedArgument, "unexpected argument; global flags must precede the subcommand", .{});
    const id = args[index];
    if (id.len == 0 or std.mem.indexOfScalar(u8, id, 0) != null or std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or std.mem.startsWith(u8, id, "-"))
    {
        return oci.validationError(error.InvalidId, "container id: must not be empty, contain / or NUL, or equal . or ..", .{});
    }
    const signal = if (subcommand == .kill and remaining == 2) args[index + 1] else null;
    if (signal) |value| {
        if (value.len == 0 or std.mem.startsWith(u8, value, "-")) return oci.validationError(error.UnexpectedArgument, "kill: signal must not be empty or start with '-'", .{});
    }
    return .{
        .root = root,
        .subcommand = subcommand,
        .id = id,
        .systemd = systemd,
        .log = log.*,
        .log_format = log_format.*,
        .bundle = bundle,
        .pid_file = pid_file,
        .console_socket = console_socket,
        .signal = signal,
        .force = force,
        .all = all,
        .ps_format = ps_format,
        .ps_args = if (subcommand == .ps) args[index + 1 ..] else &.{},
        .process_file = process_file,
        .resources_file = resources_file,
        .resource_flags = resource_flags,
        .detach = detach,
        .tty = tty,
        .exec_cwd = exec_cwd,
        .exec_user = exec_user,
        .exec_flags = if (subcommand == .exec) args[flags_start..index] else &.{},
        .exec_args = if (subcommand == .exec) args[index + 1 ..] else &.{},
    };
}

pub fn optionValue(args: []const []const u8, index: *usize, comptime missing: error{
    MissingProcessFile,
    MissingResources,
    MissingResourceValue,
    MissingPidFile,
    MissingConsoleSocket,
    MissingCwd,
    MissingEnv,
    MissingUser,
    MissingFormat,
}) ![]const u8 {
    const token = args[index.*];
    const flag = token[0 .. std.mem.indexOfScalar(u8, token, '=') orelse token.len];
    const value = if (std.mem.indexOfScalar(u8, args[index.*], '=')) |equals|
        args[index.*][equals + 1 ..]
    else value: {
        index.* += 1;
        if (index.* >= args.len) return oci.validationError(missing, "{s}: missing value", .{flag});
        if (std.mem.startsWith(u8, args[index.*], "-") and
            !(missing == error.MissingResources and std.mem.eql(u8, args[index.*], "-")) and
            !(missing == error.MissingResourceValue and args[index.*].len > 1 and std.ascii.isDigit(args[index.*][1])))
            return oci.validationError(missing, "{s}: missing value", .{flag});
        break :value args[index.*];
    };
    if (value.len == 0) return oci.validationError(missing, "{s}: missing value", .{flag});
    return value;
}

fn boolOption(flag: []const u8) !bool {
    const equals = std.mem.indexOfScalar(u8, flag, '=') orelse return true;
    const value = flag[equals + 1 ..];
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return oci.validationError(error.InvalidBoolean, "boolean option: expected true or false", .{});
}

fn parseUser(value: []const u8) !ExecUser {
    var parts = std.mem.splitScalar(u8, value, ':');
    const uid = try numericId(parts.next().?);
    const gid: ?u32 = if (parts.next()) |part| try numericId(part) else null;
    if (parts.next() != null) return oci.validationError(error.InvalidUser, "--user: expected UID[:GID]", .{});
    return .{ .uid = uid, .gid = gid };
}

fn numericId(value: []const u8) !u32 {
    if (value.len == 0) return oci.validationError(error.InvalidUser, "--user: ID must not be empty", .{});
    for (value) |byte| if (!std.ascii.isDigit(byte)) return oci.validationError(error.InvalidUser, "--user: IDs must be decimal numbers", .{});
    return std.fmt.parseInt(u32, value, 10) catch oci.validationError(error.InvalidUser, "--user: ID exceeds u32", .{});
}

test "create argument parsing accepts console sockets and rejects missing values" {
    for ([_][]const []const u8{
        &.{ "igvano", "create", "--console-socket", "/tmp/console.sock", "example" },
        &.{ "igvano", "create", "--console-socket=/tmp/console.sock", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("/tmp/console.sock", config.console_socket.?);
    }
    for ([_][]const []const u8{
        &.{ "igvano", "create", "--console-socket" },
        &.{ "igvano", "create", "--console-socket=" },
        &.{ "igvano", "create", "--console-socket", "--bundle", "/tmp" },
    }) |args| try std.testing.expectError(error.MissingConsoleSocket, parseArgs(args));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "start", "--console-socket", "/tmp/console.sock", "example" }));
}

test "exec argument parsing supports shim flags and equals forms" {
    for ([_][]const []const u8{
        &.{ "igvano", "--root", "/run/test", "--log", "/tmp/log", "--log-format", "json", "exec", "--process", "/tmp/process.json", "--detach", "--pid-file", "/tmp/pid", "--console-socket", "/tmp/console", "example" },
        &.{ "igvano", "--root=/run/test", "--log=/tmp/log", "--log-format=json", "exec", "--process=/tmp/process.json", "-d", "--pid-file=/tmp/pid", "--console-socket=/tmp/console", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqual(Subcommand.exec, config.subcommand);
        try std.testing.expectEqualStrings("/tmp/process.json", config.process_file.?);
        try std.testing.expect(config.detach);
        try std.testing.expectEqualStrings("/tmp/pid", config.pid_file.?);
        try std.testing.expectEqualStrings("/tmp/console", config.console_socket.?);
        try std.testing.expectEqual(@as(usize, 0), config.exec_args.len);
    }
    const config = try parseArgs(&.{ "igvano", "exec", "--detach=false", "--tty=true", "example", "sh", "-c", "exit 7" });
    try std.testing.expect(!config.detach);
    try std.testing.expect(config.tty.?);
    try std.testing.expectEqualStrings("-c", config.exec_args[1]);
}

test "exec argument parsing rejects missing values invalid users and conflicting commands" {
    const cases = [_]struct { args: []const []const u8, expected: anyerror }{
        .{ .args = &.{ "igvano", "exec" }, .expected = error.MissingId },
        .{ .args = &.{ "igvano", "exec", "example" }, .expected = error.MissingCommand },
        .{ .args = &.{ "igvano", "exec", "--process", "p.json", "example", "true" }, .expected = error.UnexpectedArgument },
        .{ .args = &.{ "igvano", "exec", "--process" }, .expected = error.MissingProcessFile },
        .{ .args = &.{ "igvano", "exec", "--process=" }, .expected = error.MissingProcessFile },
        .{ .args = &.{ "igvano", "exec", "--pid-file", "--detach", "example", "true" }, .expected = error.MissingPidFile },
        .{ .args = &.{ "igvano", "exec", "--console-socket=" }, .expected = error.MissingConsoleSocket },
        .{ .args = &.{ "igvano", "exec", "--cwd=" }, .expected = error.MissingCwd },
        .{ .args = &.{ "igvano", "exec", "--env=" }, .expected = error.MissingEnv },
        .{ .args = &.{ "igvano", "exec", "--env", "INVALID", "example", "true" }, .expected = error.InvalidProcess },
        .{ .args = &.{ "igvano", "exec", "--env==value", "example", "true" }, .expected = error.InvalidProcess },
        .{ .args = &.{ "igvano", "exec", "--user=" }, .expected = error.MissingUser },
        .{ .args = &.{ "igvano", "exec", "--user=root", "example", "true" }, .expected = error.InvalidUser },
        .{ .args = &.{ "igvano", "exec", "--user=1:", "example", "true" }, .expected = error.InvalidUser },
        .{ .args = &.{ "igvano", "exec", "--user=1:2:3", "example", "true" }, .expected = error.InvalidUser },
        .{ .args = &.{ "igvano", "exec", "--user=4294967296", "example", "true" }, .expected = error.InvalidUser },
        .{ .args = &.{ "igvano", "exec", "--tty=maybe", "example", "true" }, .expected = error.InvalidBoolean },
        .{ .args = &.{ "igvano", "exec", "--bundle=/tmp", "example", "true" }, .expected = error.UnknownOption },
        .{ .args = &.{ "igvano", "exec", "--process=p.json", "--detach" }, .expected = error.MissingId },
    };
    for (cases) |case| try std.testing.expectError(case.expected, parseArgs(case.args));
}

test "features takes no id and accepts shim global flags" {
    const plain = try parseArgs(&.{ "igvano", "features" });
    try std.testing.expectEqualStrings("features", @tagName(plain.subcommand));
    try std.testing.expectEqualStrings("", plain.id);
    for ([_][]const []const u8{
        &.{ "igvano", "--root", "/run/test", "--log", "/tmp/runtime.log", "--log-format", "json", "--debug", "features" },
        &.{ "igvano", "--root=/run/test", "--log=/tmp/runtime.log", "--log-format=json", "features" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("features", @tagName(config.subcommand));
        try std.testing.expectEqualStrings("/run/test", config.root);
        try std.testing.expectEqualStrings("/tmp/runtime.log", config.log.?);
        try std.testing.expectEqual(LogFormat.json, config.log_format);
        try std.testing.expectEqualStrings("", config.id);
    }
}

test "features rejects ids and subcommand flags" {
    for ([_][]const []const u8{
        &.{ "igvano", "features", "example" },
        &.{ "igvano", "features", "--root=/run/test" },
        &.{ "igvano", "features", "--log", "/tmp/runtime.log" },
        &.{ "igvano", "features", "--debug" },
    }) |args| try std.testing.expectError(error.UnexpectedArgument, parseArgs(args));
}

test "argument parsing uses the default root and positional container id" {
    const config = try parseArgs(&.{ "igvano", "state", "example" });
    try std.testing.expectEqualStrings(default_root, config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
    try std.testing.expect(config.log == null);
    try std.testing.expectEqual(LogFormat.text, config.log_format);
}

test "argument parsing accepts a global root before the subcommand" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "state", "example" });
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
}

test "argument parsing accepts a global root with an equals sign" {
    const config = try parseArgs(&.{ "igvano", "--root=/tmp/containers", "state", "example" });
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
}

test "argument parsing accepts global log flags in both forms" {
    for ([_][]const []const u8{
        &.{ "igvano", "--root", "/tmp/containers", "--log", "/tmp/runtime.log", "--log-format", "json", "state", "example" },
        &.{ "igvano", "--log-format=json", "--log=/tmp/runtime.log", "--root=/tmp/containers", "state", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("/tmp/containers", config.root);
        try std.testing.expectEqualStrings("/tmp/runtime.log", config.log.?);
        try std.testing.expectEqual(LogFormat.json, config.log_format);
        try std.testing.expectEqual(Subcommand.state, config.subcommand);
        try std.testing.expectEqualStrings("example", config.id);
    }
    for ([_][]const []const u8{
        &.{ "igvano", "--log", "/tmp/runtime.log", "state", "example" },
        &.{ "igvano", "--log-format", "text", "state", "example" },
        &.{ "igvano", "--log-format=text", "state", "example" },
    }) |args| try std.testing.expectEqual(LogFormat.text, (try parseArgs(args)).log_format);
}

test "argument parsing rejects missing log values and invalid log formats" {
    for ([_][]const []const u8{
        &.{ "igvano", "--log" },
        &.{ "igvano", "--log", "", "state", "example" },
        &.{ "igvano", "--log=" },
        &.{ "igvano", "--log", "--debug", "state", "example" },
    }) |args| try std.testing.expectError(error.MissingLog, parseArgs(args));
    for ([_][]const []const u8{
        &.{ "igvano", "--log-format" },
        &.{ "igvano", "--log-format", "", "state", "example" },
        &.{ "igvano", "--log-format=" },
        &.{ "igvano", "--log-format", "--debug", "state", "example" },
    }) |args| try std.testing.expectError(error.MissingLogFormat, parseArgs(args));
    for ([_][]const []const u8{
        &.{ "igvano", "--log-format", "yaml", "state", "example" },
        &.{ "igvano", "--log-format=JSON", "state", "example" },
    }) |args| try std.testing.expectError(error.InvalidLogFormat, parseArgs(args));
}

test "argument parsing accepts the global systemd cgroup driver" {
    const config = try parseArgs(&.{ "igvano", "--debug", "state", "example" });
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
    _ = try parseArgs(&.{ "igvano", "--systemd-cgroup", "state", "example" });
}

test "logging flags and debug remain global" {
    for ([_][]const u8{ "--log", "--log=/tmp/runtime.log", "--log-format", "--log-format=json", "--debug", "--systemd-cgroup" }) |flag| {
        try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "create", flag, "example" }));
        try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "delete", flag, "example" }));
        try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "example", flag }));
    }
}

test "argument parsing preserves log settings on later failures" {
    for ([_][]const []const u8{
        &.{ "igvano", "--log", "/tmp/runtime.log", "--log-format", "json", "--unknown" },
        &.{ "igvano", "--log=/tmp/runtime.log", "--log-format=json", "create", "--unknown", "example" },
    }) |args| {
        var log: ?[]const u8 = null;
        var log_format: LogFormat = .text;
        try std.testing.expectError(error.UnknownOption, parseArgsWithLog(args, &log, &log_format));
        try std.testing.expectEqualStrings("/tmp/runtime.log", log.?);
        try std.testing.expectEqual(LogFormat.json, log_format);
    }
    var log: ?[]const u8 = null;
    var log_format: LogFormat = .text;
    try std.testing.expectError(error.InvalidLogFormat, parseArgsWithLog(&.{ "igvano", "--log=runtime.log", "--log-format=bad" }, &log, &log_format));
    try std.testing.expectEqualStrings("runtime.log", log.?);
    try std.testing.expectEqual(LogFormat.text, log_format);
}

test "argument parsing rejects missing arguments and misplaced global flags" {
    try std.testing.expectError(error.MissingSubcommand, parseArgs(&.{"igvano"}));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root" }));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root", "" }));
    try std.testing.expectError(error.MissingRoot, parseArgs(&.{ "igvano", "--root=" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "state" }));
    try std.testing.expectError(error.UnknownSubcommand, parseArgs(&.{ "igvano", "unknown", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "--unknown", "state", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "example", "extra" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "--root", "/tmp", "example" }));
}

test "argument parsing rejects ids that escape the container directory" {
    for ([_][]const u8{ "", ".", "..", "../example", "/example", "example/other", "example\x00other", "-example" }) |id| {
        try std.testing.expectError(error.InvalidId, parseArgs(&.{ "igvano", "state", id }));
    }
}

test "ps pause and resume parsing accepts runc command forms" {
    for ([_][]const []const u8{
        &.{ "igvano", "ps", "example" },
        &.{ "igvano", "ps", "--format", "json", "example" },
        &.{ "igvano", "ps", "--format=table", "example", "-ef" },
        &.{ "igvano", "pause", "example" },
        &.{ "igvano", "resume", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings(args[1], @tagName(config.subcommand));
        try std.testing.expectEqualStrings("example", config.id);
    }
    try std.testing.expectEqual(PsFormat.table, (try parseArgs(&.{ "igvano", "ps", "example" })).ps_format);
    try std.testing.expectEqual(PsFormat.json, (try parseArgs(&.{ "igvano", "ps", "--format=json", "example" })).ps_format);
    const config = try parseArgs(&.{ "igvano", "ps", "example", "-o", "pid,comm" });
    try std.testing.expectEqualSlices([]const u8, &.{ "-o", "pid,comm" }, config.ps_args);
}

test "ps pause and resume reject invalid flags values and extra arguments" {
    try std.testing.expectError(error.MissingFormat, parseArgs(&.{ "igvano", "ps", "--format" }));
    try std.testing.expectError(error.MissingFormat, parseArgs(&.{ "igvano", "ps", "--format=", "example" }));
    try std.testing.expectError(error.MissingFormat, parseArgs(&.{ "igvano", "ps", "--format", "--other", "example" }));
    try std.testing.expectError(error.InvalidFormat, parseArgs(&.{ "igvano", "ps", "--format", "yaml", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "ps", "--unknown", "example" }));
    for ([_][]const u8{ "ps", "pause", "resume" }) |command| {
        try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", command }));
        try std.testing.expectError(error.InvalidId, parseArgs(&.{ "igvano", command, "../example" }));
    }
    for ([_][]const u8{ "pause", "resume" }) |command|
        try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", command, "example", "extra" }));
}

test "argument diagnostics identify the offending exec option command or kill signal" {
    defer oci.clearDiagnostic();
    try std.testing.expectError(error.MissingEnv, parseArgs(&.{ "igvano", "exec", "--env=" }));
    try std.testing.expectEqualStrings("--env: missing value", oci.diagnosticFor(error.MissingEnv).?);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "exec", "--process=p.json", "example", "true" }));
    try std.testing.expect(std.mem.indexOf(u8, oci.diagnosticFor(error.UnexpectedArgument).?, "global flags") == null);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "kill", "example", "-TERM" }));
    try std.testing.expect(std.mem.indexOf(u8, oci.diagnosticFor(error.UnexpectedArgument).?, "signal") != null);
    try std.testing.expect(std.mem.indexOf(u8, oci.diagnosticFor(error.UnexpectedArgument).?, "global flags") == null);
}

test "create parsing accepts bundle and optional pid file after the subcommand" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "create", "--bundle", "/tmp/bundle", "--pid-file", "/tmp/init.pid", "example" });
    try std.testing.expectEqual(Subcommand.create, config.subcommand);
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqualStrings("example", config.id);
    try std.testing.expectEqualStrings("/tmp/bundle", config.bundle.?);
    try std.testing.expectEqualStrings("/tmp/init.pid", config.pid_file.?);

    const no_pid = try parseArgs(&.{ "igvano", "create", "--bundle", "bundle", "example" });
    try std.testing.expectEqualStrings("bundle", no_pid.bundle.?);
    try std.testing.expect(no_pid.pid_file == null);
    const equals = try parseArgs(&.{ "igvano", "create", "--pid-file=/tmp/init.pid", "--bundle=/tmp/bundle", "example" });
    try std.testing.expectEqualStrings("/tmp/bundle", equals.bundle.?);
    try std.testing.expectEqualStrings("/tmp/init.pid", equals.pid_file.?);
}

test "create parsing defaults the bundle to the current directory" {
    const config = try parseArgs(&.{ "igvano", "create", "example" });
    try std.testing.expectEqualStrings(".", config.bundle.?);
    const with_pid = try parseArgs(&.{ "igvano", "create", "--pid-file", "init.pid", "example" });
    try std.testing.expectEqualStrings(".", with_pid.bundle.?);
    try std.testing.expectEqualStrings("init.pid", with_pid.pid_file.?);
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "create" }));
}

test "create parsing rejects missing bundle and pid file values" {
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle", "", "example" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle=" }));
    try std.testing.expectError(error.MissingBundle, parseArgs(&.{ "igvano", "create", "--bundle", "--pid-file", "init.pid", "example" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle" }));
    try std.testing.expectError(error.MissingPidFile, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "--pid-file" }));
    try std.testing.expectError(error.MissingPidFile, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "--pid-file=" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "create", "--root", "/tmp", "--bundle", "/tmp/bundle", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "example", "--pid-file", "init.pid" }));
}

test "kill parsing preserves an optional positional signal" {
    const default_signal = try parseArgs(&.{ "igvano", "kill", "example" });
    try std.testing.expect(default_signal.signal == null);
    try std.testing.expect(!default_signal.all);
    const explicit_signal = try parseArgs(&.{ "igvano", "kill", "example", "TERM" });
    try std.testing.expectEqualStrings("TERM", explicit_signal.signal.?);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "kill", "example", "TERM", "extra" }));
}

test "kill parsing accepts all before the id" {
    const default_signal = try parseArgs(&.{ "igvano", "kill", "--all", "example" });
    try std.testing.expectEqual(Subcommand.kill, default_signal.subcommand);
    try std.testing.expectEqualStrings("example", default_signal.id);
    try std.testing.expect(default_signal.signal == null);
    try std.testing.expect(default_signal.all);
    const explicit_signal = try parseArgs(&.{ "igvano", "kill", "-a", "example", "15" });
    try std.testing.expectEqualStrings("example", explicit_signal.id);
    try std.testing.expectEqualStrings("15", explicit_signal.signal.?);
    try std.testing.expect(explicit_signal.all);
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "kill", "--all" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "kill", "-a" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "kill", "example", "--all" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "kill", "example", "-a" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "--all", "kill", "example" }));
    const rejected = [_]struct { subcommand: []const u8, err: anyerror }{
        .{ .subcommand = "create", .err = error.UnknownOption },
        .{ .subcommand = "state", .err = error.UnexpectedArgument },
        .{ .subcommand = "start", .err = error.UnexpectedArgument },
        .{ .subcommand = "delete", .err = error.UnknownOption },
    };
    for (rejected) |case| {
        for ([_][]const u8{ "--all", "-a" }) |flag|
            try std.testing.expectError(case.err, parseArgs(&.{ "igvano", case.subcommand, flag, "example" }));
    }
}

test "argument parsing accepts force only for delete" {
    const config = try parseArgs(&.{ "igvano", "--root", "/tmp/containers", "delete", "--force", "example" });
    try std.testing.expectEqual(Subcommand.delete, config.subcommand);
    try std.testing.expectEqualStrings("/tmp/containers", config.root);
    try std.testing.expectEqualStrings("example", config.id);
    try std.testing.expect(config.force);
    try std.testing.expect(!(try parseArgs(&.{ "igvano", "delete", "example" })).force);
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "delete", "--force" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "--force", "delete", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "delete", "--force=true", "example" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "delete", "example", "--force" }));
    const rejected = [_]struct { subcommand: []const u8, err: anyerror }{
        .{ .subcommand = "create", .err = error.UnknownOption },
        .{ .subcommand = "state", .err = error.UnexpectedArgument },
        .{ .subcommand = "start", .err = error.UnexpectedArgument },
        .{ .subcommand = "kill", .err = error.InvalidId },
    };
    for (rejected) |case| {
        try std.testing.expectError(case.err, parseArgs(&.{ "igvano", case.subcommand, "--force", "example" }));
    }
}

pub const usage =
    "Usage: igvano [--root <dir>] [--log <file>] [--log-format text|json] <state|start|pause|resume> <id>\n" ++
    "       igvano [global flags] features\n" ++
    "       igvano [global flags] ps [--format table|json] <id> [ps args...]\n" ++
    "       igvano [global flags] update [--resources|-r <file|->] [resource flags...] <id>\n" ++
    "              --resources/-r ignores individual resource flags\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] delete [--force] <id>\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] kill [--all] <id> [signal]\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] create [--bundle <path>] [--pid-file <file>] [--console-socket <path>] <id>\n" ++
    "       igvano [global flags] exec [--process <file>] [--detach|-d] [--pid-file <file>] [--console-socket <path>]\n" ++
    "              [--tty|-t] [--cwd <dir>] [--env K=V]... [--user UID[:GID]] <id> [command args...]\n";

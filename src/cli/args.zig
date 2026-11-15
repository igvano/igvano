const std = @import("std");
const oci = @import("igvano").oci;
const LogFormat = @import("log.zig").LogFormat;
const parseDuration = @import("events.zig").parseDuration;

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
    spec,
    run,
    list,
    events,
    checkpoint,
    restore,
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
    /// --pidfd-socket: receives a pidfd of the container or exec process.
    pidfd_socket: ?[]const u8 = null,
    /// create/run --no-pivot: chroot into the rootfs instead of pivot_root.
    no_pivot: bool = false,
    signal: ?[]const u8 = null,
    systemd: bool = false,
    /// spec --rootless.
    rootless: bool = false,
    /// $PATH, for newuidmap/newgidmap lookups by a non-root runtime.
    path_env: ?[]const u8 = null,
    /// $NOTIFY_SOCKET: relay the container's sd_notify READY= (notify.zig).
    notify_socket: ?[]const u8 = null,
    /// --debug; main opens debug_log from it.
    debug: bool = false,
    debug_log: ?@import("libcontainer").DebugLog = null,
    force: bool = false,
    all: bool = false,
    ps_format: PsFormat = .table,
    ps_args: []const []const u8 = &.{},
    process_file: ?[]const u8 = null,
    resources_file: ?[]const u8 = null,
    resource_flags: oci.Spec.Resources = .{},
    detach: bool = false,
    keep: bool = false,
    quiet: bool = false,
    events_stats: bool = false,
    events_interval_ns: u64 = 5 * std.time.ns_per_s,
    tty: ?bool = null,
    exec_cwd: ?[]const u8 = null,
    exec_user: ?ExecUser = null,
    /// Borrowed option tokens, scanned again to collect repeated --env values.
    exec_flags: []const []const u8 = &.{},
    exec_no_new_privs: ?bool = null,
    exec_apparmor: ?[]const u8 = null,
    exec_process_label: ?[]const u8 = null,
    /// --cgroup: a sub-cgroup of the container's to join.
    ignore_paused: bool = false,
    /// --preserve-fds: pass fds 3..3+N-1 through to the process.
    preserve_fds: u16 = 0,
    exec_args: []const []const u8 = &.{},
    criu: CriuFlags = .{},
};

/// runc checkpoint and restore flags, kept as given; the frontend validates.
pub const CriuFlags = struct {
    image_path: ?[]const u8 = null,
    work_path: ?[]const u8 = null,
    parent_path: ?[]const u8 = null,
    page_server: ?[]const u8 = null,
    manage_cgroups_mode: ?[]const u8 = null,
    lsm_profile: ?[]const u8 = null,
    lsm_mount_context: ?[]const u8 = null,
    status_fd: ?i32 = null,
    /// --empty-ns network, as CLONE_NEWNET; runc only knows network.
    empty_ns: u32 = 0,
    leave_running: bool = false,
    tcp_established: bool = false,
    tcp_skip_in_flight: bool = false,
    link_remap: bool = false,
    ext_unix_sk: bool = false,
    shell_job: bool = false,
    lazy_pages: bool = false,
    file_locks: bool = false,
    pre_dump: bool = false,
    auto_dedup: bool = false,
    no_subreaper: bool = false,
};

pub fn parseArgs(args: []const []const u8) !Config {
    var log: ?[]const u8 = null;
    var log_format: LogFormat = .text;
    return parseArgsWithLog(args, &log, &log_format);
}

// Keep the settings already parsed available when a later argument fails.
pub fn parseArgsWithLog(args: []const []const u8, log: *?[]const u8, log_format: *LogFormat) !Config {
    // The subcommand is assigned before any successful return; every error drops config.
    var config: Config = .{ .root = default_root, .subcommand = undefined, .id = "" };
    var index: usize = 1;
    try parseGlobalOptions(args, &index, &config, log, log_format);
    if (index >= args.len) return oci.validationError(error.MissingSubcommand, "missing subcommand", .{});
    config.subcommand = std.meta.stringToEnum(Subcommand, args[index]) orelse
        return oci.validationError(error.UnknownSubcommand, "unknown subcommand '{s}'", .{args[index]});
    config.log = log.*;
    config.log_format = log_format.*;
    index += 1;
    if (config.subcommand == .features) {
        if (index != args.len) return oci.validationError(error.UnexpectedArgument, "unexpected argument; global flags must precede the subcommand", .{});
        return config;
    }
    var reordered: [max_reordered_args][]const u8 = undefined;
    const command_args = try reorderArgs(commandFlagNames(config.subcommand), args[index..], &reordered);
    var command_index: usize = 0;
    try parseCommandOptions(command_args, &command_index, &config);
    if (config.subcommand == .spec or config.subcommand == .list) {
        if (command_index != command_args.len) return oci.validationError(error.UnexpectedArgument, "{s}: takes no arguments", .{@tagName(config.subcommand)});
        return config;
    }
    try parseCommandArguments(command_args, command_index, &config);
    // exec and ps are never reordered, so these slices borrow args, not the buffer.
    if (config.subcommand == .exec) config.exec_flags = command_args[0..command_index];
    return config;
}

// ponytail: fixed stack buffer instead of an allocator; non-exec/ps commands
// never come close. Raise it, or pass an allocator, if a command ever needs more.
const max_reordered_args = 128;

/// Flag names (without dashes) each subcommand moves ahead of its positional
/// arguments. exec and ps keep runc's SkipArgReorder; the rest take no flags.
fn commandFlagNames(subcommand: Subcommand) []const []const u8 {
    return switch (subcommand) {
        .create => &.{ "bundle", "b", "pid-file", "console-socket", "pidfd-socket", "no-pivot", "preserve-fds" },
        .run => &.{ "bundle", "b", "pid-file", "console-socket", "pidfd-socket", "no-pivot", "preserve-fds", "detach", "d", "keep" },
        .checkpoint, .restore => &criu_flag_names,
        .spec => &.{ "bundle", "b", "rootless" },
        .list => &.{ "quiet", "q", "format", "f" },
        .events => &.{ "stats", "interval" },
        .delete => &.{ "force", "f" },
        .kill => &.{ "all", "a" },
        .update => &.{
            "resources",  "r",         "memory",      "memory-reservation", "memory-swap",   "kernel-memory",
            "cpu-shares", "cpu-share", "cpu-period",  "cpu-quota",          "cpu-rt-period", "cpu-rt-runtime",
            "cpu-idle",   "cpu-burst", "cpuset-cpus", "cpuset-mems",        "pids-limit",    "blkio-weight",
        },
        else => &.{},
    };
}

/// Port of urfave/cli v1 reorderArgs, which runc relies on: the subcommand's
/// own flags, each with the argument that may follow it, move ahead of the
/// positional arguments, and everything after a bare `--` stays positional.
fn reorderArgs(flag_names: []const []const u8, args: []const []const u8, buffer: *[max_reordered_args][]const u8) ![]const []const u8 {
    if (flag_names.len == 0) return args;
    if (args.len > buffer.len) return oci.validationError(error.UnexpectedArgument, "too many arguments", .{});
    var remaining: [max_reordered_args][]const u8 = undefined;
    var flags_len: usize = 0;
    var remaining_len: usize = 0;
    var may_take_value = false;
    for (args, 0..) |arg, i| {
        if (may_take_value and !isCommandFlag(flag_names, arg)) {
            may_take_value = false;
            buffer[flags_len] = arg;
            flags_len += 1;
        } else if (std.mem.eql(u8, arg, "--")) {
            // The delimiter goes first, then the earlier positionals, then the rest verbatim.
            std.mem.copyBackwards([]const u8, remaining[1 .. remaining_len + 1], remaining[0..remaining_len]);
            remaining[0] = arg;
            remaining_len += 1;
            for (args[i + 1 ..]) |rest| {
                remaining[remaining_len] = rest;
                remaining_len += 1;
            }
            break;
        } else if (isCommandFlag(flag_names, arg)) {
            buffer[flags_len] = arg;
            flags_len += 1;
            may_take_value = std.mem.indexOfScalar(u8, arg, '=') == null;
        } else {
            remaining[remaining_len] = arg;
            remaining_len += 1;
        }
    }
    @memcpy(buffer[flags_len..][0..remaining_len], remaining[0..remaining_len]);
    return buffer[0 .. flags_len + remaining_len];
}

fn isCommandFlag(flag_names: []const []const u8, arg: []const u8) bool {
    if (std.mem.eql(u8, arg, "-") or std.mem.eql(u8, arg, "--") or !std.mem.startsWith(u8, arg, "-")) return false;
    var name = if (std.mem.startsWith(u8, arg, "--")) arg[2..] else arg;
    if (std.mem.startsWith(u8, name, "-")) name = name[1..];
    name = name[0 .. std.mem.indexOfScalar(u8, name, '=') orelse name.len];
    for (flag_names) |flag_name| {
        if (std.mem.eql(u8, flag_name, name)) return true;
    }
    return false;
}

fn optionName(flag: []const u8) []const u8 {
    return flag[0 .. std.mem.indexOfScalar(u8, flag, '=') orelse flag.len];
}

fn longOptionValue(args: []const []const u8, index: *usize, comptime missing: error{ MissingRoot, MissingLog, MissingLogFormat, MissingBundle, MissingPidFile, MissingConsoleSocket, MissingPidfdSocket }, allow_dash_value: bool) ![]const u8 {
    const flag = optionName(args[index.*]);
    const value = if (std.mem.indexOfScalar(u8, args[index.*], '=')) |equals|
        args[index.*][equals + 1 ..]
    else value: {
        index.* += 1;
        if (index.* >= args.len) return oci.validationError(missing, "{s}: missing value", .{flag});
        if (!allow_dash_value and std.mem.startsWith(u8, args[index.*], "--"))
            return oci.validationError(missing, "{s}: missing value", .{flag});
        break :value args[index.*];
    };
    if (value.len == 0) return oci.validationError(missing, "{s}: missing value", .{flag});
    return value;
}

fn parseGlobalOptions(args: []const []const u8, index: *usize, config: *Config, log: *?[]const u8, log_format: *LogFormat) !void {
    const options = std.StaticStringMap(enum { root, log, log_format, debug, systemd }).initComptime(.{
        .{ "--root", .root },   .{ "--log", .log },                .{ "--log-format", .log_format },
        .{ "--debug", .debug }, .{ "--systemd-cgroup", .systemd },
    });
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        const flag = args[index.*];
        const option = options.get(optionName(flag)) orelse return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        switch (option) {
            .root => config.root = try longOptionValue(args, index, error.MissingRoot, true),
            .log => log.* = try longOptionValue(args, index, error.MissingLog, false),
            .log_format => {
                const value = try longOptionValue(args, index, error.MissingLogFormat, false);
                log_format.* = std.meta.stringToEnum(LogFormat, value) orelse return oci.validationError(error.InvalidLogFormat, "--log-format: expected text or json", .{});
            },
            .debug, .systemd => {
                if (std.mem.indexOfScalar(u8, flag, '=') != null) return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
                if (option == .systemd) config.systemd = true else config.debug = true;
            },
        }
    }
}

fn parseCommandOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    switch (config.subcommand) {
        .exec => try parseExecOptions(args, index, config),
        .create, .run, .spec => try parseCreateOptions(args, index, config),
        .update => {
            const update = try parseUpdateArgs(args, index.*);
            index.* = update.index;
            config.resources_file = update.resources_file;
            config.resource_flags = update.resource_flags;
        },
        .delete => try parseDeleteOptions(args, index, config),
        .checkpoint, .restore => try parseCriuOptions(args, index, config),
        .ps, .list => try parsePsOptions(args, index, config),
        .events => try parseEventsOptions(args, index, config),
        .kill => {
            while (index.* < args.len and (std.mem.eql(u8, args[index.*], "--all") or
                std.mem.eql(u8, args[index.*], "-a"))) : (index.* += 1)
            {
                config.all = true;
            }
        },
        else => {},
    }
}

pub const ExecOption = enum { detach, tty, process, pid_file, console_socket, pidfd_socket, cwd, user, env, additional_gids, cap, no_new_privs, apparmor, process_label, preserve_fds, cgroup, ignore_paused };

/// runc exec's flags, short aliases included.
pub const exec_options = std.StaticStringMap(ExecOption).initComptime(.{
    .{ "--detach", .detach },             .{ "-d", .detach },                         .{ "--tty", .tty },                     .{ "-t", .tty },
    .{ "--process", .process },           .{ "-p", .process },                        .{ "--pid-file", .pid_file },           .{ "--console-socket", .console_socket },
    .{ "--cwd", .cwd },                   .{ "--user", .user },                       .{ "-u", .user },                       .{ "--env", .env },
    .{ "-e", .env },                      .{ "--additional-gids", .additional_gids }, .{ "-g", .additional_gids },            .{ "--cap", .cap },
    .{ "-c", .cap },                      .{ "--no-new-privs", .no_new_privs },       .{ "--apparmor", .apparmor },           .{ "--process-label", .process_label },
    .{ "--preserve-fds", .preserve_fds }, .{ "--cgroup", .cgroup },                   .{ "--ignore-paused", .ignore_paused }, .{ "--pidfd-socket", .pidfd_socket },
});

pub fn execOptionIsBool(option: ExecOption) bool {
    return switch (option) {
        .detach, .tty, .no_new_privs, .ignore_paused => true,
        else => false,
    };
}

/// The values of a repeatable exec flag (--env, --additional-gids, --cap),
/// in order, from the already validated exec_flags.
pub const ExecValues = struct {
    flags: []const []const u8,
    option: ExecOption,
    index: usize = 0,

    pub fn next(self: *ExecValues) ?[]const u8 {
        while (self.index < self.flags.len) {
            const flag = self.flags[self.index];
            const option = exec_options.get(optionName(flag)).?;
            const inline_value = std.mem.indexOfScalar(u8, flag, '=');
            self.index += 1;
            if (execOptionIsBool(option)) continue;
            const value = if (inline_value) |equals| flag[equals + 1 ..] else value: {
                self.index += 1;
                break :value self.flags[self.index - 1];
            };
            if (option == self.option) return value;
        }
        return null;
    }
};

fn applyExecBool(config: *Config, option: ExecOption, value: bool) void {
    switch (option) {
        .detach => config.detach = value,
        .tty => config.tty = value,
        .no_new_privs => config.exec_no_new_privs = value,
        .ignore_paused => config.ignore_paused = value,
        else => unreachable,
    }
}

fn parseExecOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        const flag = args[index.*];
        const option = exec_options.get(optionName(flag)) orelse return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        // Short boolean flags accept only their bare form.
        if (execOptionIsBool(option) and flag.len > 1 and flag[1] != '-' and std.mem.indexOfScalar(u8, flag, '=') != null)
            return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        try applyExecOption(args, index, config, option, flag);
    }
}

fn applyExecOption(args: []const []const u8, index: *usize, config: *Config, option: ExecOption, flag: []const u8) !void {
    if (execOptionIsBool(option)) return applyExecBool(config, option, try boolOption(flag));
    switch (option) {
        .detach, .tty, .no_new_privs, .ignore_paused => unreachable,
        .process => config.process_file = try optionValue(args, index, error.MissingProcessFile),
        .pid_file => config.pid_file = try optionValue(args, index, error.MissingPidFile),
        .console_socket => config.console_socket = try optionValue(args, index, error.MissingConsoleSocket),
        .pidfd_socket => config.pidfd_socket = try optionValue(args, index, error.MissingPidfdSocket),
        .cwd => config.exec_cwd = try optionValue(args, index, error.MissingCwd),
        .user => config.exec_user = try parseUser(try optionValue(args, index, error.MissingUser)),
        .env => try oci.validateEnv(try optionValue(args, index, error.MissingEnv)),
        .additional_gids => _ = try numericId(try optionValue(args, index, error.MissingExecValue)),
        // --cgroup is parsed later from exec_flags (see exec.subCgroups).
        .cap, .cgroup => _ = try optionValue(args, index, error.MissingExecValue),
        .process_label => config.exec_process_label = try optionValue(args, index, error.MissingExecValue),
        .apparmor => config.exec_apparmor = try optionValue(args, index, error.MissingExecValue),
        .preserve_fds => config.preserve_fds = try preserveFds(try optionValue(args, index, error.MissingExecValue)),
    }
}

fn preserveFds(value: []const u8) !u16 {
    return std.fmt.parseUnsigned(u16, value, 10) catch
        oci.validationError(error.InvalidExecValue, "--preserve-fds: expected a number", .{});
}

const CreateOption = enum { bundle, pid_file, console_socket, pidfd_socket, no_pivot, preserve_fds, detach, keep, rootless };

// spec takes only the bundle; detach and keep are run-only booleans.
fn createOptionAllowed(subcommand: Subcommand, option: CreateOption, flag: []const u8) bool {
    if (subcommand == .spec) return option == .bundle or (option == .rootless and std.mem.indexOfScalar(u8, flag, '=') == null);
    if (option == .rootless) return false;
    if (option == .no_pivot) return std.mem.indexOfScalar(u8, flag, '=') == null;
    if (option != .detach and option != .keep) return true;
    return subcommand == .run and std.mem.indexOfScalar(u8, flag, '=') == null;
}

fn parseCreateOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    const options = std.StaticStringMap(CreateOption).initComptime(.{
        .{ "--bundle", .bundle },             .{ "-b", .bundle },           .{ "--pid-file", .pid_file },         .{ "--console-socket", .console_socket },
        .{ "--detach", .detach },             .{ "-d", .detach },           .{ "--keep", .keep },                 .{ "--rootless", .rootless },
        .{ "--pidfd-socket", .pidfd_socket }, .{ "--no-pivot", .no_pivot }, .{ "--preserve-fds", .preserve_fds },
    });
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        const flag = args[index.*];
        const option = options.get(optionName(flag)) orelse return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        if (!createOptionAllowed(config.subcommand, option, flag))
            return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        switch (option) {
            .bundle => config.bundle = try longOptionValue(args, index, error.MissingBundle, false),
            .pid_file => config.pid_file = try longOptionValue(args, index, error.MissingPidFile, false),
            .console_socket => config.console_socket = try longOptionValue(args, index, error.MissingConsoleSocket, false),
            .pidfd_socket => config.pidfd_socket = try longOptionValue(args, index, error.MissingPidfdSocket, false),
            .no_pivot => config.no_pivot = true,
            .preserve_fds => config.preserve_fds = try preserveFds(try optionValue(args, index, error.MissingExecValue)),
            .detach => config.detach = true,
            .keep => config.keep = true,
            .rootless => config.rootless = true,
        }
    }
    if (config.bundle == null) config.bundle = ".";
}

const CriuCommand = enum { checkpoint, restore, both };
const CriuFlag = struct { name: []const u8, field: []const u8, command: CriuCommand };

/// runc's checkpoint and restore flags, with the Config or CriuFlags field
/// each sets; bool fields take bare flags or =true/=false.
const criu_flags = [_]CriuFlag{
    .{ .name = "image-path", .field = "image_path", .command = .both },
    .{ .name = "work-path", .field = "work_path", .command = .both },
    .{ .name = "parent-path", .field = "parent_path", .command = .checkpoint },
    .{ .name = "leave-running", .field = "leave_running", .command = .checkpoint },
    .{ .name = "tcp-established", .field = "tcp_established", .command = .both },
    .{ .name = "tcp-skip-in-flight", .field = "tcp_skip_in_flight", .command = .checkpoint },
    .{ .name = "link-remap", .field = "link_remap", .command = .checkpoint },
    .{ .name = "ext-unix-sk", .field = "ext_unix_sk", .command = .both },
    .{ .name = "shell-job", .field = "shell_job", .command = .both },
    .{ .name = "lazy-pages", .field = "lazy_pages", .command = .both },
    .{ .name = "status-fd", .field = "status_fd", .command = .checkpoint },
    .{ .name = "page-server", .field = "page_server", .command = .checkpoint },
    .{ .name = "file-locks", .field = "file_locks", .command = .both },
    .{ .name = "pre-dump", .field = "pre_dump", .command = .checkpoint },
    .{ .name = "manage-cgroups-mode", .field = "manage_cgroups_mode", .command = .both },
    .{ .name = "empty-ns", .field = "empty_ns", .command = .both },
    .{ .name = "auto-dedup", .field = "auto_dedup", .command = .both },
    .{ .name = "no-subreaper", .field = "no_subreaper", .command = .restore },
    .{ .name = "lsm-profile", .field = "lsm_profile", .command = .restore },
    .{ .name = "lsm-mount-context", .field = "lsm_mount_context", .command = .restore },
    .{ .name = "console-socket", .field = "console_socket", .command = .restore },
    .{ .name = "bundle", .field = "bundle", .command = .restore },
    .{ .name = "b", .field = "bundle", .command = .restore },
    .{ .name = "detach", .field = "detach", .command = .restore },
    .{ .name = "d", .field = "detach", .command = .restore },
    .{ .name = "pid-file", .field = "pid_file", .command = .restore },
    .{ .name = "no-pivot", .field = "no_pivot", .command = .restore },
};

const criu_flag_names = names: {
    var names: [criu_flags.len][]const u8 = undefined;
    for (criu_flags, &names) |flag, *name| name.* = flag.name;
    break :names names;
};

fn parseCriuOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-") and !std.mem.eql(u8, args[index.*], "--")) : (index.* += 1) {
        const flag = args[index.*];
        var name = optionName(flag)[1..];
        if (std.mem.startsWith(u8, name, "-")) name = name[1..];
        inline for (criu_flags) |entry| {
            if (std.mem.eql(u8, name, entry.name) and (entry.command == .both or
                std.mem.eql(u8, @tagName(entry.command), @tagName(config.subcommand))))
                break try applyCriuOption(args, index, config, entry.field, flag);
        } else return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
    }
    if (config.subcommand == .restore and config.bundle == null) config.bundle = ".";
}

fn applyCriuOption(args: []const []const u8, index: *usize, config: *Config, comptime field: []const u8, flag: []const u8) !void {
    const target = if (@hasField(CriuFlags, field)) &@field(config.criu, field) else &@field(config, field);
    switch (@TypeOf(target.*)) {
        bool => target.* = try boolOption(flag),
        u32 => {
            const value = try optionValue(args, index, error.MissingCriuValue);
            if (!std.mem.eql(u8, value, "network"))
                return oci.validationError(error.InvalidCriuValue, "namespace \"{s}\" is not supported", .{value});
            target.* |= std.os.linux.CLONE.NEWNET;
        },
        ?i32 => {
            const value = try optionValue(args, index, error.MissingCriuValue);
            target.* = std.fmt.parseInt(i32, value, 10) catch
                return oci.validationError(error.InvalidCriuValue, "{s}: expected a number", .{optionName(flag)});
        },
        else => target.* = try optionValue(args, index, error.MissingCriuValue),
    }
}

fn parseEventsOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        const flag = args[index.*];
        if (std.mem.eql(u8, flag, "--stats")) {
            config.events_stats = true;
        } else if (std.mem.eql(u8, optionName(flag), "--interval")) {
            const value = try optionValue(args, index, error.MissingInterval);
            config.events_interval_ns = parseDuration(value) catch
                return oci.validationError(error.InvalidDuration, "duration interval must be greater than 0 (got '{s}')", .{value});
        } else return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
    }
}

fn parseDeleteOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        if (!std.mem.eql(u8, args[index.*], "--force") and !std.mem.eql(u8, args[index.*], "-f")) return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index.*]});
        config.force = true;
    }
}

fn parsePsOptions(args: []const []const u8, index: *usize, config: *Config) !void {
    while (index.* < args.len and std.mem.startsWith(u8, args[index.*], "-")) : (index.* += 1) {
        const flag = args[index.*];
        if (config.subcommand == .list and (std.mem.eql(u8, flag, "--quiet") or std.mem.eql(u8, flag, "-q"))) {
            config.quiet = true;
            continue;
        }
        const name = optionName(flag);
        if (!std.mem.eql(u8, name, "--format") and !std.mem.eql(u8, name, "-f"))
            return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{args[index.*]});
        config.ps_format = std.meta.stringToEnum(PsFormat, try optionValue(args, index, error.MissingFormat)) orelse
            return oci.validationError(error.InvalidFormat, "--format: expected table or json", .{});
    }
}

fn parseCommandArguments(args: []const []const u8, index: usize, config: *Config) !void {
    if (index >= args.len) return oci.validationError(error.MissingId, "container id: required", .{});
    const remaining = args.len - index;
    try requireArgumentCount(config.*, remaining);
    const id = args[index];
    if (id.len == 0 or std.mem.indexOfScalar(u8, id, 0) != null or std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or std.mem.startsWith(u8, id, "-"))
    {
        return oci.validationError(error.InvalidId, "container id: must not be empty, contain / or NUL, or equal . or ..", .{});
    }
    config.id = id;
    config.signal = if (config.subcommand == .kill and remaining == 2) args[index + 1] else null;
    if (config.signal) |value| {
        if (value.len == 0 or std.mem.startsWith(u8, value, "-")) return oci.validationError(error.UnexpectedArgument, "kill: signal must not be empty or start with '-'", .{});
    }
    if (config.subcommand == .ps) config.ps_args = args[index + 1 ..];
    if (config.subcommand == .exec) config.exec_args = args[index + 1 ..];
}

fn requireArgumentCount(config: Config, remaining: usize) !void {
    if (config.subcommand == .exec) {
        if (config.process_file != null and remaining != 1) return oci.validationError(error.UnexpectedArgument, "exec: --process cannot be combined with command arguments", .{});
        if (config.process_file == null and remaining == 1) return oci.validationError(error.MissingCommand, "exec: requires a command or --process", .{});
    } else if (config.subcommand != .ps and remaining != 1 and !(config.subcommand == .kill and remaining == 2)) return oci.validationError(error.UnexpectedArgument, "unexpected argument; global flags must precede the subcommand", .{});
}

pub fn parseUpdateArgs(args: []const []const u8, start_index: usize) !struct {
    index: usize,
    resources_file: ?[]const u8,
    resource_flags: oci.Spec.Resources,
} {
    var index = start_index;
    var resources_file: ?[]const u8 = null;
    var resource_flags: oci.Spec.Resources = .{};
    var has_resource_flags = false;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
        const flag = args[index];
        const name = flag[0 .. std.mem.indexOfScalar(u8, flag, '=') orelse flag.len];
        if (std.mem.eql(u8, name, "--resources") or std.mem.eql(u8, name, "-r")) {
            resources_file = try optionValue(args, &index, error.MissingResources);
            continue;
        }
        const matched = try parseMemoryOption(args, &index, name, &resource_flags) or
            try parseCpuOption(args, &index, name, &resource_flags) or
            try parseCpusetOption(args, &index, name, &resource_flags) or
            try parseOtherResourceOption(args, &index, name, &resource_flags);
        if (!matched) return oci.validationError(error.UnknownOption, "unknown option '{s}'", .{flag});
        has_resource_flags = true;
    }
    if (resources_file == null and !has_resource_flags) return oci.validationError(error.MissingResources, "update: requires --resources <file|-> or resource flags", .{});
    return .{ .index = index, .resources_file = resources_file, .resource_flags = resource_flags };
}

fn parseMemoryOption(args: []const []const u8, index: *usize, name: []const u8, resources: *oci.Spec.Resources) !bool {
    inline for (.{
        .{ "--memory", "limit" },
        .{ "--memory-reservation", "reservation" },
        .{ "--memory-swap", "swap" },
        .{ "--kernel-memory", "kernel" },
    }) |entry| {
        if (std.mem.eql(u8, name, entry[0])) {
            const value = try optionValue(args, index, error.MissingResourceValue);
            if (resources.memory == null) resources.memory = .{};
            @field(resources.memory.?, entry[1]) = parseMemoryBytes(value) catch
                return oci.validationError(error.InvalidResourceValue, "{s}: invalid memory size '{s}'", .{ name, value });
            return true;
        }
    }
    return false;
}

fn parseCpuOption(args: []const []const u8, index: *usize, name: []const u8, resources: *oci.Spec.Resources) !bool {
    inline for (.{
        .{ "--cpu-shares", "shares", u64 },
        .{ "--cpu-share", "shares", u64 },
        .{ "--cpu-period", "period", u64 },
        .{ "--cpu-quota", "quota", i64 },
        .{ "--cpu-rt-period", "realtimePeriod", u64 },
        .{ "--cpu-rt-runtime", "realtimeRuntime", i64 },
        .{ "--cpu-idle", "idle", i64 },
        .{ "--cpu-burst", "burst", u64 },
    }) |entry| {
        if (std.mem.eql(u8, name, entry[0])) {
            const value = try optionValue(args, index, error.MissingResourceValue);
            if (resources.cpu == null) resources.cpu = .{};
            @field(resources.cpu.?, entry[1]) = try resourceNumber(entry[2], name, value);
            return true;
        }
    }
    return false;
}

fn parseCpusetOption(args: []const []const u8, index: *usize, name: []const u8, resources: *oci.Spec.Resources) !bool {
    inline for (.{ .{ "--cpuset-cpus", "cpus" }, .{ "--cpuset-mems", "mems" } }) |entry| {
        if (std.mem.eql(u8, name, entry[0])) {
            if (resources.cpu == null) resources.cpu = .{};
            @field(resources.cpu.?, entry[1]) = try optionValue(args, index, error.MissingResourceValue);
            return true;
        }
    }
    return false;
}

fn parseOtherResourceOption(args: []const []const u8, index: *usize, name: []const u8, resources: *oci.Spec.Resources) !bool {
    if (std.mem.eql(u8, name, "--pids-limit")) {
        resources.pids = .{ .limit = try resourceNumber(i64, name, try optionValue(args, index, error.MissingResourceValue)) };
        return true;
    }
    if (std.mem.eql(u8, name, "--blkio-weight")) {
        resources.blockIO = .{ .weight = try resourceNumber(u16, name, try optionValue(args, index, error.MissingResourceValue)) };
        return true;
    }
    return false;
}

fn resourceNumber(comptime T: type, flag: []const u8, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10) catch
        oci.validationError(error.InvalidResourceValue, "{s}: invalid integer '{s}'", .{ flag, value });
}

// Decimal digits[.digits], with RAMInBytes' binary, case-insensitive b/k/m/g/t/p
// units and optional b/ib after k/m/g/t/p. One space may precede a unit.
fn parseMemoryBytes(value: []const u8) !i64 {
    // runc also accepts -1 for an unlimited limit.
    if (std.mem.eql(u8, value, "-1")) return -1;
    const number_end = try memoryNumberEnd(value);
    var suffix_start = number_end;
    if (suffix_start < value.len and value[suffix_start] == ' ') {
        suffix_start += 1;
        if (suffix_start == value.len) return error.InvalidResourceValue;
    }
    const suffix = value[suffix_start..];
    var amount = std.fmt.parseFloat(f64, value[0..number_end]) catch return error.InvalidResourceValue;
    amount *= try memoryMultiplier(suffix);
    if (!std.math.isFinite(amount) or amount < 0 or amount >= 0x1p63) return error.InvalidResourceValue;
    return @intFromFloat(amount);
}

fn memoryNumberEnd(value: []const u8) !usize {
    var number_end: usize = 0;
    while (number_end < value.len and std.ascii.isDigit(value[number_end])) : (number_end += 1) {}
    if (number_end == 0) return error.InvalidResourceValue;
    if (number_end < value.len and value[number_end] == '.') {
        number_end += 1;
        const fraction_start = number_end;
        while (number_end < value.len and std.ascii.isDigit(value[number_end])) : (number_end += 1) {}
        if (number_end == fraction_start) return error.InvalidResourceValue;
    }
    return number_end;
}

fn memoryMultiplier(suffix: []const u8) !f64 {
    if (suffix.len > 0) {
        if (suffix.len > 3) return error.InvalidResourceValue;
        if (std.ascii.toLower(suffix[0]) == 'b') {
            if (suffix.len != 1) return error.InvalidResourceValue;
        } else {
            const power: u6 = switch (std.ascii.toLower(suffix[0])) {
                'k' => 10,
                'm' => 20,
                'g' => 30,
                't' => 40,
                'p' => 50,
                else => return error.InvalidResourceValue,
            };
            if ((suffix.len == 2 and std.ascii.toLower(suffix[1]) != 'b') or
                (suffix.len == 3 and !std.ascii.eqlIgnoreCase(suffix[1..], "ib"))) return error.InvalidResourceValue;
            return @floatFromInt(@as(u64, 1) << power);
        }
    }
    return 1;
}

pub fn optionValue(args: []const []const u8, index: *usize, comptime missing: error{
    MissingProcessFile,
    MissingPidfdSocket,
    MissingResources,
    MissingResourceValue,
    MissingPidFile,
    MissingConsoleSocket,
    MissingCwd,
    MissingEnv,
    MissingUser,
    MissingFormat,
    MissingInterval,
    MissingExecValue,
    MissingCriuValue,
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
}

test "run and spec parsing accept runc's flags" {
    const run = try parseArgs(&.{ "igvano", "run", "-d", "--console-socket", "/tmp/c.sock", "example", "-b", "/tmp/bundle", "--keep" });
    try std.testing.expectEqual(Subcommand.run, run.subcommand);
    try std.testing.expectEqualStrings("example", run.id);
    try std.testing.expectEqualStrings("/tmp/bundle", run.bundle.?);
    try std.testing.expectEqualStrings("/tmp/c.sock", run.console_socket.?);
    try std.testing.expect(run.detach and run.keep);
    const plain = try parseArgs(&.{ "igvano", "run", "example" });
    try std.testing.expect(!plain.detach and !plain.keep);
    try std.testing.expectEqualStrings(".", plain.bundle.?);
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "create", "-d", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "run", "--detach=true", "example" }));
    try std.testing.expectError(error.MissingId, parseArgs(&.{ "igvano", "run", "-d" }));
    try std.testing.expectEqualStrings("/tmp/bundle", (try parseArgs(&.{ "igvano", "create", "-b", "/tmp/bundle", "example" })).bundle.?);
    try std.testing.expectEqualStrings(".", (try parseArgs(&.{ "igvano", "spec" })).bundle.?);
    try std.testing.expectEqualStrings("/tmp/b", (try parseArgs(&.{ "igvano", "spec", "--bundle=/tmp/b" })).bundle.?);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "spec", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "spec", "--pid-file", "x" }));
    const list = try parseArgs(&.{ "igvano", "list", "-q", "--format=json" });
    try std.testing.expect(list.quiet);
    try std.testing.expectEqual(PsFormat.json, list.ps_format);
    try std.testing.expectEqual(PsFormat.json, (try parseArgs(&.{ "igvano", "list", "-f", "json" })).ps_format);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "list", "example" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "ps", "-q", "example" }));
}

test "command flags after the id are reordered like runc" {
    const create = try parseArgs(&.{ "igvano", "create", "example", "--bundle", "/tmp/bundle", "--pid-file=init.pid" });
    try std.testing.expectEqualStrings("example", create.id);
    try std.testing.expectEqualStrings("/tmp/bundle", create.bundle.?);
    try std.testing.expectEqualStrings("init.pid", create.pid_file.?);
    const mixed = try parseArgs(&.{ "igvano", "create", "--bundle", "/tmp/bundle", "example", "--pid-file", "init.pid" });
    try std.testing.expectEqualStrings("example", mixed.id);
    try std.testing.expectEqualStrings("init.pid", mixed.pid_file.?);
    for ([_][]const u8{ "--all", "-a" }) |flag| {
        const kill = try parseArgs(&.{ "igvano", "kill", "example", "TERM", flag });
        try std.testing.expect(kill.all);
        try std.testing.expectEqualStrings("example", kill.id);
        try std.testing.expectEqualStrings("TERM", kill.signal.?);
    }
    try std.testing.expect((try parseArgs(&.{ "igvano", "delete", "example", "--force" })).force);
    try std.testing.expect((try parseArgs(&.{ "igvano", "delete", "-f", "example" })).force);
    const update = try parseArgs(&.{ "igvano", "update", "example", "--pids-limit", "10" });
    try std.testing.expectEqualStrings("example", update.id);
    try std.testing.expectEqual(@as(?i64, 10), update.resource_flags.pids.?.limit);
    // Like urfave/cli, a flag takes the next non-flag argument with it.
    try std.testing.expectError(error.InvalidId, parseArgs(&.{ "igvano", "kill", "example", "--all", "../x" }));
    // Only the subcommand's own flags move; global flags stay positional, and `--` is still rejected.
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "state", "example", "--root", "/tmp" }));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "igvano", "create", "example", "--root", "/tmp" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "delete", "--force", "--", "example" }));
    // exec and ps keep their trailing arguments in place.
    try std.testing.expectEqualSlices([]const u8, &.{ "sh", "--all" }, (try parseArgs(&.{ "igvano", "exec", "example", "sh", "--all" })).exec_args);
    try std.testing.expectEqualSlices([]const u8, &.{"--format"}, (try parseArgs(&.{ "igvano", "ps", "example", "--format" })).ps_args);
    var too_many: [max_reordered_args + 3][]const u8 = @splat("--force");
    too_many[0] = "igvano";
    too_many[1] = "delete";
    too_many[2] = "example";
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&too_many));
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

test "update parsing accepts resource files stdin and shim global flags" {
    for ([_][]const []const u8{
        &.{ "igvano", "update", "--resources", "resources.json", "example" },
        &.{ "igvano", "update", "--resources=resources.json", "example" },
        &.{ "igvano", "update", "-r", "resources.json", "example" },
        &.{ "igvano", "update", "--resources", "-", "example" },
        &.{ "igvano", "update", "-r", "-", "example" },
        &.{ "igvano", "--root", "/tmp/containers", "--log", "/tmp/runtime.log", "--log-format", "json", "update", "--resources=-", "example" },
    }) |args| {
        const config = try parseArgs(args);
        try std.testing.expectEqualStrings("update", @tagName(config.subcommand));
        try std.testing.expectEqualStrings("example", config.id);
        const value = args[args.len - 2];
        try std.testing.expectEqualStrings(if (std.mem.indexOfScalar(u8, value, '=')) |equals|
            value[equals + 1 ..]
        else
            value, config.resources_file.?);
    }
}

test "update parsing accepts every per-field flag with separate and equals values" {
    const flags = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "--memory", .value = "64m" },
        .{ .name = "--memory-reservation", .value = "32MiB" },
        .{ .name = "--memory-swap", .value = "-1" },
        .{ .name = "--kernel-memory", .value = "1g" },
        .{ .name = "--cpu-shares", .value = "512" },
        .{ .name = "--cpu-period", .value = "100000" },
        .{ .name = "--cpu-quota", .value = "-1" },
        .{ .name = "--cpu-rt-period", .value = "1000000" },
        .{ .name = "--cpu-rt-runtime", .value = "-1" },
        .{ .name = "--cpu-idle", .value = "1" },
        .{ .name = "--cpuset-cpus", .value = "0-2" },
        .{ .name = "--cpuset-mems", .value = "0" },
        .{ .name = "--pids-limit", .value = "-1" },
        .{ .name = "--blkio-weight", .value = "500" },
    };
    for (flags) |flag| {
        const separate = try parseArgs(&.{ "igvano", "update", flag.name, flag.value, "example" });
        try std.testing.expectEqualStrings("example", separate.id);
        const equals = try std.fmt.allocPrint(std.testing.allocator, "{s}={s}", .{ flag.name, flag.value });
        defer std.testing.allocator.free(equals);
        _ = try parseArgs(&.{ "igvano", "update", equals, "example" });
        _ = try parseArgs(&.{ "igvano", "update", "--resources=r.json", flag.name, flag.value, "example" });
        _ = try parseArgs(&.{ "igvano", "update", flag.name, flag.value, "--resources=r.json", "example" });
    }
}

test "update flags translate units unlimited and explicit zero to OCI resource fields" {
    const config = try parseArgs(&.{
        "igvano",                  "update",              "--memory=64m",      "--memory-reservation", "1.5 MiB",
        "--memory-swap=-1",        "--kernel-memory=1g",  "--cpu-shares=512",  "--cpu-period=100000",  "--cpu-quota=-1",
        "--cpu-rt-period=1000000", "--cpu-rt-runtime=-1", "--cpuset-cpus=0-2", "--cpuset-mems=0",      "--pids-limit=-1",
        "--blkio-weight=500",      "example",
    });
    const resources = try oci.cgroupResources(std.testing.allocator, config.resource_flags);
    defer oci.freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqual(@as(?i64, 67108864), resources.memory.?.limit);
    try std.testing.expectEqual(@as(?i64, 1572864), resources.memory.?.reservation);
    try std.testing.expectEqual(@as(?i64, -1), resources.memory.?.swap);
    try std.testing.expectEqual(@as(?i64, 1073741824), resources.memory.?.kernel);
    try std.testing.expectEqual(@as(?u64, 512), resources.cpu.?.shares);
    for ([_][]const []const u8{
        &.{ "igvano", "update", "--cpu-share", "512", "example" },
        &.{ "igvano", "update", "--cpu-share=512", "example" },
    }) |args| {
        const alias = try parseArgs(args);
        try std.testing.expectEqual(config.resource_flags.cpu.?.shares, alias.resource_flags.cpu.?.shares);
    }
    try std.testing.expectEqual(@as(?u64, 100000), resources.cpu.?.period);
    try std.testing.expectEqual(@as(?i64, -1), resources.cpu.?.quota);
    try std.testing.expectEqual(@as(?u64, 1000000), resources.cpu.?.realtime_period);
    try std.testing.expectEqual(@as(?i64, -1), resources.cpu.?.realtime_runtime);
    try std.testing.expectEqualStrings("0-2", resources.cpu.?.cpus.?);
    try std.testing.expectEqualStrings("0", resources.cpu.?.mems.?);
    try std.testing.expectEqual(@as(?i64, -1), resources.pids.?.limit);
    try std.testing.expectEqual(@as(?u16, 500), resources.block_io.?.weight);
    const zero = try parseArgs(&.{ "igvano", "update", "--memory=0", "--pids-limit=0", "example" });
    try std.testing.expectEqual(@as(?i64, 0), zero.resource_flags.memory.?.limit);
    try std.testing.expectEqual(@as(?i64, 0), zero.resource_flags.pids.?.limit);
    for ([_][]const u8{ "--memory", "--memory-reservation", "--memory-swap", "--kernel-memory" }) |name| {
        const unlimited = try parseArgs(&.{ "igvano", "update", name, "-1", "example" });
        const translated = try oci.cgroupResources(std.testing.allocator, unlimited.resource_flags);
        defer oci.freeCgroupResources(std.testing.allocator, translated);
    }
}

test "memory flags use decimal quantities and RAMInBytes units" {
    const cases = [_]struct { value: []const u8, bytes: i64 }{
        .{ .value = "64", .bytes = 64 },
        .{ .value = "64b", .bytes = 64 },
        .{ .value = "64 B", .bytes = 64 },
        .{ .value = "1k", .bytes = 1024 },
        .{ .value = "1KB", .bytes = 1024 },
        .{ .value = "1KiB", .bytes = 1024 },
        .{ .value = "1 KIB", .bytes = 1024 },
        .{ .value = "1.5m", .bytes = 1572864 },
        .{ .value = "1.5 MiB", .bytes = 1572864 },
        .{ .value = "1G", .bytes = 1073741824 },
        .{ .value = "1t", .bytes = 1099511627776 },
        .{ .value = "1p", .bytes = 1125899906842624 },
        .{ .value = "0.5b", .bytes = 0 },
        .{ .value = "-1", .bytes = -1 },
    };
    for (cases) |case| {
        const config = try parseArgs(&.{ "igvano", "update", "--memory", case.value, "example" });
        try std.testing.expectEqual(@as(?i64, case.bytes), config.resource_flags.memory.?.limit);
    }
    for ([_][]const u8{
        "-2",     "64mbb",               "1ki",  "1e",    "nan",   "inf",
        "8192p",  "9223372036854775808", "1 m ", "1e5",   "1e5kb", "0x10",
        "0x10b",  "1 ",                  "1.5 ", "1kb ",  "1.",    ".5m",
        "1.2.3m", "+1",                  " 1",   "1  kb", "1\tkb", "1_000",
        "1bkb",
    }) |value|
        try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", "--memory", value, "example" }));
    for ([_][]const u8{ "--cpu-shares", "--cpu-period", "--cpu-rt-period", "--blkio-weight" }) |name|
        try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", name, "-1", "example" }));
    try std.testing.expectError(error.InvalidResourceValue, parseArgs(&.{ "igvano", "update", "--blkio-weight=65536", "example" }));
    try std.testing.expectError(error.MissingResourceValue, parseArgs(&.{ "igvano", "update", "--memory=", "example" }));
    try std.testing.expectError(error.MissingResourceValue, parseArgs(&.{ "igvano", "update", "--memory", "--cpu-shares=512", "example" }));
}

test "update parsing requires resources or flags and rejects malformed options" {
    const cases = [_]struct { args: []const []const u8, expected: anyerror }{
        .{ .args = &.{ "igvano", "update", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources=", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "-r", "", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources", "--other", "example" }, .expected = error.MissingResources },
        .{ .args = &.{ "igvano", "update", "--resources=-" }, .expected = error.MissingId },
        .{ .args = &.{ "igvano", "update", "--resources=-", "../example" }, .expected = error.InvalidId },
        .{ .args = &.{ "igvano", "update", "--resources=-", "example", "extra" }, .expected = error.UnexpectedArgument },
        .{ .args = &.{ "igvano", "update", "--resources=-", "--unknown", "64m", "example" }, .expected = error.UnknownOption },
        .{ .args = &.{ "igvano", "--resources=-", "update", "example" }, .expected = error.UnknownOption },
    };
    for (cases) |case| try std.testing.expectError(case.expected, parseArgs(case.args));
}

pub const usage =
    "Usage: igvano [--root <dir>] [--log <file>] [--log-format text|json] <state|start|pause|resume> <id>\n" ++
    "       igvano [global flags] features\n" ++
    "       igvano [global flags] ps [--format table|json] <id> [ps args...]\n" ++
    "       igvano [global flags] update [--resources|-r <file|->] [resource flags...] <id>\n" ++
    "              --resources/-r ignores individual resource flags\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] delete [--force|-f] <id>\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] kill [--all] <id> [signal]\n" ++
    "       igvano [--root <dir>] [--log <file>] [--log-format text|json] create [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] <id>\n" ++
    "       igvano [global flags] run [--bundle|-b <path>] [--pid-file <file>] [--console-socket <path>] [--detach|-d] [--keep] <id>\n" ++
    "       igvano [global flags] spec [--bundle|-b <path>]\n" ++
    "       igvano [global flags] list [--quiet|-q] [--format|-f table|json]\n" ++
    "       igvano [global flags] events [--stats] [--interval <duration>] <id>\n" ++
    "       igvano [global flags] exec [--process <file>] [--detach|-d] [--pid-file <file>] [--console-socket <path>]\n" ++
    "              [--tty|-t] [--cwd <dir>] [--env K=V]... [--user UID[:GID]] <id> [command args...]\n";

test "checkpoint and restore take runc's flags, in any position" {
    var config = try parseArgs(&.{ "igvano", "checkpoint", "--work-path", "./w", "ctr", "--leave-running", "--empty-ns", "network", "--status-fd=5" });
    try std.testing.expectEqualStrings("ctr", config.id);
    try std.testing.expectEqualStrings("./w", config.criu.work_path.?);
    try std.testing.expect(config.criu.leave_running);
    try std.testing.expectEqual(std.os.linux.CLONE.NEWNET, config.criu.empty_ns);
    try std.testing.expectEqual(@as(?i32, 5), config.criu.status_fd);
    config = try parseArgs(&.{ "igvano", "restore", "-d", "--console-socket", "/s", "-b", "/b", "--pid-file=p", "ctr" });
    try std.testing.expect(config.detach);
    try std.testing.expectEqualStrings("/s", config.console_socket.?);
    try std.testing.expectEqualStrings("/b", config.bundle.?);
    try std.testing.expectEqualStrings("p", config.pid_file.?);
    // Restore-only and checkpoint-only flags are rejected by the other command.
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "checkpoint", "--detach", "ctr" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "igvano", "restore", "--leave-running", "ctr" }));
    try std.testing.expectError(error.InvalidCriuValue, parseArgs(&.{ "igvano", "checkpoint", "--empty-ns", "pid", "ctr" }));
    oci.clearDiagnostic();
}

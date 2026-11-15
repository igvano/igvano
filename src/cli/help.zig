//! runc-style -h/--help and -v/--version, handled before argument parsing.
//! The program name is argv[0]'s basename, as urfave/cli prints it.
const std = @import("std");
const oci = @import("igvano").oci;

/// Keep in step with build.zig.zon.
pub const version = "0.1.0";

const Command = struct { name: []const u8, usage: []const u8, summary: []const u8 };

/// runc's command set.
const commands = [_]Command{
    .{ .name = "checkpoint", .usage = "[command options] <container-id>", .summary = "checkpoint a running container" },
    .{ .name = "create", .usage = "[command options] <container-id>", .summary = "create a container" },
    .{ .name = "delete", .usage = "[command options] <container-id>", .summary = "delete any resources held by the container often used with detached container" },
    .{ .name = "events", .usage = "[command options] <container-id>", .summary = "display container events such as OOM notifications, cpu, memory, and IO usage statistics" },
    .{ .name = "exec", .usage = "[command options] <container-id> <command> [command options]", .summary = "execute new process inside the container" },
    .{ .name = "features", .usage = "", .summary = "show the enabled features" },
    .{ .name = "kill", .usage = "[command options] <container-id> [signal]", .summary = "kill sends the specified signal (default: SIGTERM) to the container's init process" },
    .{ .name = "list", .usage = "[command options]", .summary = "lists containers started by runc with the given root" },
    .{ .name = "pause", .usage = "<container-id>", .summary = "pause suspends all processes inside the container" },
    .{ .name = "ps", .usage = "[command options] <container-id> [ps options]", .summary = "ps displays the processes running inside a container" },
    .{ .name = "restore", .usage = "[command options] <container-id>", .summary = "restore a container from a previous checkpoint" },
    .{ .name = "resume", .usage = "<container-id>", .summary = "resumes all processes that have been previously paused" },
    .{ .name = "run", .usage = "[command options] <container-id>", .summary = "create and run a container" },
    .{ .name = "spec", .usage = "[command options]", .summary = "create a new specification file" },
    .{ .name = "start", .usage = "<container-id>", .summary = "executes the user defined process in a created container" },
    .{ .name = "state", .usage = "<container-id>", .summary = "output the state of a container" },
    .{ .name = "update", .usage = "[command options] <container-id>", .summary = "update container resource constraints" },
};

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}

fn isVersion(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version");
}

/// Global flags that take a separate value, so their value is skipped.
fn takesValue(arg: []const u8) bool {
    for ([_][]const u8{ "--root", "--log", "--log-format" }) |flag| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

/// Writes help or version text and returns the exit status, or null when
/// the arguments ask for neither.
pub fn handle(args: []const []const u8, writer: *std.Io.Writer, errors: *std.Io.Writer) !?u8 {
    const name = std.fs.path.basename(if (args.len > 0) args[0] else "igvano");
    var index: usize = 1;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) : (index += 1) {
        if (isHelp(args[index])) return try appHelp(writer, name);
        if (isVersion(args[index])) return try printVersion(writer, name);
        if (takesValue(args[index])) index += 1;
    }
    if (index + 1 >= args.len or !isHelp(args[index + 1])) return null;
    const command = args[index];
    for (commands) |entry| {
        if (!std.mem.eql(u8, entry.name, command)) continue;
        try writer.print("NAME:\n   {s} {s} - {s}\n\nUSAGE:\n   {s} {s} {s}\n", .{ name, entry.name, entry.summary, name, entry.name, entry.usage });
        return 0;
    }
    try errors.print("No help topic for '{s}'\n", .{command});
    return 3;
}

fn appHelp(writer: *std.Io.Writer, name: []const u8) !u8 {
    try writer.print("NAME:\n   {s} - Open Container Initiative runtime (igvano)\n\nUSAGE:\n   {s} [global options] command [command options] [arguments...]\n\nVERSION:\n   {s}\n\nCOMMANDS:\n", .{ name, name, version });
    for (commands) |entry| try writer.print("   {s: <12}{s}\n", .{ entry.name, entry.summary });
    try writer.writeAll(
        \\
        \\GLOBAL OPTIONS:
        \\   --debug               enable debug logging
        \\   --log value           set the log file to write runc logs to (default is '/dev/stderr')
        \\   --log-format value    set the log format ('text' (default), or 'json')
        \\   --root value          root directory for storage of container state
        \\   --systemd-cgroup      enable systemd cgroup support
        \\   --help, -h            show help
        \\   --version, -v         print the version
        \\
    );
    return 0;
}

fn printVersion(writer: *std.Io.Writer, name: []const u8) !u8 {
    try writer.print("{s} version {s}\ncommit: igvano\nspec: {s}\n", .{ name, version, oci.oci_version_max });
    return 0;
}

fn run(args: []const []const u8, out: []u8, err: []u8) !struct { status: ?u8, out: []const u8, err: []const u8 } {
    var writer: std.Io.Writer = .fixed(out);
    var errors: std.Io.Writer = .fixed(err);
    const status = try handle(args, &writer, &errors);
    return .{ .status = status, .out = writer.buffered(), .err = errors.buffered() };
}

test "help and version match runc's first lines" {
    var out: [4096]u8 = undefined;
    var err: [256]u8 = undefined;
    var result = try run(&.{ "/usr/bin/runc", "--root", "/r", "-h" }, &out, &err);
    try std.testing.expectEqual(@as(?u8, 0), result.status);
    try std.testing.expect(std.mem.startsWith(u8, result.out, "NAME:\n   runc - Open Container Initiative runtime"));
    result = try run(&.{ "runc", "list", "--help" }, &out, &err);
    try std.testing.expect(std.mem.startsWith(u8, result.out, "NAME:\n   runc list - "));
    result = try run(&.{ "runc", "foo", "-h" }, &out, &err);
    try std.testing.expectEqual(@as(?u8, 3), result.status);
    try std.testing.expectEqualStrings("No help topic for 'foo'\n", result.err);
    result = try run(&.{ "runc", "-v" }, &out, &err);
    try std.testing.expect(std.mem.startsWith(u8, result.out, "runc version " ++ version ++ "\ncommit: "));
    // Help is only the first argument after the command.
    result = try run(&.{ "runc", "exec", "ctr", "sh", "-h" }, &out, &err);
    try std.testing.expectEqual(@as(?u8, null), result.status);
}

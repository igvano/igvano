const std = @import("std");
const oci = @import("igvano").oci;

const Subcommand = enum {
    state,
    create,
    start,
    kill,
    delete,
};

const Config = struct {
    root: []const u8 = "/run/igvano",
    subcommand: Subcommand,
    id: []const u8,
};

fn parseArgs(args: []const []const u8) !Config {
    var root: []const u8 = "/run/igvano";
    var index: usize = 1;
    while (index < args.len and std.mem.startsWith(u8, args[index], "-")) {
        if (std.mem.eql(u8, args[index], "--root")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) return error.MissingRoot;
            root = args[index];
        } else if (std.mem.startsWith(u8, args[index], "--root=")) {
            root = args[index]["--root=".len..];
            if (root.len == 0) return error.MissingRoot;
        } else {
            return error.UnknownOption;
        }
        index += 1;
    }
    if (index >= args.len) return error.MissingSubcommand;
    const subcommand = std.meta.stringToEnum(Subcommand, args[index]) orelse
        return error.UnknownSubcommand;
    index += 1;
    if (index >= args.len) return error.MissingId;
    if (args.len - index != 1) return error.UnexpectedArgument;
    const id = args[index];
    if (id.len == 0 or std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..") or
        std.mem.indexOfScalar(u8, id, '/') != null or std.mem.startsWith(u8, id, "-"))
    {
        return error.InvalidId;
    }
    return .{ .root = root, .subcommand = subcommand, .id = id };
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const config = parseArgs(args) catch |err| {
        const message = switch (err) {
            error.MissingRoot => "missing value for --root",
            error.MissingSubcommand => "missing subcommand",
            error.UnknownOption => "unknown global option",
            error.UnknownSubcommand => "unknown subcommand",
            error.MissingId => "missing container id",
            error.UnexpectedArgument => "unexpected argument; global flags must precede the subcommand",
            error.InvalidId => "invalid container id",
        };
        std.debug.print("igvano: {s}\nUsage: igvano [--root <dir>] <state|create|start|kill|delete> <id>\n", .{message});
        return 1;
    };
    switch (config.subcommand) {
        .state => {
            var buffer: [4096]u8 = undefined;
            var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
            oci.writeState(allocator, init.io, config.root, config.id, &stdout.interface) catch |err| {
                if (err == error.FileNotFound) {
                    std.debug.print("igvano: container '{s}' does not exist\n", .{config.id});
                } else {
                    std.debug.print("igvano: state for '{s}' failed: {s}\n", .{ config.id, @errorName(err) });
                }
                return 1;
            };
            try stdout.interface.flush();
            return 0;
        },
        .create, .start, .kill, .delete => std.debug.print("not implemented\n", .{}),
    }
    return 1;
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

test "argument parsing uses the default root and positional container id" {
    const config = try parseArgs(&.{ "igvano", "state", "example" });
    try std.testing.expectEqualStrings("/run/igvano", config.root);
    try std.testing.expectEqual(Subcommand.state, config.subcommand);
    try std.testing.expectEqualStrings("example", config.id);
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
    for ([_][]const u8{ "", ".", "..", "../example", "/example", "example/other" }) |id| {
        try std.testing.expectError(error.InvalidId, parseArgs(&.{ "igvano", "state", id }));
    }
}

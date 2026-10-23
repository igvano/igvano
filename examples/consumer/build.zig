const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const libcontainer = b.dependency("igvano", .{
        .target = target,
        .optimize = optimize,
    }).module("libcontainer");
    const exe = b.addExecutable(.{
        .name = "libcontainer-consumer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "libcontainer", .module = libcontainer }},
        }),
    });
    b.installArtifact(exe);
}

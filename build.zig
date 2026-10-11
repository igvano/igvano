const std = @import("std");
const builtin = @import("builtin");

comptime {
    const minimum = @import("build.zig.zon").minimum_zig_version;
    const required = std.SemanticVersion.parse(minimum) catch
        @compileError("invalid minimum_zig_version in build.zig.zon");
    if (builtin.zig_version.order(required) == .lt) {
        @compileError("igvano requires Zig " ++ minimum ++
            " or newer; found " ++ builtin.zig_version_string);
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const library = b.addModule("igvano", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "igvano", .module = library }},
    });

    const exe = b.addExecutable(.{
        .name = "igvano",
        .root_module = root_module,
    });
    b.installArtifact(exe);

    const library_tests = b.addTest(.{ .root_module = library });
    const exe_tests = b.addTest(.{ .root_module = root_module });
    const test_step = b.step("test", "Run library and executable tests");
    test_step.dependOn(&b.addRunArtifact(library_tests).step);
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
}

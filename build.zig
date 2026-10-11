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
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });

    const exe = b.addExecutable(.{
        .name = "igvano",
        .root_module = root_module,
    });
    b.installArtifact(exe);

    const tests = b.addTest(.{ .root_module = root_module });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);
}

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
    const probe = b.addExecutable(.{
        .name = "seccomp-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test/seccomp-probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const exe_tests = b.addTest(.{ .root_module = root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const probe_path = b.allocator.create(ProbePath) catch @panic("OOM");
    probe_path.* = .{
        .step = std.Build.Step.init(.{ .id = .custom, .name = "Set seccomp probe path", .owner = b, .makeFn = ProbePath.make }),
        .run = run_exe_tests,
        .path = probe.getEmittedBin(),
    };
    probe_path.path.addStepDependencies(&probe_path.step);
    run_exe_tests.step.dependOn(&probe_path.step);
    const test_step = b.step("test", "Run library and executable tests");
    test_step.dependOn(&b.addRunArtifact(library_tests).step);
    test_step.dependOn(&run_exe_tests.step);
}

// The emitted path is only available after compilation, before the test run.
const ProbePath = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    path: std.Build.LazyPath,

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) !void {
        const self: *ProbePath = @fieldParentPtr("step", step);
        self.run.setEnvironmentVariable("IGVANO_SECCOMP_PROBE", self.path.getPath2(step.owner, step));
    }
};

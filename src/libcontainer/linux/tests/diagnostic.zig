const libcontainer = @import("../../root.zig");
const std = @import("std");
const LinuxContainer = @import("../../linux.zig").Container;
const diagnostics = @import("../diagnostic.zig");
const reportDiagnostic = diagnostics.reportDiagnostic;
const childError = diagnostics.childError;

test "backend diagnostic records formatted detail and truncates safely" {
    defer diagnostics.last_diagnostic_len = 0;
    diagnostics.last_diagnostic_len = 0;
    var instance = LinuxContainer.load(.{ .id = "example", .pid = 0, .starttime = "" });
    const container = instance.container();
    try std.testing.expect(container.diagnostic() == null);
    reportDiagnostic("failed at {s}: {d}", .{ "/proc", 42 });
    try std.testing.expectEqualStrings("failed at /proc: 42", container.diagnostic().?);
    reportDiagnostic("{s}", .{"x" ** 600});
    try std.testing.expectEqualStrings("x" ** 512, container.diagnostic().?);
    reportDiagnostic("{s}{s}", .{ "x" ** 511, "é" });
    try std.testing.expectEqualStrings("x" ** 511, container.diagnostic().?);
    reportDiagnostic("short", .{});
    try std.testing.expectEqualStrings("short", container.diagnostic().?);
    try std.testing.expectEqualStrings("short", libcontainer.linux.diagnostic().?);
    childError(": ", error.CreateFailed);
    try std.testing.expectEqualStrings(": CreateFailed", container.diagnostic().?);
}

test "backend diagnostics are isolated between threads" {
    defer diagnostics.last_diagnostic_len = 0;
    reportDiagnostic("main thread", .{});
    const worker = try std.Thread.spawn(.{}, struct {
        fn run() void {
            reportDiagnostic("worker thread", .{});
        }
    }.run, .{});
    worker.join();
    try std.testing.expectEqualStrings("main thread", libcontainer.linux.diagnostic().?);
}

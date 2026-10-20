const std = @import("std");
const LinuxBackend = @import("../../linux.zig").LinuxBackend;
const diagnostics = @import("../diagnostic.zig");
const reportDiagnostic = diagnostics.reportDiagnostic;
const childError = diagnostics.childError;

test "backend diagnostic records formatted detail and truncates safely" {
    var implementation: LinuxBackend = .{};
    const backend = implementation.backend();
    defer diagnostics.last_diagnostic_len = 0;
    diagnostics.last_diagnostic_len = 0;
    try std.testing.expect(backend.diagnostic() == null);
    reportDiagnostic("failed at {s}: {d}", .{ "/proc", 42 });
    try std.testing.expectEqualStrings("failed at /proc: 42", backend.diagnostic().?);
    reportDiagnostic("{s}", .{"x" ** 600});
    try std.testing.expectEqualStrings("x" ** 512, backend.diagnostic().?);
    reportDiagnostic("{s}{s}", .{ "x" ** 511, "é" });
    try std.testing.expectEqualStrings("x" ** 511, backend.diagnostic().?);
    reportDiagnostic("short", .{});
    try std.testing.expectEqualStrings("short", backend.diagnostic().?);
    childError(": ", error.CreateFailed);
    try std.testing.expectEqualStrings(": CreateFailed", backend.diagnostic().?);
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
    var implementation: LinuxBackend = .{};
    try std.testing.expectEqualStrings("main thread", implementation.backend().diagnostic().?);
}

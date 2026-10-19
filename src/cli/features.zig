const std = @import("std");
const oci = @import("igvano").oci;

pub fn features(allocator: std.mem.Allocator, io: std.Io) !void {
    const json = try oci.featuresJson(allocator);
    defer allocator.free(json);
    try std.Io.File.stdout().writeStreamingAll(io, json);
}

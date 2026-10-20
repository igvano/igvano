const std = @import("std");

pub const oci = @import("oci.zig");

test {
    std.testing.refAllDecls(@This());
}

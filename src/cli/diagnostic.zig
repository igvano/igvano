const libcontainer = @import("libcontainer");

var container_detail_buffer: [512]u8 = undefined;

pub var last_container_detail: ?[]const u8 = null;

/// Keeps the current detail across cleanup that may replace it.
pub const SavedDetail = struct {
    buffer: [512]u8 = undefined,
    len: ?usize = null,

    pub fn save() SavedDetail {
        var saved: SavedDetail = .{};
        if (last_container_detail) |detail| {
            @memcpy(saved.buffer[0..detail.len], detail);
            saved.len = detail.len;
        }
        return saved;
    }

    pub fn restore(self: *const SavedDetail) void {
        const len = self.len orelse {
            last_container_detail = null;
            return;
        };
        @memcpy(container_detail_buffer[0..len], self.buffer[0..len]);
        last_container_detail = container_detail_buffer[0..len];
    }
};

// Copy failed-operation detail before cleanup can change the container's buffer.
pub fn containerResult(container: libcontainer.Container, result: anytype) @TypeOf(result) {
    last_container_detail = null;
    return result catch |err| {
        return resultWithDetail(container.diagnostic(), @as(@TypeOf(result), err));
    };
}

pub fn resultWithDetail(detail: ?[]const u8, result: anytype) @TypeOf(result) {
    last_container_detail = null;
    return result catch |err| {
        if (detail) |message| {
            const len = @min(message.len, container_detail_buffer.len);
            @memcpy(container_detail_buffer[0..len], message[0..len]);
            last_container_detail = container_detail_buffer[0..len];
        }
        return err;
    };
}

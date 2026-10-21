const libcontainer = @import("libcontainer");

var container_detail_buffer: [512]u8 = undefined;

pub var last_container_detail: ?[]const u8 = null;

// Copy failed-operation detail before cleanup can change the container's buffer.
pub fn containerResult(container: libcontainer.Container, result: anytype) @TypeOf(result) {
    last_container_detail = null;
    return result catch |err| {
        return createResult(container.diagnostic(), @as(@TypeOf(result), err));
    };
}

pub fn createResult(detail: ?[]const u8, result: anytype) @TypeOf(result) {
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

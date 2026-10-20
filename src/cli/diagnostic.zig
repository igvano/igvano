const libcontainer = @import("libcontainer");
const Backend = libcontainer.Backend;

var backend_detail_buffer: [512]u8 = undefined;

pub var last_backend_detail: ?[]const u8 = null;

// Copy failed-operation detail before cleanup can change the backend's buffer.
pub fn backendResult(backend: Backend, result: anytype) @TypeOf(result) {
    last_backend_detail = null;
    return result catch |err| {
        if (backend.diagnostic()) |detail| {
            const len = @min(detail.len, backend_detail_buffer.len);
            @memcpy(backend_detail_buffer[0..len], detail[0..len]);
            last_backend_detail = backend_detail_buffer[0..len];
        }
        return err;
    };
}

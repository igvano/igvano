//! Sends a seccomp notify fd to the agent at linux.seccomp.listenerPath, with
//! the runtime-spec ContainerProcessState JSON, like runc.
const std = @import("std");
const builtin = @import("builtin");
const oci = @import("igvano").oci;
const libcontainer = @import("libcontainer");

pub const Agent = struct {
    allocator: std.mem.Allocator,
    listener_path: []const u8,
    metadata: []const u8,
    /// Copied into the payload; pid is filled from the init's host PID when 0.
    state: oci.State,
    /// The frontend error behind a failed callback, with its diagnostic.
    failure: ?anyerror = null,

    /// Null unless the seccomp profile has notify rules.
    pub fn init(allocator: std.mem.Allocator, seccomp: ?oci.Spec.Seccomp, state: oci.State) ?Agent {
        const config = seccomp orelse return null;
        if (!oci.seccompNotifies(config)) return null;
        return .{ .allocator = allocator, .listener_path = config.listenerPath.?, .metadata = config.listenerMetadata orelse "", .state = state };
    }

    pub fn fromSpec(allocator: std.mem.Allocator, spec: oci.Spec, state: oci.State) ?Agent {
        const settings = spec.linux orelse return null;
        return init(allocator, settings.seccomp, state);
    }

    pub fn callbackOf(agent: *?Agent) ?libcontainer.SeccompListenerCallback {
        return if (agent.*) |*value| value.callback() else null;
    }

    pub fn failureOf(agent: ?Agent) ?anyerror {
        return if (agent) |value| value.failure else null;
    }

    pub fn callback(self: *Agent) libcontainer.SeccompListenerCallback {
        return .{ .ptr = self, .run = run };
    }

    fn run(ptr: *anyopaque, fd: std.posix.fd_t, pid: i32) libcontainer.Error!void {
        const self: *Agent = @ptrCast(@alignCast(ptr));
        self.send(fd, pid) catch |err| {
            self.failure = err;
            return error.CreateFailed;
        };
    }

    fn send(self: *Agent, fd: std.posix.fd_t, pid: i32) !void {
        var state = self.state;
        if (state.pid == null) state.pid = pid;
        const json = try payload(self.allocator, pid, self.metadata, state);
        defer self.allocator.free(json);
        const socket = try connect(self.listener_path);
        defer _ = std.os.linux.close(socket);
        libcontainer.linux.console.sendFdWithData(socket, fd, json) catch |err|
            return oci.validationError(err, "cannot send seccomp fd to {s}", .{self.listener_path});
    }
};

/// runtime-spec ContainerProcessState.
pub fn payload(allocator: std.mem.Allocator, pid: i32, metadata: []const u8, state: oci.State) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{
        .ociVersion = state.ociVersion,
        .fds = &[_][]const u8{"seccompFd"},
        .pid = pid,
        .metadata = metadata,
        .state = state,
    }, .{ .emit_null_optional_fields = false });
}

/// A path, or "@name" for an abstract socket, as Go's net.Dial("unix") takes.
fn connect(path: []const u8) !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    const linux = std.os.linux;
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len == 0 or path.len >= address.path.len or std.mem.indexOfScalar(u8, path, 0) != null)
        return oci.validationError(error.SeccompAgentFailed, "failed to connect with seccomp agent specified in the seccomp profile: invalid listenerPath", .{});
    @memcpy(address.path[0..path.len], path);
    if (path[0] == '@') address.path[0] = 0;
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SeccompAgentFailed;
    const fd: std.posix.fd_t = @intCast(opened);
    errdefer _ = linux.close(fd);
    const length: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len);
    while (true) {
        const result = linux.connect(fd, &address, length);
        switch (linux.errno(result)) {
            .SUCCESS => return fd,
            .INTR => continue,
            else => |errno| return oci.validationError(error.SeccompAgentFailed, "failed to connect with seccomp agent specified in the seccomp profile: {s}: E{s}", .{ path, @tagName(errno) }),
        }
    }
}

test "seccomp agent payload follows runtime-spec ContainerProcessState" {
    const json = try payload(std.testing.allocator, 42, "bar", .{ .id = "c", .status = .creating, .pid = 42, .bundle = "/b" });
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.startsWith(u8, json, "{\"ociVersion\":\""));
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fds\":[\"seccompFd\"],\"pid\":42,\"metadata\":\"bar\",\"state\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"c\",\"status\":\"creating\",\"pid\":42,\"bundle\":\"/b\"") != null);
}

test "seccomp agent connect reports a missing listener" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    defer oci.clearDiagnostic();
    try std.testing.expectError(error.SeccompAgentFailed, connect("/igvano-missing-listener.sock"));
    try std.testing.expect(std.mem.indexOf(u8, oci.diagnosticFor(error.SeccompAgentFailed).?, "failed to connect with seccomp agent") != null);
    try std.testing.expectError(error.SeccompAgentFailed, connect("@igvano-missing-abstract"));
}

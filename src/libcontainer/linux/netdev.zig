//! runtime-spec linux.netDevices: move host interfaces into the container's
//! network namespace over rtnetlink, optionally renamed, keeping their
//! permanent global-scope addresses (the kernel drops them on the move).
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const libcontainer = @import("../root.zig");
const closeFd = @import("syscall.zig").closeFd;
const openPath = @import("syscall.zig").openPath;
const forkProcess = @import("syscall.zig").forkProcess;
const waitChild = @import("syscall.zig").waitChild;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;

const RTM_NEWLINK = 16;
const RTM_NEWADDR = 20;
const RTM_GETADDR = 22;
const NLMSG_ERROR = 2;
const NLMSG_DONE = 3;
const NLM_F_REQUEST = 0x1;
const NLM_F_ACK = 0x4;
const NLM_F_EXCL = 0x200;
const NLM_F_CREATE = 0x400;
const NLM_F_DUMP = 0x300;
const NLM_F_DUMP_INTR = 0x10;
const IFLA_IFNAME = 3;
const IFLA_NET_NS_FD = 28;
const IFA_ADDRESS = 1;
const IFA_LOCAL = 2;
const IFA_FLAGS = 8;
const IFA_F_PERMANENT = 0x80;
const RT_SCOPE_UNIVERSE = 0;

const MsgHdr = extern struct { len: u32, type: u16, flags: u16, seq: u32 = 0, pid: u32 = 0 };
const IfInfoMsg = extern struct { family: u8 = 0, pad: u8 = 0, type: u16 = 0, index: i32, flags: u32 = 0, change: u32 = 0 };
const IfAddrMsg = extern struct { family: u8, prefixlen: u8, flags: u8, scope: u8, index: u32 };
const RtAttr = extern struct { len: u16, type: u16 };

/// One address to re-add: family, prefix and the IFA_LOCAL/IFA_ADDRESS bytes.
const Address = struct {
    family: u8,
    prefixlen: u8,
    scope: u8,
    local: [16]u8 = @splat(0),
    local_len: u8 = 0,
    address: [16]u8 = @splat(0),
    address_len: u8 = 0,
};
// ponytail: a fixed per-device cap; raise it if a device carries more.
const max_addresses = 32;

/// Interface names are at most 15 bytes and never contain '/' or spaces.
pub fn validateName(name: []const u8) libcontainer.Error!void {
    if (name.len == 0 or name.len > 15 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
        std.mem.indexOfAny(u8, name, "/:\x00" ++ std.ascii.whitespace) != null)
    {
        reportDiagnostic("linux.netDevices: invalid interface name '{s}'", .{name});
        return error.InvalidConfig;
    }
}

/// youki's checks: valid names, a network namespace of the container's own
/// (new or joined) and a root runtime (moving needs CAP_NET_ADMIN on the host).
pub fn validate(devices: []const libcontainer.NetDevice, namespaces: []const libcontainer.Namespace) libcontainer.Error!void {
    if (devices.len == 0) return;
    for (devices) |device| {
        try validateName(device.host_name);
        if (device.name.len != 0) try validateName(device.name);
    }
    for (namespaces) |namespace| {
        if (namespace.kind != .network) continue;
        if (comptime builtin.os.tag == .linux) if (linux.geteuid() != 0 or @import("devices.zig").runningInUserNamespace()) {
            reportDiagnostic("linux.netDevices is not supported for rootless containers", .{});
            return error.InvalidConfig;
        };
        return;
    }
    reportDiagnostic("linux.netDevices requires a network namespace", .{});
    return error.InvalidConfig;
}

/// Moves each device into the network namespace of `pid`.
pub fn moveNetDevices(devices: []const libcontainer.NetDevice, pid: i32) libcontainer.Error!void {
    if (devices.len == 0) return;
    if (comptime builtin.os.tag != .linux) return error.NotImplemented;
    var path_buffer: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/net", .{pid}) catch unreachable;
    const netns = try openPath(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    defer closeFd(netns);
    for (devices) |device| try moveNetDevice(device, netns);
}

fn moveNetDevice(device: libcontainer.NetDevice, netns: posix.fd_t) libcontainer.Error!void {
    const target = if (device.name.len != 0) device.name else device.host_name;
    const index = interfaceIndex(device.host_name) orelse {
        reportDiagnostic("linux.netDevices: no network device '{s}' on the host", .{device.host_name});
        return error.InvalidConfig;
    };
    var addresses: [max_addresses]Address = undefined;
    const count = try listAddresses(index, &addresses);
    const socket = try openNetlink();
    defer closeFd(socket);
    var buffer: [256]u8 align(4) = undefined;
    var message: Message = .init(&buffer, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    message.put(IfInfoMsg{ .index = index });
    message.attr(IFLA_NET_NS_FD, std.mem.asBytes(&@as(u32, @intCast(netns))));
    if (!std.mem.eql(u8, target, device.host_name)) message.attrString(IFLA_IFNAME, target);
    transact(socket, message.bytes()) catch |err| {
        reportDiagnostic("linux.netDevices: cannot move '{s}' into the container: {s}", .{ device.host_name, @errorName(err) });
        return err;
    };
    if (count != 0) try addAddressesIn(netns, target, addresses[0..count]);
}

fn interfaceIndex(name: []const u8) ?i32 {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer closeFd(@intCast(fd));
    var request = std.mem.zeroes(linux.ifreq);
    if (name.len >= request.ifrn.name.len) return null;
    @memcpy(request.ifrn.name[0..name.len], name);
    if (linux.errno(linux.ioctl(@intCast(fd), linux.SIOCGIFINDEX, @intFromPtr(&request))) != .SUCCESS) return null;
    return request.ifru.ivalue;
}

fn openNetlink() libcontainer.Error!posix.fd_t {
    const fd = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (linux.errno(fd) != .SUCCESS) return error.CreateFailed;
    return @intCast(fd);
}

const Message = struct {
    buffer: []align(4) u8,
    len: usize,

    fn init(buffer: []align(4) u8, kind: u16, flags: u16) Message {
        @memset(buffer, 0);
        const header: *MsgHdr = @ptrCast(buffer.ptr);
        header.* = .{ .len = 0, .type = kind, .flags = flags, .seq = 1 };
        return .{ .buffer = buffer, .len = @sizeOf(MsgHdr) };
    }

    fn put(self: *Message, value: anytype) void {
        const raw = std.mem.asBytes(&value);
        @memcpy(self.buffer[self.len..][0..raw.len], raw);
        self.len = std.mem.alignForward(usize, self.len + raw.len, 4);
    }

    fn attr(self: *Message, kind: u16, data: []const u8) void {
        const header: RtAttr = .{ .len = @intCast(@sizeOf(RtAttr) + data.len), .type = kind };
        @memcpy(self.buffer[self.len..][0..@sizeOf(RtAttr)], std.mem.asBytes(&header));
        @memcpy(self.buffer[self.len + @sizeOf(RtAttr) ..][0..data.len], data);
        self.len = std.mem.alignForward(usize, self.len + header.len, 4);
    }

    fn attrString(self: *Message, kind: u16, text: []const u8) void {
        var copy: [16]u8 = @splat(0);
        @memcpy(copy[0..text.len], text);
        self.attr(kind, copy[0 .. text.len + 1]);
    }

    fn bytes(self: *Message) []const u8 {
        const header: *MsgHdr = @ptrCast(self.buffer.ptr);
        header.len = @intCast(self.len);
        return self.buffer[0..self.len];
    }
};

fn send(socket: posix.fd_t, message: []const u8) libcontainer.Error!void {
    const result = linux.sendto(socket, message.ptr, message.len, 0, null, 0);
    if (linux.errno(result) != .SUCCESS or result != message.len) return error.CreateFailed;
}

/// Sends a request and waits for its ACK; a kernel error maps to an errno.
fn transact(socket: posix.fd_t, message: []const u8) libcontainer.Error!void {
    try send(socket, message);
    var buffer: [4096]u8 align(4) = undefined;
    const received = linux.recvfrom(socket, &buffer, buffer.len, 0, null, null);
    if (linux.errno(received) != .SUCCESS or received < @sizeOf(MsgHdr) + 4) return error.CreateFailed;
    const header: *const MsgHdr = @ptrCast(&buffer);
    if (header.type != NLMSG_ERROR) return error.CreateFailed;
    const code = std.mem.readInt(i32, buffer[@sizeOf(MsgHdr)..][0..4], .little);
    return switch (code) {
        0 => {},
        -@as(i32, @intFromEnum(linux.E.PERM)), -@as(i32, @intFromEnum(linux.E.ACCES)) => error.PermissionDenied,
        -@as(i32, @intFromEnum(linux.E.EXIST)) => error.InvalidConfig,
        else => error.CreateFailed,
    };
}

/// Dumps the device's permanent, global-scope addresses (runtime-spec).
fn listAddresses(index: i32, out: *[max_addresses]Address) libcontainer.Error!usize {
    const socket = try openNetlink();
    defer closeFd(socket);
    var request_buffer: [64]u8 align(4) = undefined;
    var request: Message = .init(&request_buffer, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
    request.put(IfAddrMsg{ .family = linux.AF.UNSPEC, .prefixlen = 0, .flags = 0, .scope = 0, .index = 0 });
    try send(socket, request.bytes());
    var count: usize = 0;
    var buffer: [16384]u8 align(4) = undefined;
    while (true) {
        // MSG_TRUNC returns the full length, so a cut datagram is caught.
        const received = linux.recvfrom(socket, &buffer, buffer.len, linux.MSG.TRUNC, null, null);
        if (linux.errno(received) != .SUCCESS or received > buffer.len) return error.CreateFailed;
        var offset: usize = 0;
        while (offset + @sizeOf(MsgHdr) <= received) {
            const header: *const MsgHdr = @ptrCast(@alignCast(&buffer[offset]));
            if (header.len < @sizeOf(MsgHdr) or offset + header.len > received) return error.CreateFailed;
            // An interrupted dump may miss addresses; fail before moving.
            if (header.flags & NLM_F_DUMP_INTR != 0) return error.CreateFailed;
            switch (header.type) {
                NLMSG_DONE => return count,
                NLMSG_ERROR => return error.CreateFailed,
                RTM_NEWADDR => if (parseAddress(@alignCast(buffer[offset + @sizeOf(MsgHdr) .. offset + header.len]), index)) |address| {
                    if (count == out.len) return error.CreateFailed;
                    out[count] = address;
                    count += 1;
                },
                else => {},
            }
            offset += std.mem.alignForward(usize, header.len, 4);
        }
    }
}

fn parseAddress(payload: []align(4) const u8, index: i32) ?Address {
    if (payload.len < @sizeOf(IfAddrMsg)) return null;
    const message: *const IfAddrMsg = @ptrCast(payload.ptr);
    if (message.index != @as(u32, @intCast(index)) or message.scope != RT_SCOPE_UNIVERSE) return null;
    var flags: u32 = message.flags;
    var address: Address = .{ .family = message.family, .prefixlen = message.prefixlen, .scope = message.scope };
    var offset: usize = std.mem.alignForward(usize, @sizeOf(IfAddrMsg), 4);
    while (offset + @sizeOf(RtAttr) <= payload.len) {
        const header: *const RtAttr = @ptrCast(@alignCast(&payload[offset]));
        if (header.len < @sizeOf(RtAttr) or offset + header.len > payload.len) break;
        const data = payload[offset + @sizeOf(RtAttr) .. offset + header.len];
        switch (header.type) {
            IFA_LOCAL => if (data.len <= 16) {
                @memcpy(address.local[0..data.len], data);
                address.local_len = @intCast(data.len);
            },
            IFA_ADDRESS => if (data.len <= 16) {
                @memcpy(address.address[0..data.len], data);
                address.address_len = @intCast(data.len);
            },
            IFA_FLAGS => if (data.len == 4) {
                flags = std.mem.readInt(u32, data[0..4], .little);
            },
            else => {},
        }
        offset += std.mem.alignForward(usize, header.len, 4);
    }
    if (flags & IFA_F_PERMANENT == 0) return null;
    return address;
}

/// Re-adds the addresses from inside the container's network namespace.
fn addAddressesIn(netns: posix.fd_t, name: []const u8, addresses: []const Address) libcontainer.Error!void {
    var messages: [max_addresses][96]u8 align(4) = undefined;
    var lengths: [max_addresses]usize = undefined;
    for (addresses, 0..) |address, i| lengths[i] = buildNewAddress(&messages[i], address);
    var name_buffer: [16]u8 = @splat(0);
    @memcpy(name_buffer[0..name.len], name);
    const child = try forkProcess();
    if (child == 0) {
        if (linux.errno(linux.setns(netns, linux.CLONE.NEWNET)) != .SUCCESS) linux.exit_group(2);
        const index = interfaceIndex(name_buffer[0..name.len]) orelse linux.exit_group(3);
        const socket = openNetlink() catch linux.exit_group(4);
        for (addresses, 0..) |_, i| {
            const message: *align(4) [96]u8 = &messages[i];
            const ifa: *IfAddrMsg = @ptrCast(@alignCast(message[@sizeOf(MsgHdr)..]));
            ifa.index = @intCast(index);
            transact(socket, message[0..lengths[i]]) catch linux.exit_group(5);
        }
        linux.exit_group(0);
    }
    const status = try waitChild(child);
    if (status != 0) {
        reportDiagnostic("linux.netDevices: cannot restore the addresses of '{s}' in the container (status {d})", .{ name, status });
        return error.CreateFailed;
    }
}

fn buildNewAddress(buffer: *align(4) [96]u8, address: Address) usize {
    var message: Message = .init(buffer, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    message.put(IfAddrMsg{ .family = address.family, .prefixlen = address.prefixlen, .flags = IFA_F_PERMANENT, .scope = address.scope, .index = 0 });
    if (address.local_len != 0) message.attr(IFA_LOCAL, address.local[0..address.local_len]);
    if (address.address_len != 0) message.attr(IFA_ADDRESS, address.address[0..address.address_len]);
    return message.bytes().len;
}

test "net device names follow the kernel's interface name rules" {
    defer @import("diagnostic.zig").last_diagnostic_len = 0;
    try validateName("eth0");
    try validateName("abcdefghijklmno");
    for ([_][]const u8{ "", "abcdefghijklmnop", ".", "..", "a/b", "a b", "a:b" }) |name|
        try std.testing.expectError(error.InvalidConfig, validateName(name));
}

test "net devices need valid names and a network namespace" {
    defer @import("diagnostic.zig").last_diagnostic_len = 0;
    try validate(&.{}, &.{});
    try std.testing.expectError(error.InvalidConfig, validate(&.{.{ .host_name = "eth0" }}, &.{.{ .kind = .mount }}));
    try std.testing.expectError(error.InvalidConfig, validate(&.{.{ .host_name = "eth0", .name = "a/b" }}, &.{.{ .kind = .network }}));
}

test "rtnetlink address messages keep family, prefix and both addresses" {
    var buffer: [96]u8 align(4) = undefined;
    const len = buildNewAddress(&buffer, .{ .family = linux.AF.INET, .prefixlen = 24, .scope = 0, .local = .{ 244, 178, 44, 111 } ++ @as([12]u8, @splat(0)), .local_len = 4, .address = .{ 244, 178, 44, 111 } ++ @as([12]u8, @splat(0)), .address_len = 4 });
    try std.testing.expectEqual(@as(usize, @sizeOf(MsgHdr) + @sizeOf(IfAddrMsg) + 2 * 8), len);
    const parsed = parseAddress(@alignCast(buffer[@sizeOf(MsgHdr)..len]), 0).?;
    try std.testing.expectEqual(@as(u8, 24), parsed.prefixlen);
    try std.testing.expectEqualSlices(u8, &.{ 244, 178, 44, 111 }, parsed.local[0..parsed.local_len]);
}

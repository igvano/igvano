const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

test "StartTransientUnit encodes aligned header and property variants" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .name = "Delegate", .value = .{ .boolean = true } },
        .{ .name = "PIDs", .value = .{ .uint32s = &.{42} } },
        .{ .name = "MemoryMax", .value = .{ .uint64 = 4096 } },
    };
    const encoded = try marshalCall(allocator, 1, "/m", "x.y", "x.y", "StartTransientUnit", &.{
        .{ .string = "x.scope" },       .{ .string = "replace" },
        .{ .properties = &properties }, .{ .auxiliary = &.{} },
    });
    defer allocator.free(encoded);
    // Offsets are measured from the start of the message. Header fields are
    // 8-aligned structs; the final field ends at 118, body begins at 120.
    const header =
        "l\x01\x00\x01\x78\x00\x00\x00\x01\x00\x00\x00\x66\x00\x00\x00" ++
        "\x01\x01o\x00\x02\x00\x00\x00/m\x00" ++ "\x00" ** 5 ++
        "\x02\x01s\x00\x03\x00\x00\x00x.y\x00" ++ "\x00" ** 4 ++
        "\x03\x01s\x00\x12\x00\x00\x00StartTransientUnit\x00" ++ "\x00" ** 5 ++
        "\x06\x01s\x00\x03\x00\x00\x00x.y\x00" ++ "\x00" ** 4 ++
        "\x08\x01g\x00\x10ssa(sv)a(sa(sv))\x00" ++ "\x00" ** 2;
    const body =
        "\x07\x00\x00\x00x.scope\x00" ++
        "\x07\x00\x00\x00replace\x00" ++
        "\x50\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x08\x00\x00\x00Delegate\x00\x01b\x00\x01\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x04\x00\x00\x00PIDs\x00\x02au\x00" ++ "\x00" ** 3 ++ "\x04\x00\x00\x00\x2a\x00\x00\x00" ++
        "\x09\x00\x00\x00MemoryMax\x00\x01t\x00" ++ "\x00" ** 7 ++ "\x00\x10\x00\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00" ++ "\x00" ** 4;
    try std.testing.expectEqualSlices(u8, header ++ body, encoded);
}

test "parsing D-Bus errors retains the name and message" {
    const bytes = "l\x03\x00\x01\x09\x00\x00\x00\x02\x00\x00\x00\x1f\x00\x00\x00" ++
        "\x04\x01s\x00\x03\x00\x00\x00x.E\x00" ++ "\x00" ** 4 ++
        "\x05\x01u\x00\x01\x00\x00\x00" ++
        "\x08\x01g\x00\x01s\x00\x00" ++
        "\x04\x00\x00\x00oops\x00";
    const message = try Message.parse(bytes);
    try std.testing.expectEqual(@as(u8, 3), message.kind);
    try std.testing.expectEqual(@as(u32, 1), message.reply_serial);
    try std.testing.expectEqualStrings("x.E", message.error_name);
    try std.testing.expectEqualStrings("oops", try message.errorText());
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidMessage, Message.parse(bytes[0..len]));
}

test "D-Bus replies skip unknown header field 10 with variant alignment" {
    const bytes = "l\x02\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00\x20\x00\x00\x00" ++
        "\x0a\x01v\x00\x02at\x00" ++
        "\x08\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x2a\x00\x00\x00\x00\x00\x00\x00" ++
        "\x05\x01u\x00\x01\x00\x00\x00";
    const message = try Message.parse(bytes);
    try std.testing.expectEqual(@as(u32, 1), message.reply_serial);
    try std.testing.expectEqual(@as(usize, 0), message.body.len);
    for (0..bytes.len) |len|
        try std.testing.expectError(error.InvalidMessage, Message.parse(bytes[0..len]));
}

test "D-Bus unknown fields skip structs containing dictionaries and variants" {
    const bytes = "l\x02\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00\x30\x00\x00\x00" ++
        "\x0a\x08(ua{sv})\x00" ++ "\x00" ** 5 ++
        "\x07\x00\x00\x00\x0a\x00\x00\x00" ++
        "\x01\x00\x00\x00X\x00\x01y\x00\xff" ++ "\x00" ** 6 ++
        "\x05\x01u\x00\x01\x00\x00\x00";
    try std.testing.expectEqual(@as(u32, 1), (try Message.parse(bytes)).reply_serial);
    // The unknown value must still contain exactly one valid complete type.
    for ([_][]const u8{
        "\x00\x00",      "\x02()\x00", "\x01a\x00",  "\x04{sv}\x00",
        "\x05a{vs}\x00", "\x02(u\x00", "\x02uu\x00",
    }) |variant| {
        var reader: Reader = .{ .bytes = variant };
        try std.testing.expectError(error.InvalidMessage, reader.skipVariant(0));
    }
}

test "D-Bus big-endian messages are rejected explicitly" {
    const bytes = "B\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x08" ++
        "\x05\x01u\x00\x00\x00\x00\x01";
    try std.testing.expectError(error.UnsupportedByteOrder, Message.parse(bytes));
}

test "D-Bus property operations renew an expired deadline even with no properties" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.deadline = 1;
    const started = try now();
    try client.setProperties("x.scope", &.{});
    try std.testing.expect(client.deadline >= started + timeout_ms);
}

test "JobRemoved parsing reads the job path unit and result" {
    const bytes = "l\x04\x00\x01\x21\x00\x00\x00\x03\x00\x00\x00\x42\x00\x00\x00" ++
        "\x01\x01o\x00\x02\x00\x00\x00/m\x00" ++ "\x00" ** 5 ++
        "\x02\x01s\x00\x03\x00\x00\x00x.y\x00" ++ "\x00" ** 4 ++
        "\x03\x01s\x00\x0a\x00\x00\x00JobRemoved\x00" ++ "\x00" ** 5 ++
        "\x08\x01g\x00\x04uoss\x00" ++ "\x00" ** 6 ++
        "\x2a\x00\x00\x00\x02\x00\x00\x00/j\x00\x00" ++
        "\x07\x00\x00\x00x.scope\x00" ++
        "\x04\x00\x00\x00done\x00";
    const message = try Message.parse(bytes);
    try std.testing.expectEqualStrings("", message.sender);
    const job = (try message.jobRemoved()).?;
    try std.testing.expectEqualStrings("/j", job.path);
    try std.testing.expectEqualStrings("x.scope", job.unit);
    try std.testing.expectEqualStrings("done", job.result);
}

test "system bus ignores JobRemoved signals without a sender" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.watched_unit = "x.scope";
    client.bus_owner = try std.testing.allocator.dupe(u8, ":1.42");
    try client.remember(.{
        .kind = 4,
        .path = manager_path,
        .interface = manager_interface,
        .member = "JobRemoved",
        .signature = "uoss",
        .body = "\x2a\x00\x00\x00\x02\x00\x00\x00/j\x00\x00" ++
            "\x07\x00\x00\x00x.scope\x00" ++
            "\x04\x00\x00\x00done\x00",
    });
    try std.testing.expectEqual(@as(usize, 0), client.jobs.items.len);
}

test "D-Bus sender header is borrowed from wire bytes" {
    const bytes: []const u8 = "l\x04\x00\x01\x00\x00\x00\x00\x03\x00\x00\x00\x1e\x00\x00\x00" ++
        "\x06\x01s\x00\x05\x00\x00\x00:1.99\x00" ++ "\x00" ** 2 ++
        "\x07\x01s\x00\x05\x00\x00\x00:1.42\x00" ++ "\x00" ** 2;
    const message = try Message.parse(bytes);
    try std.testing.expectEqualStrings(":1.42", message.sender);
    try std.testing.expectEqual(@intFromPtr(bytes.ptr) + 40, @intFromPtr(message.sender.ptr));
}

test "system bus owner is retained independently of its method reply" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();
    {
        const bytes = try allocator.dupe(u8, "l\x02\x00\x01\x0a\x00\x00\x00\x02\x00\x00\x00\x0f\x00\x00\x00" ++
            "\x05\x01u\x00\x01\x00\x00\x00" ++
            "\x08\x01g\x00\x01s\x00\x00" ++
            "\x05\x00\x00\x00:1.42\x00");
        defer allocator.free(bytes);
        try client.pinBusOwner(try Message.parse(bytes));
        @memset(bytes, 0);
    }
    try std.testing.expectEqualStrings(":1.42", client.bus_owner.?);
}

test "system bus owner rejects invalid method reply signatures and bodies" {
    const valid_body = "\x05\x00\x00\x00:1.42\x00";
    const cases = [_]struct { kind: u8 = 2, signature: []const u8 = "s", body: []const u8 }{
        .{ .kind = 4, .body = valid_body },
        .{ .signature = "o", .body = valid_body },
        .{ .signature = "ss", .body = valid_body ++ valid_body },
        .{ .body = "" },
        .{ .body = "\x00\x00\x00\x00\x00" },
        .{ .body = "\x01\x00\x00\x00:\x00" },
        .{ .body = "\x07\x00\x00\x00systemd\x00" },
        .{ .body = valid_body[0 .. valid_body.len - 1] },
        .{ .body = valid_body ++ "\x00" },
        .{ .body = valid_body ++ "\x00\x00" ++ valid_body },
    };
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    for (cases) |case| {
        try std.testing.expectError(error.InvalidMessage, client.pinBusOwner(.{
            .kind = case.kind,
            .signature = case.signature,
            .body = case.body,
        }));
        try std.testing.expect(client.bus_owner == null);
    }
}

test "system bus accepts JobRemoved from its pinned owner" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.watched_unit = "x.scope";
    client.bus_owner = try std.testing.allocator.dupe(u8, ":1.42");
    try client.remember(.{
        .kind = 4,
        .path = manager_path,
        .interface = manager_interface,
        .member = "JobRemoved",
        .sender = ":1.42",
        .signature = "uoss",
        .body = "\x2a\x00\x00\x00\x02\x00\x00\x00/j\x00\x00" ++
            "\x07\x00\x00\x00x.scope\x00" ++
            "\x04\x00\x00\x00done\x00",
    });
    try std.testing.expectEqual(@as(usize, 1), client.jobs.items.len);
    try std.testing.expectEqualStrings("/j", client.jobs.items[0].path);
    try std.testing.expectEqualStrings("done", client.jobs.items[0].result);
}

test "system bus ignores forged done and failed JobRemoved without filling the queue" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.watched_unit = "x.scope";
    client.bus_owner = try std.testing.allocator.dupe(u8, ":1.42");
    const prefix = "\x2a\x00\x00\x00\x02\x00\x00\x00/j\x00\x00" ++
        "\x07\x00\x00\x00x.scope\x00";
    const bodies = [_][]const u8{
        prefix ++ "\x04\x00\x00\x00done\x00",
        prefix ++ "\x06\x00\x00\x00failed\x00",
    };
    for ([_][]const u8{ ":1.99", ":1.43" }) |sender| {
        for (bodies) |body| {
            for (0..40) |_| {
                try client.remember(.{
                    .kind = 4,
                    .path = manager_path,
                    .interface = manager_interface,
                    .member = "JobRemoved",
                    .sender = sender,
                    .signature = "uoss",
                    .body = body,
                });
                try std.testing.expectEqual(@as(usize, 0), client.jobs.items.len);
            }
        }
    }
}

test "system bus ignores malformed untrusted JobRemoved before parsing the body" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.watched_unit = "x.scope";
    client.bus_owner = try std.testing.allocator.dupe(u8, ":1.42");
    for ([_][]const u8{ ":1.99", "" }) |sender| {
        const message: Message = .{
            .kind = 4,
            .path = manager_path,
            .interface = manager_interface,
            .member = "JobRemoved",
            .sender = sender,
            .signature = "uoss",
            .body = "",
        };
        try std.testing.expectError(error.InvalidMessage, message.jobRemoved());
        try client.remember(message);
        try std.testing.expectEqual(@as(usize, 0), client.jobs.items.len);
    }
}

test "private peer accepts JobRemoved without a sender" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    client.watched_unit = "x.scope";
    try client.remember(.{
        .kind = 4,
        .path = manager_path,
        .interface = manager_interface,
        .member = "JobRemoved",
        .signature = "uoss",
        .body = "\x2a\x00\x00\x00\x02\x00\x00\x00/j\x00\x00" ++
            "\x07\x00\x00\x00x.scope\x00" ++
            "\x04\x00\x00\x00done\x00",
    });
    try std.testing.expectEqual(@as(usize, 1), client.jobs.items.len);
    try std.testing.expectEqualStrings("/j", client.jobs.items[0].path);
    try std.testing.expectEqualStrings("done", client.jobs.items[0].result);
}

pub const Error = error{ NotAvailable, SocketFailed, AuthenticationFailed, Disconnected, Timeout, InvalidMessage, UnsupportedByteOrder, RemoteError, JobFailed } || std.mem.Allocator.Error;
pub const Property = struct { name: []const u8, value: Value };
pub const Auxiliary = struct { name: []const u8, properties: []const Property };

/// Only the types used by systemd's manager calls. Strings are borrowed.
pub const Value = union(enum) {
    string: []const u8,
    object_path: []const u8,
    boolean: bool,
    uint32: u32,
    uint64: u64,
    int32: i32,
    strings: []const []const u8,
    string_pairs: []const [2][]const u8,
    uint32s: []const u32,
    bytes: []const u8,
    properties: []const Property,
    auxiliary: []const Auxiliary,
    variant: *const Value,

    fn signature(self: Value) []const u8 {
        return switch (self) {
            .string => "s",
            .object_path => "o",
            .boolean => "b",
            .uint32 => "u",
            .uint64 => "t",
            .int32 => "i",
            .strings => "as",
            .string_pairs => "a(ss)",
            .uint32s => "au",
            .bytes => "ay",
            .properties => "a(sv)",
            .auxiliary => "a(sa(sv))",
            .variant => "v",
        };
    }
};

const Encoder = struct {
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,

    fn alignTo(self: *Encoder, alignment: usize) !void {
        try self.data.appendNTimes(self.allocator, 0, std.mem.alignForward(usize, self.data.items.len, alignment) - self.data.items.len);
    }

    fn integer(self: *Encoder, comptime T: type, value: T) !void {
        try self.alignTo(@sizeOf(T));
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, .little);
        try self.data.appendSlice(self.allocator, &bytes);
    }

    fn text(self: *Encoder, value: []const u8) !void {
        if (value.len > std.math.maxInt(u32) or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidMessage;
        try self.integer(u32, @intCast(value.len));
        try self.data.appendSlice(self.allocator, value);
        try self.data.append(self.allocator, 0);
    }

    fn signature(self: *Encoder, value: []const u8) !void {
        if (value.len > 255) return error.InvalidMessage;
        try self.data.append(self.allocator, @intCast(value.len));
        try self.data.appendSlice(self.allocator, value);
        try self.data.append(self.allocator, 0);
    }

    fn beginArray(self: *Encoder, alignment: usize) !struct { size: usize, start: usize } {
        try self.integer(u32, 0);
        const size = self.data.items.len - 4;
        try self.alignTo(alignment);
        return .{ .size = size, .start = self.data.items.len };
    }

    fn finishArray(self: *Encoder, array: anytype) !void {
        const len = self.data.items.len - array.start;
        if (len > std.math.maxInt(u32)) return error.InvalidMessage;
        std.mem.writeInt(u32, self.data.items[array.size..][0..4], @intCast(len), .little);
    }

    fn variant(self: *Encoder, value: Value) Error!void {
        try self.signature(value.signature());
        try self.encode(value);
    }

    fn encode(self: *Encoder, v: Value) Error!void {
        switch (v) {
            .string, .object_path => |text_value| try self.text(text_value),
            .boolean => |b| try self.integer(u32, @intFromBool(b)),
            .uint32 => |u| try self.integer(u32, u),
            .uint64 => |t| try self.integer(u64, t),
            .int32 => |i| try self.integer(i32, i),
            .strings => |strings| try self.stringArray(strings),
            .string_pairs => |pairs| try self.stringPairs(pairs),
            .uint32s => |numbers| try self.uint32Array(numbers),
            .bytes => |bytes| try self.byteArray(bytes),
            .properties => |properties| try self.propertyArray(properties),
            .auxiliary => |units| try self.auxiliaryArray(units),
            .variant => |inner| try self.variant(inner.*),
        }
    }

    fn stringArray(self: *Encoder, strings: []const []const u8) Error!void {
        const array = try self.beginArray(4);
        for (strings) |s| try self.text(s);
        try self.finishArray(array);
    }

    fn stringPairs(self: *Encoder, pairs: []const [2][]const u8) Error!void {
        const array = try self.beginArray(8);
        for (pairs) |pair| {
            try self.alignTo(8);
            try self.text(pair[0]);
            try self.text(pair[1]);
        }
        try self.finishArray(array);
    }

    fn uint32Array(self: *Encoder, numbers: []const u32) Error!void {
        const array = try self.beginArray(4);
        for (numbers) |u| try self.integer(u32, u);
        try self.finishArray(array);
    }

    fn byteArray(self: *Encoder, bytes: []const u8) Error!void {
        const array = try self.beginArray(1);
        try self.data.appendSlice(self.allocator, bytes);
        try self.finishArray(array);
    }

    fn propertyArray(self: *Encoder, properties: []const Property) Error!void {
        const array = try self.beginArray(8);
        for (properties) |property| {
            try self.alignTo(8);
            try self.text(property.name);
            try self.variant(property.value);
        }
        try self.finishArray(array);
    }

    fn auxiliaryArray(self: *Encoder, units: []const Auxiliary) Error!void {
        const array = try self.beginArray(8);
        for (units) |unit| {
            try self.alignTo(8);
            try self.text(unit.name);
            try self.encode(.{ .properties = unit.properties });
        }
        try self.finishArray(array);
    }

    fn field(self: *Encoder, code: u8, v: Value) !void {
        try self.alignTo(8);
        try self.data.append(self.allocator, code);
        try self.variant(v);
    }
};

pub fn marshalCall(allocator: std.mem.Allocator, serial: u32, path: []const u8, interface: []const u8, destination: []const u8, member: []const u8, values: []const Value) Error![]u8 {
    if (serial == 0) return error.InvalidMessage;
    var encoder: Encoder = .{ .allocator = allocator };
    errdefer encoder.data.deinit(allocator);
    try encoder.data.appendSlice(allocator, "l\x01\x00\x01" ++ "\x00" ** 12);
    try encoder.field(1, .{ .object_path = path });
    try encoder.field(2, .{ .string = interface });
    try encoder.field(3, .{ .string = member });
    try encoder.field(6, .{ .string = destination });
    if (values.len != 0) {
        var signature: std.ArrayList(u8) = .empty;
        defer signature.deinit(allocator);
        for (values) |v| try signature.appendSlice(allocator, v.signature());
        try encoder.alignTo(8);
        try encoder.data.append(allocator, 8);
        try encoder.signature("g");
        try encoder.signature(signature.items);
    }
    const fields_len = encoder.data.items.len - 16;
    try encoder.alignTo(8);
    const body_start = encoder.data.items.len;
    for (values) |v| try encoder.encode(v);
    const body_len = encoder.data.items.len - body_start;
    if (fields_len > std.math.maxInt(u32) or body_len > std.math.maxInt(u32)) return error.InvalidMessage;
    std.mem.writeInt(u32, encoder.data.items[4..8], @intCast(body_len), .little);
    std.mem.writeInt(u32, encoder.data.items[8..12], serial, .little);
    std.mem.writeInt(u32, encoder.data.items[12..16], @intCast(fields_len), .little);
    return encoder.data.toOwnedSlice(allocator);
}

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.bytes.len - self.offset) return error.InvalidMessage;
        const value = self.bytes[self.offset..][0..len];
        self.offset += len;
        return value;
    }

    fn alignTo(self: *Reader, alignment: usize) Error!void {
        const next = std.mem.alignForward(usize, self.offset, alignment);
        const padding = try self.take(next - self.offset);
        for (padding) |byte| if (byte != 0) return error.InvalidMessage;
    }

    fn integer(self: *Reader, comptime T: type) Error!T {
        try self.alignTo(@sizeOf(T));
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    fn text(self: *Reader) Error![]const u8 {
        const len = try self.integer(u32);
        const text_value = try self.take(len);
        if ((try self.take(1))[0] != 0 or std.mem.indexOfScalar(u8, text_value, 0) != null or !std.unicode.utf8ValidateSlice(text_value)) return error.InvalidMessage;
        return text_value;
    }

    fn signature(self: *Reader) Error![]const u8 {
        const len = (try self.take(1))[0];
        const s = try self.take(len);
        if ((try self.take(1))[0] != 0) return error.InvalidMessage;
        return s;
    }

    fn skipVariant(self: *Reader, depth: usize) Error!void {
        var signature_value = try self.signature();
        const value_type = try nextType(&signature_value, 0, false);
        if (signature_value.len != 0) return error.InvalidMessage;
        try self.skipValue(value_type, depth);
    }

    fn skipValue(self: *Reader, value_type: []const u8, depth: usize) Error!void {
        if (depth > 64) return error.InvalidMessage;
        try self.alignTo(try typeAlignment(value_type));
        switch (value_type[0]) {
            'y' => _ = try self.take(1),
            'n', 'q' => _ = try self.take(2),
            'b', 'i', 'u', 'h' => _ = try self.take(4),
            'x', 't', 'd' => _ = try self.take(8),
            's', 'o' => _ = try self.text(),
            'g' => _ = try self.signature(),
            'v' => try self.skipVariant(depth + 1),
            'a' => {
                const len = try self.integer(u32);
                const element = value_type[1..];
                try self.alignTo(try typeAlignment(element));
                if (len > self.bytes.len - self.offset) return error.InvalidMessage;
                const end = self.offset + len;
                var array: Reader = .{ .bytes = self.bytes[0..end], .offset = self.offset };
                while (array.offset < end) try array.skipValue(element, depth + 1);
                self.offset = end;
            },
            '(', '{' => {
                var fields = value_type[1 .. value_type.len - 1];
                while (fields.len != 0) try self.skipValue(try nextType(&fields, 0, false), depth + 1);
            },
            else => return error.InvalidMessage,
        }
    }
};

fn typeAlignment(value_type: []const u8) Error!usize {
    if (value_type.len == 0) return error.InvalidMessage;
    return switch (value_type[0]) {
        'y', 'g', 'v' => 1,
        'n', 'q' => 2,
        'b', 'i', 'u', 'h', 's', 'o', 'a' => 4,
        'x', 't', 'd', '(', '{' => 8,
        else => error.InvalidMessage,
    };
}

/// Consume one complete type; dictionary entries are valid only in arrays.
fn nextType(signature_value: *[]const u8, depth: usize, dictionary: bool) Error![]const u8 {
    if (signature_value.len == 0 or depth > 64) return error.InvalidMessage;
    const start = signature_value.*;
    signature_value.* = start[1..];
    switch (start[0]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h', 'v' => {},
        'a' => _ = try nextType(signature_value, depth + 1, true),
        '(' => try nextStruct(signature_value, depth),
        '{' => try nextDictionary(signature_value, depth, dictionary),
        else => return error.InvalidMessage,
    }
    return start[0 .. start.len - signature_value.len];
}

fn nextStruct(signature_value: *[]const u8, depth: usize) Error!void {
    if (signature_value.len == 0 or signature_value.*[0] == ')') return error.InvalidMessage;
    while (signature_value.len != 0 and signature_value.*[0] != ')')
        _ = try nextType(signature_value, depth + 1, false);
    if (signature_value.len == 0) return error.InvalidMessage;
    signature_value.* = signature_value.*[1..];
}

fn nextDictionary(signature_value: *[]const u8, depth: usize, dictionary: bool) Error!void {
    if (!dictionary or signature_value.len == 0 or
        std.mem.indexOfScalar(u8, "ybnqiuxtdsogh", signature_value.*[0]) == null) return error.InvalidMessage;
    _ = try nextType(signature_value, depth + 1, false);
    _ = try nextType(signature_value, depth + 1, false);
    if (signature_value.len == 0 or signature_value.*[0] != '}') return error.InvalidMessage;
    signature_value.* = signature_value.*[1..];
}

pub const Message = struct {
    kind: u8,
    reply_serial: u32 = 0,
    error_name: []const u8 = "",
    path: []const u8 = "",
    interface: []const u8 = "",
    member: []const u8 = "",
    sender: []const u8 = "",
    signature: []const u8 = "",
    body: []const u8,

    pub fn parse(bytes: []const u8) Error!Message {
        const body_start = try bodyStart(bytes);
        const fields_len: usize = std.mem.readInt(u32, bytes[12..16], .little);
        var reader: Reader = .{ .bytes = bytes[0 .. 16 + fields_len], .offset = 16 };
        var message: Message = .{ .kind = bytes[1], .body = bytes[body_start..] };
        var seen: u16 = 0;
        while (reader.offset < reader.bytes.len) {
            try reader.alignTo(8);
            const code = (try reader.take(1))[0];
            if (code == 0) return error.InvalidMessage;
            if (code > 9) {
                try reader.skipVariant(0);
                continue;
            }
            const bit = @as(u16, 1) << @intCast(code);
            if (seen & bit != 0) return error.InvalidMessage;
            seen |= bit;
            try message.readField(&reader, code);
        }
        if ((message.kind == 2 or message.kind == 3) and message.reply_serial == 0) return error.InvalidMessage;
        if (message.kind == 3 and message.error_name.len == 0) return error.InvalidMessage;
        return message;
    }

    fn bodyStart(bytes: []const u8) Error!usize {
        // The encoder and readers support little-endian D-Bus messages only.
        if (bytes.len < 16) return error.InvalidMessage;
        if (bytes[0] == 'B') return error.UnsupportedByteOrder;
        if (bytes[0] != 'l' or bytes[1] < 1 or bytes[1] > 4 or bytes[3] != 1 or std.mem.readInt(u32, bytes[8..12], .little) == 0) return error.InvalidMessage;
        const fields_len: usize = std.mem.readInt(u32, bytes[12..16], .little);
        const body_start = std.mem.alignForward(usize, 16 + fields_len, 8);
        const body_len: usize = std.mem.readInt(u32, bytes[4..8], .little);
        if (body_start > bytes.len or body_len != bytes.len - body_start) return error.InvalidMessage;
        return body_start;
    }

    fn readField(self: *Message, reader: *Reader, code: u8) Error!void {
        const sig = try reader.signature();
        switch (code) {
            1, 2, 3, 4, 6, 7 => try self.readTextField(reader, code, sig),
            5, 9 => {
                if (!std.mem.eql(u8, sig, "u")) return error.InvalidMessage;
                const u = try reader.integer(u32);
                if (code == 5) self.reply_serial = u;
                if (code == 9 and u != 0) return error.InvalidMessage; // no FD passing
            },
            8 => {
                if (!std.mem.eql(u8, sig, "g")) return error.InvalidMessage;
                self.signature = try reader.signature();
            },
            else => unreachable,
        }
    }

    fn readTextField(self: *Message, reader: *Reader, code: u8, sig: []const u8) Error!void {
        if (!std.mem.eql(u8, sig, if (code == 1) "o" else "s")) return error.InvalidMessage;
        const text_value = try reader.text();
        switch (code) {
            1 => self.path = text_value,
            2 => self.interface = text_value,
            3 => self.member = text_value,
            4 => self.error_name = text_value,
            7 => self.sender = text_value,
            else => {},
        }
    }

    pub fn errorText(self: Message) Error![]const u8 {
        if (self.signature.len == 0) return "";
        if (self.signature[0] != 's') return error.InvalidMessage;
        var reader: Reader = .{ .bytes = self.body };
        return reader.text();
    }

    pub fn jobRemoved(self: Message) Error!?Job {
        if (self.kind != 4 or !std.mem.eql(u8, self.member, "JobRemoved")) return null;
        if (!std.mem.eql(u8, self.signature, "uoss")) return error.InvalidMessage;
        var reader: Reader = .{ .bytes = self.body };
        _ = try reader.integer(u32);
        const job: Job = .{ .path = try reader.text(), .unit = try reader.text(), .result = try reader.text() };
        if (reader.offset != self.body.len) return error.InvalidMessage;
        return job;
    }
};

pub const Job = struct { path: []const u8, unit: []const u8, result: []const u8 };
const manager_path = "/org/freedesktop/systemd1";
const manager_interface = "org.freedesktop.systemd1.Manager";
const manager_destination = "org.freedesktop.systemd1";
const bus_path = "/org/freedesktop/DBus";
const bus_interface = "org.freedesktop.DBus";
const timeout_ms = 30_000;
const max_message = 1024 * 1024;

/// Each public operation gets a fresh monotonic deadline, shared by its
/// method replies and job signals. Connecting has its own deadline.
pub const Client = struct {
    allocator: std.mem.Allocator,
    fd: i32 = -1,
    serial: u32 = 0,
    deadline: i64 = 0,
    error_name: [256]u8 = @splat(0),
    error_name_len: usize = 0,
    detail: [512]u8 = @splat(0),
    detail_len: usize = 0,
    watched_unit: ?[]const u8 = null,
    bus_owner: ?[]u8 = null,
    unit_started: bool = false,
    auth_barrier: bool = false,
    /// Connected to a per-user manager (see userBus).
    user_bus: bool = false,
    jobs: std.ArrayList(struct { path: []u8, result: []u8 }) = .empty,

    pub fn init(allocator: std.mem.Allocator) Client {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Client) void {
        if (comptime builtin.os.tag == .linux) {
            if (self.fd >= 0) _ = linux.close(self.fd);
        }
        if (self.bus_owner) |owner| self.allocator.free(owner);
        for (self.jobs.items) |job| {
            self.allocator.free(job.path);
            self.allocator.free(job.result);
        }
        self.jobs.deinit(self.allocator);
    }

    pub fn diagnostic(self: *const Client) []const u8 {
        return self.detail[0..self.detail_len];
    }
    pub fn isRemote(self: *const Client, name: []const u8) bool {
        return std.mem.eql(u8, self.error_name[0..self.error_name_len], name);
    }

    fn note(self: *Client, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.bufPrint(&self.detail, format, args) catch {
            self.detail_len = self.detail.len;
            return;
        };
        self.detail_len = text.len;
    }

    pub fn connect(self: *Client) Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotAvailable;
        self.deadline = (try now()) + timeout_ms;
        if (try self.userBus()) |bus| {
            self.fd = openSocket(bus.address(), bus.abstract) catch |err| {
                self.note("cannot connect to the user D-Bus {s}: {s}", .{ bus.address(), @errorName(err) });
                return err;
            };
            self.user_bus = true;
            return self.joinBus(bus.uid);
        }
        self.fd = openSocket("/run/systemd/private", false) catch |private_err| fallback: {
            const fd = openSocket("/run/dbus/system_bus_socket", false) catch |bus_err| {
                if (private_err == error.NotAvailable and bus_err == error.NotAvailable) {
                    self.note("systemd cgroup driver requested but systemd is not available", .{});
                    return error.NotAvailable;
                }
                self.note("cannot connect to systemd D-Bus: private socket {s}, system bus {s}", .{ @errorName(private_err), @errorName(bus_err) });
                return bus_err;
            };
            self.fd = fd;
            try self.joinBus(linux.geteuid());
            break :fallback fd;
        };
        // joinBus authenticated and issued Hello for the bus.
        // Private connections need AUTH but must not issue Hello.
        if (self.serial == 0) {
            try self.authenticate(linux.geteuid());
            self.auth_barrier = true;
        }
    }

    /// Authenticates on a message bus and subscribes to systemd's signals.
    fn joinBus(self: *Client, uid: u32) Error!void {
        try self.authenticate(uid);
        const hello = try self.callAt(bus_path, bus_interface, bus_interface, "Hello", &.{});
        self.allocator.free(hello);
        const owner_reply = try self.callAt(bus_path, bus_interface, bus_interface, "GetNameOwner", &.{.{ .string = manager_destination }});
        defer self.allocator.free(owner_reply);
        try self.pinBusOwner(try Message.parse(owner_reply));
        // Register interest before Subscribe, otherwise the bus will not
        // forward systemd's broadcast JobRemoved signals to this client.
        const rule = "type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved',path='/org/freedesktop/systemd1'";
        const matched = try self.callAt(bus_path, bus_interface, bus_interface, "AddMatch", &.{.{ .string = rule }});
        self.allocator.free(matched);
    }

    /// runc's rootless systemd driver uses the per-user manager on the
    /// session bus; null selects the system manager.
    fn userBus(self: *Client) Error!?UserBus {
        const uid = userBusOwner() orelse return null;
        if (sessionBus(uid)) |bus| return bus;
        // Root in a user namespace without a session bus is treated as root,
        // as runc does when busctl --user cannot answer.
        if (linux.geteuid() == 0) return null;
        self.note("could not detect DBUS_SESSION_BUS_ADDRESS from the environment; make sure you have installed the dbus-user-session or dbus-daemon package; note you may need to re-login", .{});
        return error.NotAvailable;
    }

    /// The absolute cgroup of the connected manager, owned by the caller.
    pub fn managerControlGroup(self: *Client) Error![]u8 {
        self.deadline = (try now()) + timeout_ms;
        const reply = try self.callAt(manager_path, "org.freedesktop.DBus.Properties", manager_destination, "Get", &.{
            .{ .string = manager_interface },
            .{ .string = "ControlGroup" },
        });
        defer self.allocator.free(reply);
        const control_group = try stringVariant(try Message.parse(reply));
        if (control_group.len == 0 or control_group[0] != '/') return error.InvalidMessage;
        return self.allocator.dupe(u8, control_group);
    }

    fn pinBusOwner(self: *Client, message: Message) Error!void {
        if (message.kind != 2 or !std.mem.eql(u8, message.signature, "s")) return error.InvalidMessage;
        var reader: Reader = .{ .bytes = message.body };
        const owner = try reader.text();
        if (owner.len < 2 or owner[0] != ':' or reader.offset != message.body.len) return error.InvalidMessage;
        self.bus_owner = try self.allocator.dupe(u8, owner);
    }

    fn authenticate(self: *Client, owner: u32) Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotAvailable;
        var uid_buf: [20]u8 = undefined;
        const uid = std.fmt.bufPrint(&uid_buf, "{d}", .{owner}) catch unreachable;
        var auth: [80]u8 = undefined;
        const prefix = "\x00AUTH EXTERNAL ";
        @memcpy(auth[0..prefix.len], prefix);
        const hex = "0123456789abcdef";
        for (uid, 0..) |byte, i| {
            auth[prefix.len + i * 2] = hex[byte >> 4];
            auth[prefix.len + i * 2 + 1] = hex[byte & 15];
        }
        const end = prefix.len + uid.len * 2;
        @memcpy(auth[end..][0..2], "\r\n");
        try self.send(auth[0 .. end + 2]);
        var line: [512]u8 = undefined;
        var len: usize = 0;
        while (len < line.len) {
            try self.read(line[len..][0..1]);
            len += 1;
            if (len >= 2 and std.mem.eql(u8, line[len - 2 .. len], "\r\n")) break;
        }
        if (!std.mem.startsWith(u8, line[0..len], "OK ") or len == line.len) {
            self.note("systemd D-Bus AUTH EXTERNAL rejected: {s}", .{std.mem.trim(u8, line[0..len], "\r\n")});
            return error.AuthenticationFailed;
        }
        try self.send("BEGIN\r\n");
    }

    fn call(self: *Client, member: []const u8, values: []const Value) Error![]u8 {
        return self.callAt(manager_path, manager_interface, manager_destination, member, values);
    }

    fn callAt(self: *Client, path: []const u8, interface: []const u8, destination: []const u8, member: []const u8, values: []const Value) Error![]u8 {
        self.error_name_len = 0;
        self.serial +%= 1;
        if (self.serial == 0) self.serial = 1;
        const serial = self.serial;
        const request = try marshalCall(self.allocator, serial, path, interface, destination, member, values);
        defer self.allocator.free(request);
        try self.send(request);
        if (self.auth_barrier) {
            self.auth_barrier = false;
            self.serial +%= 1;
            if (self.serial == 0) self.serial = 1;
            // sd-bus v255 can consume BEGIN and a whole small first message
            // in its auth read, then wait for socket readiness despite buffered
            // data. Pipeline Peer.Ping so data remains after that read. Its
            // reply has a separate serial and is ignored by the usual loop.
            const ping = try marshalCall(self.allocator, self.serial, manager_path, "org.freedesktop.DBus.Peer", manager_destination, "Ping", &.{});
            defer self.allocator.free(ping);
            try self.send(ping);
        }
        while (true) {
            const bytes = try self.receive();
            errdefer self.allocator.free(bytes);
            const message = try Message.parse(bytes);
            if (message.kind == 4) try self.remember(message);
            if ((message.kind == 2 or message.kind == 3) and message.reply_serial == serial) {
                if (message.kind == 2) return bytes;
                try self.noteRemoteError(message, destination, member);
                return error.RemoteError;
            }
            self.allocator.free(bytes);
        }
    }

    fn noteRemoteError(self: *Client, message: Message, destination: []const u8, member: []const u8) Error!void {
        self.error_name_len = @min(message.error_name.len, self.error_name.len);
        @memcpy(self.error_name[0..self.error_name_len], message.error_name[0..self.error_name_len]);
        const remote_text = try message.errorText();
        if ((std.mem.eql(u8, destination, manager_destination) and
            (self.isRemote("org.freedesktop.DBus.Error.ServiceUnknown") or self.isRemote("org.freedesktop.DBus.Error.NameHasNoOwner"))) or
            (std.mem.eql(u8, destination, bus_interface) and std.mem.eql(u8, member, "GetNameOwner") and
                self.isRemote("org.freedesktop.DBus.Error.NameHasNoOwner")))
            self.note("systemd cgroup driver requested but systemd is not available: {s}: {s}", .{ message.error_name, remote_text })
        else
            self.note("{s}: {s}: {s}", .{ member, message.error_name, remote_text });
    }

    fn remember(self: *Client, message: Message) Error!void {
        const unit = self.watched_unit orelse return;
        if (self.bus_owner) |owner| {
            if (!std.mem.eql(u8, message.sender, owner)) return;
        }
        if (!std.mem.eql(u8, message.path, manager_path) or !std.mem.eql(u8, message.interface, manager_interface)) return;
        const removed = (try message.jobRemoved()) orelse return;
        if (!std.mem.eql(u8, removed.unit, unit)) return;
        if (self.jobs.items.len >= 32) return error.InvalidMessage;
        const path = try self.allocator.dupe(u8, removed.path);
        errdefer self.allocator.free(path);
        const result = try self.allocator.dupe(u8, removed.result);
        errdefer self.allocator.free(result);
        try self.jobs.append(self.allocator, .{ .path = path, .result = result });
    }

    fn resetFailed(self: *Client, unit: []const u8) Error!void {
        const reply = self.call("ResetFailedUnit", &.{.{ .string = unit }}) catch |err| {
            if (err == error.RemoteError and self.isRemote("org.freedesktop.systemd1.NoSuchUnit")) return;
            return err;
        };
        self.allocator.free(reply);
    }

    pub fn start(self: *Client, unit: []const u8, properties: []const Property) Error!void {
        self.deadline = (try now()) + timeout_ms;
        try self.resetFailed(unit);
        try self.runJob("StartTransientUnit", unit, &.{ .{ .string = unit }, .{ .string = "replace" }, .{ .properties = properties }, .{ .auxiliary = &.{} } });
    }

    pub fn stop(self: *Client, unit: []const u8) Error!void {
        self.deadline = (try now()) + timeout_ms;
        self.runJob("StopUnit", unit, &.{ .{ .string = unit }, .{ .string = "replace" } }) catch |err| {
            if (!(err == error.RemoteError and self.isRemote("org.freedesktop.systemd1.NoSuchUnit"))) return err;
        };
        try self.resetFailed(unit);
    }

    pub fn setProperties(self: *Client, unit: []const u8, properties: []const Property) Error!void {
        self.deadline = (try now()) + timeout_ms;
        if (properties.len == 0) return;
        const reply = try self.call("SetUnitProperties", &.{ .{ .string = unit }, .{ .boolean = true }, .{ .properties = properties } });
        self.allocator.free(reply);
    }

    /// Compare systemd's absolute ControlGroup with a saved relative cgroup path.
    pub fn controlGroupMatches(self: *Client, unit: []const u8, cgroup_path: []const u8) Error!bool {
        self.deadline = (try now()) + timeout_ms;
        const unit_reply = try self.call("GetUnit", &.{.{ .string = unit }});
        defer self.allocator.free(unit_reply);
        const unit_message = try Message.parse(unit_reply);
        if (!std.mem.eql(u8, unit_message.signature, "o")) return error.InvalidMessage;
        var unit_reader: Reader = .{ .bytes = unit_message.body };
        const unit_path = try unit_reader.text();
        if (unit_path.len == 0 or unit_path[0] != '/' or unit_reader.offset != unit_message.body.len)
            return error.InvalidMessage;
        const reply = try self.callAt(unit_path, "org.freedesktop.DBus.Properties", manager_destination, "Get", &.{
            .{ .string = "org.freedesktop.systemd1.Unit" },
            .{ .string = "ControlGroup" },
        });
        defer self.allocator.free(reply);
        const control_group = try stringVariant(try Message.parse(reply));
        return control_group.len != 0 and control_group[0] == '/' and
            std.mem.eql(u8, control_group[1..], cgroup_path);
    }

    fn runJob(self: *Client, member: []const u8, unit: []const u8, values: []const Value) Error!void {
        const subscribed = try self.call("Subscribe", &.{});
        self.allocator.free(subscribed);
        self.watched_unit = unit;
        defer self.watched_unit = null;
        const reply = try self.call(member, values);
        if (std.mem.eql(u8, member, "StartTransientUnit")) self.unit_started = true;
        defer self.allocator.free(reply);
        const message = try Message.parse(reply);
        if (!std.mem.eql(u8, message.signature, "o")) return error.InvalidMessage;
        var reader: Reader = .{ .bytes = message.body };
        const job_path = try reader.text();
        if (reader.offset != message.body.len) return error.InvalidMessage;
        while (true) {
            for (self.jobs.items) |completed| {
                if (std.mem.eql(u8, completed.path, job_path)) {
                    if (std.mem.eql(u8, completed.result, "done")) return;
                    self.note("{s} {s}: systemd job {s} finished with result {s}", .{ member, unit, job_path, completed.result });
                    return error.JobFailed;
                }
            }
            const bytes = self.receive() catch |err| {
                if (err == error.Timeout) self.note("timed out waiting for systemd job {s} ({s} {s})", .{ job_path, member, unit });
                return err;
            };
            defer self.allocator.free(bytes);
            try self.remember(try Message.parse(bytes));
        }
    }

    fn receive(self: *Client) Error![]u8 {
        var header: [16]u8 = undefined;
        try self.read(&header);
        if (header[0] == 'B') {
            self.note("big-endian D-Bus messages are unsupported; expected little-endian byte order", .{});
            return error.UnsupportedByteOrder;
        }
        if (header[0] != 'l' or header[3] != 1) return error.InvalidMessage;
        const fields: usize = std.mem.readInt(u32, header[12..16], .little);
        const body: usize = std.mem.readInt(u32, header[4..8], .little);
        if (fields > max_message or body > max_message) return error.InvalidMessage;
        const total = std.mem.alignForward(usize, 16 + fields, 8) + body;
        if (total > max_message) return error.InvalidMessage;
        const bytes = try self.allocator.alloc(u8, total);
        errdefer self.allocator.free(bytes);
        @memcpy(bytes[0..16], &header);
        try self.read(bytes[16..]);
        return bytes;
    }

    fn wait(self: *Client, events: i16) Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotAvailable;
        while (true) {
            const remaining = self.deadline - (try now());
            if (remaining <= 0) {
                self.note("systemd D-Bus operation timed out after 30 seconds", .{});
                return error.Timeout;
            }
            var fds = [_]linux.pollfd{.{ .fd = self.fd, .events = events, .revents = 0 }};
            const result = linux.poll(&fds, 1, @intCast(@min(remaining, timeout_ms)));
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.SocketFailed,
            }
            if (result == 0) continue;
            if (fds[0].revents & events != 0) return;
            return error.Disconnected;
        }
    }

    fn send(self: *Client, bytes: []const u8) Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotAvailable;
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.wait(linux.POLL.OUT);
            const result = linux.sendto(self.fd, bytes[offset..].ptr, bytes.len - offset, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return error.Disconnected,
            }
            if (result == 0) return error.Disconnected;
            offset += result;
        }
    }

    fn read(self: *Client, bytes: []u8) Error!void {
        if (comptime builtin.os.tag != .linux) return error.NotAvailable;
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.wait(linux.POLL.IN);
            const result = linux.read(self.fd, bytes[offset..].ptr, bytes.len - offset);
            switch (linux.errno(result)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return error.Disconnected,
            }
            if (result == 0) return error.Disconnected;
            offset += result;
        }
    }
};

fn now() Error!i64 {
    if (comptime builtin.os.tag != .linux) return error.NotAvailable;
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return error.SocketFailed;
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// A Properties.Get reply holding a string.
fn stringVariant(message: Message) Error![]const u8 {
    if (!std.mem.eql(u8, message.signature, "v")) return error.InvalidMessage;
    var reader: Reader = .{ .bytes = message.body };
    if (!std.mem.eql(u8, try reader.signature(), "s")) return error.InvalidMessage;
    const text = try reader.text();
    if (reader.offset != message.body.len) return error.InvalidMessage;
    return text;
}

/// The frontend's $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR, which
/// locate the user bus as go-systemd does.
pub var session_bus_address: ?[]const u8 = null;
pub var runtime_dir: ?[]const u8 = null;

const UserBus = struct {
    path: [108]u8 = undefined,
    len: usize = 0,
    abstract: bool = false,
    uid: u32,

    fn address(self: *const UserBus) []const u8 {
        return self.path[0..self.len];
    }
};

/// The UID this process has outside its user namespace, when non-zero.
/// runc asks `busctl --user` for the bus OwnerUID instead.
// ponytail: only the parent user namespace is consulted; nested
// namespaces would need the bus owner from the bus itself.
pub fn userBusOwner() ?u32 {
    if (comptime builtin.os.tag != .linux) return null;
    const euid = linux.geteuid();
    var buffer: [1024]u8 = undefined;
    const fd = std.posix.openat(std.posix.AT.FDCWD, "/proc/self/uid_map", .{ .CLOEXEC = true }, 0) catch
        return if (euid == 0) null else euid;
    defer _ = linux.close(fd);
    const count = std.posix.read(fd, &buffer) catch return if (euid == 0) null else euid;
    const outer = mapUid(buffer[0..count], euid) orelse return null;
    return if (outer == 0) null else outer;
}

fn mapUid(map: []const u8, uid: u32) ?u32 {
    var lines = std.mem.tokenizeScalar(u8, map, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const inside = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        const outside = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        const length = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        if (uid >= inside and uid - inside < length) return outside +% (uid - inside);
    }
    return null;
}

/// The first unix:path= or unix:abstract= address, else $XDG_RUNTIME_DIR/bus.
fn sessionBus(uid: u32) ?UserBus {
    var bus: UserBus = .{ .uid = uid };
    if (session_bus_address) |addresses| {
        var alternatives = std.mem.tokenizeScalar(u8, addresses, ';');
        while (alternatives.next()) |entry| {
            const params = std.mem.cutPrefix(u8, entry, "unix:") orelse continue;
            if (unixAddress(&bus, params)) return bus;
        }
        return null;
    }
    const dir = runtime_dir orelse return null;
    const path = std.fmt.bufPrint(&bus.path, "{s}/bus", .{dir}) catch return null;
    if (comptime builtin.os.tag == .linux) {
        var z: [109]u8 = undefined;
        if (path.len >= z.len) return null;
        @memcpy(z[0..path.len], path);
        z[path.len] = 0;
        if (linux.errno(linux.access(z[0..path.len :0], linux.F_OK)) != .SUCCESS) return null;
    }
    bus.len = path.len;
    return bus;
}

/// The path= or abstract= key of one unix: address, into `bus`.
fn unixAddress(bus: *UserBus, params: []const u8) bool {
    var pairs = std.mem.tokenizeScalar(u8, params, ',');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        if (!std.mem.eql(u8, key, "path") and !std.mem.eql(u8, key, "abstract")) continue;
        bus.abstract = std.mem.eql(u8, key, "abstract");
        bus.len = unescapeAddress(&bus.path, pair[eq + 1 ..]) orelse continue;
        // A NUL would turn a path into an abstract address.
        if (std.mem.indexOfScalar(u8, bus.address(), 0) != null) continue;
        if (!bus.abstract and bus.path[0] != '/') continue;
        return true;
    }
    return false;
}

/// D-Bus address values escape bytes as %xx.
fn unescapeAddress(out: []u8, value: []const u8) ?usize {
    var len: usize = 0;
    var i: usize = 0;
    while (i < value.len) : (len += 1) {
        if (len >= out.len - 1) return null;
        if (value[i] == '%') {
            if (i + 3 > value.len) return null;
            out[len] = std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16) catch return null;
            i += 3;
        } else {
            out[len] = value[i];
            i += 1;
        }
    }
    return if (len == 0) null else len;
}

test "user bus addresses and UID maps resolve like go-systemd" {
    defer session_bus_address = null;
    session_bus_address = "tcp:host=x;unix:guid=1,path=/run/user/1000/b%2cus";
    const bus = sessionBus(1000).?;
    try std.testing.expectEqualStrings("/run/user/1000/b,us", bus.address());
    try std.testing.expect(!bus.abstract);
    session_bus_address = "unix:abstract=/tmp/dbus-x";
    try std.testing.expect(sessionBus(1).?.abstract);
    session_bus_address = "tcp:host=x";
    try std.testing.expectEqual(@as(?UserBus, null), sessionBus(1));
    for ([_][]const u8{ "unix:path=/a%00b", "unix:path=relative" }) |address| {
        session_bus_address = address;
        try std.testing.expectEqual(@as(?UserBus, null), sessionBus(1));
    }
    try std.testing.expectEqual(@as(?u32, 1000), mapUid("         0       1000          1\n         1     100000      65536\n", 0));
    try std.testing.expectEqual(@as(?u32, 100004), mapUid("0 1000 1\n1 100000 65536\n", 5));
    try std.testing.expectEqual(@as(?u32, 0), mapUid("0 0 4294967295\n", 0));
    try std.testing.expectEqual(@as(?u32, null), mapUid("0 1000 1\n", 7));
}

fn openSocket(path: []const u8, abstract: bool) Error!i32 {
    if (comptime builtin.os.tag != .linux) return error.NotAvailable;
    const opened = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(opened);
    errdefer _ = linux.close(fd);
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    // An abstract address starts with NUL and has no terminator.
    const start: usize = @intFromBool(abstract);
    if (start + path.len >= addr.path.len) return error.SocketFailed;
    @memcpy(addr.path[start..][0..path.len], path);
    switch (linux.errno(linux.connect(fd, &addr, @intCast(@offsetOf(linux.sockaddr.un, "path") + start + path.len + @intFromBool(!abstract))))) {
        .SUCCESS => return fd,
        .NOENT, .CONNREFUSED => return error.NotAvailable,
        else => return error.SocketFailed,
    }
}

test "linux private connection processes a small first call after authentication" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0 or linux.errno(linux.access("/run/systemd/private", linux.F_OK)) != .SUCCESS)
        return error.SkipZigTest;
    for (0..8) |_| {
        var client = Client.init(std.testing.allocator);
        defer client.deinit();
        try client.connect();
        const response = try client.call("Subscribe", &.{});
        defer std.testing.allocator.free(response);
        try std.testing.expectEqual(@as(u8, 2), (try Message.parse(response)).kind);
    }
}

test "D-Bus string arrays auxiliary units and byte variants have independent wire fixtures" {
    const allocator = std.testing.allocator;
    var strings: Encoder = .{ .allocator = allocator };
    defer strings.data.deinit(allocator);
    try strings.encode(.{ .strings = &.{ "a", "bc" } });
    try std.testing.expectEqualSlices(u8, "\x0f\x00\x00\x00\x01\x00\x00\x00a\x00\x00\x00\x02\x00\x00\x00bc\x00", strings.data.items);
    var auxiliary: Encoder = .{ .allocator = allocator };
    defer auxiliary.data.deinit(allocator);
    try auxiliary.encode(.{ .auxiliary = &.{.{ .name = "x", .properties = &.{.{ .name = "A", .value = .{ .int32 = -2 } }} }} });
    const expected = "\x20\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x01\x00\x00\x00x\x00\x00\x00\x10\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x01\x00\x00\x00A\x00\x01i\x00" ++ "\x00" ** 3 ++ "\xfe\xff\xff\xff";
    try std.testing.expectEqualSlices(u8, expected, auxiliary.data.items);
    var variant: Encoder = .{ .allocator = allocator };
    defer variant.data.deinit(allocator);
    const inner: Value = .{ .bytes = &.{ 0xff, 1 } };
    try variant.encode(.{ .variant = &inner });
    try std.testing.expectEqualSlices(u8, "\x02ay\x00\x02\x00\x00\x00\xff\x01", variant.data.items);
}

test "D-Bus DeviceAllow variants encode aligned string pairs" {
    var encoder: Encoder = .{ .allocator = std.testing.allocator };
    defer encoder.data.deinit(std.testing.allocator);
    const inner: Value = .{ .string_pairs = &.{
        .{ "/dev/char/1:3", "rw" },
        .{ "char-136", "rwm" },
    } };
    try encoder.encode(.{ .variant = &inner });
    const expected = "\x05a(ss)\x00\x00\x38\x00\x00\x00" ++ "\x00" ** 4 ++
        "\x0d\x00\x00\x00/dev/char/1:3\x00" ++ "\x00" ** 2 ++
        "\x02\x00\x00\x00rw\x00" ++ "\x00" ** 5 ++
        "\x08\x00\x00\x00char-136\x00" ++ "\x00" ** 3 ++
        "\x03\x00\x00\x00rwm\x00";
    try std.testing.expectEqualSlices(u8, expected, encoder.data.items);
    encoder.data.clearRetainingCapacity();
    try encoder.encode(.{ .string_pairs = &.{} });
    try std.testing.expectEqualSlices(u8, "\x00" ** 8, encoder.data.items);
}

test "D-Bus marshalling frees partially allocated messages" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const bytes = try marshalCall(allocator, 1, manager_path, manager_interface, manager_destination, "StartTransientUnit", &.{
                .{ .string = "x.scope" }, .{ .string = "replace" },
                .{ .properties = &.{
                    .{ .name = "PIDs", .value = .{ .uint32s = &.{42} } },
                    .{ .name = "DeviceAllow", .value = .{ .string_pairs = &.{.{ "/dev/char/1:3", "rwm" }} } },
                } },
                .{ .auxiliary = &.{} },
            });
            allocator.free(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

test "linux absent systemd sockets report the requested driver" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.errno(linux.access("/run/systemd/private", linux.F_OK)) != .NOENT or
        linux.errno(linux.access("/run/dbus/system_bus_socket", linux.F_OK)) != .NOENT) return error.SkipZigTest;
    var client = Client.init(std.testing.allocator);
    defer client.deinit();
    try std.testing.expectError(error.NotAvailable, client.connect());
    try std.testing.expect(std.mem.indexOf(u8, client.diagnostic(), "systemd cgroup driver requested but systemd is not available") != null);
}

test "linux D-Bus method errors carry their remote name and message" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0, &fds)) != .SUCCESS)
        return error.SocketFailed;
    defer _ = linux.close(fds[1]);
    var client = Client.init(std.testing.allocator);
    client.fd = fds[0];
    defer client.deinit();
    client.deadline = (try now()) + timeout_ms;
    const bytes = "l\x03\x00\x01\x09\x00\x00\x00\x02\x00\x00\x00\x1f\x00\x00\x00" ++
        "\x04\x01s\x00\x03\x00\x00\x00x.E\x00" ++ "\x00" ** 4 ++
        "\x05\x01u\x00\x01\x00\x00\x00" ++
        "\x08\x01g\x00\x01s\x00\x00" ++
        "\x04\x00\x00\x00oops\x00";
    try std.testing.expectEqual(@as(usize, bytes.len), linux.write(fds[1], bytes.ptr, bytes.len));
    try std.testing.expectError(error.RemoteError, client.call("Subscribe", &.{}));
    try std.testing.expect(client.isRemote("x.E"));
    try std.testing.expect(std.mem.indexOf(u8, client.diagnostic(), "x.E: oops") != null);
}

test "linux ControlGroup lookup uses Unit properties and renews its deadline" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const unit_reply = "l\x02\x00\x01\x07\x00\x00\x00\x01\x00\x00\x00\x0f\x00\x00\x00" ++
        "\x05\x01u\x00\x01\x00\x00\x00" ++
        "\x08\x01g\x00\x01o\x00\x00" ++
        "\x02\x00\x00\x00/u\x00";
    const property_reply = "l\x02\x00\x01\x2b\x00\x00\x00\x02\x00\x00\x00\x0f\x00\x00\x00" ++
        "\x05\x01u\x00\x02\x00\x00\x00" ++
        "\x08\x01g\x00\x01v\x00\x00" ++
        "\x01s\x00\x00\x22\x00\x00\x00/system.slice/igvano-example.scope\x00";
    const cases = [_]struct {
        path: []const u8 = "system.slice/igvano-example.scope",
        matches: bool = false,
        unit_signature: u8 = 'o',
        property_signature: u8 = 'v',
        value_signature: u8 = 's',
        invalid: bool = false,
    }{
        .{ .matches = true },
        .{ .path = "user.slice/session-1.scope" },
        .{ .path = "system.slice/igvano-example.scope/child" },
        .{ .path = "system.slice/igvano-example.scop" },
        .{ .unit_signature = 's', .invalid = true },
        .{ .property_signature = 's', .invalid = true },
        .{ .value_signature = 'o', .invalid = true },
    };
    for (cases) |case| {
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0, &fds)) != .SUCCESS)
            return error.SocketFailed;
        defer _ = linux.close(fds[1]);
        var client = Client.init(std.testing.allocator);
        client.fd = fds[0];
        defer client.deinit();
        client.deadline = 1;
        const started = try now();
        var reply: [unit_reply.len + property_reply.len]u8 = undefined;
        @memcpy(reply[0..unit_reply.len], unit_reply);
        @memcpy(reply[unit_reply.len..], property_reply);
        reply[29] = case.unit_signature;
        reply[unit_reply.len + 29] = case.property_signature;
        reply[unit_reply.len + 33] = case.value_signature;
        try std.testing.expectEqual(reply.len, linux.write(fds[1], &reply, reply.len));
        const result = client.controlGroupMatches("igvano-example.scope", case.path);
        if (case.invalid)
            try std.testing.expectError(error.InvalidMessage, result)
        else
            try std.testing.expectEqual(case.matches, try result);
        try std.testing.expect(client.deadline >= started + timeout_ms);
        if (case.invalid) continue;
        const get_unit = try marshalCall(std.testing.allocator, 1, manager_path, manager_interface, manager_destination, "GetUnit", &.{.{ .string = "igvano-example.scope" }});
        defer std.testing.allocator.free(get_unit);
        const get_property = try marshalCall(std.testing.allocator, 2, "/u", "org.freedesktop.DBus.Properties", manager_destination, "Get", &.{
            .{ .string = "org.freedesktop.systemd1.Unit" },
            .{ .string = "ControlGroup" },
        });
        defer std.testing.allocator.free(get_property);
        var requests: [1024]u8 = undefined;
        const length = get_unit.len + get_property.len;
        var received: usize = 0;
        while (received < length) {
            const size = linux.read(fds[1], requests[received..].ptr, length - received);
            if (linux.errno(size) != .SUCCESS or size == 0) return error.Disconnected;
            received += size;
        }
        try std.testing.expectEqualSlices(u8, get_unit, requests[0..get_unit.len]);
        try std.testing.expectEqualSlices(u8, get_property, requests[get_unit.len..length]);
    }
}

test "linux GetNameOwner errors preserve systemd availability and remote diagnostics" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct { bytes: []const u8, name: []const u8, diagnostic: []const u8, unavailable: bool }{
        .{
            .bytes = "l\x03\x00\x01\x0f\x00\x00\x00\x02\x00\x00\x00\x47\x00\x00\x00" ++
                "\x04\x01s\x00\x29\x00\x00\x00org.freedesktop.DBus.Error.NameHasNoOwner\x00" ++ "\x00" ** 6 ++
                "\x05\x01u\x00\x01\x00\x00\x00" ++
                "\x08\x01g\x00\x01s\x00\x00" ++
                "\x0a\x00\x00\x00no systemd\x00",
            .name = "org.freedesktop.DBus.Error.NameHasNoOwner",
            .diagnostic = "org.freedesktop.DBus.Error.NameHasNoOwner: no systemd",
            .unavailable = true,
        },
        .{
            .bytes = "l\x03\x00\x01\x0b\x00\x00\x00\x02\x00\x00\x00\x3f\x00\x00\x00" ++
                "\x04\x01s\x00\x27\x00\x00\x00org.freedesktop.DBus.Error.AccessDenied\x00" ++
                "\x05\x01u\x00\x01\x00\x00\x00" ++
                "\x08\x01g\x00\x01s\x00\x00" ++
                "\x06\x00\x00\x00denied\x00",
            .name = "org.freedesktop.DBus.Error.AccessDenied",
            .diagnostic = "GetNameOwner: org.freedesktop.DBus.Error.AccessDenied: denied",
            .unavailable = false,
        },
    };
    for (cases) |case| {
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0, &fds)) != .SUCCESS)
            return error.SocketFailed;
        defer _ = linux.close(fds[1]);
        var client = Client.init(std.testing.allocator);
        client.fd = fds[0];
        defer client.deinit();
        client.deadline = (try now()) + timeout_ms;
        try std.testing.expectEqual(@as(usize, case.bytes.len), linux.write(fds[1], case.bytes.ptr, case.bytes.len));
        try std.testing.expectError(error.RemoteError, client.callAt(bus_path, bus_interface, bus_interface, "GetNameOwner", &.{.{ .string = manager_destination }}));
        try std.testing.expect(client.isRemote(case.name));
        try std.testing.expect(std.mem.indexOf(u8, client.diagnostic(), case.diagnostic) != null);
        const unavailable = std.mem.indexOf(u8, client.diagnostic(), "systemd cgroup driver requested but systemd is not available") != null;
        try std.testing.expectEqual(case.unavailable, unavailable);
    }
}

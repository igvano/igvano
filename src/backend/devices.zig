// SPDX-License-Identifier: Apache-2.0
// Port of opencontainers/cgroups devices/devices_emulator.go.
// Copyright (C) 2020 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2020 SUSE LLC
const std = @import("std");
pub const Rule = @import("../backend.zig").Backend.Resources.DeviceRule;
pub const Error = std.mem.Allocator.Error || error{ InvalidConfig, CannotPunchHole };

pub fn accessMask(access: []const u8) error{InvalidConfig}!u3 {
    if (access.len == 0) return error.InvalidConfig;
    var result: u3 = 0;
    for (access) |byte| result |= switch (byte) {
        'm' => @as(u3, 1),
        'r' => @as(u3, 2),
        'w' => @as(u3, 4),
        else => return error.InvalidConfig,
    };
    return result;
}

pub fn permissions(mask: u3) []const u8 {
    return ([_][]const u8{ "", "m", "r", "rm", "w", "wm", "rw", "rwm" })[mask];
}

fn number(value: ?i64) error{InvalidConfig}!?i64 {
    const n = value orelse return null;
    if (n == -1) return null;
    if (n < 0 or n > std.math.maxInt(u32)) return error.InvalidConfig;
    return n;
}

pub const Emulator = struct {
    pub const Entry = struct {
        kind: @FieldType(Rule, "kind"),
        major: ?i64,
        minor: ?i64,
        access: u3,

        fn matches(a: Entry, b: Entry) bool {
            return a.kind == b.kind and a.major == b.major and a.minor == b.minor;
        }

        fn lessThan(_: void, a: Entry, b: Entry) bool {
            const am = a.major orelse -1;
            const bm = b.major orelse -1;
            const an = a.minor orelse -1;
            const bn = b.minor orelse -1;
            return am < bm or (am == bm and an < bn) or
                (am == bm and an == bn and a.kind == .block and b.kind == .char);
        }

        fn rule(self: Entry, allow: bool, mask: u3) Rule {
            return .{ .allow = allow, .kind = self.kind, .major = self.major, .minor = self.minor, .access = permissions(mask) };
        }
    };

    default_allow: bool = false,
    entries: std.ArrayList(Entry) = .empty,
    /// Retained on failure so callers can describe the unsupported removal.
    hole: ?struct { requested: Entry, wildcard: Entry } = null,

    pub fn deinit(self: *Emulator, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    pub fn init(allocator: std.mem.Allocator, configured: []const Rule) Error!Emulator {
        var self: Emulator = .{};
        errdefer self.deinit(allocator);
        for (configured) |rule| try self.apply(allocator, rule);
        return self;
    }

    pub fn isAllowAll(self: Emulator) bool {
        return self.default_allow and self.entries.items.len == 0;
    }

    fn access(self: Emulator, entry: Entry) u3 {
        for (self.entries.items) |old| {
            if (old.matches(entry)) return old.access;
        }
        return 0;
    }

    pub fn apply(self: *Emulator, allocator: std.mem.Allocator, configured: Rule) Error!void {
        self.hole = null;
        const entry: Entry = .{
            .kind = configured.kind,
            .major = try number(configured.major),
            .minor = try number(configured.minor),
            .access = try accessMask(configured.access),
        };
        // The kernel treats every 'a' rule as a mode switch, regardless of
        // numbers or permissions, and clears even when the mode is unchanged.
        if (entry.kind == .all) {
            self.default_allow = configured.allow;
            self.entries.clearRetainingCapacity();
            return;
        }
        if (configured.allow != self.default_allow) {
            for (self.entries.items) |*old| {
                if (old.matches(entry)) {
                    old.access |= entry.access;
                    return;
                }
            }
            try self.entries.append(allocator, entry);
            return;
        }
        // runc deliberately rejects removals that v1 would silently ignore.
        for ([_]Entry{
            .{ .kind = entry.kind, .major = null, .minor = entry.minor, .access = 0 },
            .{ .kind = entry.kind, .major = entry.major, .minor = null, .access = 0 },
            .{ .kind = entry.kind, .major = null, .minor = null, .access = 0 },
        }) |partial| {
            if (entry.matches(partial)) continue;
            const mask = self.access(partial);
            if (mask & entry.access != 0) {
                var wildcard = partial;
                wildcard.access = mask;
                self.hole = .{ .requested = entry, .wildcard = wildcard };
                return error.CannotPunchHole;
            }
        }
        // A broader removal does not modify narrower exceptions.
        for (self.entries.items, 0..) |*old, index| {
            if (!old.matches(entry)) continue;
            old.access &= ~entry.access;
            if (old.access == 0) _ = self.entries.orderedRemove(index);
            return;
        }
    }

    /// devices.list hides deny-list exceptions; reconstruct that mode as allow-all.
    pub fn fromList(allocator: std.mem.Allocator, text: []const u8) Error!Emulator {
        var self: Emulator = .{};
        errdefer self.deinit(allocator);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (line.len == 0 and lines.index == null) break;
            var fields = std.mem.tokenizeAny(u8, line, " :");
            const kind = fields.next() orelse return error.InvalidConfig;
            const major = fields.next() orelse return error.InvalidConfig;
            const minor = fields.next() orelse return error.InvalidConfig;
            const perms = fields.next() orelse return error.InvalidConfig;
            if (fields.next() != null) return error.InvalidConfig;
            if (std.mem.eql(u8, kind, "a")) {
                try self.apply(allocator, .{ .allow = true });
                continue;
            }
            const rule: Rule = .{
                .allow = true,
                .kind = if (std.mem.eql(u8, kind, "b")) .block else if (std.mem.eql(u8, kind, "c")) .char else return error.InvalidConfig,
                .major = try parseNumber(major),
                .minor = try parseNumber(minor),
                .access = perms,
            };
            try self.apply(allocator, rule);
        }
        return self;
    }

    fn parseNumber(text: []const u8) error{InvalidConfig}!?i64 {
        if (std.mem.eql(u8, text, "*")) return null;
        return std.fmt.parseInt(u32, text, 10) catch return error.InvalidConfig;
    }

    /// Minimal, deterministic writes; deny-list sources must reset because
    /// devices.list cannot reveal their exceptions.
    pub fn transition(self: Emulator, allocator: std.mem.Allocator, target: Emulator) std.mem.Allocator.Error![]Rule {
        var result: std.ArrayList(Rule) = .empty;
        errdefer result.deinit(allocator);
        const reset = self.default_allow or self.default_allow != target.default_allow;
        if (reset) try result.append(allocator, .{ .allow = target.default_allow });
        const old = if (reset) &.{} else self.entries.items;
        for (old) |entry| {
            const dropped = entry.access & ~target.access(entry);
            if (dropped != 0) try result.append(allocator, entry.rule(target.default_allow, dropped));
        }
        const removed = result.items.len;
        for (target.entries.items) |entry| {
            const gained = entry.access & ~if (reset) @as(u3, 0) else self.access(entry);
            if (gained != 0) try result.append(allocator, entry.rule(!target.default_allow, gained));
        }
        // Sort the removals and additions independently, as in runc.
        const start: usize = if (reset) 1 else 0;
        std.mem.sort(Rule, result.items[start..removed], {}, ruleLessThan);
        std.mem.sort(Rule, result.items[removed..], {}, ruleLessThan);
        return result.toOwnedSlice(allocator);
    }

    fn ruleLessThan(_: void, a: Rule, b: Rule) bool {
        return Entry.lessThan({}, .{ .kind = a.kind, .major = a.major, .minor = a.minor, .access = 0 }, .{ .kind = b.kind, .major = b.major, .minor = b.minor, .access = 0 });
    }

    pub fn rules(self: Emulator, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Rule {
        return (Emulator{}).transition(allocator, self);
    }

    /// A new cgroup inherits its parent's policy. Reset it, then preserve the
    /// effective config order so devices.list exposes the same insertion order.
    pub fn creationRules(self: Emulator, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Rule {
        const result = try allocator.alloc(Rule, self.entries.items.len + 1);
        result[0] = .{ .allow = self.default_allow };
        for (self.entries.items, result[1..]) |entry, *rule|
            rule.* = entry.rule(!self.default_allow, entry.access);
        return result;
    }
};

/// runc devices/v2.go canSkipEBPFError: check the original, unmerged rules.
pub fn canSkipEBPFError(in_user_namespace: bool, rules: []const Rule) bool {
    if (in_user_namespace) return true;
    for (rules) |rule| {
        if (!rule.allow or
            std.mem.indexOfScalar(u8, rule.access, 'r') == null or
            std.mem.indexOfScalar(u8, rule.access, 'w') == null or
            std.mem.indexOfScalar(u8, rule.access, 'm') == null) return false;
    }
    return true;
}

test "runc emulator sorts removals before additions by major minor and type" {
    const allocator = std.testing.allocator;
    var source = try Emulator.fromList(allocator, "c 9:0 rw\nc 1:2 rwm\nb 1:2 rw\n");
    defer source.deinit(allocator);
    var target = try Emulator.fromList(allocator, "b 8:* m\nc 1:2 rm\nb *:* m\n");
    defer target.deinit(allocator);
    const writes = try source.transition(allocator, target);
    defer allocator.free(writes);
    try std.testing.expectEqualDeep(&[_]Rule{
        .{ .allow = false, .kind = .block, .major = 1, .minor = 2, .access = "rw" },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 2, .access = "w" },
        .{ .allow = false, .kind = .char, .major = 9, .minor = 0, .access = "rw" },
        .{ .allow = true, .kind = .block, .access = "m" },
        .{ .allow = true, .kind = .block, .major = 8, .access = "m" },
    }, writes);
    for (writes) |rule| try source.apply(allocator, rule);
    const normalized = try source.rules(allocator);
    defer allocator.free(normalized);
    const expected = try target.rules(allocator);
    defer allocator.free(expected);
    try std.testing.expectEqualDeep(expected, normalized);
}

test "runc emulator releases every partial allocation on build load and transition failure" {
    const AllocationTest = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var current = try Emulator.fromList(allocator, "c 1:3 rwm\nb 8:* rw\n");
            defer current.deinit(allocator);
            var target = try Emulator.init(allocator, &.{
                .{ .allow = false },
                .{ .allow = true, .kind = .char, .major = 1, .minor = 3 },
                .{ .allow = true, .kind = .char, .major = 1, .minor = 5, .access = "r" },
                .{ .allow = true, .kind = .char, .major = 1, .minor = 5, .access = "w" },
            });
            defer target.deinit(allocator);
            const writes = try current.transition(allocator, target);
            defer allocator.free(writes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, AllocationTest.run, .{});
}

test "runc emulator loads modes, wildcard numbers, duplicate and malformed lists" {
    const allocator = std.testing.allocator;
    for ([_]struct { list: []const u8, allow: bool, count: usize }{
        .{ .list = "", .allow = false, .count = 0 },
        .{ .list = "a *:* rwm\n", .allow = true, .count = 0 },
        .{ .list = "c 4:2 rw\nb 0:* m\n", .allow = false, .count = 2 },
        .{ .list = "c *:* rwm\nc 1:1 r\n", .allow = false, .count = 2 },
        .{ .list = "c 4:2 r\nc 4:2 w", .allow = false, .count = 1 },
    }) |case| {
        var emu = try Emulator.fromList(allocator, case.list);
        defer emu.deinit(allocator);
        try std.testing.expectEqual(case.allow, emu.default_allow);
        try std.testing.expectEqual(case.count, emu.entries.items.len);
        if (std.mem.eql(u8, case.list, "c 4:2 r\nc 4:2 w"))
            try std.testing.expectEqual(@as(u3, 6), emu.entries.items[0].access);
    }
    for ([_][]const u8{ "b 1:0", "p *:* rwm", "c -1:3 rwm", "c foo:27 rwm", "b 1:-4 rwm", "b 1:foo rwm", "b 1:7 rwk", "c 4294967296:0 rwm" }) |list|
        try std.testing.expectError(error.InvalidConfig, Emulator.fromList(allocator, list));
}

test "runc emulator applies resets, merges, exact and partial removals in both modes" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |default| {
        var emu: Emulator = .{ .default_allow = default };
        defer emu.deinit(allocator);
        var rule: Rule = .{ .allow = !default, .kind = .char, .major = 42, .minor = 1337, .access = "r" };
        try emu.apply(allocator, rule);
        rule.access = "wm";
        try emu.apply(allocator, rule);
        try std.testing.expectEqual(@as(u3, 7), emu.entries.items[0].access);
        rule.allow = default;
        rule.access = "r";
        try emu.apply(allocator, rule);
        try std.testing.expectEqual(@as(u3, 5), emu.entries.items[0].access);
        rule.minor = null;
        try emu.apply(allocator, rule); // Broad removals leave concrete entries alone.
        try std.testing.expectEqual(@as(u3, 5), emu.entries.items[0].access);
        rule.minor = 1337;
        rule.access = "rwm";
        try emu.apply(allocator, rule);
        try std.testing.expectEqual(@as(usize, 0), emu.entries.items.len);
        try emu.apply(allocator, rule); // Nonexistent removal is a no-op.
        rule.allow = !default;
        try emu.apply(allocator, rule);
        try emu.apply(allocator, .{ .allow = default, .access = "r", .major = 99 });
        try std.testing.expectEqual(default, emu.default_allow);
        try std.testing.expectEqual(@as(usize, 0), emu.entries.items.len);
        try emu.apply(allocator, rule);
        try emu.apply(allocator, .{ .allow = !default });
        try std.testing.expectEqual(!default, emu.default_allow);
        try std.testing.expectEqual(@as(usize, 0), emu.entries.items.len);
    }
}

test "runc emulator rejects only overlapping wildcard holes in both modes" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |default| {
        for ([_]Rule{
            .{ .allow = !default, .kind = .char, .major = 42, .access = "rm" },
            .{ .allow = !default, .kind = .char, .minor = 1337, .access = "rm" },
            .{ .allow = !default, .kind = .char, .access = "rm" },
        }) |wildcard| {
            var emu: Emulator = .{ .default_allow = default };
            defer emu.deinit(allocator);
            try emu.apply(allocator, wildcard);
            const remove: Rule = .{ .allow = default, .kind = .char, .major = 42, .minor = 1337, .access = "r" };
            try std.testing.expectError(error.CannotPunchHole, emu.apply(allocator, remove));
            var disjoint = remove;
            disjoint.access = "w";
            try emu.apply(allocator, disjoint);
            var exact = wildcard;
            exact.allow = default;
            try emu.apply(allocator, exact);
            try std.testing.expectEqual(@as(usize, 0), emu.entries.items.len);
        }
    }
}

test "runc emulator transitions are minimal, sorted and replayable" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |default| {
        for ([_]struct { old: []const u8, new: []const u8, dropped: []const u8, gained: []const u8 }{
            .{ .old = "rw", .new = "rw", .dropped = "", .gained = "" },
            .{ .old = "r", .new = "rwm", .dropped = "", .gained = "wm" },
            .{ .old = "rw", .new = "w", .dropped = "r", .gained = "" },
            .{ .old = "rw", .new = "rm", .dropped = "w", .gained = "m" },
        }) |case| {
            var source: Emulator = .{ .default_allow = default };
            defer source.deinit(allocator);
            var target: Emulator = .{ .default_allow = default };
            defer target.deinit(allocator);
            const old: Rule = .{ .allow = !default, .kind = .char, .major = 1, .minor = 2, .access = case.old };
            var new = old;
            new.access = case.new;
            try source.apply(allocator, old);
            try target.apply(allocator, new);
            const writes = try source.transition(allocator, target);
            defer allocator.free(writes);
            if (default) {
                try std.testing.expectEqual(@as(usize, 2), writes.len);
                try std.testing.expectEqualDeep(Rule{ .allow = true }, writes[0]);
                try std.testing.expectEqualDeep(new, writes[1]);
            } else {
                var expected: std.ArrayList(Rule) = .empty;
                defer expected.deinit(allocator);
                if (case.dropped.len != 0) {
                    var rule = old;
                    rule.allow = default;
                    rule.access = case.dropped;
                    try expected.append(allocator, rule);
                }
                if (case.gained.len != 0) {
                    var rule = new;
                    rule.access = case.gained;
                    try expected.append(allocator, rule);
                }
                try std.testing.expectEqualDeep(expected.items, writes);
            }
            for (writes) |rule| try source.apply(allocator, rule);
            try std.testing.expectEqualDeep(target.entries.items, source.entries.items);
            try target.apply(allocator, .{ .allow = !default });
            try target.apply(allocator, .{ .allow = default, .kind = .block, .major = 42, .access = "wm" });
            const switched = try source.transition(allocator, target);
            defer allocator.free(switched);
            try std.testing.expectEqualDeep(&[_]Rule{
                .{ .allow = !default },
                .{ .allow = default, .kind = .block, .major = 42, .access = "wm" },
            }, switched);
        }
    }
}

test "runc BPF error skipping uses userns or full-access allows without merging" {
    for ([_][]const Rule{
        &.{},
        &.{.{ .allow = true, .kind = .char, .major = 1 }},
        &.{.{ .allow = true, .access = "wmrr" }},
        &.{.{ .allow = true, .access = "rwmx" }}, // isRWM ignores unrelated characters.
    }) |rules| try std.testing.expect(canSkipEBPFError(false, rules));
    for ([_][]const Rule{
        &.{.{ .allow = false }},
        &.{.{ .allow = true, .access = "rw" }},
        &.{ .{ .allow = true, .access = "r" }, .{ .allow = true, .access = "wm" } },
    }) |rules| {
        try std.testing.expect(!canSkipEBPFError(false, rules));
        try std.testing.expect(canSkipEBPFError(true, rules));
    }
}

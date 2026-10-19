const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Backend = @import("../../backend.zig").Backend;
const Resources = Backend.Resources;
const devicefilter = @import("../devicefilter.zig");
const devices_emulator = @import("../devices.zig");
const diagnostics = @import("diagnostic.zig");
const checkResult = @import("syscall.zig").checkResult;
const closeFd = @import("syscall.zig").closeFd;
const reportDiagnostic = @import("diagnostic.zig").reportDiagnostic;

// runc libcontainer/specconv.AllowedDevices; /dev/console (5:1) is not included.
const default_device_rules = [_]Resources.DeviceRule{
    .{ .allow = true, .kind = .char, .access = "m" },
    .{ .allow = true, .kind = .block, .access = "m" },
    .{ .allow = true, .kind = .char, .major = 1, .minor = 3 },
    .{ .allow = true, .kind = .char, .major = 1, .minor = 8 },
    .{ .allow = true, .kind = .char, .major = 1, .minor = 7 },
    .{ .allow = true, .kind = .char, .major = 5, .minor = 0 },
    .{ .allow = true, .kind = .char, .major = 1, .minor = 5 },
    .{ .allow = true, .kind = .char, .major = 1, .minor = 9 },
    .{ .allow = true, .kind = .char, .major = 136 },
    .{ .allow = true, .kind = .char, .major = 5, .minor = 2 },
    .{ .allow = true, .kind = .char, .major = 10, .minor = 200 },
};

/// As on v1, append required device allows after the user's policy.
pub fn v2DeviceRules(allocator: std.mem.Allocator, rules: []const Resources.DeviceRule, devices: []const Backend.Device) Backend.Error![]Resources.DeviceRule {
    var result: std.ArrayList(Resources.DeviceRule) = .empty;
    defer result.deinit(allocator);
    try result.appendSlice(allocator, rules);
    try result.appendSlice(allocator, &default_device_rules);
    for (devices) |device| {
        if (device.kind == .fifo) continue;
        try result.append(allocator, .{
            .allow = true,
            .kind = if (device.kind == .character) .char else .block,
            .major = device.major,
            .minor = device.minor,
        });
    }
    return result.toOwnedSlice(allocator);
}

test "v2 device rules append default and configured allows after explicit denies" {
    const allocator = std.testing.allocator;
    const rules = try v2DeviceRules(allocator, &.{
        .{ .allow = false },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 3 },
        .{ .allow = false, .kind = .block, .major = 8, .minor = 0 },
    }, &.{
        .{ .path = "/dev/custom", .kind = .character, .major = 10, .minor = 237 },
        .{ .path = "/dev/disk", .kind = .block, .major = 8, .minor = 0 },
        .{ .path = "/dev/fifo", .kind = .fifo },
    });
    defer allocator.free(rules);
    const expected: []const Resources.DeviceRule = &.{
        .{ .allow = false },
        .{ .allow = false, .kind = .char, .major = 1, .minor = 3 },
        .{ .allow = false, .kind = .block, .major = 8, .minor = 0 },
        .{ .allow = true, .kind = .char, .access = "m" },
        .{ .allow = true, .kind = .block, .access = "m" },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 3 },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 8 },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 7 },
        .{ .allow = true, .kind = .char, .major = 5, .minor = 0 },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 5 },
        .{ .allow = true, .kind = .char, .major = 1, .minor = 9 },
        .{ .allow = true, .kind = .char, .major = 136 },
        .{ .allow = true, .kind = .char, .major = 5, .minor = 2 },
        .{ .allow = true, .kind = .char, .major = 10, .minor = 200 },
        .{ .allow = true, .kind = .char, .major = 10, .minor = 237 },
        .{ .allow = true, .kind = .block, .major = 8, .minor = 0 },
    };
    try std.testing.expectEqualDeep(expected, @as([]const Resources.DeviceRule, rules));
}

fn deviceBpfError(path: []const u8, operation: []const u8, err: linux.E) Backend.Error {
    reportDiagnostic("cgroup '{s}' cannot enforce v2 devices: {s}(BPF_CGROUP_DEVICE): {s}", .{ path, operation, @tagName(err) });
    return error.CgroupWriteFailed;
}

fn skipDeviceBpfError(rules: []const Resources.DeviceRule, path: []const u8, operation: []const u8, err: linux.E) bool {
    // Match runc's canSkipEBPFError for every load/attach errno: userns always
    // permits skipping, otherwise every original rule must allow full rwm.
    if (!devices_emulator.canSkipEBPFError(runningInUserNamespace(), rules)) return false;
    reportDiagnostic("warning: cgroup '{s}' {s}(BPF_CGROUP_DEVICE): {s}; proceeding without a device filter", .{ path, operation, @tagName(err) });
    return true;
}

pub fn runningInUserNamespace() bool {
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, "/proc/self/ns/user", 0, .{ .INO = true }, &stat)) != .SUCCESS) return false;
    // PROC_USER_INIT_INO remains stable even with /proc/1 in a nested namespace.
    return stat.mask.INO and stat.ino != 0xeffffffd;
}

/// Query only this cgroup's programs, never effective filters inherited from
/// ancestors. Retry if the kernel reports a larger list than our buffer.
pub fn queryDevicePrograms(allocator: std.mem.Allocator, cgroup: posix.fd_t, path: []const u8) Backend.Error![]u32 {
    var ids = try allocator.alloc(u32, 64);
    errdefer allocator.free(ids);
    for (0..10) |_| {
        var attr: linux.BPF.Attr = .{ .query = std.mem.zeroes(linux.BPF.QueryAttr) };
        attr.query.target_fd = cgroup;
        attr.query.attach_type = @intFromEnum(linux.BPF.AttachType.cgroup_device);
        attr.query.prog_ids = @intFromPtr(ids.ptr);
        attr.query.prog_cnt = @intCast(ids.len);
        const err = linux.errno(linux.bpf(.prog_query, &attr, @sizeOf(linux.BPF.QueryAttr)));
        switch (err) {
            .SUCCESS => return allocator.realloc(ids, attr.query.prog_cnt),
            .NOSPC => ids = try allocator.realloc(ids, attr.query.prog_cnt),
            .INTR => continue,
            else => return deviceBpfError(path, "BPF_PROG_QUERY", err),
        }
    }
    reportDiagnostic("cgroup '{s}' cannot query a stable list of BPF_CGROUP_DEVICE programs", .{path});
    return error.CgroupWriteFailed;
}

pub fn applyV2DeviceFilter(allocator: std.mem.Allocator, cgroup: posix.fd_t, rules: []const Resources.DeviceRule, path: []const u8, update: bool) Backend.Error!void {
    var emu = deviceEmulator(allocator, rules) catch |err| {
        if (err == error.InvalidConfig and diagnostics.last_diagnostic_len == 0)
            reportDiagnostic("cgroup '{s}' has invalid v2 device rules", .{path});
        return err;
    };
    defer emu.deinit(allocator);
    const insns = devicefilter.compileEmulator(allocator, emu) catch |err| return switch (err) {
        error.CannotPunchHole => error.InvalidConfig,
        else => |other| other,
    };
    defer allocator.free(insns);
    var log: []u8 = &.{};
    defer allocator.free(log);
    const program = (try loadV2DeviceProgram(allocator, insns, rules, path, &log)) orelse return;
    defer closeFd(program);
    const ids: []const u32 = if (update) try queryDevicePrograms(allocator, cgroup, path) else &.{};
    defer if (update) allocator.free(ids);
    var old: std.ArrayList(posix.fd_t) = .empty;
    defer {
        for (old.items) |fd| closeFd(fd);
        old.deinit(allocator);
    }
    try openDevicePrograms(allocator, ids, path, &old);
    var attach: linux.BPF.Attr = .{ .prog_attach = std.mem.zeroes(linux.BPF.ProgAttachAttr) };
    attach.prog_attach.target_fd = cgroup;
    attach.prog_attach.attach_bpf_fd = program;
    attach.prog_attach.attach_type = @intFromEnum(linux.BPF.AttachType.cgroup_device);
    attach.prog_attach.attach_flags = linux.BPF.F_ALLOW_MULTI;
    const err = linux.errno(linux.bpf(.prog_attach, &attach, @sizeOf(linux.BPF.ProgAttachAttr)));
    if (err != .SUCCESS) {
        if (skipDeviceBpfError(rules, path, "BPF_PROG_ATTACH", err)) return;
        return deviceBpfError(path, "BPF_PROG_ATTACH", err);
    }
    // Keep the new program attached even if detaching an old one fails:
    // stacked device programs are ANDed, so this fails closed.
    for (old.items) |fd| {
        var detach: linux.BPF.Attr = .{ .prog_attach = std.mem.zeroes(linux.BPF.ProgAttachAttr) };
        detach.prog_attach.target_fd = cgroup;
        detach.prog_attach.attach_bpf_fd = fd;
        detach.prog_attach.attach_type = @intFromEnum(linux.BPF.AttachType.cgroup_device);
        const detached = linux.errno(linux.bpf(.prog_detach, &detach, @sizeOf(linux.BPF.ProgAttachAttr)));
        if (detached != .SUCCESS) return deviceBpfError(path, "BPF_PROG_DETACH", detached);
    }
}

fn loadV2DeviceProgram(allocator: std.mem.Allocator, insns: []const devicefilter.Insn, rules: []const Resources.DeviceRule, path: []const u8, log: *[]u8) Backend.Error!?posix.fd_t {
    var load: linux.BPF.Attr = .{ .prog_load = std.mem.zeroes(linux.BPF.ProgLoadAttr) };
    load.prog_load.prog_type = @intFromEnum(linux.BPF.ProgType.cgroup_device);
    load.prog_load.insn_cnt = @intCast(insns.len);
    load.prog_load.insns = @intFromPtr(insns.ptr);
    // Same MODULE_LICENSE string as runc's devicefilter.go.
    load.prog_load.license = @intFromPtr("Apache");
    // Older kernels charge BPF allocations to memlock. Restore both limits
    // immediately after loading so init cannot inherit the temporary increase.
    var original: linux.rlimit = undefined;
    try checkResult(linux.getrlimit(.MEMLOCK, &original));
    const memlock: linux.rlimit = .{ .cur = linux.RLIM.INFINITY, .max = linux.RLIM.INFINITY };
    const raised = linux.errno(linux.setrlimit(.MEMLOCK, &memlock)) == .SUCCESS;
    // A valid large program can overflow a fixed verifier log. Enable logging
    // only for a diagnostic retry after a load with all log fields zero fails.
    var loaded = linux.bpf(.prog_load, &load, @sizeOf(linux.BPF.ProgLoadAttr));
    if (linux.errno(loaded) != .SUCCESS) {
        log.* = allocator.alloc(u8, 64 * 1024) catch |err| {
            if (raised) try checkResult(linux.setrlimit(.MEMLOCK, &original));
            return err;
        };
        @memset(log.*, 0);
        load.prog_load.log_level = 1;
        load.prog_load.log_size = @intCast(log.*.len);
        load.prog_load.log_buf = @intFromPtr(log.*.ptr);
        loaded = linux.bpf(.prog_load, &load, @sizeOf(linux.BPF.ProgLoadAttr));
    }
    if (raised) {
        const restored = linux.errno(linux.setrlimit(.MEMLOCK, &original));
        if (restored != .SUCCESS) {
            if (linux.errno(loaded) == .SUCCESS) closeFd(@intCast(loaded));
            reportDiagnostic("cgroup '{s}' cannot restore RLIMIT_MEMLOCK after BPF_PROG_LOAD: {s}", .{ path, @tagName(restored) });
            return error.CgroupWriteFailed;
        }
    }
    if (linux.errno(loaded) != .SUCCESS) {
        if (skipDeviceBpfError(rules, path, "BPF_PROG_LOAD", linux.errno(loaded))) return null;
        const detail = std.mem.sliceTo(log.*, 0);
        reportDiagnostic("cgroup '{s}' cannot enforce v2 devices: BPF_PROG_LOAD(BPF_CGROUP_DEVICE): {s}; verifier: {s}", .{ path, @tagName(linux.errno(loaded)), detail });
        return error.CgroupWriteFailed;
    }
    return @intCast(loaded);
}

fn openDevicePrograms(allocator: std.mem.Allocator, ids: []const u32, path: []const u8, old: *std.ArrayList(posix.fd_t)) Backend.Error!void {
    for (ids) |id| {
        var attr: linux.BPF.Attr = .{ .get_id = std.mem.zeroes(linux.BPF.GetIdAttr) };
        attr.get_id.id.prog_id = id;
        const fd = linux.bpf(.prog_get_fd_by_id, &attr, @sizeOf(linux.BPF.GetIdAttr));
        switch (linux.errno(fd)) {
            .SUCCESS => {
                const owned: posix.fd_t = @intCast(fd);
                errdefer closeFd(owned);
                try old.append(allocator, owned);
            },
            // Like runc, leave LSM-protected programs alone. Other attached
            // programs can only restrict our new policy further.
            .ACCES, .PERM => continue,
            else => |err| return deviceBpfError(path, "BPF_PROG_GET_FD_BY_ID", err),
        }
    }
}

fn applyDeviceRule(allocator: std.mem.Allocator, emu: *devices_emulator.Emulator, rule: Resources.DeviceRule) Backend.Error!void {
    emu.apply(allocator, rule) catch |err| {
        if (emu.hole) |hole| {
            const requested = hole.requested;
            const wildcard = hole.wildcard;
            const kind: u8 = if (requested.kind == .char) 'c' else 'b';
            reportDiagnostic("unable to remove '{s}' exception: requested rule [{{{d} {d} {d}}} {s}] not supported by devices cgroupv1 (cannot punch hole in existing wildcard rule [{{{d} {d} {d}}} {s}])", .{
                if (emu.default_allow) "deny" else "allow",
                kind,
                requested.major orelse -1,
                requested.minor orelse -1,
                devices_emulator.permissions(requested.access),
                kind,
                wildcard.major orelse -1,
                wildcard.minor orelse -1,
                devices_emulator.permissions(wildcard.access),
            });
            return error.InvalidConfig;
        }
        return switch (err) {
            error.CannotPunchHole => error.InvalidConfig,
            else => |other| other,
        };
    };
}

pub fn deviceEmulator(allocator: std.mem.Allocator, rules: []const Resources.DeviceRule) Backend.Error!devices_emulator.Emulator {
    var emu: devices_emulator.Emulator = .{};
    errdefer emu.deinit(allocator);
    for (rules) |rule| try applyDeviceRule(allocator, &emu, rule);
    return emu;
}

pub fn deviceEmulatorFromList(allocator: std.mem.Allocator, list: []const u8) Backend.Error!devices_emulator.Emulator {
    return devices_emulator.Emulator.fromList(allocator, list) catch |err| switch (err) {
        error.CannotPunchHole => error.InvalidConfig,
        else => |other| other,
    };
}

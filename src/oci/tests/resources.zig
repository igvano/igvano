const std = @import("std");
const Backend = @import("../../backend.zig").Backend;
const Spec = @import("../spec.zig").Spec;
const cgroupResources = @import("../resources.zig").cgroupResources;
const freeCgroupResources = @import("../resources.zig").freeCgroupResources;

test "OCI resources parse every supported resource field" {
    const parsed = try std.json.parseFromSlice(Spec.Resources, std.testing.allocator,
        \\{"memory":{"limit":64,"reservation":32,"swap":128,"kernel":-1,"kernelTCP":16,"swappiness":50,"disableOOMKiller":false},
        \\"cpu":{"shares":1024,"quota":50000,"period":100000,"realtimeRuntime":-1,"realtimePeriod":1000000,"cpus":"0-2","mems":"0"},
        \\"pids":{"limit":32},
        \\"blockIO":{"weight":100,"leafWeight":200,"weightDevice":[{"major":8,"minor":0,"weight":300,"leafWeight":400}],
        \\"throttleReadBpsDevice":[{"major":8,"minor":0,"rate":1000}],"throttleWriteBpsDevice":[{"major":8,"minor":1,"rate":2000}],
        \\"throttleReadIOPSDevice":[{"major":8,"minor":2,"rate":30}],"throttleWriteIOPSDevice":[{"major":8,"minor":3,"rate":40}]},
        \\"hugepageLimits":[{"pageSize":"2MB","limit":4194304}],
        \\"network":{"classID":123,"priorities":[{"name":"eth0","priority":7}]},
        \\"devices":[{"allow":false},{"allow":true,"type":"c","major":1,"minor":3,"access":"rw"}],
        \\"unified":{"memory.high":"48","cpu.max":"max 200000"}}
    , .{});
    defer parsed.deinit();
    const resources = try cgroupResources(std.testing.allocator, parsed.value);
    defer freeCgroupResources(std.testing.allocator, resources);
    try std.testing.expectEqualDeep(Backend.Resources.Memory{
        .limit = 64,
        .reservation = 32,
        .swap = 128,
        .kernel = -1,
        .kernel_tcp = 16,
        .swappiness = 50,
        .disable_oom_killer = false,
    }, resources.memory.?);
    try std.testing.expectEqualDeep(Backend.Resources.Cpu{
        .shares = 1024,
        .quota = 50000,
        .period = 100000,
        .realtime_runtime = -1,
        .realtime_period = 1000000,
        .cpus = "0-2",
        .mems = "0",
    }, resources.cpu.?);
    try std.testing.expectEqual(@as(?i64, 32), resources.pids.?.limit);
    const block = resources.block_io.?;
    try std.testing.expectEqual(@as(?u16, 100), block.weight);
    try std.testing.expectEqual(@as(?u16, 200), block.leaf_weight);
    try std.testing.expectEqualDeep(Backend.Resources.WeightDevice{
        .major = 8,
        .minor = 0,
        .weight = 300,
        .leaf_weight = 400,
    }, block.weight_device[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 0, .rate = 1000 }, block.throttle_read_bps[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 1, .rate = 2000 }, block.throttle_write_bps[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 2, .rate = 30 }, block.throttle_read_iops[0]);
    try std.testing.expectEqualDeep(Backend.Resources.ThrottleDevice{ .major = 8, .minor = 3, .rate = 40 }, block.throttle_write_iops[0]);
    try std.testing.expectEqualDeep(Backend.Resources.HugepageLimit{ .page_size = "2MB", .limit = 4194304 }, resources.hugepage_limits[0]);
    try std.testing.expectEqual(@as(?u32, 123), resources.network.?.class_id);
    try std.testing.expectEqualDeep(Backend.Resources.Priority{ .name = "eth0", .priority = 7 }, resources.network.?.priorities[0]);
    try std.testing.expectEqualDeep(Backend.Resources.DeviceRule{ .allow = false }, resources.devices[0]);
    try std.testing.expectEqualDeep(Backend.Resources.DeviceRule{
        .allow = true,
        .kind = .char,
        .major = 1,
        .minor = 3,
        .access = "rw",
    }, resources.devices[1]);
    try std.testing.expectEqualDeep(Backend.Resources.Unified{ .key = "memory.high", .value = "48" }, resources.unified[0]);
    try std.testing.expectEqualDeep(Backend.Resources.Unified{ .key = "cpu.max", .value = "max 200000" }, resources.unified[1]);
}

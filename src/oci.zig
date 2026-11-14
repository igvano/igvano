pub const clearDiagnostic = @import("oci/diagnostic.zig").clearDiagnostic;
pub const diagnostic = @import("oci/diagnostic.zig").diagnostic;
pub const diagnosticFor = @import("oci/diagnostic.zig").diagnosticFor;
pub const validationError = @import("oci/diagnostic.zig").validationError;
pub const recordDiagnostic = @import("oci/diagnostic.zig").recordDiagnostic;
pub const invalidConfig = @import("oci/diagnostic.zig").invalidConfig;
pub const diagnosticContext = @import("oci/diagnostic.zig").diagnosticContext;

pub const runtime_oci_version = @import("oci/spec.zig").runtime_oci_version;
pub const oci_version_min = @import("oci/spec.zig").oci_version_min;
pub const oci_version_max = @import("oci/spec.zig").oci_version_max;
pub const Spec = @import("oci/spec.zig").Spec;
pub const json_size_limit = @import("oci/spec.zig").json_size_limit;
pub const loadSpec = @import("oci/spec.zig").loadSpec;
pub const resolveRootfs = @import("oci/spec.zig").resolveRootfs;

pub const state_file_name = @import("oci/state.zig").state_file_name;
pub const lock_file_name = @import("oci/state.zig").lock_file_name;
pub const exec_fifo_name = @import("oci/state.zig").exec_fifo_name;
pub const starttime_file_name = @import("oci/state.zig").starttime_file_name;
pub const process_file_name = @import("oci/state.zig").process_file_name;
pub const cgroup_file_name = @import("oci/state.zig").cgroup_file_name;
pub const cgroup_driver_file_name = @import("oci/state.zig").cgroup_driver_file_name;
pub const rootfs_mount_file_name = @import("oci/state.zig").rootfs_mount_file_name;
pub const hooks_file_name = @import("oci/state.zig").hooks_file_name;
pub const Status = @import("oci/state.zig").Status;
pub const requireStart = @import("oci/state.zig").requireStart;
pub const requireKill = @import("oci/state.zig").requireKill;
pub const requireUpdate = @import("oci/state.zig").requireUpdate;
pub const requirePause = @import("oci/state.zig").requirePause;
pub const requireResume = @import("oci/state.zig").requireResume;
pub const requireDelete = @import("oci/state.zig").requireDelete;
pub const State = @import("oci/state.zig").State;
pub const stateJson = @import("oci/state.zig").stateJson;
pub const atomicWrite = @import("oci/state.zig").atomicWrite;
pub const saveState = @import("oci/state.zig").saveState;
pub const loadState = @import("oci/state.zig").loadState;

pub const requireCreate = @import("oci/validate.zig").requireCreate;
pub const validateEnv = @import("oci/validate.zig").validateEnv;
pub const validateProcess = @import("oci/validate.zig").validateProcess;

pub const resolveCgroupPath = @import("oci/resources.zig").resolveCgroupPath;
pub const cgroupResources = @import("oci/resources.zig").cgroupResources;
pub const freeCgroupResources = @import("oci/resources.zig").freeCgroupResources;
pub const loadResources = @import("oci/resources.zig").loadResources;

pub const rootfsPropagation = @import("oci/mounts.zig").rootfsPropagation;
pub const MountOptions = @import("oci/mounts.zig").MountOptions;
pub const mount_option_table = @import("oci/mounts.zig").mount_option_table;
pub const parseMountOptions = @import("oci/mounts.zig").parseMountOptions;
pub const validateMountDestination = @import("oci/mounts.zig").validateMountDestination;
pub const resolveMountDestination = @import("oci/mounts.zig").resolveMountDestination;
pub const resolveContainerMountDestination = @import("oci/mounts.zig").resolveContainerMountDestination;
pub const validateIDMappings = @import("oci/mounts.zig").validateIDMappings;
pub const mountMappings = @import("oci/mounts.zig").mountMappings;
pub const containerIDMappings = @import("oci/mounts.zig").containerIDMappings;

pub const capability_names = @import("oci/process.zig").capability_names;
pub const capabilityNumber = @import("oci/process.zig").capabilityNumber;
pub const rlimitResource = @import("oci/process.zig").rlimitResource;
pub const processCapabilities = @import("oci/process.zig").processCapabilities;
pub const processRlimits = @import("oci/process.zig").processRlimits;
pub const cpuAffinity = @import("oci/process.zig").cpuAffinity;
pub const processScheduler = @import("oci/process.zig").processScheduler;
pub const processIOPriority = @import("oci/process.zig").processIOPriority;
pub const processConfig = @import("oci/process.zig").processConfig;

pub const prepareSeccomp = @import("oci/seccomp.zig").prepareSeccomp;
pub const seccompNotifies = @import("oci/seccomp.zig").seccompNotifies;
pub const freeSeccomp = @import("oci/seccomp.zig").freeSeccomp;

pub const SystemdCgroup = @import("oci/systemd.zig").SystemdCgroup;
pub const expandSystemdSlice = @import("oci/systemd.zig").expandSystemdSlice;
pub const parseSystemdCgroupPath = @import("oci/systemd.zig").parseSystemdCgroupPath;

pub const featuresJson = @import("oci/features.zig").featuresJson;

pub const validateHooks = @import("oci/hooks.zig").validateHooks;
pub const prepareHooks = @import("oci/hooks.zig").prepareHooks;

pub const validateSysctls = @import("oci/sysctl.zig").validateSysctls;
pub const prepareSysctls = @import("oci/sysctl.zig").prepareSysctls;

pub const prepareDevices = @import("oci/devices.zig").prepareDevices;
pub const freeDevices = @import("oci/devices.zig").freeDevices;
pub const deviceSymlinks = @import("oci/devices.zig").deviceSymlinks;

comptime {
    if (@import("builtin").is_test) {
        _ = @import("oci/diagnostic.zig");
        _ = @import("oci/spec.zig");
        _ = @import("oci/state.zig");
        _ = @import("oci/validate.zig");
        _ = @import("oci/resources.zig");
        _ = @import("oci/mounts.zig");
        _ = @import("oci/process.zig");
        _ = @import("oci/seccomp.zig");
        _ = @import("oci/systemd.zig");
        _ = @import("oci/features.zig");
        _ = @import("oci/hooks.zig");
        _ = @import("oci/sysctl.zig");
        _ = @import("oci/devices.zig");
        _ = @import("oci/tests/resources.zig");
        _ = @import("oci/tests/seccomp.zig");
        _ = @import("oci/tests/spec.zig");
    }
}

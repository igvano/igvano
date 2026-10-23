ARG KIND_NODE_IMAGE=kindest/node:v1.34.0
FROM ${KIND_NODE_IMAGE} AS base

COPY igvano /usr/local/bin/igvano
RUN printf '%s\n' \
    '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.igvano]' \
    '  runtime_type = "io.containerd.runc.v2"' \
    '  base_runtime_spec = "/etc/containerd/cri-base.json"' \
    '  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.igvano.options]' \
    '    BinaryName = "/usr/local/bin/igvano"' \
    '    SystemdCgroup = true' >> /etc/containerd/config.toml

# Match kubelet's cgroupfs driver for every runtime, including kind's runc.
FROM base AS cgroupfs
RUN sed -i '/SystemdCgroup[[:space:]]*=[[:space:]]*true/d' /etc/containerd/config.toml

# Default target. kind has no D-Bus; igvano uses /run/systemd/private.
FROM base AS systemd

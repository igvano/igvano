# Using it with containerd

igvano runs under the stock `containerd-shim-runc-v2`; no shim of its own:

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.igvano]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.igvano.options]
    BinaryName = "/usr/local/bin/igvano"
    # SystemdCgroup = true   # optional
```

`ctr run --runc-binary /usr/local/bin/igvano ...` and
`nerdctl run --runtime /usr/local/bin/igvano ...` work too.

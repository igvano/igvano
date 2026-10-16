`docker-default.json` is trimmed from
https://github.com/moby/profiles/blob/main/seccomp/default.json (retrieved 2026-10-16).
The upstream profile is licensed under Apache-2.0.

The fixture retains the base allowlist, argument conditions, clone3 errno,
CAP_SYS_CHROOT rule, and x86/Arm architecture rules (377 distinct syscall names).
Docker-specific capability and architecture selectors have been resolved for
these four ABIs, and the arch map is expressed as OCI `architectures`. Rules
requiring additional capabilities and other ABIs are omitted.

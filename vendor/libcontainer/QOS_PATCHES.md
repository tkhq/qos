# QOS libcontainer patches

This is `libcontainer` 0.6.0 from crates.io, vendored because upstream forces
the systemd cgroup manager for every user-namespace container even when its
library caller explicitly selects `with_systemd(false)`.

QOS runs as PID 1/root in a systemd-free enclave. It can create the container
cgroup before entering the requested user namespace, so the explicit cgroupfs
selection is both sufficient and required. The local patch in
`src/container/builder_impl.rs` makes cgroup creation and cleanup honor that
selection.

The init process also sends the debug representation of errors to its parent.
Several upstream display strings omit the source error, making otherwise
actionable enclave boot failures appear only as `failed syscall`.

QOS selects libcontainer's public `with_no_pivot(true)` mode because the
enclave host root is an initramfs, from which Linux rejects `pivot_root(2)`.
The replacement path moves the prepared root mount and enters it with chroot
inside the container's dedicated mount namespace.

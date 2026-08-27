# OCI Image Boot

QOS can boot a manifest-approved Linux OCI image as the enclave workload. The
signed manifest contains the image-manifest digest and an optional OCI Runtime
Spec. QOS verifies the supplied OCI image layout, materializes its layers in
RAM, and delegates container lifecycle and isolation to
[`libcontainer`](https://docs.rs/libcontainer/latest/libcontainer/).

The image digest in the signed QOS manifest is the trust anchor. Image bytes are
untrusted until QOS has verified the manifest, configuration, layer descriptor
graph, compressed blob digests, and uncompressed layer diff IDs.

## Runtime model

The enclave init process mounts procfs, sysfs, cgroup v2, devtmpfs, devpts, and
the RAM-backed runtime filesystems required by containers. OCI content, bundles,
runtime state, and writable container filesystems live below `/run/qos/oci`.

After quorum provisioning, QOS:

1. Re-verifies the stored image descriptor graph.
2. Applies the image layers to a fresh RAM-backed rootfs.
3. Creates the built-in and image-declared mount points.
4. Materializes the QOS key and manifest files in the rootfs.
5. Produces an OCI runtime bundle and `config.json`.
6. Uses `libcontainer` to create, start, wait for, and delete the container.
7. Applies the manifest restart policy to the resulting exit status.

The enclave boots from initramfs, from which Linux rejects `pivot_root(2)`.
QOS therefore selects libcontainer's mount-move plus chroot transition inside
the container's dedicated mount namespace. Container roots remain isolated by
the namespace; QOS does not use the old hand-written process launcher.

QOS is systemd-free. Its vendored libcontainer patch honors
`with_systemd(false)` for user-namespace containers and uses the cgroupfs
manager. The patch is documented in
`vendor/libcontainer/QOS_PATCHES.md`.

## Manifest configuration

An OCI workload uses `pivot.type = "ociImage"`:

```json
{
  "type": "ociImage",
  "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "platform": {
    "os": "linux",
    "architecture": "amd64"
  },
  "restart": "never",
  "args": null,
  "env": {},
  "debugMode": false,
  "bridgeConfig": [],
  "limits": {
    "maxCompressedBytes": "268435456",
    "maxUnpackedBytes": "1073741824",
    "maxEntries": "200000"
  },
  "runtime": null
}
```

`args`, when present, is the exact process argv. Otherwise QOS uses the image
`Entrypoint` followed by `Cmd`. Manifest environment values override image
environment values by name.

`runtime` accepts an OCI Runtime Spec. QOS preserves approved namespaces,
mounts, capabilities, cgroup resources, hooks, hostname, root propagation,
masked paths, read-only paths, scheduler settings, and other libcontainer
fields. QOS replaces the bundle root path and writes the final process argv,
environment, and working directory derived from the approved configuration.

When a runtime spec is supplied, its process fields are intentional inputs:
runtime process args and working directory take precedence unless the manifest
provides `pivot.args`; runtime environment is merged before manifest
environment. Because `Spec::default()` contains a default `sh` process, callers
constructing a runtime spec should set its process fields explicitly.

Seccomp profiles are rejected because the statically linked enclave runtime is
built without libseccomp. AppArmor, SELinux, systemd, host device injection, and
container registry credentials are not provided by the enclave image.

## Rootless containers

OCI user namespaces and UID/GID mappings are supported through libcontainer.
The layer materializer preserves numeric tar ownership on Linux, without
following final symlinks, so image-owned writable directories remain usable
after a rootless mapping.

QOS resolves image `Config.User` values in these forms:

- numeric UID;
- numeric `UID:GID`;
- user name;
- `user:group`.

Named users and groups are resolved from the materialized `/etc/passwd` and
`/etc/group`. A supplied runtime spec can define the process user and Linux ID
mappings directly.

The default image-derived runtime runs in the enclave's network namespace so
loopback and QOS VSOCK/TCP bridges remain available. An approved runtime spec
may request a separate network namespace. Rootless BuildKit uses a user, mount,
PID, IPC, UTS, and cgroup namespace, the native snapshotter, and the OCI worker
without a process sandbox.

## Image transport and verification

Boot and key-forward image requests carry an uncompressed tar archive containing
an OCI image layout:

```text
oci-layout
index.json
blobs/
  sha256/
    <digest>
```

QOS resolves exactly the image-manifest digest in the signed manifest. Tags and
additional images in the archive have no authority. QOS does not pull from a
registry.

Supported image inputs are:

- Linux `amd64` OCI image manifests;
- OCI image configuration;
- uncompressed OCI tar layers;
- gzip-compressed OCI tar layers;
- regular files, directories, symbolic links, and hard links;
- OCI whiteouts and opaque-directory whiteouts;
- image `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, `Volumes`, and
  `ExposedPorts`.

Archive and layer processing rejects:

- absolute archive entry paths or paths containing traversal;
- symlinks that resolve above the container root;
- sparse files;
- device nodes, FIFOs, and sockets;
- setuid and setgid bits;
- PAX xattrs and unsupported PAX metadata;
- unsupported descriptor algorithms or media types;
- missing, malformed, oversized, or digest-mismatched blobs.

Container-rooted absolute symlinks such as `/lib/libc.so.6` are valid. Relative
symlinks may use `..` when lexical resolution from the link's parent remains
inside the container root.

The manifest limits compressed bytes, total unpacked regular-file bytes, and
entry count. Content and writable state are volatile and disappear when the
enclave shuts down.

## Filesystem and mounts

The runtime directory layout is:

```text
/run/qos/oci/
  content/blobs/sha256/
  bundles/<image-manifest-digest>/
    rootfs/
    config.json
  runtime/
```

QOS supplies `/proc`, `/dev`, `/dev/pts`, `/dev/shm`, `/sys`, and
`/sys/fs/cgroup` through the OCI runtime spec. `/tmp`, `/run`, `/dev/shm`, and
image volume targets are RAM-backed. An approved runtime spec can replace or add
OCI mounts, subject to QOS validation of critical paths.

The following QOS-managed files are materialized read-only inside the container
after provisioning:

- `/qos.quorum.key`
- `/qos.ephemeral.key`
- `/qos.manifest`

The image and its approved runtime configuration are trusted workload code.
These files intentionally remain available to that workload, matching the
existing QOS application trust model.

## Networking and lifecycle

The default OCI container shares the enclave network namespace. QOS bridge
rules continue to expose approved VSOCK/TCP connections to the workload.
OCI `ExposedPorts` is authenticated image metadata but does not create a bridge,
listener, NAT rule, or firewall rule by itself.

`debugMode` keeps workload stdin/stdout/stderr attached to enclave logs. Without
debug mode, standard streams are connected to `/dev/null`.

QOS records the workload state, exit status, and launch error. Any failure in
manifest approval, image verification, unpacking, bundle creation, container
creation, or process execution fails closed.

## End-to-end verification

The QEMU test builds a pinned StageX fixture containing rootless BuildKit, boots
the actual StageX Nitro kernel and QOS initramfs, imports the OCI layout through
the production verifier, starts it through libcontainer, and asks BuildKit to
build and execute a simple StageX package:

```sh
make test-qemu-stagex-buildkit
```

Success requires both serial-console markers:

```text
QOS_STAGEX_PACKAGE_BUILT_OK
QOS_STAGEX_BUILDKIT_E2E_OK
```

The fixture and QEMU artifact builder use digest-pinned StageX and BuildKit
images. Generated kernel, initramfs, OCI archive, and serial log artifacts are
written under `target/qemu-stagex-buildkit-e2e/`.

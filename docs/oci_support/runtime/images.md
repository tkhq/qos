# OCI Images

Status: Initial normative specification

Each OCI workload identifies one approved OCI image manifest with an image
reference of `type: "ociManifest"` and a digest.

The digest is the image trust anchor. An image name, repository, registry, and
tag are not trust anchors.

## Accepted image shape

The initial runtime MUST accept a platform-specific OCI image manifest.

The image manifest MUST identify one OCI image configuration and all image
layers.

The image manifest MUST use schema version 2 and media type
`application/vnd.oci.image.manifest.v1+json`.

The image configuration MUST use media type
`application/vnd.oci.image.config.v1+json`.

The initial runtime does not have to accept an OCI image index.

The initial runtime MUST support Linux images for the enclave architecture.

QOS MUST reject an unsupported operating system, architecture, image media
type, configuration media type, or layer media type.

The initial runtime MUST support these OCI layer media types:

- `application/vnd.oci.image.layer.v1.tar`;
- `application/vnd.oci.image.layer.v1.tar+gzip`;
- `application/vnd.oci.image.layer.v1.tar+zstd`.

QOS MUST reject another manifest, configuration, or layer media type.

## Digest verification

QOS MUST verify the image manifest digest against Manifest V3.

QOS MUST verify the image configuration digest and size.

QOS MUST verify every layer digest and size.

The image configuration MUST contain `rootfs.type` equal to `layers`.

The image configuration MUST contain exactly one `rootfs.diff_ids` entry for
each layer in the image manifest, in the same order.

QOS MUST verify every DiffID against the uncompressed tar bytes of its layer.

QOS MUST verify that the image configuration selects Linux and the enclave
architecture.

QOS MUST fail before workload start when required content is missing or
invalid.

## Layer application

QOS MUST apply layers in image order.

QOS MUST implement OCI whiteouts, including opaque directory whiteouts.

QOS MUST reject a layer entry that escapes the workload root file system.

QOS MUST support regular files, directories, symbolic links, hard links, and
FIFOs in an OCI layer.

QOS MUST support safe absolute and relative symbolic-link targets. It MUST
interpret an absolute target relative to the container root, not the parent
QOS root. It MUST NOT follow a symbolic link while writing a later layer entry.

A hard-link target MUST resolve to an existing non-directory entry inside the
workload root file system. QOS MUST reject a symbolic link, hard link, or link
target that can escape that root file system.

QOS MUST reject duplicate paths in one layer.

QOS MUST process a whiteout as an OCI removal instruction. It MUST NOT create
the whiteout marker in the resulting root file system.

QOS MUST NOT use an image-provided device node or socket. Runtime devices come
only from the QOS-generated runtime configuration.

QOS MUST preserve numeric UID, numeric GID, permission mode, and modification
time. It MUST ignore tar user and group names.

The initial runtime MUST preserve `user.*` extended attributes,
`security.capability`, and POSIX access and default ACL attributes when they are
present. It MUST ignore SELinux, IMA, and EVM labels because those labels belong
to another runtime environment. It MUST reject another `security.*` or
`trusted.*` attribute.

QOS MUST reject an entry when its required ownership, mode, link, capability,
or ACL metadata cannot be represented. QOS MUST reject metadata that would
refer to a parent QOS path or external resource.

QOS MUST apply internal limits to archive entries, paths, expanded bytes, and
compression ratios. These safety limits do not have to be manifest fields.

## Root file system

QOS MUST create a separate root file system from the verified layers for each
workload.

One workload MUST NOT share a writable root file system with another
workload.

The initial root file system MUST be writable and volatile.

QOS MUST create a fresh writable root file system from the verified image for
the initial start and for every workload restart. Changes made to the writable
root file system during one run MUST NOT appear in the next run.

QOS MUST retain verified image content or an immutable prepared image snapshot
inside the enclave for as long as a workload can restart. A restart MUST NOT
request replacement image bytes from the host.

Top-level volumes have a separate lifecycle. Their contents MUST survive an
individual workload restart and remain available until QOS removes the volume
during node shutdown.

QOS MUST create runtime device nodes. QOS MUST NOT trust device nodes from an
image layer.

QOS MUST mount `/proc`, a read-only `/sys`, and a runtime-owned `/dev`.

All OCI workloads MUST receive the same runtime-owned `/dev/shm` mount so they
can use Pod-style POSIX shared memory. `/tmp` and `/run` remain part of each
workload's writable root file system unless the workload has a declared mount
below one of those paths.

## Image configuration

QOS MUST use the verified OCI image configuration as the source of process
defaults.

The process conversion rules are in [Processes](processes.md).

Image fields that request host mounts, devices, runtime hooks, namespace
sharing, security profiles, or QOS policy MUST NOT change the fixed QOS
container policy.

OCI image `Volumes` entries MUST NOT create a top-level volume or grant access
to one. OCI image `ExposedPorts` entries are informational in the initial
loopback-only network policy.

QOS MUST ignore an OCI image-configuration field that this specification does
not use. An unknown image field MUST NOT change QOS runtime policy. This rule
does not apply to unknown Manifest V3 fields, which QOS rejects.

# User Namespaces

Status: Future normative addendum

This document defines planned UID and GID defense-in-depth separation for OCI
workloads. It is not part of the initial `min-oci-support` conformance
requirements.

The initial feature honors the OCI image `User` value inside each container. It does not require a Linux user namespace. This future extension adds a separate parent identity range for each workload while preserving the container-visible identities from the image.

This extension does not create a security boundary. The deployer MUST continue
to trust every workload in the manifest. Separate users, groups, mappings, and
user namespaces MUST NOT be used to justify placing mutually untrusted
software in one enclave.

An escape from one of these internal identity restrictions that remains within
the shared enclave Linux kernel is a hardening defect, not a violation of the
QOS security model. QOS welcomes reports of these defects.

## Manifest compatibility

Manifest V3 does not need UID maps, GID maps, parent IDs, or a `userns` switch in its initial workload schema.

UID and GID values in OCI image metadata are container-relative IDs. QOS
chooses parent UID and GID mappings. Host-specific mapping values MUST NOT be
signed into the manifest.

If a later policy needs an author-controlled identity setting, it MUST be an
optional workload hardening field. When that field is absent, the defined
default behavior MUST remain valid.

## Separation model

A conforming implementation of this extension MUST:

- create a distinct user namespace for each OCI workload or for an explicitly defined workload sandbox;
- map container UID 0 to an unprivileged parent UID;
- map enough IDs to run normal OCI images, with at least container IDs 0 through 65535 as the design target;
- prevent the mapped range from including a QOS supervisor identity;
- use non-overlapping parent ranges for workloads when the platform permits it;
- apply the same mapping to every process in one workload.

QOS MUST reject an image when its required UID or GID cannot be represented by the selected mapping. It MUST NOT change the image user to make the image run.

The user namespace is an added defense-in-depth layer. It does not replace
mount, PID, IPC, UTS, or network namespaces, and none of these namespaces is a
QOS trust boundary between manifest-approved workloads.

## Root filesystems and volumes

The workload root filesystem and every writable mount MUST present ownership that is valid inside the workload user namespace.

Idmapped mounts are the preferred mechanism when the kernel, file system, and runtime support them. They allow the same underlying files to appear with workload-relative ownership without a recursive `chown`.

If idmapped mounts are not available, an implementation MUST define another safe ownership mechanism. It MUST account for shared volumes, startup cost, crashes during ownership changes, and conflicts between workloads. A recursive `chown` is not an acceptable implicit fallback for a shared persistent volume.

Each supported volume type and file system MUST state whether it supports the selected identity mechanism. QOS MUST reject an incompatible workload and volume combination.

A later extension MAY add group-based shared-volume policy, similar to a volume group setting. Such a field MUST be optional and MUST have precise ownership and permission rules. It is not part of this extension's initial manifest shape.

## Parent QOS file mounts

QOS MUST map or idmap a parent-QOS file mount so that its source ownership is
valid inside the workload. The manifest MUST NOT contain a parent UID or GID.
If a later file-mount extension adds an owner, that owner MUST be
container-relative.

## Runtime requirements

The libcontainer integration MUST configure the user namespace and its UID and GID mappings before it starts the workload process. It MUST configure rootfs and volume mounts with compatible ownership semantics.

Support for Linux user-namespace mappings alone is not enough. The complete implementation MUST also support the selected idmapped-mount or ownership mechanism. Until the complete path exists, QOS MUST NOT claim conformance with this extension.

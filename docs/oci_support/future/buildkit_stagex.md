# BuildKit and StageX

Status: Future normative addendum

This document describes requirements for building OCI images inside an enclave. It is not part of the initial `min-oci-support` conformance requirements.

The initial OCI runtime design MUST NOT block this extension. The extension stays in Manifest V3 and uses a named workload.

## Builder workload

A builder is an approved OCI image with a distinct builder workload type or an optional builder configuration. A later specification MUST select one form and define its exact manifest fields.

The manifest MUST identify the builder image by digest. It MUST also identify or constrain all build inputs that affect the result. QOS MUST report the output image manifest digest and the approved build inputs in an attestable result.

Building an image MUST NOT automatically authorize QOS to run that image as a production workload. Runtime authorization remains a separate manifest decision.

The host MUST provide the build context and other external build inputs over a
bounded QOS control message. The manifest or another approved statement MUST
bind each input digest. The enclave MUST verify every bound digest before the
builder uses the input.

QOS MUST NOT expose a host Docker socket or another host container-runtime
socket to the builder.

## Isolation

The builder SHOULD run rootless inside its container. The implementation MUST define its user namespace, mount namespace, process namespace, capability, seccomp, and resource policies.

Build steps MUST remain inside the builder runtime environment. If BuildKit
starts nested build-step containers, the implementation MUST define how it
creates and cleans their namespaces, processes, mounts, and cgroups.

Builder containers and nested build-step containers are defense in depth. They
do not permit QOS to build mutually untrusted software in one enclave under an
adversarial container-isolation claim.

Builder permissions MUST NOT become the default permissions for ordinary OCI workloads. In particular, ordinary workloads MUST NOT receive broad mount capabilities, host device access, or `/dev/fuse` because a builder MAY need them.

## Storage and snapshotters

Builder state and cache MUST use named top-level volumes and workload `mounts`
entries with `type: "volume"`. A manifest MAY select volatile or persistent
cache only after the related top-level volume type is defined.

The implementation MUST define which BuildKit snapshotters it supports. Possible choices include a native snapshotter, overlayfs, and fuse-overlayfs. Each choice MUST state its kernel, mount, device, and user-namespace requirements.

If a builder uses FUSE, QOS MUST expose `/dev/fuse` only to that builder. QOS MUST constrain the FUSE daemon and its mount namespace. FUSE support for a builder does not add a general FUSE volume type.

The builder MUST export its result as a verified OCI image layout. QOS MUST
calculate and report the output image-manifest digest. The host MAY receive the
layout after QOS has calculated the digest.

## Network and secrets

Builder network access MUST be explicit. The specification MUST define whether a build has no network, limited network, or approved proxy access. It MUST NOT inherit an unrestricted host network path.

Build secrets MUST use an explicit protected parent-QOS file mount. The builder
MUST NOT write a secret into an image layer, cache record, build log, or
attestation. Secret file mounts MUST be temporary and read-only.

## StageX requirements

A StageX build MUST use verified builder and input artifacts. The implementation MUST record enough information to reproduce and audit the build decision. The output OCI image MUST use the normal digest verification path before any later workload can run it.

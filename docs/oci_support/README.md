# OCI Support

Status: Draft

This directory specifies the QOS feature named `min-oci-support`.

`min-oci-support` lets QOS run OCI containers inside an enclave. Manifest V3
enables the feature. The feature is not named "OCI V3." The term "V3" refers
only to the QOS manifest version.

This specification defines the target design. An implementation can be
incomplete while the design is under development.

## Normative language

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative
when they use uppercase letters.

## Overview

A Manifest V3 contains a list of named workloads. Each initial workload names
one approved OCI image by digest. QOS can run one or more OCI workloads in the
same enclave.

The QOS Host obtains the OCI image content. It sends the content to the enclave
over the QOS control connection in a Borsh message. The enclave verifies the
image digest, configuration, and layers before it runs image content.

QOS creates a separate OCI runtime bundle for each OCI workload. QOS generates
the runtime configuration. QOS then uses `libcontainer` to create, start,
monitor, and delete the container. These containers are an execution and
packaging mechanism. They are not security boundaries.

Manifest V3 also introduces named top-level volumes. An OCI workload receives
a volume only through an explicit `mounts` entry with `type: "volume"`. This
model uses the same separation between a named volume and a container volume
mount that Kubernetes uses.

QOS keys are not OCI image content. A workload MAY receive a key through an
explicit `mounts` entry with `type: "file"`. The same mechanism can mount
another approved regular file from the parent QOS environment.

The initial OCI workload group follows the Kubernetes Pod communication model.
Its OCI workloads share localhost, IPC, a hostname, and `/dev/shm`. They keep
separate PID, mount, and writable root file systems. Initial OCI support has no
network connection outside the workload group.

The initial OCI root file system is writable. A workload volume mount is also
writable unless its `readOnly` value is `true`. Protected QOS files, including
key files, are always mounted read-only.

## Security and trust model

The deployer MUST trust QOS and every workload approved by one Manifest V3.
The workload list does not create separate trust domains.

All workloads in one enclave share one Linux kernel. QOS does not claim
adversarial isolation between these workloads or between a workload and the
parent QOS environment. A deployer MUST NOT use OCI containers, Linux users or
groups, user namespaces, mount namespaces, capabilities, seccomp, or cgroups
as a reason to place mutually untrusted software in one enclave.

When QOS uses these mechanisms, it uses them for process management,
compatibility, accidental interference reduction, and defense in depth. They
can reduce the effect of an ordinary defect, but they do not create a QOS
security boundary. This remains true when a later implementation assigns
different users, groups, or user namespaces to workloads.

An escape from an internal container, UID, GID, or namespace that remains
inside the enclave's shared Linux kernel is a hardening defect, not a violation
of the QOS security model. QOS welcomes reports of these defects.

The security boundary covered by this specification is between the measured,
manifest-approved enclave system and untrusted host or unapproved input. A
failure that crosses the enclave boundary, bypasses manifest approval or image
verification, falsifies attestation, or exposes enclave material to an
unapproved external party remains a security violation.

## Initial feature boundary

Initial `min-oci-support` includes:

- Manifest V3 with existing Manifest V2 control-plane fields;
- a required `enclave.type` discriminator;
- one or more named OCI workloads;
- OCI images approved by digest;
- host delivery of OCI content with Borsh;
- enclave verification of OCI content;
- one runtime bundle and container lifecycle per workload;
- named volatile volumes backed by tmpfs;
- a tagged per-workload `mounts` list;
- named volume mounts and explicit parent-QOS file mounts;
- a fixed QOS-owned namespace, capability, mount, and device policy.

Initial `min-oci-support` does not include:

- enclave image pulls;
- registry credentials in the manifest or enclave;
- persistent volumes;
- user namespaces or manifest-controlled UID mappings;
- process overrides;
- per-container resource limits;
- seccomp filtering;
- host-supplied container settings;
- BuildKit or StageX builds;
- pivot workloads in the workload list;
- workload-name key derivation.

The initial schema omits fields for these capabilities. Later Manifest V3
specifications can add optional fields or new tagged types without changing
the meaning of an existing field.

## Document map

### Manifest

- [Manifest V3](manifest/README.md) defines the top-level schema, enclave type,
  compatibility rules, and complete example.
- [OCI workloads](manifest/workloads.md) defines workload identity, image
  selection, restart behavior, and process defaults.
- [Mounts](manifest/mounts.md) defines the tagged workload mount list.
- [Volumes](manifest/volumes.md) defines named top-level volumes and workload
  mounts with `type: "volume"`.
- [File mounts](manifest/file_mounts.md) defines explicit parent-QOS file
  mounts with `type: "file"`, including QOS key files.

### Runtime behavior

- [OCI images](runtime/images.md) defines accepted image content and secure
  layer extraction.
- [Processes](runtime/processes.md) defines how QOS converts OCI image process
  defaults into runtime settings.
- [Separation and hardening](runtime/isolation.md) defines the initial fixed
  container policy.

### Implementation

- [Control protocol](implementation/control_protocol.md) defines host image
  delivery and enclave verification.
- [`libcontainer`](implementation/libcontainer.md) defines bundle creation and
  container operations.
- [Lifecycle and attestation](implementation/lifecycle.md) defines boot order,
  restart behavior, status, cleanup, and attestation binding.
- [Conformance](implementation/conformance.md) defines the initial testable
  requirements.

### Future work

The documents under [future](future/README.md) are not part of initial
`min-oci-support` conformance.

- [Persistent volumes](future/persistent_volumes.md)
- [User namespaces](future/user_namespaces.md)
- [Seccomp hardening](future/seccomp.md)
- [BuildKit and StageX](future/buildkit_stagex.md)
- [Additional workload types](future/additional_workload_types.md)
- [Workload key derivation](future/key_derivation.md)

## Stable compatibility rules

Manifest V3 is the long-lived manifest format for OCI support.

A later specification MAY add an optional top-level field, workload field,
workload type, image-reference type, volume type, or mount type.

A later specification MUST NOT remove an existing field or change its meaning.

Every new optional field MUST define behavior for the absent case. The absent
case MUST preserve the behavior defined by this initial specification.

An initial implementation MUST reject every unknown Manifest V3 field and
every unknown tagged type. An implementation MAY accept a field or type after
a later Manifest V3 specification defines it and that implementation supports
it.

## Approval boundary

The signed manifest approves workload names and types, image-reference types
and digests, volume grants, typed mount grants, and restart behavior.

The QOS Host transports content and storage. It is not a trust anchor.

The enclave verifies all approved content before use.

An OCI image supplies trusted application content and process defaults after
verification. It does not supply QOS policy, QOS keys, host paths, runtime
configuration, or parent identity mappings.

## Reference specifications

- [OCI Image Specification](https://specs.opencontainers.org/image-spec/)
- [OCI Runtime Specification](https://specs.opencontainers.org/runtime-spec/)
- [OCI Distribution Specification](https://specs.opencontainers.org/distribution-spec/)
- [`libcontainer` Rust documentation](https://docs.rs/libcontainer/latest/libcontainer/)

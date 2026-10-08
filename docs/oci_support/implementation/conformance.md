# Initial Conformance

Status: Initial normative specification

An implementation conforms to initial `min-oci-support` when it satisfies this
document and every initial normative document linked from the top-level
[OCI Support](../README.md) README.

Future-work documents are not part of initial conformance.

## Required capabilities

A conforming implementation:

- accepts Manifest V3 with the existing Manifest V2 control-plane fields;
- requires `enclave.type` equal to `nitro` and signed `attested` or `debug` mode;
- accepts an object keyed by workload name, with `pivot` and `oci` values;
- verifies pivot binaries and uses the existing direct pivot launch model;
- accepts optional named top-level tmpfs volumes;
- accepts an OCI `mounts` list with only the initial `volume` type;
- provides the reserved implicit read-only `qos` volume;
- rejects duplicate raw JSON member names before decoding objects into maps;
- continues to accept Manifest V1 and V2;
- receives OCI content from the QOS Host through Borsh control messages;
- verifies every approved image by digest inside the enclave;
- creates one QOS-controlled runtime bundle per OCI workload;
- uses upstream `libcontainer` for each OCI container lifecycle;
- applies the fixed QOS container hardening policy;
- supports multiple concurrent workload state records;
- reports status by workload name;
- rejects every unknown Manifest V3 field and tagged type.

A QOS release MAY set a maximum workload count.

It MUST reject a manifest that exceeds the limit. It MUST NOT ignore an
additional workload.

## Required tests

Conformance tests MUST cover:

### Manifest and attestation

- one OCI workload;
- two OCI workloads;
- one pivot workload and mixed pivot/OCI workloads;
- rejection of workload arrays and workload values containing `name`;
- duplicate raw JSON member rejection, including escaped-equivalent names;
- workload-count limit rejection before any workload starts;
- unsupported workload-type rejection;
- lowercase restart values for both types and rejection of V2 casing;
- V1/V2 backward compatibility;
- unsupported image-reference-type rejection;
- missing enclave-type rejection;
- unsupported enclave-type rejection;
- missing and unsupported enclave-mode rejection;
- missing, malformed, wrong-length, and uppercase PCR rejection in both modes;
- parse-time rejection of an attested manifest with PCR0, PCR1, and PCR2 all zero;
- attested PCR comparison and rejection of mismatched or debug evidence;
- zero PCR3 alone does not classify evidence as debug evidence;
- debug acceptance with four 96-zero PCRs and rejection of nonzero PCRs;
- changing enclave mode changes the signed manifest hash;
- evidence and enclave-type mismatch rejection;
- rejection of every unknown Manifest V3 field;
- workload member reordering preserves the canonical manifest hash;
- workload renaming or changing approved workload or mount values changes the hash.

### Image delivery and verification

- Borsh image delivery over the control connection;
- rejection of JSON-encoded image bytes;
- two workloads sharing one image artifact by digest;
- image digest mismatch rejection;
- missing manifest, configuration, or layer rejection;
- outer OCI layout path, link, special-file, and duplicate rejection;
- rejection of a root digest that is absent from `index.json`;
- Borsh length and artifact-count limit enforcement;
- unsafe layer path rejection;
- safe symbolic-link and hard-link support;
- symbolic-link and hard-link escape rejection;
- DiffID count, order, and digest verification;
- OCI whiteout behavior;
- supported compression behavior;
- numeric ownership, permission, and metadata behavior;
- image `Volumes` entries do not create or grant a QOS volume;
- image-size and expansion-limit enforcement.

### Process behavior

- OCI `Entrypoint` plus `Cmd` ordering;
- empty command rejection;
- environment and working-directory behavior;
- duplicate environment names use the last value;
- default `PATH` and executable lookup;
- empty OCI `User` running as UID 0 and GID 0;
- numeric and named OCI user handling;
- primary and supplementary group resolution;
- unresolved user or group rejection;
- stdin, output collection, and non-terminal behavior;
- image `StopSignal`, default `SIGTERM`, and forced-stop timeout;
- PostgreSQL or an equivalent nontrivial OCI image smoke test.

### Container separation and hardening

- separate root file systems;
- separate PID and mount namespaces;
- one shared OCI-workload IPC, UTS, and network namespace;
- inter-workload localhost and shared-memory communication;
- shared sandbox persistence across one workload restart;
- loopback-only networking with no external ingress or egress;
- top-level `dns` does not add OCI workload networking;
- `no_new_privileges` enforcement;
- exact root and non-root capability policy enforcement;
- absence of a seccomp filter in the generated runtime configuration;
- rejection of a host- or image-supplied seccomp profile;
- fixed device policy without per-workload resource manifest fields;
- fixed device allowlist and no arbitrary parent path or device access;
- read-only `/sys` and fixed `/proc` restrictions;
- no claim that container separation permits mutually untrusted workloads;
- cleanup after partial create and workload exit.

### Volumes

- named tmpfs volume creation at the parent QOS mount path;
- fixed `01777` tmpfs root mode;
- no OCI workload volume access without a typed `mounts` entry;
- named volume resolution without a workload-supplied parent path;
- one volume mounted at different paths in two workloads;
- independent read-only and read-write mounts of one volume;
- executable volume behavior;
- duplicate and overlapping workload mount-path rejection;
- reserved runtime mount-path rejection;
- volume target creation and image-content obscuring without copying;
- implicit `qos` volume contains approved manifest, quorum key, and live ephemeral key;
- `qos` access through an explicit read-only volume mount;
- no implicit `qos` mount when the workload does not request it;
- rejection of a top-level volume named `qos`;
- rejection of writable `qos` mounts and unresolved volume sources;
- rejection of unsupported mount types and parent paths as volume sources;
- no setup ephemeral private key in the implicit volume;
- source and target symbolic-link rejection;
- protected QOS files remain read-only and readable inside the granted workload;
- no key bytes in QOS-generated status, diagnostics, or runtime configuration.

### Lifecycle

- independent workload status;
- `never` restart behavior;
- `always` OCI restart behavior with backoff and V2-style pivot restart delay;
- a fresh writable root file system after each restart;
- restart from retained verified image content without another host artifact;
- top-level volume contents preserved across a workload restart;
- `waiting`, `running`, and `terminated` status transitions;
- separate signal and normal-exit status reporting;
- cleanup of mounts, bundles, and runtime state;
- node shutdown with multiple workloads.

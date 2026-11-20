# Future OCI Support Work

Status: Future normative addenda

The documents in this directory describe planned extensions to OCI support.
They are not part of the initial `min-oci-support` conformance requirements.

The normative language rules in the top-level [OCI Support](../README.md)
README apply to these addenda. A requirement becomes active only when an
implementation claims support for that addendum.

The initial feature MUST NOT block these extensions. However, an implementation
MUST NOT claim support for an extension until it meets the requirements in that
extension's specification.

## Planned extensions

- [Persistent volumes](persistent_volumes.md) add durable block-backed storage.
- [User namespaces](user_namespaces.md) add per-workload UID and GID
  defense-in-depth separation.
- [Seccomp hardening](seccomp.md) adds an optional QOS-owned syscall policy.
- [BuildKit and StageX](buildkit_stagex.md) add OCI image builds inside the
  enclave.
- [Additional workload types](additional_workload_types.md) add workloads such
  as pivots.
- [Workload key derivation](key_derivation.md) adds keys derived for a named workload.

## Manifest compatibility

All extensions in this directory extend Manifest V3. They do not require
Manifest V4.

An extension MUST add optional fields or new tagged variants. It MUST NOT
change the meaning of an existing field. It MUST NOT change behavior when its
new fields are absent.

An implementation MUST reject a requested extension that it does not support.
It MUST NOT silently ignore a field that affects security, storage, identity,
or execution.

# Workload Key Derivation

Status: Future normative addendum

The initial `min-oci-support` feature exposes the quorum key and live
ephemeral key to an OCI workload through an explicit read-only volume mount
with `source: "qos"`. This document defines requirements for a future
derived-key mode.

## Manifest compatibility

The signed object key in `workloads` provides the stable workload identity
that a later key derivation can use. No initial manifest field selects
derivation.

The future extension MAY add a volume type or mount type for derived material.
It MUST define the exact schema before use. It MUST preserve the existing
direct-key meaning of `source: "qos"`.

An implementation that does not support the requested derivation MUST reject
the manifest. It MUST NOT mount the source key instead.

## Derivation requirements

The derivation specification MUST define:

- the KDF and its parameters;
- a domain-separation label;
- the exact byte encoding of the workload name and all other context;
- the source key type, such as the quorum key or live ephemeral key;
- the output length and allowed uses;
- behavior during manifest change, key rotation, restart, and recovery.

The signed workload name MUST be part of the context. Two different workload names MUST NOT receive the same derived key from the same source key and derivation version.

The derivation context MUST distinguish workload keys from volume keys and every other QOS key purpose. A workload rename MAY therefore change its derived key. The later specification MUST state this effect clearly.

QOS MUST create the derived key inside the enclave, mount only the derived result, and erase temporary key material when it is no longer needed.

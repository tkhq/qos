# Additional Workload Types

Status: Future normative addendum

Initial `min-oci-support` defines `pivot` and `oci` workloads in the signed
`workloads` object. Their fields are defined in [Workloads](../manifest/workloads.md).
Manifest V3 can later add tagged workload types without changing the version.

## Tagged workload model

Each workload's object key is its signed identity. Each workload value has a
`type` and no `name` field. An implementation MUST reject unsupported types.

New workload types MUST NOT change the meaning of `pivot` or `oci`. Fields
that apply to all workloads MAY be added only when their absent behavior is
clear and compatible.

A later specification MUST define each new type's manifest fields, content
verification, launch behavior, status, restart behavior, and cleanup rules.

## Future pivot process-user separation

A later Manifest V3 extension MAY run each pivot under a separate QOS-assigned
Unix user. That change MUST preserve the parent-QOS execution model and the
existing pivot fields.

Separate pivot users are defense in depth. They do not permit mutually
untrusted pivots to share one enclave. They do not create a security boundary
between a pivot and QOS.

Parent UID and GID values MUST NOT appear in the manifest. If a later
author-controlled user field is required, it MUST be optional and MUST define
its absent behavior.

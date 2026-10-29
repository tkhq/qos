# Seccomp Hardening

Status: Future normative addendum

This document defines future seccomp support for OCI workloads. It is not part
of the initial `min-oci-support` conformance requirements.

Initial `min-oci-support` runs OCI workloads without a seccomp filter. This
matches the behavior of a Kubernetes workload that does not select a seccomp
profile and runs on a node without seccomp defaulting enabled.

Seccomp is defense in depth. It does not create a QOS security boundary. A
deployer MUST continue to trust every workload approved by one manifest.

## Manifest compatibility

A future seccomp extension MUST use an optional, typed workload field. The
field is not part of the initial OCI workload schema.

When the field is absent, the workload MUST retain the initial unconfined
behavior. This preserves the meaning of an existing Manifest V3 document.

The extension MAY define a QOS-owned default policy type. It MUST NOT allow the
host or OCI image to supply or weaken a policy.

The extension MAY later define another policy type without changing Manifest
V3. Each type MUST define its complete behavior.

## Policy requirements

A QOS-owned seccomp policy MUST be part of the QOS codebase and covered by the
enclave measurement.

The policy specification MUST define:

- its allowed and denied system calls;
- its behavior for a denied call;
- its supported architectures;
- any argument-dependent rules;
- startup behavior when the kernel or runtime cannot apply the policy;
- conformance tests for allowed and denied calls.

QOS MUST apply a selected policy through the QOS-generated OCI runtime
configuration. QOS MUST fail workload start if it cannot apply a policy that
the signed manifest selects.

A future BuildKit or StageX policy MAY allow additional system calls. It MUST
use a separately defined policy type or another explicit extension. It MUST
NOT silently weaken the policy for an ordinary OCI workload.

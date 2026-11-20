# Initial Container Separation and Hardening

Status: Initial normative specification

QOS owns one fixed container hardening policy. The host, image, and manifest do
not supply an arbitrary OCI runtime configuration.

The QOS release and enclave measurement identify the fixed policy.

This policy is defense in depth. It is not an adversarial security boundary.
The deployer MUST trust every workload in the manifest. QOS makes no guarantee
that a malicious or compromised workload cannot escape a container, user,
group, namespace, capability set, seccomp filter, or cgroup while it shares the
enclave Linux kernel with QOS and other workloads.

The mechanisms in this document provide predictable runtime behavior, reduce
accidental interference, and can limit the effect of ordinary defects. Their
presence MUST NOT be used to justify running mutually untrusted workloads in
one enclave.

## Namespaces

The initial policy MUST use a separate mount namespace for each OCI workload.

The initial policy MUST use a separate PID namespace for each OCI workload.

The initial policy MUST create one IPC namespace, one UTS namespace, and one
network namespace for the complete OCI workload group. Every OCI workload in
the manifest MUST join these three namespaces.

This follows the Kubernetes Pod model. OCI workloads can communicate through
localhost, System V IPC, POSIX shared memory, and an explicitly shared volume.
They share one port space and MUST coordinate port use.

The shared UTS namespace MUST use the fixed hostname `qos`.

The shared network namespace MUST contain loopback only. The initial feature
does not provide network egress, network ingress, service-name DNS, or a host
bridge for OCI workloads.

The existing top-level `dns` field retains its parent-QOS meaning. It does not
add DNS or network access to an OCI workload. QOS MUST NOT mount the parent
QOS resolver configuration into an OCI workload. The workload keeps the
`/etc/resolv.conf` supplied by its writable image root file system.

QOS MUST reject OCI workload-group startup when a required shared namespace is
unavailable. It MUST reject an individual workload when its required PID or
mount namespace is unavailable.

QOS MUST NOT silently join a parent QOS namespace. It MUST NOT share a PID or
mount namespace between OCI workloads.

User namespaces are not required for initial conformance. Their future design
is in [User namespaces](../future/user_namespaces.md).

## Privilege hardening

The initial policy MUST set `no_new_privileges` before application execution.

The initial root-process capability set follows the Docker-compatible default
set. It contains only:

- `CAP_AUDIT_WRITE`;
- `CAP_CHOWN`;
- `CAP_DAC_OVERRIDE`;
- `CAP_FOWNER`;
- `CAP_FSETID`;
- `CAP_KILL`;
- `CAP_MKNOD`;
- `CAP_NET_BIND_SERVICE`;
- `CAP_NET_RAW`;
- `CAP_SETFCAP`;
- `CAP_SETGID`;
- `CAP_SETPCAP`;
- `CAP_SETUID`;
- `CAP_SYS_CHROOT`.

A non-root process MUST receive no effective, permitted, inheritable, or
ambient capabilities. It MAY retain the fixed set in its bounding set.

QOS MUST drop every capability that is not in the fixed set from the bounding,
permitted, inheritable, effective, and ambient sets.

The initial policy MUST run OCI workloads without a seccomp filter. The
QOS-generated OCI runtime configuration MUST omit `linux.seccomp`.

The host, image, and manifest MUST NOT supply a seccomp profile. A later
Manifest V3 extension can add an optional, typed QOS-owned seccomp policy as
defined in [Seccomp hardening](../future/seccomp.md).

The host, image, and manifest MUST NOT add a capability.

QOS MUST fail workload start if it cannot apply a required capability
restriction.

## Mount restrictions

The root mount MUST be private.

QOS MUST prevent mount propagation from a workload into the parent QOS mount
namespace or another workload.

QOS MUST mount declared workload volumes with `nodev` and `nosuid`.

Declared workload volumes MUST allow execution. Manifest V3 does not contain
an `exec` option. A later volume type MAY define a stricter fixed policy.

QOS MUST provide only these fixed runtime devices and interfaces:

- `/dev/null`;
- `/dev/zero`;
- `/dev/full`;
- `/dev/random`;
- `/dev/urandom`;
- `/dev/tty`;
- `/dev/ptmx` and a runtime-owned `/dev/pts`;
- the shared runtime-owned `/dev/shm`.

The QOS-generated device policy MUST deny access to another device even if a
workload creates a device node with `CAP_MKNOD`.

QOS MUST mount `/sys` read-only. It MUST use a fixed QOS-owned list of masked
and read-only `/proc` paths based on the normal Docker runtime defaults.

The initial feature MUST NOT expose an undeclared or policy-forbidden parent
path, block device, host device, or `/dev/fuse` to an ordinary OCI workload.

## Resource safety

The initial Manifest V3 has no per-container memory, CPU, or process-count
fields.

The initial runtime MUST enforce the fixed device-access policy through the
mechanism supported by upstream `libcontainer` and the enclave kernel. The
manifest does not select that mechanism.

QOS MAY use cgroup v2 for node-wide policy enforcement and accounting. It MUST
NOT set a per-workload memory, CPU, or process-count limit from Manifest V3.

The QOS codebase MUST define node-wide limits for image import, total
processes, open files, and other resources that can prevent the enclave from
operating. These are node policy, not per-workload manifest fields.

QOS MAY reject an image or workload that cannot run safely within enclave
limits.

QOS MUST NOT interpret the absence of manifest resource fields as permission
to consume unsafe unbounded enclave resources.

## Failure rule

Every required separation and hardening operation is fail-closed.

QOS MUST NOT start the application without required hardening after a namespace,
mount, capability, or privilege operation fails.

Fail-closed configuration is a conformance requirement for the selected
hardening policy. It does not convert the policy into a security boundary
between manifest-approved workloads.

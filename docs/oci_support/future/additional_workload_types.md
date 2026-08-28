# Additional Workload Types

Status: Future normative addendum

The initial `min-oci-support` feature defines only the `oci` workload type. Manifest V3 can later add tagged workload types without changing the manifest version.

## Tagged workload model

Every workload has a unique `name` and a `type`. The `type` selects the fields and lifecycle rules for that workload. An implementation MUST reject a workload type that it does not support.

New workload types MUST NOT change the meaning of `oci`. Fields that apply to all workloads MAY be added only when their absent behavior is clear and compatible.

## Pivot workloads

A future `pivot` workload type extends the Manifest V2 binary pivot model from
one pivot to multiple named pivots.

A pivot runs as a direct QOS child process in the parent QOS execution
environment. It does not run in an OCI container. QOS MUST NOT create an OCI
root file system, OCI runtime bundle, or `libcontainer` container for it.

The first pivot workload schema SHOULD match the current Manifest V2 binary
pivot fields, with only `name` and `type` added:

```json
{
  "name": "control-service",
  "type": "pivot",
  "hash": "...",
  "restart": "always",
  "bridgeConfig": [],
  "debugMode": false,
  "args": [],
  "env": {}
}
```

The fields have these meanings:

- `name` is the unique workload name.
- `type` MUST be `pivot`.
- `hash` approves the pivot binary with the same hash rules as Manifest V2.
- `restart` has the same meaning as the Manifest V2 pivot restart policy.
- `bridgeConfig` has the same meaning as Manifest V2 bridge configuration.
- `debugMode` has the same meaning as Manifest V2 pivot debug mode.
- `args` is the argument list for the pivot binary.
- `env` is the environment added to the pivot process.

QOS MUST use the existing Manifest V2 pivot launch behavior for each pivot.
The pivot binary is the executable. There is no OCI `Entrypoint`, `Cmd`, image
user, or image environment.

## Parent QOS files and volumes

All pivot workloads run in the parent QOS file-system and mount environment,
as Manifest V2 pivots do. They do not use the OCI `mounts` list.

Top-level Manifest V3 volumes are mounted in that parent environment. Each
pivot can use the signed top-level `mountPath`. A pivot can read and write a
volume according to the volume mount state and normal file permissions. A key
file being read-only does not make the pivot file system or a volume
read-only.

The first pivot workload extension SHOULD retain the existing Manifest V2 key
paths and key availability rules. It SHOULD NOT add OCI `mounts` to pivots
unless a later specification has a reason to change the V2 behavior.

## Multiple pivots

Manifest V3 MAY contain one or more pivot workloads. It MAY also contain OCI
and pivot workloads in the same `workloads` list.

QOS MAY set a node-wide workload-count safety limit. It MUST validate that
limit before it starts any workload, and it MUST reject the complete manifest
when the workload list exceeds the limit.

QOS MUST keep the process ID, status, restart count, exit status, and cleanup
state for each pivot name. It MUST NOT depend on one global pivot process slot.

The host MUST provide one approved binary for each distinct pivot hash. One
binary MAY satisfy several pivot workloads that approve the same hash. QOS
MUST verify each binary before it executes that binary.

Each pivot uses its own `args`, `env`, `restart`, `bridgeConfig`, and
`debugMode`. QOS MUST reject bridge configurations that claim the same parent
listener twice.

Every pivot is required during initial boot. If one pivot fails its initial
start, QOS MUST use the same all-or-nothing startup rule as OCI workloads.
After successful boot, QOS MUST apply each pivot restart policy independently.

## Future process-user separation

A later Manifest V3 extension MAY run each pivot under a separate QOS-assigned
Unix user. That change MUST preserve the parent-QOS execution model and the
existing pivot fields.

Separate pivot users are defense in depth. They do not permit mutually
untrusted pivots to share one enclave, and they do not create a security
boundary between a pivot and QOS.

The initial pivot extension does not need a manifest user field. Parent UID
and GID values MUST NOT appear in the manifest. If a later author-controlled
user field is required, it MUST be optional and MUST define its absent
behavior.

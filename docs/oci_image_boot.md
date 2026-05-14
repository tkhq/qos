# OCI Image Boot Specification

## Goal

QOS should be able to boot an enclave application from an OCI image instead of a
single submitted pivot binary. A manifest-set-approved QOS manifest specifies an
OCI image digest. QOS resolves, verifies, unpacks, mounts, and runs the image
after quorum key provisioning.

The digest in the signed manifest is the trust anchor. In the first
implementation, image bytes are supplied to the TEE through the QOS boot protocol
message, analogous to today's pivot-app bytes. QOS must not execute any image
content until every referenced descriptor has been verified against the signed
manifest's image digest.

For the first implementation, all image filesystems and runtime mounts are
RAM-backed. Egress, registry networking, and general workload networking are out
of scope.

## Terminology

* **OCI image digest**: A digest string using OCI descriptor syntax, such as
  `sha256:<64 lowercase hex characters>`. In the supported subset, the digest
  identifies an OCI image manifest. Image indexes are rejected.
* **OCI content store**: A content-addressed store containing OCI blobs. Blobs
  are addressed by digest and are considered untrusted until QOS verifies their
  bytes.
* **Runtime bundle**: The verified, unpacked root filesystem plus runtime
  metadata derived from the image config and QOS manifest. This is QOS's runtime
  bundle, not a promise to implement the complete OCI Runtime Spec.
* **Workload**: The enclave application QOS starts after quorum key provisioning.
  In the existing system this is the pivot app.
* **RAM-backed mount**: A mount backed by tmpfs or equivalent volatile memory.
  Its contents are lost on enclave shutdown.

## Non-Goals

* QOS does not provide image registry egress in this phase.
* QOS does not provide general workload networking, inbound bridge setup, outbound
  bridge setup, DNS, NAT, or transparent proxying for OCI images in this phase.
* QOS does not persist unpacked root filesystems or writable container state.
* QOS does not implement a full container runtime surface such as Kubernetes
  pods, image pull secrets, container networking, cgroups, seccomp profiles, or
  device plugins.
* QOS does not trust image tags. Tags may be useful for operator tooling, but the
  signed manifest must approve a digest.

## Supported Subset

The first implementation supports a deliberately small OCI subset:

* Linux OCI image manifests for `amd64`.
* A signed manifest digest that identifies an OCI image manifest, not an OCI
  image index. Operators must resolve multi-platform image indexes outside QOS
  and put the platform-specific image manifest digest in the QOS manifest.
* OCI image config fields needed to launch one process:
  `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, `Volumes`, and
  `ExposedPorts`.
* OCI layer media types:
  * `application/vnd.oci.image.layer.v1.tar`
  * `application/vnd.oci.image.layer.v1.tar+gzip`
* RAM-backed rootfs materialization and RAM-backed mounts for `/tmp`, `/run`,
  `/dev/shm`, and image `Config.Volumes`.
* No network setup. `Config.ExposedPorts` is verified as part of the signed image
  config but is informational only.
* Root user only. Images whose config sets `User` to a non-empty value other than
  `0` or `root` are rejected.

The first implementation rejects:

* image indexes;
* non-Linux images;
* non-`amd64` images;
* zstd-compressed layers;
* Docker media types, unless a later change explicitly adds them;
* image-declared or manifest-declared host, bind, block, device, persistent, or
  network mounts;
* non-empty QOS `bridge_config` on OCI image pivots;
* setuid/setgid files, device nodes, FIFOs, sockets, file capabilities, xattrs,
  and unsupported layer entry types.

## Manifest Schema

OCI image boot expands the existing v2 manifest schema. v2 is the JSON,
canonicalized manifest line intended for additive extension, so OCI image boot
must not introduce a v3 manifest only to replace the pivot binary hash.

The v2 `pivot` field becomes a workload mode. Existing v2 manifests without an
explicit pivot `type` remain legacy binary pivot manifests. OCI image manifests
set `pivot.type` to `ociImage` and specify an image digest instead of
`pivot.hash`.

```rust
enum ManifestVersion {
    V2,
}

struct ManifestV2 {
    version: ManifestVersion, // V2
    namespace: Namespace,
    pivot: PivotConfigV2,
    manifest_set: ManifestSet,
    share_set: ShareSet,
    enclave: NitroConfig,
}

#[serde(untagged)]
enum PivotConfigV2 {
    // Try this first: OCI image manifests carry an explicit type field.
    OciImage(PivotOciImageConfigV2),

    // Compatibility mode for existing v2 manifests. Existing manifests do not
    // contain `type`, so they continue to decode as this variant.
    Binary(PivotBinaryConfigV2),
}

struct PivotBinaryConfigV2 {
    hash: Hash256,
    restart: RestartPolicy,
    bridge_config: Vec<BridgeConfig>,
    debug_mode: bool,
    args: Vec<String>,
    env: PivotEnv,
}

struct PivotOciImageConfigV2 {
    // Required discriminator. Must equal "ociImage".
    r#type: PivotKind,

    // Required. Digest of an OCI image manifest.
    digest: OciDigest,

    // Required for the supported subset. Must be linux/amd64.
    platform: OciPlatform,

    // Restart policy for the workload process.
    restart: RestartPolicy,

    // Optional process argument override. If absent, QOS uses image config
    // Entrypoint + Cmd. If present, QOS uses this exact argv.
    args: Option<Vec<String>>,

    // Environment variables injected in addition to image config Env.
    // Manifest env overrides image env by variable name.
    env: PivotEnv,

    // Whether QOS should pipe workload stdout/stderr to enclave logs.
    debug_mode: bool,

    // Must be empty while networking is out of scope for OCI image boot.
    bridge_config: Vec<BridgeConfig>,

    // Runtime resource bounds for RAM-backed image materialization.
    limits: OciRuntimeLimits,
}

enum PivotKind {
    #[serde(rename = "ociImage")]
    OciImage,
}

struct OciPlatform {
    os: String,           // "linux"
    architecture: String, // "amd64" for current Nitro x86_64 builds
}

struct OciRuntimeLimits {
    // Maximum bytes allowed for compressed blobs fetched into the content store.
    max_compressed_bytes: u64,

    // Maximum bytes allowed for the unpacked rootfs and runtime tmpfs mounts.
    max_unpacked_bytes: u64,

    // Maximum number of filesystem entries after layer application.
    max_entries: u64,
}
```

Canonical JSON hashing rules remain the v2 rules: approvals sign the canonical
QOS JSON hash of the manifest. The image digest is therefore covered by manifest
set approvals and by the manifest hash placed in attestation `user_data`.

Changing any image config field, including `Config.Volumes` or
`Config.ExposedPorts`, changes the image config blob digest, which changes the
image manifest digest. Those fields are therefore covered by the signed QOS
manifest because `pivot.digest` is signed.

### JSON Example

```json
{
  "version": "v2",
  "namespace": {
    "name": "example",
    "nonce": "7",
    "quorumKey": "..."
  },
  "pivot": {
    "type": "ociImage",
    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "platform": {
      "os": "linux",
      "architecture": "amd64"
    },
    "restart": "never",
    "args": null,
    "env": {},
    "debugMode": false,
    "bridgeConfig": [],
    "limits": {
      "maxCompressedBytes": "268435456",
      "maxUnpackedBytes": "1073741824",
      "maxEntries": "200000"
    }
  },
  "manifestSet": { "threshold": "2", "members": [] },
  "shareSet": { "threshold": "2", "members": [] },
  "enclave": {
    "pcr0": "...",
    "pcr1": "...",
    "pcr2": "...",
    "pcr3": "...",
    "awsRootCertificate": "...",
    "qosCommit": "..."
  }
}
```

## Boot API

OCI image boot should follow the existing pivot-app transport model: the client
sends the approved manifest envelope and the application artifact to the TEE in
one boot protocol message. For binary pivots, that artifact is raw pivot bytes.
For OCI image pivots, that artifact is an OCI image-layout archive.

```rust
enum ProtocolMsg {
    BootStandardImageRequest {
        manifest_envelope: Box<VersionedManifestEnvelope>,
        #[serde(with = "qos_hex::serde")]
        oci_layout: Vec<u8>,
    },
}
```

Legacy boot requests that include `pivot: Vec<u8>` continue to exist for older
v1 manifests and for v2 binary-pivot manifests. QOS rejects a v2 OCI image
manifest sent through a legacy pivot-binary boot path, and rejects a v1 or v2
binary-pivot manifest sent through the image boot path.

The image boot request is JSON wire only, matching v2 manifest support. The
`oci_layout` field is encoded with the same hex-byte JSON convention used by the
existing `pivot` field. The request is subject to the existing
`MAX_ENCODED_MSG_LEN` processor bound. First implementation images must fit
inside that single-message bound after JSON encoding; chunked upload is a future
extension.

The boot response remains:

```rust
struct BootStandardResponse {
    nsm_response: NsmResponse,
}
```

### Boot Request Handling

On `BootStandardImageRequest`, QOS performs:

1. Decode the manifest envelope as v2.
2. Verify manifest set approvals against the v2 canonical manifest hash.
3. Reject non-empty share set approvals.
4. Validate `pivot.type == "ociImage"`.
5. Validate the OCI digest syntax and runtime limits.
6. Reject non-empty `pivot.bridge_config` while networking is out of scope.
7. Validate the submitted OCI image-layout archive, hash every blob before
   parsing, and verify that `pivot.digest` resolves to an OCI image manifest
   inside the archive.
8. Verify the image manifest, config descriptor, layer descriptors, and image
   config metadata. Do not unpack layers yet.
9. Store the verified OCI blobs in a RAM-backed QOS content store.
10. Generate the boot ephemeral key.
11. Write the manifest envelope and ephemeral key to QOS state.
12. Request attestation with the manifest hash in `user_data` and the ephemeral
   public key in `public_key`.
13. Return the attestation document to the client.

QOS resolves and verifies the submitted image archive before returning
attestation, just as it verifies a submitted pivot binary before attestation.
QOS does not unpack image layers or launch the image before quorum key
provisioning. Share holders rely on the signed manifest hash and Nitro PCRs; the
node has already accepted only image bytes matching the approved digest.

## Image Resolution

Since egress is out of scope, the first implementation resolves images only from
an OCI image-layout archive supplied in the boot protocol message. QOS verifies
the archive and imports the required blobs into a RAM-backed content store inside
the TEE. The submitted archive is untrusted until every blob used by the
approved image has been hashed and checked against its descriptor.

QOS resolves an image by digest:

1. Parse the submitted archive as an OCI image layout.
2. Load the blob named by `pivot.digest`.
3. Hash the exact blob bytes and compare to `pivot.digest`.
4. Parse the blob as an OCI image manifest.
5. Reject the blob if it is an OCI image index or any other media type.
6. Verify the manifest `config` descriptor media type and digest.
7. Fetch and verify the config blob referenced by the manifest.
8. Validate `config.os == "linux"` and `config.architecture == "amd64"`.
9. Verify every layer descriptor media type and digest.
10. Fetch and verify every layer blob referenced by the manifest, in order.
11. Verify uncompressed layer `diff_ids` from the image config while unpacking.

All descriptor media types must be explicitly allowlisted. Unknown media types
are rejected unless support is deliberately added later.

Initial allowlist:

* `application/vnd.oci.image.manifest.v1+json`
* `application/vnd.oci.image.config.v1+json`
* `application/vnd.oci.image.layer.v1.tar`
* `application/vnd.oci.image.layer.v1.tar+gzip`

Docker-compatible media types may be added behind the same verification rules,
but OCI media types are the normative path.

## Image Transport Contract

The initial implementation does not pull from registries and does not depend on
host-side filesystem staging. Operators are responsible for sending the image
artifact to QOS through the boot protocol, the same trust boundary used for pivot
app bytes today. QOS is responsible for deciding whether those bytes match the
signed manifest.

The request carries an uncompressed tar archive whose contents are an OCI image
layout:

```text
oci-layout
index.json
blobs/
  sha256/
    <hex>
```

Transport bytes are untrusted. The presence, name, or path of a blob inside the
archive does not prove integrity. QOS must hash the actual bytes it reads and
compare the result to the expected descriptor digest before parsing or unpacking
that blob.

Archive import rules:

* Accept only a tar archive containing relative paths under the OCI layout root.
* Require `oci-layout` and `index.json` to exist for OCI layout compliance.
  `index.json` is not authoritative for image selection; `pivot.digest` is.
* Accept blobs only at `blobs/sha256/<64 lowercase hex>`.
* Reject absolute paths, `..`, symlinks, hardlinks, device nodes, FIFOs,
  sockets, sparse entries, setuid/setgid bits, xattrs, and any entry outside the
  OCI layout subset.
* Enforce `max_compressed_bytes` over the bytes imported from the archive.
* Import only blobs reachable from `pivot.digest`: the image manifest, its config
  blob, and its layers. Extra blobs may be ignored after archive validation.
* Store verified blobs in RAM-backed content storage under
  `/run/qos/oci/content/blobs/sha256/<hex>`.

The signed manifest contains the approved image digest, not the transport hash.
The OCI layout archive may contain extra images or tags, but they are irrelevant.
QOS resolves exactly `pivot.digest`, verifies its descriptor graph, and fails
closed if any required blob is missing or mismatched. It does not attempt network
access.

The archive itself is not persisted after import. The verified content store is
RAM-backed and may be discarded on enclave shutdown.

## Rust Dependency Choices

Do not add registry clients or container runtime crates for the first
implementation. Egress is out of scope, and QOS needs a verifier/unpacker for a
local OCI image layout, not a pull client or full runtime.

The following dependencies are approved for the implementation:

* Reuse existing workspace dependencies for hashing and JSON:
  * `qos_crypto::sha_256` or workspace `sha2` for descriptor digest
    calculation.
  * workspace `serde` and `serde_json` for QOS manifest and OCI JSON decoding.
  * workspace `nix` and `libc` for mount, chroot, and process setup.
  * Enable the existing workspace `nix` `fs` and `mount` features for safe
    wrappers around `chroot`, `chdir`, and `mount`; do not add unsafe
    `Command::pre_exec` setup code for this phase.
* Add `oci-spec` only for OCI image-layout, image-manifest, descriptor,
  config, media-type, platform, and digest types:
  * workspace dependency:
    `oci-spec = { version = "0.9", default-features = false, features = ["image"] }`
  * `qos_core` dependency:
    `oci-spec = { workspace = true }`
* Add `tar` for streaming TAR entry parsing, but disable default features:
  * workspace dependency:
    `tar = { version = "0.4", default-features = false }`
  * `qos_core` dependency: `tar = { workspace = true }`
  * QOS rejects xattrs in the first implementation, so the `tar` crate's
    default `xattr` feature should not be enabled.
* Add `flate2` for `application/vnd.oci.image.layer.v1.tar+gzip`:
  * workspace dependency:
    `flate2 = { version = "1.1", default-features = false, features = ["miniz_oxide"] }`
  * `qos_core` dependency: `flate2 = { workspace = true }`
  * This selects the pure-Rust gzip backend and avoids C zlib dependencies.

Avoid in the first implementation:

* `oci-client` / `oci-distribution`: useful for OCI registry distribution, but
  registry pull, auth, retries, and remote transports are out of scope.
* `ocidir`: useful for higher-level OCI layout handling, but the first QOS
  implementation needs a very small read-only content-store surface and should
  hash every blob before parsing. Direct path construction from verified
  `sha256` digests is simpler to audit.
* `containerd`, `youki`, `runc` wrappers, or OCI runtime crates: QOS is not
  delegating process isolation to a general container runtime in this phase.

After adding the new dependencies, review their resolved transitive dependencies
with `cargo tree` and keep them pinned through `Cargo.lock` like the rest of the
workspace.

## Key Forward Compatibility

Key forwarding uses the same image manifest and image transport semantics as boot
standard. The new node's approved manifest contains the OCI image digest, so no
pivot binary is submitted with the key-forward boot request. The new node does
receive the OCI image-layout archive through its key-forward boot protocol
message, matching the way binary key-forward boot receives pivot bytes today.

```rust
enum ProtocolMsg {
    BootKeyForwardImageRequest {
        manifest_envelope: Box<VersionedManifestEnvelope>,
        #[serde(with = "qos_hex::serde")]
        oci_layout: Vec<u8>,
    },
}
```

The original node verifies the new node's attestation against the new v2 manifest
hash. Namespace, nonce, manifest approval, PCR, and quorum key checks are
unchanged. The original node does not need to receive, fetch, or verify the new
image content before forwarding the quorum key; it verifies that the new node
attested to the approved manifest. The new node verifies and imports the
submitted image archive before attestation, then unpacks it locally before
launch.

Legacy key-forward requests with `pivot: Vec<u8>` remain valid only for legacy
pivot-binary manifests.

## Runtime Filesystem

QOS materializes the image into RAM only.

Required mount layout:

```text
/run/qos/oci/
  content/                 # tmpfs content store populated by image boot
  bundles/
    <manifest-digest-hex>/
      rootfs/              # tmpfs, unpacked image root filesystem
      mounts/              # tmpfs backing directories for declared mounts
      state/               # runtime metadata generated by QOS
```

The rootfs is created by mounting tmpfs at the bundle `rootfs` path and applying
OCI layers in manifest order. QOS must enforce `max_compressed_bytes`,
`max_unpacked_bytes`, and `max_entries` during import and unpack.

The rootfs is writable tmpfs for the first implementation. QOS does not provide a
separate persistent writable layer or overlay filesystem. Any writes made by the
workload are lost when the enclave exits.

Layer application rules:

* Reject archive entries with absolute paths, `..` components, empty paths, or
  paths that escape the rootfs after symlink resolution.
* Apply regular files, directories, symlinks, and hardlinks only when they remain
  inside rootfs.
* Preserve executable bits and directory permissions required to run the image.
* Handle OCI whiteouts:
  * `.wh.<name>` removes `<name>` from the current merged rootfs.
  * `.wh..wh..opq` makes the containing directory opaque by removing lower-layer
    entries not present in the current layer.
* Reject device nodes, FIFOs, sockets, setuid bits, setgid bits, file
  capabilities, and xattrs for the first implementation.
* Reject images whose config requests a non-Linux OS or non-`amd64`
  architecture.

### RAM-Backed Runtime Mounts

The first implementation provides only RAM-backed mounts:

* `/tmp` is tmpfs.
* `/run` is tmpfs.
* `/dev/shm` is tmpfs.
* OCI config `Volumes` entries, if present, are created as tmpfs mounts.

Mounts are created after layer unpack and before process start. A mount target
must be an absolute path inside rootfs. Mount targets that escape rootfs or
replace critical QOS-managed paths are rejected.

`Config.Volumes` is interpreted as an instruction to mask the target path with a
fresh tmpfs mount. If the image contains files at a volume path, QOS does not
copy those files into the tmpfs mount in the first implementation.

Initial mount options:

* `nosuid`
* `nodev`
* `noexec`
* size bounded by `max_unpacked_bytes`

There is no manifest-declared mount list in the first implementation. If QOS
later adds explicit mounts, they must be added as a separate v2 manifest
extension and must be covered by the manifest hash.

### QOS State File Access

Existing pivot binaries are not isolated from the enclave root filesystem. In
production, QOS writes state files at stable root paths and then spawns the pivot
binary directly. A legacy pivot can therefore read these files today:

* `/qos.quorum.key`
* `/qos.ephemeral.key`
* `/qos.manifest`

This is part of the current QOS trust model: the manifest set approves the exact
application code, and that approved application receives access to the quorum key
after provisioning. The file permissions are read-only for accidental mutation,
not a confidentiality boundary against the pivot process.

OCI image boot must not broaden this exposure. It must either preserve the same
file interface inside the OCI rootfs or introduce a separate, explicit QOS app
secret API before removing file access. For the first implementation, QOS
preserves compatibility by materializing these QOS-managed files inside the
RAM-backed rootfs immediately before process launch. These files are not part of
the OCI image, are not read from image layers, and are not present before quorum
key provisioning and ephemeral key rotation complete.

`Config.Volumes` and built-in tmpfs mounts must not mask these paths, the root
path `/`, or any future QOS-managed compatibility path.

## Process Launch

After quorum key provisioning succeeds and the quorum key is written, the reaper
starts the OCI workload instead of spawning `handles.pivot_path()`.

QOS derives the workload process from the verified image config:

1. `argv` is `pivot.args` when present.
2. Otherwise `argv` is image config `Entrypoint` followed by image config `Cmd`.
3. If the resulting `argv` is empty, QOS rejects the image at launch time.
4. The working directory is image config `WorkingDir`, or `/` when absent.
5. The environment is image config `Env` plus QOS-required variables plus
   manifest `pivot.env`, with manifest env taking precedence.
6. The user is root. If image config `User` is empty, `0`, or `root`, QOS starts
   the process as root. Any other value is rejected.
7. `Config.ExposedPorts` is ignored for runtime setup because networking is out
   of scope. QOS reports it in status for operator visibility.

The process starts with:

* current root set to the unpacked rootfs, using a QOS-owned launcher helper
  process that reads a QOS-generated launch spec, calls `chroot`/`chdir`, and
  starts the workload inside the rootfs;
* stdin closed or connected to `/dev/null`;
* stdout/stderr piped only when `debug_mode` is true, otherwise connected to
  `/dev/null`;
* restart behavior controlled by `pivot.restart`;
* no configured network interfaces beyond what QOS already needs internally.

QOS must pass the same quorum key and ephemeral key availability guarantees to an
OCI workload that it currently gives to a pivot binary. The exact paths or
environment variables used for QOS secrets should stay compatible with existing
pivot applications unless changed by a separate spec.

## Attestation and Approval Semantics

The attestation document continues to bind the node to:

* Nitro PCR values from `manifest.enclave`;
* the QOS build identity in the PCRs;
* the manifest hash in `user_data`;
* the ephemeral public key in `public_key`.

The image digest is not placed directly in the attestation document. It is
included in the signed manifest, and the manifest hash is attested. Share holders
verify the manifest envelope exactly as they do today, then inspect the approved
OCI image digest instead of a pivot hash.

A share holder should approve provisioning only after confirming:

1. The manifest hash in attestation `user_data` matches the manifest envelope.
2. The manifest envelope has enough valid manifest set approvals.
3. The Nitro PCRs match the approved QOS enclave configuration.
4. The namespace, nonce, quorum key, and OCI image digest are expected.
5. The share holder belongs to the manifest's share set.

## Error Handling

QOS must fail closed. If any of the following occur, the workload is not started:

* manifest approval verification fails;
* the OCI digest is invalid or unsupported;
* the image/config/layer blob is missing;
* any blob digest does not match its descriptor;
* any uncompressed layer diff ID does not match the image config;
* image platform does not match the enclave platform;
* the approved digest resolves to an image index;
* any layer entry attempts path traversal or unsupported filesystem features;
* unpacked size or entry count exceeds manifest limits;
* required RAM-backed mounts cannot be created;
* image config cannot produce a valid process argv;
* image config requests a non-root user;
* image config declares invalid `Volumes` or `ExposedPorts` entries;
* an image config field requests behavior outside the supported subset and cannot
  be safely ignored.

Unknown image config fields that do not affect launch, filesystem
materialization, mounts, or networking are ignored. This preserves OCI image
extensibility while keeping the supported runtime behavior small.

Failures before quorum key reconstruction should leave the node in the existing
boot/provisioning phase and report a protocol error. Failures after quorum key
reconstruction but before process launch should leave the node provisioned but
with workload status failed, so operators can inspect status without silently
running different code.

## Status Reporting

QOS status responses should expose image runtime state without leaking secrets:

```rust
struct WorkloadStatus {
    kind: "ociImage",
    digest: OciDigest,
    resolved: bool,
    unpacked: bool,
    running: bool,
    exposed_ports: Vec<String>,
    volumes: Vec<String>,
    last_exit_status: Option<i32>,
    last_error: Option<String>,
}
```

`digest` is the approved image manifest digest from the QOS manifest.
`exposed_ports` and `volumes` come from the verified image config.

## Backward Compatibility

Existing v1/v2 manifests and pivot-binary boot requests remain supported. The
runtime dispatch is based on the v2 pivot mode:

* v1 manifest or v2 binary pivot manifest: QOS expects the existing pivot binary
  bytes, verifies `pivot.hash`, writes the pivot file, and launches it directly.
* v2 OCI image pivot manifest: QOS expects no pivot bytes, but does expect an
  OCI image-layout archive in the image boot request. QOS verifies the archive
  against `pivot.digest`, imports the reachable blobs into RAM-backed content
  storage, unpacks the image to RAM-backed storage after provisioning, and
  launches the image process.

Client tooling should make this distinction explicit with separate commands or a
required pivot mode flag. It should not silently convert a pivot hash manifest
to an OCI image manifest.

## Implementation Plan

The current code assumes every manifest has `pivot.hash`, every standard boot
request carries `pivot: Vec<u8>`, and the reaper waits for
`handles.pivot_exists()` before launching `handles.pivot_path()`. OCI support is
implemented by adding a second v2 pivot mode while leaving the legacy path in
place.

1. Extend manifest types.
   * Replace `manifest::v2::PivotConfigV2` with a compatibility enum that
     deserializes existing untagged binary pivot objects and new
     `{"type":"ociImage", ...}` objects.
   * Add `PivotBinaryConfigV2`, `PivotOciImageConfigV2`, `OciDigest`,
     `OciPlatform`, and `OciRuntimeLimits`.
   * Add helper methods on `VersionedManifest` and `VersionedManifestEnvelope`:
     `pivot_kind()`, `pivot_binary_hash()`, `oci_image()`, `restart()`,
     `args_override()`, `pivot_env()`, `debug_mode()`, and `bridge_config()`.
     Existing callers of `pivot_hash()` should move to `pivot_binary_hash()` and
     handle the OCI case explicitly.
   * Keep canonical v2 JSON hashing unchanged.

2. Extend protocol messages.
   * Keep `BootStandardRequest { manifest_envelope, pivot }` for v1/v2 binary
     pivots.
   * Keep `BootStandardJsonEnvelopeRequest { manifest_envelope, pivot }` for
     legacy Borsh transport of JSON/storage-encoded binary pivot manifests.
   * Add `BootStandardImageRequest { manifest_envelope, oci_layout }`.
   * Keep `BootKeyForwardRequest { manifest_envelope, pivot }` for binary
     pivots.
   * Add `BootKeyForwardImageRequest { manifest_envelope, oci_layout }`.
   * Encode image boot requests with canonical JSON wire format. Do not add a
     Borsh-only image request unless a legacy client requires it.
   * Encode `oci_layout: Vec<u8>` with `qos_hex::serde`, matching the current
     JSON byte transport for `pivot`.
   * Route image boot messages in the same phases as the existing binary boot
     messages: `WaitingForBootInstruction -> WaitingForQuorumShards` for
     standard boot and `WaitingForBootInstruction -> WaitingForForwardedKey` for
     key-forward boot.
   * Reject mismatched request/manifest pairs early: image request with binary
     pivot manifest, or binary request with OCI image manifest.

3. Split boot validation.
   * Keep the current binary path: verify approvals, reject share approvals,
     hash submitted pivot bytes, compare to `pivot.hash`, write pivot file and
     manifest envelope, attest.
   * Add the image path: verify approvals, reject share approvals, validate
     `pivot.type`, digest, platform, limits, empty `bridge_config`, and
     `oci_layout` presence, then validate and import the submitted archive.
   * Verify `pivot.digest`, config descriptor, layer descriptors, supported
     media types, platform, root user, `Volumes`, and `ExposedPorts` before
     attesting.
   * Write only the verified RAM-backed OCI content store, manifest envelope,
     and ephemeral key before attesting. Do not unpack image layers or launch the
     process before quorum key provisioning.

4. Add OCI archive import and content store support.
   * Add the dependency entries from "Rust Dependency Choices":
     `oci-spec`, `tar`, and `flate2`.
   * Add RAM-backed OCI content paths to QOS handles or runtime config.
   * Support importing an uncompressed tar archive whose contents are an OCI
     image layout with `blobs/sha256/<hex>`.
   * Read blobs by digest and hash the bytes before parsing them.
   * Store verified reachable blobs under `/run/qos/oci/content`.
   * Do not perform network access.

5. Add OCI descriptor and config validation.
   * Use `oci-spec` image types to parse only OCI image manifest JSON and OCI
     image config JSON.
   * Reject image indexes.
   * Allow only `application/vnd.oci.image.manifest.v1+json`,
     `application/vnd.oci.image.config.v1+json`,
     `application/vnd.oci.image.layer.v1.tar`, and
     `application/vnd.oci.image.layer.v1.tar+gzip`.
   * Validate linux/amd64, root user only, valid `Entrypoint`/`Cmd`,
     `WorkingDir`, `Env`, `Volumes`, and `ExposedPorts`.
   * Treat `ExposedPorts` as status metadata only.

6. Add RAM-backed bundle creation.
   * Create `/run/qos/oci/bundles/<manifest-digest-hex>/`.
   * Mount tmpfs for `rootfs`.
   * Use `flate2` only for gzip layer decoding and `tar` only for streaming TAR
     entry inspection. Do not call `Archive::unpack` wholesale; QOS must inspect
     and validate every entry before writing it.
   * Apply layers in order, enforcing `max_compressed_bytes`,
     `max_unpacked_bytes`, and `max_entries`.
   * Compute and verify each uncompressed layer diff ID against image config
     `rootfs.diff_ids`.
   * Implement OCI whiteouts.
   * Reject path traversal, symlink escapes, unsupported file types,
     setuid/setgid, capabilities, and xattrs.

7. Add RAM-backed runtime mounts.
   * Mount tmpfs at `/tmp`, `/run`, and `/dev/shm` inside the bundle rootfs.
   * Mount tmpfs for each image `Config.Volumes` target.
   * Validate every mount target stays inside rootfs and does not replace
     QOS-managed paths.
   * Use `nosuid,nodev,noexec` for these tmpfs mounts.
   * Materialize QOS compatibility files inside the rootfs at
     `/qos.quorum.key`, `/qos.ephemeral.key`, and `/qos.manifest` after
     provisioning and before process launch. These files come from QOS handles,
     not from the OCI image.

8. Update reaper dispatch.
   * Replace the unconditional wait for `handles.pivot_exists()` with
     workload-specific readiness:
     * binary pivot: quorum key, manifest envelope, and pivot file exist;
     * OCI image pivot: quorum key and manifest envelope exist.
   * After quorum key provisioning, inspect the manifest pivot mode.
   * For binary pivots, keep the existing launch path.
   * For OCI image pivots, resolve the image from the RAM-backed content store
     populated by the boot protocol message,
     create the RAM-backed bundle, derive argv/env/cwd, write a launch spec
     under the bundle `state/` directory, and spawn the QOS launcher helper so
     the workload starts rooted at the bundle rootfs.
   * Record image resolution, unpack, launch, and exit failures in workload
     status instead of silently falling back to binary behavior.

9. Update status.
   * Preserve existing status fields for binary pivots.
   * Add OCI workload status with digest, resolved/unpacked/running flags,
     verified `Volumes`, verified `ExposedPorts`, last exit status, and last
     error.

10. Update client tooling.
    * Add manifest generation flags for OCI image digest and optional argv/env
      overrides.
    * Validate that the digest string is `sha256:<64 hex>`.
    * Show the approved image digest, platform, volumes, exposed ports, restart
      policy, and env overrides during manifest approval.
    * Add boot and key-forward commands that send image requests without pivot
      bytes.

11. Add tests.
    * Unit tests cover manifest compatibility, digest parsing, descriptor
      verification, transport archive validation, config validation, layer
      unpacking, whiteouts, RAM-backed mount planning, argv/env derivation, and
      request/manifest mismatch rejection.
    * Integration tests use a minimal OCI image-layout archive fixture and
      assert that boot standard and key forward launch the image without network
      access.

## Test Requirements

Unit tests:

* v2 OCI image manifest canonical hash is stable and approvals verify.
* existing v2 binary pivot manifests deserialize and hash exactly as before.
* invalid digest strings are rejected.
* OCI image-layout archive import rejects traversal, unsupported entry types,
  invalid blob paths, missing `oci-layout`, and missing `index.json`.
* image manifest, config, and layer descriptor digests are verified.
* image indexes are rejected.
* media type allowlist rejects unsupported descriptor types.
* image config validation rejects non-linux, non-amd64, and non-root images.
* layer unpack rejects absolute paths, `..`, symlink escapes, device nodes,
  sockets, FIFOs, setuid/setgid, and xattrs.
* whiteout and opaque directory behavior matches OCI layer semantics.
* runtime limits stop compressed and unpacked size expansion.
* process argv/env derivation matches image config and manifest overrides.
* `Config.Volumes` produces tmpfs mount plans.
* `Config.Volumes` cannot mask QOS compatibility files.
* `Config.ExposedPorts` is parsed for status and does not create networking.

Integration tests:

* boot standard image flow returns attestation with the v2 OCI image manifest
  hash.
* share provisioning reconstructs the quorum key and launches a minimal OCI
  workload from the protocol-supplied OCI image-layout archive.
* an archive missing a required blob fails closed and does not launch a workload.
* tampered layer content fails digest verification.
* an image with a declared `Volume` gets a writable tmpfs mount.
* an OCI workload can read `/qos.quorum.key`, `/qos.ephemeral.key`, and
  `/qos.manifest` from inside its rootfs.
* no network access is required for image resolution or launch.
* key forward image flow forwards the quorum key based on the attested v2 image
  manifest and the new node launches the protocol-supplied OCI workload.

## Future Extensions

Future changes may add image index platform selection, zstd layers, Docker media
types, non-root users, read-only rootfs with writable overlay, explicit
manifest-declared tmpfs mounts, or networking. Each of those changes must be
specified separately and must preserve the rule that manifest-approved digests
and QOS manifest fields are covered by the attested manifest hash.

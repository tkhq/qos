# OCI Image Control Protocol

Status: Initial normative implementation specification

The QOS Host obtains OCI content and sends it to the enclave over the QOS
control connection.

The enclave does not pull images.

## Manifest rules

Each OCI workload MUST specify its approved image-manifest digest.

Manifest V3 MUST NOT specify a pull method, registry URL, tag, or registry
credential.

## Host behavior

The QOS Host MUST obtain the OCI content required by each OCI workload.

The host SHOULD obtain registry content by digest. It MAY use a verified local
cache or local OCI image layout.

The host SHOULD verify content before transport. Host verification does not
replace enclave verification.

Registry credentials MUST remain outside the enclave. The host MUST NOT send
them in the control protocol.

## Borsh encoding

OCI control messages MUST use Borsh encoding.

The protocol MUST NOT encode image bytes as JSON, hexadecimal JSON, or base64
JSON.

Standard boot and key-forward boot MUST use separate QOS protocol variants.
Both variants MUST carry this payload in one Borsh control message:

```text
OciBootPayloadV3 {
    manifestEnvelope: Bytes,
    artifacts: Vec<OciArtifactV3>
}

OciArtifactV3 {
    digest: String,
    ociLayoutArchive: Bytes
}
```

`manifestEnvelope` contains the existing QOS encoding of the approved Manifest
V3 envelope. This specification does not change that encoding.

The QOS protocol enum provides the standard-boot or key-forward message tag.
Within either variant, Borsh MUST encode `manifestEnvelope` first and
`artifacts` second. Within an artifact, Borsh MUST encode `digest` first and
`ociLayoutArchive` second. The QOS Host and enclave MUST use the same protocol
definition from the QOS codebase.

`Bytes` is a Borsh byte vector. `Vec` is a Borsh vector. Image bytes remain raw
bytes inside the Borsh message and MUST NOT use JSON text encoding.

`digest` MUST have the form `sha256:` followed by exactly 64 lowercase
hexadecimal characters.

The request MUST contain the approved Manifest V3 envelope and exactly one
artifact for each distinct image digest that its workloads require. It MUST
NOT contain an artifact for another digest.

`ociLayoutArchive` MUST be a tar archive in the OCI Image Layout format. It
MUST contain `oci-layout`, `index.json`, and every descriptor blob needed for
the approved platform-specific image manifest.

The outer archive MUST be an uncompressed POSIX tar archive. It MAY use PAX
headers. QOS MUST apply path and size validation after it expands a PAX value.

`digest` MUST identify the root image manifest in that archive. The enclave
MUST verify this claim from the archive content.

`index.json` MUST contain a descriptor for that root image manifest. QOS MUST
select the image by the signed digest, not by descriptor order, annotation, or
tag.

QOS MUST process only the descriptor graph reachable from the signed root
digest. It MAY ignore additional regular files and unreferenced blobs that are
valid in an OCI Image Layout. They do not become trusted content.

## OCI layout archive safety

Every archive path MUST be relative and normalized. QOS MUST reject an
absolute path, `..` traversal, duplicate path, symbolic link, hard link,
device, FIFO, or socket in the outer OCI layout archive.

QOS MUST accept only regular files and directories while reading the outer
archive. It MUST NOT extract an archive entry over a parent QOS file.

Blob paths MUST have the form `blobs/sha256/<digest>`. QOS MUST verify the bytes
of every consumed blob against its path and every descriptor that refers to
it.

QOS MUST validate `oci-layout` and `index.json` before it follows a descriptor.
It MUST reject a malformed layout or an unsupported image-layout version.

QOS MAY stream the archive into an enclave-owned content store instead of
extracting it as a normal directory. The same path, type, duplicate, size, and
digest rules apply.

The QOS codebase MUST define fixed limits for artifact count, each archive
size, total message size, file count, path length, and consumed blob bytes.
These limits are not Manifest V3 fields. The Borsh decoder MUST reject a
declared length that exceeds a limit before it allocates the buffer.

The request MAY contain more than one artifact.

One artifact MAY satisfy multiple workloads that approve the same digest. The
request MUST NOT contain two artifacts for the same digest.

Artifact order MUST NOT affect workload identity or startup behavior.

## Enclave matching

The enclave MUST match artifacts to workloads by approved image-manifest
digest. It MUST NOT match by workload name, image tag, or list position.

The enclave MUST reject a missing required artifact.

The enclave MUST reject duplicate artifacts that claim the same root digest.

The enclave MUST reject an unreferenced artifact.

## Enclave verification

The enclave MUST verify the image manifest, image configuration, and every
required layer.

The enclave MUST compare the verified root digest with the digest in Manifest
V3.

The enclave MUST complete verification before it executes image content or
constructs a trusted runtime bundle.

The detailed image rules are in [OCI images](../runtime/images.md).

## Error behavior

The protocol MUST distinguish malformed Borsh, missing artifacts, digest
mismatch, unsupported media, unsafe archive content, and internal limits.

An error MUST identify the affected workload or digest without including
image credentials or key material.

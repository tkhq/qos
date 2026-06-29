# Enclave Keys

This document is for QOS app authors who need to decide which enclave key to
use from a pivot app. It explains how the reaper, pivot app, manifest, quorum
key, and ephemeral key fit together.

For Boot Proof and App Proof concepts and verification details, see Turnkey's
[Proofs and Verification](https://docs.turnkey.com/features/verifiable-cloud/proofs-and-verification)
documentation. For the control-task and app-start mechanics, see
[QOS Networking](networking.md).

## Runtime Shape

A QOS enclave contains the reaper and the pivot app. The reaper owns the QOS
control path, writes the boot state files through QOS handles, and starts the
pivot app only after the manifest, pivot binary, and quorum key are present.

```mermaid
flowchart TB
    subgraph Enclave["QOS enclave"]
        Reaper["reaper"]
        Files["files<br/>/qos.ephemeral.key<br/>/qos.quorum.key"]
        Pivot["pivot app"]

        Reaper -->|"write"| Files
        Reaper -->|"starts"| Pivot
        Files -->|"reads"| Pivot
    end

    subgraph Evidence["verifier evidence"]
        SetupEvidence["setup evidence<br/>attestation doc<br/>manifest<br/>setup pubkey<br/>PCR16"]
        LiveEvidence["live evidence<br/>attestation doc<br/>manifest<br/>live pubkey<br/>PCR17"]
        AppEvidence["app evidence<br/>app payload<br/>live key sig"]
        AppVerification["app verification<br/>app key matches<br/>PCR17 pubkey"]

        LiveEvidence --> AppVerification
        AppEvidence --> AppVerification
    end

    Reaper -->|"exposes"| SetupEvidence
    Reaper -->|"exposes"| LiveEvidence
    Pivot -->|"returns"| AppEvidence
```

The control task (collapsed into the reaper in the above diagram) accepts boot, provisioning, key-forwarding, health, status, and
attestation requests. The pivot app is the application that runs after QOS has
finished provisioning key material.

## Files Available To The App

| File | Contents | App-author use |
| --- | --- | --- |
| `/qos.manifest` | The approved QOS manifest envelope. | Inspect the namespace, nonce, pivot configuration, quorum public key, quorum sets, and enclave PCR configuration. |
| `/qos.ephemeral.key` | The current enclave Ephemeral Key. | Sign enclave results, create App Proofs, and decrypt data encrypted to this specific enclave. |
| `/qos.quorum.key` | The namespace Quorum Key. | Encrypt long-lived state and, when exact enclave attribution is not required, sign long-lived data. |

During standard boot and key forwarding, QOS creates both a setup Ephemeral Key
and a live Ephemeral Key. PCR16 commits the setup key and manifest hash for
provisioning and key-forwarding. PCR17 commits the live key and manifest hash
for app-level attestations. QOS locks the full attestable PCR range before
publishing the boot files that allow the pivot app to start.

The setup key is written to `/qos.ephemeral.key` during boot and remains the
current Ephemeral Key while QOS processes provisioning or key injection. After
the Quorum Key is reconstructed or injected, QOS rotates `/qos.ephemeral.key` to
the precommitted live key before starting the pivot app. That keeps
application-level uses of the Ephemeral Key separate from setup-time key
transport.

## Quorum Key

The Quorum Key is the long-lived key for a namespace. Multiple enclaves in the
same namespace can receive the same Quorum Key after they satisfy the QOS
provisioning or key-forwarding protocol.

Use the Quorum Key when the data or identity should survive across enclave
instances, restarts, horizontal scaling, and application upgrades. Common uses:

- encrypting application state that should exist across application versions and enclave instances;
- signing data when the verifier only needs to know that a valid namespace enclave produced the signature.

## Ephemeral Key

The Ephemeral Key is specific to an enclave instance. QOS uses two
stage-specific Ephemeral Keys:

- the setup key, verified with PCR16, for provisioning and key-forwarding;
- the live key, verified with PCR17, for app proofs and other post-provision
  uses.

The attestation document carries the selected key in `public_key` and the
manifest hash in `user_data`. Verifiers check PCR0 through PCR3 from the
manifest, require the release-pinned PCR range to be present, and recompute
PCR16 or PCR17 for the attestation stage they are verifying.

Most App Proof consumers only need the live/app check: verify the live
attestation against PCR17 and require the App Proof signature key to match the
attested live public key. PCR16 is for setup-time provisioning and key
forwarding; it is only needed by verifiers that also want to tie an App Proof
back to the setup/QK-delivery event.

Use the Ephemeral Key when the output needs to be tied to a specific attested
enclave and the code/configuration identified by its manifest. Common uses:

- proving a response came from a particular enclave instance (App Proof);
- decrypting messages or secrets encrypted to this enclave's ephemeral public key.

For App Proof payload design and verifier behavior, see Turnkey's
[Proofs and Verification](https://docs.turnkey.com/features/verifiable-cloud/proofs-and-verification)
documentation.

## Related Docs

- [Proofs and Verification](https://docs.turnkey.com/features/verifiable-cloud/proofs-and-verification)
  explains Boot Proofs, App Proofs, and public verification tooling.
- [QOS Networking](networking.md) explains how the reaper starts the control
  task, bridge tasks, and pivot app.
- [Boot Standard](boot_standard.md) explains provisioning a fresh enclave from
  quorum key shares.
- [Key Forward](key_forward.md) explains provisioning a new enclave from an
  already provisioned enclave in the same namespace.
- [QOS Key Set Specification](../src/qos_p256/SPEC.md) describes the key
  schemes used by QOS keys.

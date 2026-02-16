# QOS Provisioning Guide

## Goal
- Full Genesis ceremony (generate new quorum key)
- 2-of-3 threshold (3 members, any 2 can reconstruct)
- AWS Nitro Enclave with real attestation
- Your application as the pivot binary (referred to as `your_app` throughout this guide)

## Overview

The production flow has 9 phases:
1. **Setup**: Generate member keypairs, prepare directories
2. **Genesis**: Generate quorum key and distribute encrypted shards
3. **Share Distribution**: Each member decrypts their share
4. **Manifest**: Create and approve manifest with PCRs
5. **Boot**: Send manifest to enclave, verify attestation
6. **Provisioning**: Re-encrypt and post shares (K=2 triggers reconstruction)
7. **Verification**: Confirm the enclave is provisioned and your app is running
8. **Updates**: Deploy new application versions without redoing genesis
9. **Disaster Recovery**: Optional backup encryption of quorum key

---

## Phase 1: Environment Setup

### 1.1 Create Directory Structure

**What this does**: Creates an organized workspace for the genesis ceremony. Each directory will hold member-specific keys, shares, and ceremony artifacts. This separation ensures clear ownership and prevents mixing confidential materials between members.

```bash
# Choose a working directory for the ceremony
export WORKDIR=~/qos-production
mkdir -p $WORKDIR && cd $WORKDIR
mkdir -p {genesis-dir,member1-dir,member2-dir,member3-dir,manifest-dir,attestation-dir,shares-dir}
```

### 1.2 Generate 3 Member Keypairs

**What this does**: Creates P-256 keypairs for each quorum member. The private keys (`.secret` files) are used to decrypt shares and sign approvals. The public keys (`.pub` files) are shared with others for encryption and signature verification. In production, each member generates their own keypair on their trusted device.
```bash
# Member 1
qos_client generate-file-key \
  --master-seed-path member1-dir/member1.secret \
  --pub-path member1-dir/member1.pub

# Member 2
qos_client generate-file-key \
  --master-seed-path member2-dir/member2.secret \
  --pub-path member2-dir/member2.pub

# Member 3
qos_client generate-file-key \
  --master-seed-path member3-dir/member3.secret \
  --pub-path member3-dir/member3.pub
```

**Security Note**: In production, each member generates their keypair on their own machine and only shares the `.pub` file.

### 1.3 Prepare Genesis Directory

**What this does**: Collects all member public keys and sets the threshold for quorum key reconstruction. The threshold K=2 means any 2 out of 3 members must provide their shares to recover the quorum key. This prevents single-member compromise while ensuring operational flexibility.

```bash
cp member1-dir/member1.pub genesis-dir/
cp member2-dir/member2.pub genesis-dir/
cp member3-dir/member3.pub genesis-dir/
echo "2" > genesis-dir/quorum_threshold  # K=2
```

### 1.4 Prepare PCR3 Preimage (IAM Role)

**What this does**: Specifies the AWS IAM role ARN that will be measured in PCR3. This cryptographically binds the enclave to a specific AWS identity. During attestation, verifiers can confirm the enclave is running under the expected IAM permissions, preventing unauthorized deployments.
```bash
echo "arn:aws:iam::YOUR_AWS_ACCOUNT_ID:role/YOUR_ENCLAVE_ROLE" > genesis-dir/pcr3-preimage.txt
```

### 1.5 Build and Hash Your Application

**What this does**: Compiles your application as a statically-linked binary and calculates its SHA-256 hash. This hash will be written into the manifest and measured in PCR4 by the Nitro enclave. When provisioning, the enclave verifies the binary matches this hash before executing it, ensuring code integrity.

```bash
# Build your application as a static binary (adjust path to your app)
cd /path/to/your/app
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/your_app $WORKDIR/
cd $WORKDIR
sha256sum your_app | awk '{print $1}' > manifest-dir/pivot-hash.txt
```

### 1.6 Create QOS Release Directory

**What this does**: Defines the expected PCR0/1/2 values from your QuorumOS build. These measurements uniquely identify which version of the QuorumOS system is running. During boot and provisioning, these values are verified against the live attestation to confirm you're deploying to the correct QuorumOS version.
```bash
mkdir -p qos-release-dir
cat > qos-release-dir/aws-x86_64.pcrs << 'EOF'
<PCR0_VALUE> PCR0
<PCR1_VALUE> PCR1
<PCR2_VALUE> PCR2
EOF
```

**Important**: Replace with actual PCR values from your Nitro enclave build. For initial testing with `--unsafe-skip-attestation`, you can use placeholder values.

---

## Phase 2: Genesis Ceremony

### 2.1 Start Enclave Infrastructure

**What this does**: Launches the QuorumOS enclave and the HTTP-to-VSOCK bridge. The enclave runs isolated inside AWS Nitro, and qos_host provides the communication channel for external clients. This infrastructure must be running before any genesis or provisioning operations.

**Terminal 1: qos_enclave**
```bash
sudo docker run -d \
  --name qos_enclave \
  --privileged \
  --device /dev/nitro_enclaves \
  --device /dev/vsock \
  -v /run/nitro_enclaves:/run/nitro_enclaves \
  -v /var/log/nitro_enclaves:/var/log/nitro_enclaves \
  -e DEBUG=true \
  qos_enclave
```

**Terminal 2: qos_host**
```bash
sudo /qos/src/target/release/qos_host \
  --host-ip 0.0.0.0 \
  --host-port 3000 \
  --cid 16 \
  --port 3
```

### 2.2 Execute Genesis Boot

**What this does**: Performs the genesis ceremony inside the Nitro enclave. The enclave generates a fresh P-256 quorum keypair, splits the private key into 3 shares using Shamir Secret Sharing (threshold=2), and encrypts each share to its corresponding member's public key. This ceremony creates the root of trust for your QuorumOS deployment.

```bash
qos_client boot-genesis \
  --share-set-dir genesis-dir \
  --namespace-dir genesis-dir \
  --host-ip 127.0.0.1 \
  --host-port 3000 \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt
```

**What Happens**:
- Enclave generates new P256 quorum keypair
- Master seed split into 3 shares (threshold=2) using Shamir Secret Sharing
- Each share encrypted to corresponding member's public key
- Writes: `genesis_output`, `genesis_attestation_doc`, `quorum_key.pub`

**Verify**:
```bash
ls -la genesis-dir/
# Should see: genesis_output, genesis_attestation_doc, quorum_key.pub, genesis_dr_artifacts
```

---

## Phase 3: Member Share Distribution

**What this phase does**: Each member uses their private key to decrypt their encrypted share from the genesis output. The `after-genesis` command extracts the member's share from `genesis_output`, decrypts it with the member's private key, and re-encrypts it to the same key for safe storage. Members verify the genesis attestation to ensure the ceremony happened in a legitimate Nitro enclave.

### 3.1 Member 1

**What this does**: Member 1 recovers their encrypted share from the genesis output and stores it locally. The share remains encrypted to Member 1's public key for safe keeping until provisioning time.
```bash
qos_client after-genesis \
  --secret-path member1-dir/member1.secret \
  --share-path member1-dir/member1.share \
  --alias member1 \
  --namespace-dir genesis-dir \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
```

### 3.2 Member 2
```bash
qos_client after-genesis \
  --secret-path member2-dir/member2.secret \
  --share-path member2-dir/member2.share \
  --alias member2 \
  --namespace-dir genesis-dir \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt
```

### 3.3 Member 3
```bash
qos_client after-genesis \
  --secret-path member3-dir/member3.secret \
  --share-path member3-dir/member3.share \
  --alias member3 \
  --namespace-dir genesis-dir \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt
```

**Output**: Each member now has `memberX.share` file (encrypted share)

---

## Phase 4: Manifest Generation & Approval

**What this phase does**: Creates the manifest that defines your deployment configuration (app hash, PCRs, restart policy, quorum members). Multiple members review and cryptographically sign this manifest to approve it. The signed manifest becomes the authoritative definition of what should run in the enclave.

### 4.1 Setup Manifest/Share Set Directories

**What this does**: Organizes member public keys into two sets: manifest_set (who can approve configuration changes) and share_set (who can provision quorum key shares). Both use K=2 threshold, meaning 2 members must participate in any operation. This separation allows different security models for different operations.

There is also a third set: the **patch_set**, which defines who can approve hot-patches to the running pivot binary. In this guide we reuse the manifest_set directory for the patch_set since the same members govern both. In more advanced setups, you may want a separate patch_set with different members or a different threshold.
```bash
mkdir -p manifest-dir/manifest-set manifest-dir/share-set

# Copy public keys
cp genesis-dir/{member1,member2,member3}.pub manifest-dir/manifest-set/
cp genesis-dir/{member1,member2,member3}.pub manifest-dir/share-set/

# Set thresholds
echo "2" > manifest-dir/manifest-set/quorum_threshold
echo "2" > manifest-dir/share-set/quorum_threshold
```

### 4.2 Generate Manifest

**What this does**: Creates the unsigned manifest document that specifies exactly what will run in the enclave. This includes the app binary hash (pivot-hash), expected QuorumOS version (PCRs), AWS identity (PCR3), and governance rules (manifest/share/patch sets). The namespace and nonce create a unique identifier preventing replay attacks.

```bash
qos_client generate-manifest \
  --nonce 1 \
  --namespace production-v1 \
  --restart-policy never \
  --pivot-hash-path manifest-dir/pivot-hash.txt \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --manifest-path manifest-dir/manifest \
  --pivot-args '[]' \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub
```

### 4.3 Member 1: Approve Manifest

**What this does**: Member 1 reviews the manifest through interactive prompts (namespace, nonce, restart policy, etc.), then cryptographically signs it with their private key. This signature proves Member 1 explicitly approved this exact configuration. The approval file can be independently verified by anyone with Member 1's public key.
```bash
qos_client approve-manifest \
  --secret-path member1-dir/member1.secret \
  --manifest-path manifest-dir/manifest \
  --manifest-approvals-dir manifest-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --pivot-hash-path manifest-dir/pivot-hash.txt \
  --qos-release-dir qos-release-dir \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub \
  --alias member1
```

**Prompts** (answer 'y' to each):
- Is this the correct namespace name: production-v1?
- Is this the correct namespace nonce: 1?
- Is this the correct pivot restart policy: RestartPolicy::Never?
- Are these the correct pivot args: []?
- Is this the correct socket pool size: 1?

**Output**: `member1-production-v1-1.approval`

### 4.4 Member 2: Approve Manifest

**What this does**: Member 2 independently reviews and signs the same manifest. Since K=2, we need 2 signatures to meet the threshold. Each member's approval is cryptographically independent—they cannot forge each other's signatures. This enforces genuine multi-party approval.

```bash
qos_client approve-manifest \
  --secret-path member2-dir/member2.secret \
  --manifest-path manifest-dir/manifest \
  --manifest-approvals-dir manifest-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --pivot-hash-path manifest-dir/pivot-hash.txt \
  --qos-release-dir qos-release-dir \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub \
  --alias member2
```

**Output**: `member2-production-v1-1.approval`

### 4.5 Generate Manifest Envelope

**What this does**: Combines the unsigned manifest with the K=2 approval signatures into a single ManifestEnvelope. The enclave will verify all K signatures match members in the manifest_set and that they're valid before accepting the configuration. This envelope is the authoritative, approved deployment specification.
```bash
qos_client generate-manifest-envelope \
  --manifest-approvals-dir manifest-dir \
  --manifest-path manifest-dir/manifest
```

**Output**: `manifest_envelope` (manifest + K=2 approvals)

---

## Phase 5: Standard Boot 

**What this phase does**: Boots a fresh enclave instance with the approved manifest and pivot binary. The enclave validates all manifest signatures, generates an ephemeral key for share encryption, and enters WaitingForQuorumShards state. This is the production deployment flow (unlike genesis which was a one-time ceremony).

### 5.1 Restart Enclave (Clean State)

**What this does**: Terminates the genesis enclave instance (which is in GenesisBooted terminal state) and starts a fresh enclave for production deployment. Genesis and standard boot are separate state machines—you cannot transition from GenesisBooted to standard boot, you must start fresh.

```bash
# Kill previous instances
pkill qos_core
pkill qos_host

# Clean state files
rm -f /tmp/qos-production*

# Restart enclave and host (same commands as Phase 2.1)
```

### 5.2 Execute Boot Standard

**What this does**: Sends the manifest envelope and pivot binary to the fresh enclave. The enclave cryptographically verifies K=2 manifest approvals, validates the pivot hash, generates a fresh ephemeral keypair, and returns an attestation document. The ephemeral public key is embedded in the attestation for members to encrypt shares to.
```bash
qos_client boot-standard \
  --manifest-envelope-path manifest-dir/manifest_envelope \
  --pivot-path your_app \
  --host-port 3000 \
  --host-ip 127.0.0.1 \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt
```

**What Happens**:
- Validates manifest envelope approvals (K=2 signatures)
- Verifies pivot hash matches your application binary
- Generates ephemeral key in enclave
- Returns attestation document
- Enclave enters "WaitingForQuorumShards" phase

---

## Phase 6: Share Provisioning 

**What this phase does**: Each member decrypts their share (encrypted to their personal key), verifies the enclave attestation, and re-encrypts the share to the enclave's ephemeral public key. When K=2 shares are posted, the enclave reconstructs the quorum key using Shamir Secret Sharing and launches the pivot application.

### 6.1 Get Attestation Document

**What this does**: Retrieves the COSE-signed attestation document from the running enclave. This document contains PCR measurements, the ephemeral public key, and the manifest hash. Members use this to verify they're provisioning to the correct enclave instance before revealing their shares.

```bash
qos_client get-attestation-doc \
  --host-port 3000 \
  --host-ip 127.0.0.1 \
  --attestation-doc-path attestation-dir/attestation_doc \
  --manifest-envelope-path attestation-dir/manifest_envelope
```

### 6.2 Member 1: Re-encrypt Share to Ephemeral Key

**What this does**: Member 1 decrypts their share (using their personal private key), verifies attestation PCRs and manifest, then re-encrypts the share to the enclave's ephemeral public key. The plaintext share only exists briefly in Member 1's local memory. An approval signature proves Member 1 authorized provisioning to this specific manifest.
```bash
qos_client proxy-re-encrypt-share \
  --share-path member1-dir/member1.share \
  --secret-path member1-dir/member1.secret \
  --attestation-doc-path attestation-dir/attestation_doc \
  --eph-wrapped-share-path shares-dir/member1.eph_wrapped.share \
  --approval-path shares-dir/member1.attestation.approval \
  --manifest-envelope-path attestation-dir/manifest_envelope \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --manifest-set-dir manifest-dir/manifest-set \
  --alias member1
```

**Prompts** (answer 'y'):
- Is this the correct namespace name: production-v1?
- Is this the correct namespace nonce: 1?
- Does this AWS IAM role belong to the intended organization?
- The following manifest set members approved: [member1, member2]. Is this ok?

**Output**: `member1.eph_wrapped.share`, `member1.attestation.approval`

### 6.3 Member 1: Post Share

**What this does**: Sends Member 1's ephemeral-encrypted share and approval signature to the enclave. The enclave verifies the approval signature, decrypts the share with its ephemeral private key, and stores it. Since K=2 and this is the first share, reconstruction doesn't happen yet—the enclave waits for one more share.

```bash
qos_client post-share \
  --host-port 3000 \
  --host-ip 127.0.0.1 \
  --eph-wrapped-share-path shares-dir/member1.eph_wrapped.share \
  --approval-path shares-dir/member1.attestation.approval
```

**Output**: "The quorum key has *not* been reconstructed." (need 2 shares)

### 6.4 Member 2: Re-encrypt Share

**What this does**: Member 2 independently performs the same re-encryption process. They decrypt their personal-key-encrypted share, verify attestation, and re-encrypt to the ephemeral key. This is the second of K=2 required shares.
```bash
qos_client proxy-re-encrypt-share \
  --share-path member2-dir/member2.share \
  --secret-path member2-dir/member2.secret \
  --attestation-doc-path attestation-dir/attestation_doc \
  --eph-wrapped-share-path shares-dir/member2.eph_wrapped.share \
  --approval-path shares-dir/member2.attestation.approval \
  --manifest-envelope-path attestation-dir/manifest_envelope \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --manifest-set-dir manifest-dir/manifest-set \
  --alias member2
```

### 6.5 Member 2: Post Share (Triggers Reconstruction)

**What this does**: Posts the second share, meeting the K=2 threshold. The enclave now has 2 decrypted shares, so it runs Shamir reconstruction to recover the original master seed. It verifies the reconstructed quorum key matches the public key in the manifest, writes the key to `/qos.quorum.key`, rotates the ephemeral key for security, and **launches your pivot binary**. The enclave transitions to QuorumKeyProvisioned state.

```bash
qos_client post-share \
  --host-port 3000 \
  --host-ip 127.0.0.1 \
  --eph-wrapped-share-path shares-dir/member2.eph_wrapped.share \
  --approval-path shares-dir/member2.attestation.approval
```

**Output**: "The quorum key has been reconstructed." ✓

**What Happens**:
1. Enclave decrypts both shares with ephemeral key
2. Shamir reconstruction combines K=2 shares → recovers master seed
3. Verifies reconstructed public key matches manifest
4. Writes quorum key to `/qos.quorum.key`
5. Rotates ephemeral key for security
6. **Launches your pivot binary**

---

## Phase 7: Verification

**What this phase does**: Confirms the enclave is fully provisioned and your application is running.

### 7.1 Check Enclave Status

**What this does**: Queries the enclave status endpoint to confirm it's in QuorumKeyProvisioned state and the pivot binary is running.

```bash
curl http://127.0.0.1:3000/qos/enclave-info | jq
```

**Expected**:
```json
{
  "phase": "QuorumKeyProvisioned",
  "pivot_running": true
}
```

### 7.2 Test Your Application

At this point your pivot binary is running inside the enclave with access to the quorum key and ephemeral key. How you test depends on your application — send requests to the qos_host port and verify responses.

---

## Phase 8: Updating Your Application 

**What this phase does**: Updates your running enclave application to a new version without redoing the genesis ceremony. The quorum key remains the same - only the manifest changes with a new app hash and incremented nonce. This is the standard flow for deploying application updates while maintaining the same cryptographic identity.

### 8.1 Build Updated Application

**What this does**: Compiles your new application version and calculates its hash. This new hash will be used in the updated manifest to specify which binary should run in the enclave.

```bash
# Build your updated application
cd /path/to/your/app
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/your_app $WORKDIR/your_app_v2
cd $WORKDIR
sha256sum your_app_v2 | awk '{print $1}' > manifest-dir/pivot-hash-v2.txt
```

**Important**: Keep the old binary and manifest for rollback capability if needed.

### 8.2 Generate Updated Manifest (Increment Nonce)

**What this does**: Creates a new manifest with an incremented nonce (prevents downgrade attacks) and the new application hash. The namespace and quorum key remain the same, so you're deploying an update to the existing namespace rather than creating a new one.

```bash
qos_client generate-manifest \
  --nonce 2 \
  --namespace production-v1 \
  --restart-policy never \
  --pivot-hash-path manifest-dir/pivot-hash-v2.txt \
  --qos-release-dir qos-release-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --manifest-path manifest-dir/manifest-v2 \
  --pivot-args '[]' \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub
```

**Key Changes from Original Manifest**:
- `--nonce 2` (incremented from 1)
- `--pivot-hash-path manifest-dir/pivot-hash-v2.txt` (new app hash)
- `--manifest-path manifest-dir/manifest-v2` (new manifest file)
- All other parameters remain the same (namespace, quorum key, sets)

### 8.3 Member Approvals for Updated Manifest

**What this does**: Manifest Set members review and approve the new manifest. They verify the updated app hash, incremented nonce, and confirm they want to deploy this version. K=2 signatures are required.

#### Member 1 Approval:
```bash
qos_client approve-manifest \
  --secret-path member1-dir/member1.secret \
  --manifest-path manifest-dir/manifest-v2 \
  --manifest-approvals-dir manifest-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --pivot-hash-path manifest-dir/pivot-hash-v2.txt \
  --qos-release-dir qos-release-dir \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub \
  --alias member1
```

**Prompts** (answer 'y' to each):
- Is this the correct namespace name: production-v1?
- Is this the correct namespace nonce: 2?
- Is this the correct pivot restart policy: RestartPolicy::Never?
- Are these the correct pivot args: []?
- Is this the correct socket pool size: 1?

**Output**: `member1-production-v1-2.approval`

#### Member 2 Approval:
```bash
qos_client approve-manifest \
  --secret-path member2-dir/member2.secret \
  --manifest-path manifest-dir/manifest-v2 \
  --manifest-approvals-dir manifest-dir \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt \
  --pivot-hash-path manifest-dir/pivot-hash-v2.txt \
  --qos-release-dir qos-release-dir \
  --manifest-set-dir manifest-dir/manifest-set \
  --share-set-dir manifest-dir/share-set \
  --patch-set-dir manifest-dir/manifest-set \
  --quorum-key-path genesis-dir/quorum_key.pub \
  --alias member2
```

**Output**: `member2-production-v1-2.approval`

### 8.4 Generate Updated Manifest Envelope

**What this does**: Combines the new manifest with K=2 approvals into a ManifestEnvelope. This is the authoritative, approved specification for your updated deployment.

Make sure you remove any previous .approval files in the manifest-dir, or the command below might use the wrong ones.

```bash
qos_client generate-manifest-envelope \
  --manifest-approvals-dir manifest-dir \
  --manifest-path manifest-dir/manifest-v2
```

**Output**: `manifest_envelope` (updated manifest + K=2 approvals)

### 8.5 Restart Enclave with New Manifest

**What this does**: Terminates the current enclave instance and starts a fresh one. The old application stops running. You'll boot the new enclave with the updated manifest and new application binary.

```bash
# Kill previous instances
pkill qos_core
pkill qos_host

# Clean state files
rm -f /tmp/qos-production*

# Restart enclave and host (same commands as Phase 2.1)
```

### 8.6 Boot with Updated Manifest

**What this does**: Boots the fresh enclave with your new manifest envelope and updated application binary. The enclave validates approvals, generates a new ephemeral key, and waits for quorum key reconstruction.

```bash
qos_client boot-standard \
  --manifest-envelope-path manifest-dir/manifest_envelope \
  --pivot-path your_app_v2 \
  --host-port 3000 \
  --host-ip 127.0.0.1 \
  --pcr3-preimage-path genesis-dir/pcr3-preimage.txt
```

**What Happens**:
- Validates new manifest envelope approvals (K=2 signatures)
- Verifies new pivot hash matches your updated application binary
- Generates fresh ephemeral key for this instance
- Enclave enters "WaitingForQuorumShards" phase

### 8.7 Re-provision Shares (Same Quorum Key)

**What this does**: Members re-provision their shares to the new enclave instance. The shares are the same as before (from genesis), but they're re-encrypted to the new ephemeral key. When K=2 shares are posted, the same quorum key is reconstructed and your updated application launches.

Follow the exact same process as Phase 6 (Share Provisioning):

1. **Get attestation document** (Phase 6.1)
2. **Member 1**: Re-encrypt and post share (Phase 6.2, 6.3)
3. **Member 2**: Re-encrypt and post share (Phase 6.4, 6.5)

The quorum key reconstructs to the same value, but now your updated application binary is running inside the enclave.

---

## Key Points About Updates

**What You DON'T Need to Redo**:
- ❌ Genesis ceremony (quorum key generation)
- ❌ Quorum key sharing
- ❌ Member keypairs
- ❌ Share distribution

**What Changes**:
- ✓ Application binary (new version)
- ✓ Pivot hash in manifest (new binary hash)
- ✓ Manifest nonce (incremented for anti-downgrade)
- ✓ Ephemeral key (newly generated per boot)
- ✓ Manifest approvals (K=2 signatures on new manifest)

**What Stays the Same**:
- ✓ Quorum key (same cryptographic identity)
- ✓ Namespace (same logical grouping)
- ✓ Member shares (same encrypted shares)
- ✓ Manifest Set / Share Set / Patch Set composition
- ✓ PCR values (unless QuorumOS version changes)

**The Nonce Mechanism**: The monotonically increasing nonce prevents rollback attacks. Members should only approve manifests with nonces higher than the current deployment, ensuring adversaries cannot force downgrades to vulnerable versions.

---

## Phase 9: Disaster Recovery Key (Optional)

**What this does**: Creates an additional backup encryption of the complete quorum master seed. During genesis, if you provide `--dr-key-path`, the enclave encrypts the full master seed (not individual shares) to this DR public key. The encrypted backup is written to `genesis_dr_artifacts`. In a disaster where all K members lose their shares, you can use the DR private key to decrypt and recover the quorum key. This is an offline cold-storage recovery mechanism.

```bash
# Generate DR keypair
qos_client generate-file-key \
  --master-seed-path dr-key.secret \
  --pub-path dr-key.pub

# Add to boot-genesis
qos_client boot-genesis \
  ... \
  --dr-key-path dr-key.pub
```

This encrypts the full quorum master seed to the DR key for offline recovery.

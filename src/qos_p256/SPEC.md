# Quorum Key Set Specification

This document provides a formal specification for the cryptographic key schemes of the Quorum Key Set.

The Quorum Key Set is a collection of 3 cryptographic keys using 3 distinct schemes that comprise what is commonly referred to as a [Quorum Key](https://github.com/tkhq/qos/tree/main?tab=readme-ov-file#quorum-key). Each key is used for different cryptographic operations (more info in the [Overview](#overview) section). Additionally, 2 of the schemes, P256 Signing and P256 HPKE, are used by [Operators](https://github.com/tkhq/qos/tree/main?tab=readme-ov-file#operator).

Currently, the canonical implementation lives here, in this crate (`qos_p256`).

## Overview

A Quorum Key Set consists of three cryptographically independent keys that function together:

1. **P256 Signing Key** - ECDSA signatures for authentication
2. **P256 HPKE Key** - Hybrid public key encryption (ECDH + AES-GCM)
3. **AES-GCM-256 Key** - Symmetric encryption for data at rest

_Note:_ We use distinct keys for signing and HPKE to have clear domain separation.
_Note:_ While we use the term HPKE, this does not follow RFC 9180. See the [P256 HPKE](#2-p256-hpke) section for details.

## 1. P256 Signing Key

### Purpose

Digital signatures for message authentication using NIST P-256 (secp256r1) ECDSA.

### Algorithm

- **Curve**: [NIST P-256](https://csrc.nist.gov/publications/detail/fips/186-5/final) (secp256r1)
- **Signature Scheme**: ECDSA with SHA-256 digest
- **Signature Generation**: Deterministic per [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)
- **Signature Format**: Fixed 64 bytes (r || s, big-endian, not DER-encoded)

### Operations

#### Sign

```text
SIGN(message, private_key) -> signature

Input:
  message: arbitrary-length byte string
  private_key: P256 private key (32 bytes)

Output:
  signature: 64 bytes (r || s)

Process:
  1. Compute digest = SHA-256(message)
  2. Generate signature (r, s) per RFC 6979 deterministic ECDSA
  3. Return r || s (each 32 bytes, big-endian)
```

#### Verify

```text
VERIFY(message, signature, public_key) -> result

Input:
  message: arbitrary-length byte string
  signature: 64 bytes (r || s)
  public_key: P256 public key (65 bytes, SEC1 uncompressed)

Output:
  result: success or error

Process:
  1. Parse signature as (r, s) where r = signature[0..32], s = signature[32..64]
  2. Validate r and s are in range [1, n-1] where n is the curve order
  3. Compute digest = SHA-256(message)
  4. Perform ECDSA verification
  5. Return success if valid, error otherwise
```

## 2. P256 HPKE

### Purpose

Public key encryption using [ECDH](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) key agreement combined with [AES-GCM-256](https://csrc.nist.gov/publications/detail/sp/800-38d/final) authenticated encryption.

### Algorithm Overview

The HPKE scheme is custom. This is a historical artifact rather than an intentional design choice.

Both recipient and sender must use valid P256 keys for ECDH.

1. Generate ephemeral ECDH key pair
2. Perform ECDH with recipient's public key
3. Derive symmetric key using HMAC-SHA512
4. Encrypt with AES-GCM-256

### Constants

```text
QOS_ENCRYPTION_HMAC_MESSAGE = b"qos_encryption_hmac_message"
NONCE_LEN = 12 bytes
AES_KEY_LEN = 32 bytes
```

### Envelope Format

Serialized using Borsh encoding:

```text
Envelope {
  nonce: [u8; 12],                    // Random nonce for AES-GCM-256
  ephemeral_sender_public: [u8; 65],  // Sender's ephemeral public key (SEC1 uncompressed)
  encrypted_message: Vec<u8>,         // Ciphertext with 16-byte auth tag
}
```

### Operations

#### Encrypt

```text
ENCRYPT(plaintext, receiver_public) -> envelope

Input:
  plaintext: arbitrary-length byte string
  receiver_public: P256 public key (65 bytes, SEC1 uncompressed)

Output:
  envelope: Borsh-serialized Envelope

Process:
  1. Generate ephemeral NIST P-256 key pair:
     ephemeral_private = random P256 scalar
     ephemeral_public = ephemeral_private * G

  2. Compute ECDH shared secret:
     shared_secret = ECDH(ephemeral_private, receiver_public)
     // shared_secret is the x-coordinate of the resulting point (32 bytes, per SEC 1)

  3. Derive cipher key:
     pre_image = ephemeral_public || receiver_public || shared_secret
     mac_output = HMAC-SHA512(key=pre_image, message=QOS_ENCRYPTION_HMAC_MESSAGE)
     cipher_key = mac_output[0..32]
     // Note: This custom HMAC-based key derivation is a historical artifact.
     // HMAC-SHA512 with high-entropy input provides adequate key derivation.

  4. Compute additional associated data:
     aad = ephemeral_public || 0x41 || receiver_public || 0x41
     // Note: lengths are appended after each field rather than prepended.
     // This differs from NIST SP 800-56Ar3 5.8.2 which specifies len || data.
     // The ordering is a historical artifact. This is safe because:
     // (1) AAD is never transmitted: both parties derive it from shared context
     // (2) Since both parties compute AAD deterministically from shared context, there's no parsing attack surface

  5. Generate random nonce:
     nonce = random 12 bytes

  6. Encrypt:
     ciphertext = AES-GCM-256.Encrypt(cipher_key, nonce, plaintext, aad)

  7. Return Envelope { nonce, ephemeral_public, ciphertext }
```

#### Decrypt

```text
DECRYPT(envelope, receiver_private) -> plaintext

Input:
  envelope: Borsh-serialized Envelope
  receiver_private: P256 private key (32 bytes)

Output:
  plaintext: decrypted message

Process:
  1. Parse Envelope { nonce, ephemeral_public, ciphertext }

  2. Validate that ephemeral_public is a valid SEC1 point

  3. Compute ECDH shared secret:
     shared_secret = ECDH(receiver_private, ephemeral_public)
     // shared_secret is the x-coordinate of the resulting point (32 bytes, per SEC 1)

  4. Derive cipher key (same as encryption):
     receiver_public = receiver_private * G
     pre_image = ephemeral_public || receiver_public || shared_secret
     mac_output = HMAC-SHA512(key=pre_image, message=QOS_ENCRYPTION_HMAC_MESSAGE)
     cipher_key = mac_output[0..32]

  5. Compute AAD (same as encryption):
     aad = ephemeral_public || 0x41 || receiver_public || 0x41

  6. Decrypt:
     plaintext = AES-GCM-256.Decrypt(cipher_key, nonce, ciphertext, aad)

  7. Return plaintext (or error if authentication fails)
```

## 3. AES-GCM-256 Symmetric Encryption

### Purpose

Symmetric authenticated encryption for data at rest.

### Algorithm

- **Cipher**: AES-GCM-256
- **Key Size**: 32 bytes (256 bits)
- **Nonce Size**: 12 bytes (96 bits)
- **Tag Size**: 16 bytes (128 bits)

### Constants

```text
AES_GCM_256_HMAC_SHA512_TAG = b"qos_aes_gcm_256_hmac_sha512" (Naming for historical reasons, used as AAD)
AES_GCM_256_KEY_ID_INFO = b"AES_GCM_256_KEY_ID"
```

### Envelope Format

Serialized using Borsh encoding:

```text
SymmetricEnvelope {
  nonce: [u8; 12],           // Random nonce
  encrypted_message: Vec<u8>, // Ciphertext with 16-byte auth tag
}
```

### Operations

#### Encrypt

```text
AES_ENCRYPT(plaintext, secret) -> envelope

Input:
  plaintext: arbitrary-length byte string
  secret: 32-byte AES key

Output:
  envelope: Borsh-serialized SymmetricEnvelope

Process:
  1. Generate random nonce (12 bytes)
  2. aad = AES_GCM_256_HMAC_SHA512_TAG
  3. ciphertext = AES-GCM-256.Encrypt(secret, nonce, plaintext, aad)
  4. Return SymmetricEnvelope { nonce, ciphertext }
```

#### Decrypt

```text
AES_DECRYPT(envelope, secret) -> plaintext

Input:
  envelope: Borsh-serialized SymmetricEnvelope
  secret: 32-byte AES key

Output:
  plaintext: decrypted message

Process:
  1. Parse SymmetricEnvelope { nonce, ciphertext }
  2. aad = AES_GCM_256_HMAC_SHA512_TAG
  3. plaintext = AES-GCM-256.Decrypt(secret, nonce, ciphertext, aad)
  4. Return plaintext (or error if authentication fails)
```

### AES GCM 256 Key Identifier

A non-secret identifier derived from the AES GCM 256 key using HKDF-SHA256 for key management purposes. This identifier allows key management systems to reference and compare keys without exposing the secret material.

_Note:_ While historically we have used HKDF-SHA512, going forward we intend to standardize on HKDF-SHA256 since it is more standard among modern cryptography protocols.

```text
AES_GCM_256_KEY_ID(secret) -> identifier

Input:
  secret: 32-byte AES key

Output:
  identifier: 32-byte key identifier

Process:
  1. prk = HKDF-SHA256-Extract(salt=empty, ikm=secret)
  2. identifier = HKDF-SHA256-Expand(prk, info=AES_GCM_256_KEY_ID_INFO, length=32)
  3. Return identifier
```

## 4. Secret Management

### Overview

The QOS system supports two secret formats for storing the three cryptographic keys:

- **V0**: Single 32-byte master seed from which all three secrets are derived.
- **V1**: Three independent secrets stored explicitly

### V0 Format (Master Seed)

A single 32-byte master seed from which all three secrets are derived.

#### Derivation

All secrets are derived using HKDF-SHA512 with domain-specific salts:

```text
DERIVE_SECRET(seed, path) -> secret

Input:
  seed: 32-byte master seed
  path: domain separator byte string

Output:
  secret: 32-byte derived secret

Process:
  1. hkdf = HKDF-SHA512(salt=path, ikm=seed)
  2. secret = hkdf.expand(info=b"", length=32)
  3. Return secret
```

#### Salt Paths

- Signing: `b"qos_p256_sign"`
- HPKE: `b"qos_p256_encrypt"` (historical terminology, retained for V0 compatibility)
- AES-GCM-256: `b"qos_aes_gcm_encrypt"`

### V1 Format (Explicit Secrets)

Three independent 32-byte secrets stored with a version byte prefix.

#### Layout

```text
┌─────────┬────────────────┬──────────────┬──────────────--------┐
│ version │ hpke_secret    │ sign_secret  │ aes_gcm_256_secret   │
│ 1 byte  │ 32 bytes       │ 32 bytes     │ 32 bytes             │
└─────────┴────────────────┴──────────────┴─────────────--------─┘
Total: 97 bytes
```

#### Version Byte

```text
SECRET_V1 = 0x01
```

#### Secret Extraction

```text
Offset  Size  Content
0       1     Version byte (0x01 for V1)
1       32    hpke_secret
33      32    sign_secret
65      32    aes_gcm_256_secret
```

### Version Detection

```text
PARSE_SECRET(bytes) -> VersionedSecret | Error

Input:
  bytes: arbitrary-length byte string

Output:
  VersionedSecret or parsing error

Process:
  1. If len(bytes) == 97 AND bytes[0] == SECRET_V1:
       a. Validate hpke_secret and sign_secret are valid P256 scalars
       b. Return V1(bytes)
  2. Else if len(bytes) == 32:
       Return V0(bytes)
  3. Else:
       Return Error (invalid secret format)
```

### Design Rationale

**V0 Advantages:**
- Compact storage (32 bytes)
- Single secret to backup
- All keys cryptographically linked since they are derived from single seed

**V1 Advantages:**
- Easier integration with external key management

## 5. Quorum Key Identifier

### Overview

An identifier for a complete Quorum Key Set, suitable for key management and verification.

### V0 Format (QuorumKeyV0Public)

Two uncompressed P256 public keys concatenated.

#### Layout

```text
┌─────────────────────┬───────────────────┐
│ hpke_public         │ sign_public       │
│ 65 bytes (SEC1)     │ 65 bytes (SEC1)   │
└─────────────────────┴───────────────────┘
Total: 130 bytes
```

_Note:_ V0 does not include an AES GCM 256 key identifier. This was acceptable when all secrets were derived from a single master seed (V0 secret format).

### V1 Format (QuorumKeyId)

Uncompressed public keys plus AES GCM 256 key identifier, with a version byte prefix.

#### Layout

```text
┌─────────┬───────────────────┬───────────────────┬──────────────--------┐
│ version │ hpke_public       │ sign_public       │ aes_gcm_256_key_id   │
│ 1 byte  │ 65 bytes (SEC1)   │ 65 bytes (SEC1)   │ 32 bytes             │
└─────────┴───────────────────┴───────────────────┴─────────────--------─┘
Total: 163 bytes
```

#### Version Byte

```text
QUORUM_KEY_ID_V1 = 0x01
```

#### Field Definitions

| Field | Offset | Size | Format |
|-------|--------|------|--------|
| version | 0 | 1 | Version byte (0x01 for V1) |
| hpke_public | 1 | 65 | SEC1 uncompressed |
| sign_public | 66 | 65 | SEC1 uncompressed |
| aes_gcm_256_key_id | 131 | 32 | HKDF-SHA256 derived identifier |

#### Construction

```text
QUORUM_KEY_ID(hpke_pub, sign_pub, aes_gcm_256_secret) -> key_id

Process:
  1. version = 0x01                                                 // 1 byte
  2. hpke_uncompressed = SEC1_Uncompressed(hpke_pub)                // 65 bytes
  3. sign_uncompressed = SEC1_Uncompressed(sign_pub)                // 65 bytes
  4. aes_gcm_256_key_id = AES_GCM_256_KEY_ID(aes_gcm_256_secret)    // 32 bytes
  5. Return version || hpke_uncompressed || sign_uncompressed || aes_gcm_256_key_id
```

### Version Detection

```text
PARSE_QUORUM_KEY_ID(bytes) -> VersionedQuorumKeyId | Error

Input:
  bytes: arbitrary-length byte string

Output:
  VersionedQuorumKeyId or parsing error

Process:
  1. If len(bytes) == 163 AND bytes[0] == QUORUM_KEY_ID_V1:
       a. Validate hpke_public and sign_public are valid SEC1 uncompressed P256 points
       b. Return V1(bytes)
  2. Else if len(bytes) == 130:
       a. Validate hpke_public and sign_public are valid SEC1 uncompressed P256 points
       b. Return V0(bytes)
  3. Else:
       Return Error (invalid quorum key id format)
```

### Fingerprint

A compact 32-byte identifier for a QuorumKeyId.

**Rationale:** Hashing the entire QuorumKeyId ensures integrity of all components as a unit. This makes it easy to verify the complete key set and detect if any component has been modified or substituted. We chose SHA256 instead of an HKDF since SHA256 is more easily available for a variety of clients.

```text
QUORUM_KEY_FINGERPRINT(bytes) -> fingerprint

Input:
  bytes: 130-byte or 163-byte QuorumKeyId

Output:
  fingerprint: 32-byte identifier

Process:
  1. If PARSE_QUORUM_KEY_ID(bytes) == Error:
      Return Error (invalid quorum key id format)
  2. fingerprint = SHA-256(bytes)
  3. Return fingerprint
```

# QOS Key Set Specification

This document provides a formal specification for the cryptographic key schemes of the QOS Key Set.

The QOS Key Set is a collection of 3 cryptographic key schemes that comprise what is commonly referred to as a [Quorum Key](../../README.md#quorum-key). Additionally, 2 of the schemes, P256 Signing and P256 HPKE, are used by [Operators](../../README.md#operator).

Currently, the canon implementation lives in the `qos_p256` crate.

## Overview

A QOS Key Set consists of three cryptographically linked keys derived from a single master seed:

1. **P256 Signing Key** - ECDSA signatures for authentication
2. **P256 HPKE Key** - Hybrid public key encryption (ECDH + AES-GCM)
3. **AES-GCM-256 Key** - Symmetric encryption for data at rest

## 1. P256 Signing Key

### Purpose

Digital signatures for message authentication using NIST P-256 (secp256r1) ECDSA.

### Algorithm

- **Curve**: NIST P-256 (secp256r1)
- **Signature Scheme**: ECDSA with SHA-256 digest
- **Signature Generation**: Deterministic per RFC 6979

## 2. P256 HPKE

### Purpose

Public key encryption using ECDH key agreement combined with AES-GCM-256 authenticated encryption.

### Algorithm Overview

The HPKE scheme is custom, which is a historical artifact and not for any specific reason.

1. Generate ephemeral ECDH key pair
2. Perform ECDH with recipient's public key
3. Derive symmetric key using HMAC-SHA512
4. Encrypt with AES-GCM-256

### Constants

```
QOS_ENCRYPTION_HMAC_MESSAGE = b"qos_encryption_hmac_message"
NONCE_LEN = 12 bytes
AES_KEY_LEN = 32 bytes
```

### Envelope Format

Serialized using Borsh encoding:

```
Envelope {
  nonce: [u8; 12],                    // Random nonce for AES-GCM-256
  ephemeral_sender_public: [u8; 65],  // Sender's ephemeral public key (SEC1 uncompressed)
  encrypted_message: Vec<u8>,         // Ciphertext with 16-byte auth tag
}
```

### Operations

#### Encrypt

```
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

  3. Derive cipher key:
     pre_image = ephemeral_public || receiver_public || shared_secret
     mac_output = HMAC-SHA512(key=pre_image, message=QOS_ENCRYPTION_HMAC_MESSAGE)
     cipher_key = mac_output[0..32]

  4. Compute additional associated data:
     aad = ephemeral_public || len(ephemeral_public) || receiver_public || len(receiver_public)
     // Note: lengths are appended after each field rather than prepended.
     // This differs from NIST SP 800-56Ar3 5.8.2 which specifies len || data.
     // The ordering is a historical artifact, not intentional.
     // lengths are single bytes (0x41 = 65).
     // This is not an issue because the AAD is never parsed and is instead computed.

  5. Generate random nonce:
     nonce = random 12 bytes

  6. Encrypt:
     ciphertext = AES-GCM-256.Encrypt(cipher_key, nonce, plaintext, aad)

  7. Return Envelope { nonce, ephemeral_public, ciphertext }
```

#### Decrypt

```
DECRYPT(envelope, receiver_private) -> plaintext

Input:
  envelope: Borsh-serialized Envelope
  receiver_private: P256 private key (32 bytes)

Output:
  plaintext: decrypted message

Process:
  1. Parse Envelope { nonce, ephemeral_public, ciphertext }

  2. Validate ephemeral_public is a valid SEC1 point

  3. Compute ECDH shared secret:
     shared_secret = ECDH(receiver_private, ephemeral_public)

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

```
AES_GCM_256_HMAC_SHA512_TAG = b"qos_aes_gcm_256_hmac_sha512"
```

### Envelope Format

Serialized using Borsh encoding:

```
SymmetricEnvelope {
  nonce: [u8; 12],           // Random nonce
  encrypted_message: Vec<u8>, // Ciphertext with 16-byte auth tag
}
```

### Operations

#### Encrypt

```
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

```
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

## 4. Secret Management

### Overview

A single 32-byte master seed from which all three secrets are derived.

### Derivation

All secrets are derived using HKDF-SHA512 with domain-specific salts:

```
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

### Salt Paths

- Signing: `b"qos_p256_sign"`
- HPKE: `b"qos_p256_encrypt"`
- AES-GCM-256: `b"qos_aes_gcm_encrypt"`

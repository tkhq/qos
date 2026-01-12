# Protocol Buffer Encoding

QuorumOS uses Protocol Buffers (protobuf) for wire format encoding to enable cross-language interoperability. This document describes the encoding conventions and provides guidance for working with proto types.

## Overview

All protocol messages between the enclave, host, and client use protobuf encoding via the [prost](https://docs.rs/prost) library. The proto definitions are in [`proto/qos/v1/`](../../proto/qos/v1/) and the generated Rust types are in this crate.

## Deterministic Encoding

For cryptographic operations (hashing, signing), deterministic encoding is critical. QOS follows these rules:

1. **Field order**: Fields are serialized in ascending field number order (protobuf default)
2. **No map fields**: `map<>` fields are prohibited as their iteration order is undefined
3. **Optional fields**: Use `optional` for nullable fields
4. **Empty repeated fields**: Not serialized (protobuf default)

### ProtoHash Trait

The `ProtoHash` trait provides deterministic hashing for any proto type:

```ignore
use qos_proto::{Manifest, ProtoHash};

let manifest = Manifest::default();
let hash: [u8; 32] = manifest.proto_hash();
```

This encodes the message to protobuf bytes and computes SHA-256.

## Immutability Policy

Proto files are **immutable** once committed to main. This ensures backwards compatibility for signature verification - old messages can still be verified against signatures made with newer schemas.

If you need to make changes to proto definitions, create a new version directory (e.g., `proto/qos/v2/`).

## Regenerating Types

After adding new proto files, regenerate the Rust types:

```bash
# from the root of the repo
make proto-gen
```

# Protocol Buffer Encoding

QuorumOS uses Protocol Buffers (protobuf) for wire format encoding to enable cross-language interoperability. This document describes the encoding conventions and provides guidance for working with proto types.

## Overview

All protocol messages between the enclave, host, and client use protobuf encoding via the [prost](https://docs.rs/prost) library. The proto definitions are in [`proto/qos/v1/qos.proto`](../proto/qos/v1/qos.proto) and the generated Rust types are in the [`qos_proto`](../src/qos_proto/) crate.

## Deterministic Encoding

For cryptographic operations (hashing, signing), deterministic encoding is critical. QOS follows these rules:

1. **Field order**: Fields are serialized in ascending field number order (protobuf default)
2. **No map fields**: `map<>` fields are prohibited as their iteration order is undefined
3. **Optional fields**: Use `optional` for nullable fields
4. **Empty repeated fields**: Not serialized (protobuf default)

### ProtoHash Trait

The `ProtoHash` trait provides deterministic hashing for any proto type:

```rust
use qos_proto::{Manifest, ProtoHash};

let manifest = Manifest { /* ... */ };
let hash: [u8; 32] = manifest.proto_hash();
```

This encodes the message to protobuf bytes and computes SHA-256.

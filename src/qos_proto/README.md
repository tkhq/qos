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

## Backwards Compatible Hashing

Adding new fields to proto types can be done without breaking existing hashes, provided you follow these rules:

### Adding Optional Fields

When you add an `optional` field, existing messages (where the field is `None`) will hash identically to before:

```text
OldType { name: "test", nonce: 42 }
NewType { name: "test", nonce: 42, new_field: None }
         ↓                              ↓
   [same bytes]                   [same bytes]
         ↓                              ↓
     [same hash]   ==            [same hash]
```

### Adding Non-Optional Fields

Non-optional fields (without the `optional` keyword) also preserve hashes when set to their default value, because proto3 does not serialize default values:

```text
OldType { name: "test", nonce: 42 }
NewType { name: "test", nonce: 42, new_field: "" }  // empty = default
         ↓                              ↓
   [same bytes]                   [same bytes]  // default not serialized
         ↓                              ↓
     [same hash]   ==            [same hash]
```

### Key Difference: Optional vs Non-Optional

| Field Type | Value | Serialized? | Hash Changes? |
|------------|-------|-------------|---------------|
| `optional` | `None` | No | No |
| `optional` | `Some("")` | Yes | **Yes** |
| `optional` | `Some("value")` | Yes | **Yes** |
| non-optional | `""` (default) | No | No |
| non-optional | `"value"` | Yes | **Yes** |

The `optional` keyword allows distinguishing between "not set" (`None`) and "explicitly set to empty" (`Some("")`). Use `optional` when this distinction matters for your application logic.

## Schema Evolution Policy

Proto schemas can be evolved while maintaining backwards-compatible hashes, but certain changes are prohibited.

### Allowed Changes

- **Add new fields** (optional or non-optional with defaults)
- **Rename fields** (field names are not part of wire format)
- **Add new enum variants** (append only, don't change existing values)
- **Add doc comments**

### Prohibited Changes

These changes will break existing hashes and signatures:
- **Remove fields** - old messages would hash differently
- **Change field tag numbers** - completely breaks wire format
- **Change field types** - e.g., `string` → `bytes`
- **Reorder or renumber enum variants** - enum values are integers on wire
- **Change `optional` to non-optional** (or vice versa for some cases)

### When to Create a New Version

If you need to make a prohibited change, create a new version directory (e.g., `proto/qos/v2/`).

## Regenerating Types

After adding new proto files, regenerate the Rust types:

```bash
# from the root of the repo
make proto-gen
```

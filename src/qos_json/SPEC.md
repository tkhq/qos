# QOS Canonical JSON Specification

## Overview

This document defines the canonical JSON format used for serializing QOS types for signing and wire protocol communication. The format ensures deterministic serialization across languages.

## Rules

| Aspect | Rule | Note |
|--------|------|------|
| **Key order** | Alphabetically sorted (lexicographic) | deterministic |ordering of keys
| **Key naming** | camelCase |
| **Whitespace** | None (compact) |
| **Enums** | Externally tagged, camelCase |
| **Numbers** | Base-10 strings (e.g., `"3"` not `3`) | max int safety for javascript |
| **Binary data** | Lowercase hex-encoded strings |
| **Optional/None** | Omit field entirely | ensures older versions without field serialize the same way |
| **Unicode** | UTF-8, minimal escaping |
| **Depth limit** | Maximum 8 levels of nesting | minimize computational complexity |

## Test Vectors

### Simple Object with Numbers

**Input (conceptual):**
```
threshold: 3
version: 1
name: "test"
```

**Canonical JSON:**
```json
{"name":"test","threshold":"3","version":"1"}
```

**SHA-256 Hash:**
```
898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e
```

### Nested Object

**Input (conceptual):**
```
manifest: {
  namespace: "prod"
  version: 2
}
threshold: 3
```

**Canonical JSON:**
```json
{"manifest":{"namespace":"prod","version":"2"},"threshold":"3"}
```

### Binary Data (Hex Encoding)

**Input (conceptual):**
```
data: [0xde, 0xad, 0xbe, 0xef]
```

**Canonical JSON:**
```json
{"data":"deadbeef"}
```

### Externally Tagged Enum (Unit Variant)

**Rust:**
```rust
enum RestartPolicy { Never, Always }
let policy = RestartPolicy::Never;
```

**Canonical JSON:**
```json
"never"
```

### Externally Tagged Enum (Tuple Variant)

**Rust:**
```rust
enum BridgeConfig {
    Server(u16, String),
}
let config = BridgeConfig::Server(3000, "0.0.0.0".to_string());
```

**Canonical JSON:**
```json
{"server":["3000","0.0.0.0"]}
```

### Externally Tagged Enum (Struct Variant)

**Rust:**
```rust
enum Message {
    Request { id: u32, data: Vec<u8> }
}
let msg = Message::Request { id: 42, data: vec![0xab, 0xcd] };
```

**Canonical JSON:**
```json
{"request":{"data":"abcd","id":"42"}}
```

### Optional Field (None)

**Rust:**
```rust
struct Config {
    name: String,
    debug: Option<bool>,
}
let config = Config { name: "test".to_string(), debug: None };
```

**Canonical JSON:**
```json
{"name":"test"}
```

Note: The `debug` field is omitted entirely when `None`.

### Optional Field (Some)

**Rust:**
```rust
let config = Config { name: "test".to_string(), debug: Some(true) };
```

**Canonical JSON:**
```json
{"debug":true,"name":"test"}
```

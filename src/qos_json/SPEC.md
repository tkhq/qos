# QOS Canonical JSON

QOS uses JSON for protocol messages and signing payloads. QOS JSON is primarily
a canonicalization format for hashing/signing and verification, not a transport
format. Any JSON bytes that are hashed, signed, or verified MUST be
canonicalized using QOS-normalized
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)-style canonical JSON. QOS
intentionally differs from RFC 8785 by normalizing integer JSON numbers to
base-10 integer strings and rejecting non-integer numbers.

## Canonicalization

- Implementations MUST NOT hash or sign inbound JSON bytes directly.
- Inbound JSON used for hashing/signing MUST be parsed into the target schema
  type, then serialized with QOS canonical JSON.
- Semantically equivalent payloads MUST produce identical canonical bytes after
  deserialize-to-schema then serialize-to-QOS-JSON.
- QOS normalization treats object members with `null` values as unset fields
  and MUST omit those object members before canonicalization. Object field names
  provide domain separation, so omitting an unset field is safe. Other `null`
  values are preserved: top-level `null` is a complete JSON value, and null
  array elements are positional data that cannot be omitted without changing
  array length and indexes.
- JSON object properties MUST be sorted recursively by raw, unescaped property
  names encoded as UTF-16 code units, as specified by RFC 8785 section 3.2.3.
  This matters for non-ASCII names: for example, the RFC 8785 sample order is
  carriage return, `1`, U+0080, `ö`, `€`, grinning-face emoji, and U+FB33.
- Integer JSON number tokens MUST canonicalize as base-10 integer JSON strings:
  for example, `1` canonicalizes as `"1"` and `-42` canonicalizes as `"-42"`.
- Non-integer JSON number tokens (for example `1.0`, `1e3`, `-0.5`) MUST reject
  the entire deserialization/canonicalization operation. They are not coerced,
  rounded, or treated as absent optional values.

## Signing Object Schemas

- Each signing object MUST have a specified JSON schema. This specification
  defines canonical encoding rules.
- The schema for each signing object MUST specify object field names, enum
  representations, binary encodings, numeric encodings, and which fields are
  optional.
- Hashing/signing pipelines MUST be schema-first: deserialize inbound JSON to
  the schema type, then serialize with QOS JSON.
- Unset optional object fields are omitted by QOS canonicalization when they
  serialize as `null`. This supports append-friendly schemas: older and newer
  writers produce the same payload until the new field is populated. Rust
  schemas SHOULD use `#[serde(default)]` on optional fields that readers must
  accept when absent.
- Optional fields in QOS JSON schemas MUST also use
  `#[serde(skip_serializing_if = "Option::is_none")]` so absent values encode
  canonically as omitted object fields rather than explicit `null`.
- QOS canonicalization preserves empty arrays and empty objects. A signing
  object schema MAY specify type-specific serialization rules that omit an empty
  map/object field before canonicalization.
- New fields SHOULD be optional unless every deployed reader can tolerate the
  field.
- Public keys SHOULD be encoded as lowercase hex strings. This keeps key
  material more readable during review/audit and avoids introducing extra
  alphabet/format dependencies (for example SS58) into all implementations.
- Other binary values SHOULD be encoded as either lowercase hex strings or
  base64 strings, as specified by each signing object schema.
- Each signing object schema MUST explicitly specify the binary encoding used
  by each byte field and keep it stable for compatibility.
- Rust schemas SHOULD use `#[serde(with = "qos_hex::serde")]` for byte fields
  represented as hex. Base64-encoded byte fields SHOULD use an explicit serde
  adapter chosen by that schema.
- Enums SHOULD use serde's
  [externally tagged representation](https://serde.rs/enum-representations.html)
  unless the signing object schema explicitly specifies another representation.
- Numeric values in QOS JSON are specified as base-10 integer strings, such as
  `"0"`, `"42"`, and `"-7"`.
- Rust integer fields in QOS JSON structs SHOULD use
  `#[serde(with = "qos_json::string_or_numeric")]` to support decoding both
  string and numeric inputs.
- Floating point values MUST NOT be introduced into QOS signing payloads.

## Test Vectors

These vectors show the relevant schema pattern, canonical JSON, and SHA-256
hash. The Rust unit tests in `src/qos_json/src/lib.rs` exercise these vectors
and additional edge cases for null omission, array preservation, string
escaping, UTF-16 property ordering, typed/raw hash equivalence, numeric
normalization, and rejected non-integer JSON number tokens.

Schema: no fields.

```json
{}
```

SHA-256:
`44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`

Schema:

```rust
#[derive(serde::Serialize)]
struct Example {
    version: String,
    name: String,
    #[serde(with = "qos_json::string_or_numeric")]
    threshold: u32,
}
```

```json
{"name":"test","threshold":"3","version":"1"}
```

SHA-256:
`898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e`

Schema:

```rust
#[derive(serde::Serialize)]
struct Example {
    #[serde(with = "qos_hex::serde")]
    data: Vec<u8>,
}
```

```json
{"data":"deadbeef"}
```

SHA-256:
`03fe564ceddcb54a7a742bd7a4db57318a068cecd22ae44435ce68d35e754e13`

# QOS Canonical JSON

QOS uses JSON for protocol messages and signing payloads. Any JSON bytes that
are hashed, signed, or verified MUST be canonicalized using QOS-normalized RFC
8785-style canonical JSON. QOS intentionally differs from RFC 8785 by
normalizing integer JSON numbers to decimal strings and rejecting non-integer
numbers.

## Canonicalization

- Implementations MUST parse JSON into a JSON value and re-encode that value as
  QOS-normalized RFC 8785-style canonical JSON before hashing or signing.
- Implementations MUST NOT hash or sign raw inbound JSON bytes. Equivalent JSON
  documents can differ in whitespace or field order.
- Implementations that serialize typed values for hashing or signing MUST use
  the same canonical JSON encoding scheme used for parsed JSON values.
- QOS normalization treats object members with `null` values as unset fields
  and MUST omit those object members before canonicalization. This means typed
  optional fields that serialize as `null` are omitted by the canonical encoder.
  Other `null` values are preserved. In particular, null array elements are not
  omitted because that would change array length and indexes.
- JSON object properties MUST be sorted recursively by raw, unescaped property
  names encoded as UTF-16 code units, as specified by RFC 8785 section 3.2.3.
  This matters for non-ASCII names: for example, the RFC 8785 sample order is
  carriage return, `1`, U+0080, `ö`, `€`, grinning-face emoji, and U+FB33.
- Integer JSON number tokens MUST canonicalize as decimal JSON strings.
- Non-integer JSON number tokens (for example `1.0`, `1e3`, `-0.5`) MUST be
  rejected during canonical serialization.

## Signing Object Schemas

- Each signing object MUST have a specified JSON schema. This specification is
  not, by itself, a rule for choosing every field representation in every
  signing object.
- The schema for each signing object MUST specify object field names, enum
  representations, binary encodings, numeric encodings, and which fields are
  optional.
- Unset optional object fields are omitted by QOS canonicalization when they
  serialize as `null`. Rust schemas SHOULD use `#[serde(default)]` on optional
  fields that readers must accept when absent.
- Optional fields in QOS JSON schemas MUST also use
  `#[serde(skip_serializing_if = "Option::is_none")]` so absent values encode
  canonically as omitted object fields rather than explicit `null`.
- QOS canonicalization preserves empty arrays and empty objects. A signing
  object schema MAY specify type-specific serialization rules that omit an empty
  map/object field before canonicalization.
- New fields SHOULD be optional unless every deployed reader can tolerate the
  field. Append-friendly schemas rely on canonical null-member omission so older
  and newer writers produce the same payload until the new field is populated.
- Binary values SHOULD be lowercase hex strings unless the signing object schema
  explicitly specifies another representation. Rust schemas SHOULD use
  `#[serde(with = "qos_hex::serde")]` for byte fields represented this way.
- Enums SHOULD use serde's externally tagged representation unless the signing
  object schema explicitly specifies another representation.
- Numeric values in QOS JSON are specified as decimal strings.
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

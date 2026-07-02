# qos_hex

Utilities for encoding and decoding hex strings in QuorumOS crates.

Use `encode` and `encode_to_vec` to produce lowercase hex, and `decode`, `decode_to_buf`, `decode_from_vec`, or `FromHex` to decode hex into byte buffers, arrays, or vectors.

Enable the `serde` feature for `#[serde(with = "qos_hex::serde")]` helpers, including optional hex-encoded fields through `qos_hex::serde::option`.

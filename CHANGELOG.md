# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## `qos_client` - [0.5.1](https://github.com/tkhq/qos/compare/qos_client-v0.5.0...qos_client-v0.5.1) - 2026-03-12

### Other
- publish qos_test_primitives

## `qos_test_primitives` - [0.5.1](https://github.com/tkhq/qos/compare/qos_test_primitives-v0.5.0...qos_test_primitives-v0.5.1) - 2026-03-12

### Other
- publish qos_test_primitives
- Deny missing rust docs
- restart bridge if enclave is in a deployed state
- fix up tcp_pivot and add multi connection/accept tests
- try merge origin main

## `qos_net` - [0.5.1](https://github.com/tkhq/qos/compare/qos_net-v0.5.0...qos_net-v0.5.1) - 2026-03-12

### Other
- publish qos_test_primitives

## `qos_core` - [0.5.1](https://github.com/tkhq/qos/compare/qos_core-v0.5.0...qos_core-v0.5.1) - 2026-03-12

### Other
- publish qos_test_primitives

## `qos_p256` - [0.5.1](https://github.com/tkhq/qos/compare/qos_p256-v0.5.0...qos_p256-v0.5.1) - 2026-03-12

### Other
- publish qos_test_primitives

## `qos_core` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_core-v0.5.0) - 2026-02-28

### Added
- Async runtime with `tokio` and `tokio-vsock` — migrated the server, reaper, and I/O subsystem from synchronous to fully asynchronous ([#524](https://github.com/tkhq/qos/pull/524), [#583](https://github.com/tkhq/qos/pull/583))
- Dynamic resizing `StreamPool` with per-connection task spawning and configurable `max_connections` via semaphore ([#524](https://github.com/tkhq/qos/pull/524), [#596](https://github.com/tkhq/qos/pull/596))
- `HostBridge` for transparent VSOCK-to-TCP bridging, letting pivot applications use standard TCP without VSOCK awareness ([#596](https://github.com/tkhq/qos/pull/596))
- `BridgeConfig` in `PivotConfig` — configures bridge routing (server/client variants) as flat JSON ([#596](https://github.com/tkhq/qos/pull/596), [#631](https://github.com/tkhq/qos/pull/631))
- `pool_size` and `client_timeout` fields in Manifest, replacing pivot-args-based configuration ([#584](https://github.com/tkhq/qos/pull/584))
- `debug_mode` flag in `PivotConfig` to control output piping for pivot processes ([#596](https://github.com/tkhq/qos/pull/596))
- `StreamMode` for backward-compatible stream handling with legacy applications ([#524](https://github.com/tkhq/qos/pull/524))
- `PoolGuard` with `Mutex` on `SocketClient::call` for safe concurrent stream access ([#524](https://github.com/tkhq/qos/pull/524))
- `MAX_PAYLOAD_SIZE` (128 MiB) enforcement with gradual buffer allocation to prevent OOM ([#527](https://github.com/tkhq/qos/pull/527), [#582](https://github.com/tkhq/qos/pull/582))

### Changed
- Manifest, ManifestEnvelope, GenesisOutput, and QuorumKey serialization changed from Borsh to JSON (`*V0` types retained for backward compat) ([#594](https://github.com/tkhq/qos/pull/594), [#616](https://github.com/tkhq/qos/pull/616))
- `PivotConfig` restructured — `host_config` replaced with `bridge_config: Vec<BridgeConfig>`, old `PivotHostConfig` consolidated ([#596](https://github.com/tkhq/qos/pull/596), [#631](https://github.com/tkhq/qos/pull/631))
- Ephemeral keys rotated post-boot and retained for app proofs, improving forward secrecy ([#523](https://github.com/tkhq/qos/pull/523), [#571](https://github.com/tkhq/qos/pull/571))
- Quorum key written last during provisioning to prevent partially-provisioned state on interruption ([#523](https://github.com/tkhq/qos/pull/523))
- Removed `async` feature flags — async runtime unified into main code path ([#524](https://github.com/tkhq/qos/pull/524))
- Upgraded borsh from v0.1 to v1.0 ([#449](https://github.com/tkhq/qos/pull/449), [#458](https://github.com/tkhq/qos/pull/458), [#459](https://github.com/tkhq/qos/pull/459))
- MSRV raised to Rust 1.88 ([#524](https://github.com/tkhq/qos/pull/524), [#576](https://github.com/tkhq/qos/pull/576))

### Fixed
- Client reconnects no longer logged as errors ([#590](https://github.com/tkhq/qos/pull/590))
- `tcp_to_vsock` bridge listen loop could exit prematurely ([#596](https://github.com/tkhq/qos/pull/596))
- `HostBridge` now properly handles multiple connections on the same port ([#596](https://github.com/tkhq/qos/pull/596))
- Stream state cleanup in all error paths ([#524](https://github.com/tkhq/qos/pull/524), [#528](https://github.com/tkhq/qos/pull/528), [#583](https://github.com/tkhq/qos/pull/583))
- `ProtocolError` variants now include expected/actual values for debuggability ([#605](https://github.com/tkhq/qos/pull/605))

### Security
- Updated `rsa` crate for security patch ([#606](https://github.com/tkhq/qos/pull/606))
- Patched `bytes` crate ([#619](https://github.com/tkhq/qos/pull/619))

## `qos_client` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_client-v0.5.0) - 2026-02-28

### Added
- `json-to-borsh` CLI command for converting JSON-format Manifests back to Borsh ([#616](https://github.com/tkhq/qos/pull/616))
- `get-ephemeral-key-hex` CLI command to extract ephemeral public key from attestation documents ([#571](https://github.com/tkhq/qos/pull/571))
- Command list shown as default output when run with no arguments ([#591](https://github.com/tkhq/qos/pull/591))
- CLI arguments for `--pool-size` and `--client-timeout` ([#584](https://github.com/tkhq/qos/pull/584))
- Human approval check when setting socket pool size during manifest generation ([#589](https://github.com/tkhq/qos/pull/589))
- `generate_file_key` and `advanced_provision_yubikey` exported as public functions at crate root ([#581](https://github.com/tkhq/qos/pull/581))
- Bridge configuration CLI parsing (`--bridge-config`, `--app-host-port`) ([#596](https://github.com/tkhq/qos/pull/596))

### Changed
- Backward-compatible Manifest reading — auto-detects Borsh (`*V0`) vs JSON format ([#591](https://github.com/tkhq/qos/pull/591), [#596](https://github.com/tkhq/qos/pull/596))
- Removed `x509` crate dependency; simplified certificate name generation for Yubikey provisioning ([#564](https://github.com/tkhq/qos/pull/564))
- Updated `p256` crate to newer version ([#564](https://github.com/tkhq/qos/pull/564))
- Upgraded borsh from v0.1 to v1.0 ([#449](https://github.com/tkhq/qos/pull/449))

### Fixed
- Yubikey serial generation logic bug ([#564](https://github.com/tkhq/qos/pull/564))
- Deserialization errors now include detail context ([#620](https://github.com/tkhq/qos/pull/620))
- Filesystem write errors template the underlying OS error ([#593](https://github.com/tkhq/qos/pull/593))
- macOS dot-underscore (`._*`) files now ignored during directory traversal ([#628](https://github.com/tkhq/qos/pull/628))

## `qos_net` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_net-v0.5.0) - 2026-02-28

### Added
- Fully async `Proxy` implementation using tokio — each connection spawned as a separate task ([#524](https://github.com/tkhq/qos/pull/524))
- `max_connections` enforcement per proxy listener ([#524](https://github.com/tkhq/qos/pull/524))
- Maximum timeout (10s) bounding entire proxy request lifecycle ([#625](https://github.com/tkhq/qos/pull/625))
- `Drop` implementation on `ProxyStream` to properly close connections and prevent resource leaks ([#528](https://github.com/tkhq/qos/pull/528))
- Connection pool limit with `CloseRequest`/`CloseResponse` protocol ([#449](https://github.com/tkhq/qos/pull/449))

### Changed
- DNS resolver switched to `hickory-resolver` with full DNSSEC validation enabled ([#554](https://github.com/tkhq/qos/pull/554))
- Removed `async_proxy` feature flag — async proxy is now the only implementation ([#524](https://github.com/tkhq/qos/pull/524))
- Removed `connection_id` from all `Proxy` structs and messages ([#524](https://github.com/tkhq/qos/pull/524))
- Removed unused `ProxyMsg` variants (`ConnectionClosed`, `EmptyRead`) ([#449](https://github.com/tkhq/qos/pull/449), [#582](https://github.com/tkhq/qos/pull/582))
- Upgraded borsh from v0.1 to v1.0 ([#449](https://github.com/tkhq/qos/pull/449))

### Fixed
- Proxy error handling loop return bug ([#524](https://github.com/tkhq/qos/pull/524))
- `MAX_PAYLOAD_SIZE` enforcement on receive to prevent memory exhaustion ([#527](https://github.com/tkhq/qos/pull/527), [#582](https://github.com/tkhq/qos/pull/582))
- Connection ID collisions (switched to `u128` random IDs) ([#536](https://github.com/tkhq/qos/pull/536))
- CLI builds correctly without default features ([#504](https://github.com/tkhq/qos/pull/504))

### Security
- Full DNSSEC validation on all DNS lookups, preventing DNS spoofing ([#554](https://github.com/tkhq/qos/pull/554))
- Bumped `tracing-subscriber` to fix CVE-2025-58160 ([#587](https://github.com/tkhq/qos/pull/587))

## `qos_p256` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_p256-v0.5.0) - 2026-02-28

### Added
- Formal cryptographic specification (`SPEC.md`) for QOS Key Set covering P256 Signing, P256 HPKE, and AES-GCM-256 ([#598](https://github.com/tkhq/qos/pull/598))
- Cargo-fuzz test harnesses for coverage-guided testing ([#439](https://github.com/tkhq/qos/pull/439))

### Changed
- `P256SignPublic::from_bytes` and `P256EncryptPublic::from_bytes` now reject compressed SEC1 points (uncompressed 65-byte format only) ([#499](https://github.com/tkhq/qos/pull/499))
- File I/O errors now include the file path in error messages ([#593](https://github.com/tkhq/qos/pull/593))
- Upgraded borsh from v0.1 to v1.0 ([#449](https://github.com/tkhq/qos/pull/449))

## `qos_nsm` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_nsm-v0.5.0) - 2026-02-28

### Added
- Cargo-fuzz test harnesses for attestation document parsing and verification ([#514](https://github.com/tkhq/qos/pull/514))
- PCR0 mismatch logging with expected/actual values ([#524](https://github.com/tkhq/qos/pull/524))

### Changed
- `AttestError` variants (`DifferentUserData`, `DifferentPcr0/1/2/3`) now include `expected` and `actual` hex fields ([#605](https://github.com/tkhq/qos/pull/605))
- `InvalidPivotHash` error displays both expected and actual hash values ([#605](https://github.com/tkhq/qos/pull/605))
- Updated to `aws-nitro-enclaves-nsm-api` 0.4 ([#505](https://github.com/tkhq/qos/pull/505))
- Upgraded borsh from v0.1 to v1.0 ([#449](https://github.com/tkhq/qos/pull/449))

## `qos_hex` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_hex-v0.5.0) - 2026-02-28

### Fixed
- Corrected hex encoding/decoding logic ([#576](https://github.com/tkhq/qos/pull/576))

### Changed
- `unsafe` code denied at crate level ([#576](https://github.com/tkhq/qos/pull/576))
- Missing rust docs enforced ([#621](https://github.com/tkhq/qos/pull/621))

## `qos_crypto` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_crypto-v0.5.0) - 2026-02-28

### Added
- Cargo-fuzz test harnesses for Shamir secret sharing functionality ([#441](https://github.com/tkhq/qos/pull/441))

### Changed
- Switched to `vsss-rs` 5.1 for share generation/reconstruction with `zeroize` enabled (secret shares securely cleared from memory) ([#502](https://github.com/tkhq/qos/pull/502))
- Removed unused RSA key material ([#490](https://github.com/tkhq/qos/pull/490))

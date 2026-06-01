# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## `qos_net` - [0.10.0](https://github.com/tkhq/qos/compare/qos_net-v0.9.0...qos_net-v0.10.0) - 2026-06-01

### Changed
- [**breaking**] Removed the `vm` Cargo feature flag and now select macOS-compatible local socket behavior from `target_os = "macos"` at compile time. ([#714](https://github.com/tkhq/qos/pull/714))

## `qos_core` - [0.10.0](https://github.com/tkhq/qos/compare/qos_core-v0.9.0...qos_core-v0.10.0) - 2026-06-01

### Changed
- [**breaking**] Removed the `vm` Cargo feature flag and now select vsock-vs-Unix-socket behavior from the compile target: macOS builds use Unix sockets and non-macOS builds use vsock. ([#714](https://github.com/tkhq/qos/pull/714))

## `qos_client` - [0.9.0](https://github.com/tkhq/qos/compare/qos_client-v0.8.0...qos_client-v0.9.0) - 2026-05-28

### Fixed
- Restored compatibility for key-forwarding and key-export flows that use v0/v1 manifest envelopes by trying the legacy Borsh protocol encoding first, then falling back to JSON. v2 manifest envelopes remain JSON-only. ([#718](https://github.com/tkhq/qos/pull/718))

### Security
- Zeroized YubiKey PINs, Shamir split/reconstruct inputs, and decrypted plaintext handled by the CLI to reduce the lifetime of sensitive material in memory. ([#711](https://github.com/tkhq/qos/pull/711))

## `qos_core` - [0.9.0](https://github.com/tkhq/qos/compare/qos_core-v0.8.0...qos_core-v0.9.0) - 2026-05-28

### Fixed
- Preserved the legacy Borsh discriminant for `ProtocolError::ProtocolMsgDeserialization` by moving the newer `InvalidPivotEnv` variant to the end of the enum. ([#718](https://github.com/tkhq/qos/pull/718))

### Security
- Zeroized quorum key material, decrypted key shares, and reconstructed Shamir secrets during genesis, provisioning, and key-injection flows. ([#711](https://github.com/tkhq/qos/pull/711))

## `qos_p256` - [0.9.0](https://github.com/tkhq/qos/compare/qos_p256-v0.8.0...qos_p256-v0.9.0) - 2026-05-28

### Changed
- Updated P256 secret-handling APIs to accept or return `Zeroizing` wrappers for master seeds, derived signing/encryption secrets, and decrypted plaintext. ([#711](https://github.com/tkhq/qos/pull/711))

## `qos_crypto` - [0.9.0](https://github.com/tkhq/qos/compare/qos_crypto-v0.8.0...qos_crypto-v0.9.0) - 2026-05-28

### Changed
- Updated Shamir secret-sharing helpers so generated shares and reconstructed secrets are wrapped in `Zeroizing`, while retaining compatibility with existing share data. ([#711](https://github.com/tkhq/qos/pull/711))

## `qos_hex` - [0.9.0](https://github.com/tkhq/qos/compare/qos_hex-v0.8.0...qos_hex-v0.9.0) - 2026-05-28

### Other
- No user-facing changes; released as part of the coordinated `0.9.0` workspace version.

## `qos_net` - [0.9.0](https://github.com/tkhq/qos/compare/qos_net-v0.8.0...qos_net-v0.9.0) - 2026-05-28

### Other
- No user-facing changes; released as part of the coordinated `0.9.0` workspace version.

## `qos_nsm` - [0.9.0](https://github.com/tkhq/qos/compare/qos_nsm-v0.8.0...qos_nsm-v0.9.0) - 2026-05-28

### Other
- No user-facing changes; released as part of the coordinated `0.9.0` workspace version.

## `qos_test_primitives` - [0.9.0](https://github.com/tkhq/qos/compare/qos_test_primitives-v0.8.0...qos_test_primitives-v0.9.0) - 2026-05-28

### Other
- No user-facing changes; released as part of the coordinated `0.9.0` workspace version.

## `qos_json` - [0.9.0](https://github.com/tkhq/qos/compare/qos_json-v0.8.0...qos_json-v0.9.0) - 2026-05-28

### Other
- No user-facing changes; released as part of the coordinated `0.9.0` workspace version.

## `qos_client` - [0.8.0](https://github.com/tkhq/qos/compare/qos_client-v0.7.0...qos_client-v0.8.0) - 2026-05-17

### Added
- Added support for both JSON and Borsh wire formats, QOS JSON manifest v2 signing payloads, and legacy manifest decoding while preserving v0/v1 manifest compatibility ([#697](https://github.com/tkhq/qos/pull/697))
- Added `enclave-version` to query a running enclave for its QOS version and build commit ([#689](https://github.com/tkhq/qos/pull/689))
- Added pivot environment variable support ([#674](https://github.com/tkhq/qos/pull/674), [#685](https://github.com/tkhq/qos/pull/685))

### Changed
- Moved the Cargo workspace manifest from `src/Cargo.toml` to the repository root ([#686](https://github.com/tkhq/qos/pull/686))
- Upgraded the crate to Rust 2024 edition and the workspace Rust toolchain to 1.94 ([#696](https://github.com/tkhq/qos/pull/696), [#700](https://github.com/tkhq/qos/pull/700))
- Enforced `clippy::pedantic` and filled in missing public API docs required by the stricter lint set ([#676](https://github.com/tkhq/qos/pull/676))

### Other
- Added and normalized user-facing docs for networking, boot standard, key forwarding, YubiKey provisioning, and related README content ([#675](https://github.com/tkhq/qos/pull/675), [#678](https://github.com/tkhq/qos/pull/678), [#679](https://github.com/tkhq/qos/pull/679), [#681](https://github.com/tkhq/qos/pull/681), [#692](https://github.com/tkhq/qos/pull/692))

## `qos_test_primitives` - [0.8.0](https://github.com/tkhq/qos/compare/qos_test_primitives-v0.7.0...qos_test_primitives-v0.8.0) - 2026-05-17

### Added
- Made `PathWrapper` generic over `AsRef<Path>`, made `ChildWrapper` deref/future-friendly, and generalized socket wait helpers ([#689](https://github.com/tkhq/qos/pull/689))

### Fixed
- Fixed port selection by binding to available ports and checking TCP readiness by connecting instead of attempting to bind again ([#673](https://github.com/tkhq/qos/pull/673))

### Other
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

## `qos_net` - [0.8.0](https://github.com/tkhq/qos/compare/qos_net-v0.7.0...qos_net-v0.8.0) - 2026-05-17

### Changed
- Enforced `clippy::pedantic`, cleaned up proxy documentation/lints, and removed unnecessary async from bridge helpers that only spawn work ([#676](https://github.com/tkhq/qos/pull/676))
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

### Other
- Cleaned up fuzz-target lints and removed Docker requirements from CI ([#670](https://github.com/tkhq/qos/pull/670), [#688](https://github.com/tkhq/qos/pull/688))

## `qos_core` - [0.8.0](https://github.com/tkhq/qos/compare/qos_core-v0.7.0...qos_core-v0.8.0) - 2026-05-17

### Added
- Added support for both JSON and Borsh wire formats, including QOS JSON manifest v2, JSON protocol envelope handling, `BootStandardJsonEnvelopeRequest`, and compatibility-preserving parsing for existing v0/v1 manifests ([#697](https://github.com/tkhq/qos/pull/697))
- Added `VersionRequest` and `VersionResponse { version, commit }` protocol messages, registered across all phases, plus build-time commit capture via `QOS_GIT_COMMIT` or `git rev-parse` fallback ([#689](https://github.com/tkhq/qos/pull/689))
- Added pivot environment variable support ([#674](https://github.com/tkhq/qos/pull/674))

### Fixed
- Preserved manifest signing-payload compatibility for pivot environment variables after the initial breaking manifest change ([#685](https://github.com/tkhq/qos/pull/685))
- Moved synchronous protocol handling behind `tokio::task::block_in_place` ([#671](https://github.com/tkhq/qos/pull/671))
- Avoided undrained pivot stdout/stderr pipes by using `Stdio::null()` unless pivot debug mode is enabled ([#693](https://github.com/tkhq/qos/pull/693))

### Changed
- Moved the Cargo workspace manifest to the repository root and updated workspace paths ([#686](https://github.com/tkhq/qos/pull/686))
- Upgraded to Rust 2024 edition and Rust 1.94, including match-ergonomics and lint cleanups required by the newer toolchain ([#696](https://github.com/tkhq/qos/pull/696), [#700](https://github.com/tkhq/qos/pull/700))
- Enforced `clippy::pedantic`, removed unnecessary async from spawn-only helpers, and improved attestation validation ([#676](https://github.com/tkhq/qos/pull/676))

## `qos_p256` - [0.8.0](https://github.com/tkhq/qos/compare/qos_p256-v0.7.0...qos_p256-v0.8.0) - 2026-05-17

### Added
- Added `serde` support for `P256Error` so P256 errors can participate in JSON protocol and manifest payloads ([#697](https://github.com/tkhq/qos/pull/697))

### Changed
- Enforced `clippy::pedantic`, cleaned up fuzz-target lints, and added the missing public API error/panic documentation required by the stricter lint set ([#670](https://github.com/tkhq/qos/pull/670), [#676](https://github.com/tkhq/qos/pull/676))
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

## `qos_nsm` - [0.8.0](https://github.com/tkhq/qos/compare/qos_nsm-v0.7.0...qos_nsm-v0.8.0) - 2026-05-17

### Added
- Added `serde` support for NSM request/response/error types so they can be represented in JSON protocol payloads ([#697](https://github.com/tkhq/qos/pull/697))

### Changed
- Enforced `clippy::pedantic` and improved Nitro attestation syntactic validation ([#676](https://github.com/tkhq/qos/pull/676))
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

## `qos_json` - [0.8.0](https://github.com/tkhq/qos/compare/qos_json-v0.7.0...qos_json-v0.8.0) - 2026-05-17

### Added
- Added the `qos_json` crate with a canonical JSON format and spec for signing payloads, including stricter encoding rules than generic JSON canonicalization ([#697](https://github.com/tkhq/qos/pull/697))

## `qos_hex` - [0.8.0](https://github.com/tkhq/qos/compare/qos_hex-v0.7.0...qos_hex-v0.8.0) - 2026-05-17

### Added
- Added serde helpers for optional hex-encoded byte values used by JSON protocol and manifest payloads ([#697](https://github.com/tkhq/qos/pull/697))

### Changed
- Enforced `clippy::pedantic`, added missing error/panic docs, removed the largest fixed-size `FromHex` array impl, and made ASCII validation take bytes by value ([#676](https://github.com/tkhq/qos/pull/676))
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

## `qos_crypto` - [0.8.0](https://github.com/tkhq/qos/compare/qos_crypto-v0.7.0...qos_crypto-v0.8.0) - 2026-05-17

### Changed
- Enforced `clippy::pedantic`, cleaned up fuzz-target lints, and added missing error documentation for public crypto APIs ([#670](https://github.com/tkhq/qos/pull/670), [#676](https://github.com/tkhq/qos/pull/676))
- Upgraded to Rust 2024 edition ([#700](https://github.com/tkhq/qos/pull/700))

### Security
- Bumped dependencies with known security or soundness issues, including `rand`, `rustls-webpki`, and `openssl` transitive lockfile updates ([#690](https://github.com/tkhq/qos/pull/690))

## `qos_core` - [0.7.0](https://github.com/tkhq/qos/compare/qos_core-v0.6.1...qos_core-v0.7.0) - 2026-04-16

### Changed
- [**breaking**] Removed `Arc<RwLock<>>` wrapping from `ProtocolProcessor` — the processor is now `Clone` and passed by value, eliminating a read-lock acquisition on every incoming request ([#660](https://github.com/tkhq/qos/pull/660))
- [**breaking**] Removed `SharedProcessor<P>` type alias; `SocketServer::listen_all` and `listen_to` now take `P: RequestProcessor + Clone` instead of `&SharedProcessor<P>` ([#660](https://github.com/tkhq/qos/pull/660))
- Added blanket `RequestProcessor` impl for any `T: Deref<Target = U>` where `U: RequestProcessor` ([#660](https://github.com/tkhq/qos/pull/660))
- `EphemeralKeyHandle` is now generic over `P: AsRef<Path>` and derives `Copy` ([#660](https://github.com/tkhq/qos/pull/660))

- Adhere closer to clippy::pedantic

## `qos_p256` - [0.7.0](https://github.com/tkhq/qos/compare/qos_p256-v0.6.1...qos_p256-v0.7.0) - 2026-04-16

### Changed
- Added `#[must_use]` to `P256Pair::encryption_key()` ([#658](https://github.com/tkhq/qos/pull/658))
- Adhere closer to clippy::pedantic

## `qos_host` - 0.7.0 - 2026-04-16

### Added
- `/enclave-info` endpoint now returns the ephemeral public key extracted from the live attestation document ([#659](https://github.com/tkhq/qos/pull/659))

## `qos_client` - [0.7.0](https://github.com/tkhq/qos/compare/qos_client-v0.6.1...qos_client-v0.7.0) - 2026-04-16

### Changed
- Adhere closer to clippy::pedantic

## `qos_net` - [0.7.0](https://github.com/tkhq/qos/compare/qos_net-v0.6.1...qos_net-v0.7.0) - 2026-04-16

### Changed
- Adhere closer to clippy::pedantic

## `qos_nsm` - [0.7.0](https://github.com/tkhq/qos/compare/qos_nsm-v0.6.1...qos_nsm-v0.7.0) - 2026-04-16

### Changed
- Adhere closer to clippy::pedantic

## `qos_hex` - [0.7.0](https://github.com/tkhq/qos/compare/qos_hex-v0.6.1...qos_hex-v0.7.0) - 2026-04-16

### Changed
- Adhere closer to clippy::pedantic

## `qos_test_primitives` - [0.7.0](https://github.com/tkhq/qos/compare/qos_test_primitives-v0.6.1...qos_test_primitives-v0.7.0) - 2026-04-16

### Changed
- Adhere closer to clippy::pedantic

## `qos_client` - [0.6.1](https://github.com/tkhq/qos/compare/qos_client-v0.5.0...qos_client-v0.6.1) - 2026-04-09

### Other
- publish qos_test_primitives

## `qos_core` - [0.6.1](https://github.com/tkhq/qos/compare/qos_core-v0.6.0...qos_core-v0.6.1) - 2026-04-09

### Other
- workaround kernel bug by writing < 32KiB chunks to vsock

## `qos_p256` - [0.6.1](https://github.com/tkhq/qos/compare/qos_p256-v0.6.0...qos_p256-v0.6.1) - 2026-04-09

### Added
- Expose `encryption_secret` accessor on `P256Pair` ([#662](https://github.com/tkhq/qos/pull/662))

## `qos_net` - [0.6.0](https://github.com/tkhq/qos/compare/qos_net-v0.5.0...qos_net-v0.6.0) - 2026-04-02

### Fixed
- `ProxyMsg::ProxyError` responses now properly propagated instead of being silently dropped as `InvalidMsg` ([#655](https://github.com/tkhq/qos/pull/655))

### Changed
- Removed unused error variants `DuplicateConnectionId`, `ConnectionOverridden`, `ConnectionIdNotFound` ([#655](https://github.com/tkhq/qos/pull/655))

### Security
- Patched `aws-lc-rs`, `tar`, `rustls-webpki` ([#650](https://github.com/tkhq/qos/pull/650))
- Patched `time` and `keccak` crates ([#649](https://github.com/tkhq/qos/pull/649))


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

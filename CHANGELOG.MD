# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project used to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) but we've since
moved out of versioning: we use submodule references to pull `qos` into repositories which depend on it (git SHA pointer).

If you're changing QOS in a meaningful way, please add a changelog entry, but no need to group these in version sections.

Types of changes:

Added: for new features.
Changed: for changes in existing functionality.
Deprecated: for soon-to-be removed features.
Removed: for now removed features.
Fixed: for any bug fixes.
Security: in case of vulnerabilities.

## Unreleased

### Added

- BREAKING CHANGE: qos_core: quorum key resharding service, new state machine transitions, and new `ProtocolMsg` variants (#428)
- qos_client: commands to run quorum key resharding and high level documentation (#428)
- qos_crypto: function to generate n choose k variants (#428)
- qos_hex: support more array sizes for serde deserialize
## Added: `qos_net` crate

In PR #449 we introduce `qos_net`, a crate which contains a socket<>TCP proxy to let enclave application communicate with the outside world.

This new crate contains:

- a new CLI and associated binary containing the proxy logic, running outside enclaves (on the host side)
- a `ProxyStream` abstraction to let enclaves send `ProxyMsg` messages to `Open`, `Read`, `Write` or `Flush` proxy-held connections.

## [0.4.0] 2024.4.9

### Added

- qos_hex: support more array sizes for serde deserialize (#414)
- make test: run all tests in build container (#433)
- make lint: run automated linting from build container (#433)
- make format: run rustfmt from build container
- make docs: run rustdocs from build container

### Changed

- make flow dramatically simplified. Single file. (#433)
- all actual build steps now handled in overhauled containerfiles in src/images (#433)
- make: deterministically build all the things with stagex build container (#433)
- CI refactored to use run make {fmt, test, lint} (#433)
- CI refactored to use stagex for uploading artifacts (#433)
- qos_client: deprecate reliance on release.env (#443)

### Removed

- git lfs artifacts removed (#433)
- toolchain removed (#433)

## [0.3.0] 2023.11.27

### Changed

- qos_core: do not go in unrecoverable phase if live_attestation_doc fails. (#412)

### Added

- qos_host: `/qos/enclave-info` endpoint that returns json payload with phase and manifest envelope, if it exists. (#407)
- BREAKING CHANGE: qos_core: route to get the manifest envelope, if it exist. This is a breaking change to the serialization of `ProtocolMsg`. `qos_core` version will need to be bumped synchronously in app hosts and qos_host. (#407)
- qos_hex: serde supoort for serialize/deserialize `Vec<u8>` and some `u8` arrays. This allows us to serialize bytes to hex in json. (#407)
- This CHANGELOG along with a PR template to remind contributors to update the template. (#407)

## [0.2.1]

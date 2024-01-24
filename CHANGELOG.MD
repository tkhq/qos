# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes:

Added: for new features.
Changed: for changes in existing functionality.
Deprecated: for soon-to-be removed features.
Removed: for now removed features.
Fixed: for any bug fixes.
Security: in case of vulnerabilities.

## [Unreleased]

### Added

- BREAKING CHANGE: qos_core: quorum key resharding service, new state machine transitions, and new `ProtocolMsg` variants (#428)
- qos_client: commands to run quorum key resharding and high level documentation (#428)
- qos_crypto: function to generate n choose k variants (#428)
- qos_hex: support more array sizes for serde deserialize


## [0.3.0] 2023.11.27

### Changed

- qos_core: do not go in unrecoverable phase if live_attestation_doc fails. (#412)

### Added

- qos_host: `/qos/enclave-info` endpoint that returns json payload with phase and manifest envelope, if it exists. (#407)
- BREAKING CHANGE: qos_core: route to get the manifest envelope, if it exist. This is a breaking change to the serialization of `ProtocolMsg`. `qos_core` version will need to be bumped synchronously in app hosts and qos_host. (#407)
- qos_hex: serde supoort for serialize/deserialize `Vec<u8>` and some `u8` arrays. This allows us to serialize bytes to hex in json. (#407)
- This CHANGELOG along with a PR template to remind contributors to update the template. (#407)

## [0.2.1]

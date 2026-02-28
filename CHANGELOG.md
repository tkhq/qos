# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## `qos_client` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_client-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- change BridgeConfig formatting to flat json representation
- Merge pull-request #621
- test ._ file ignoring
- Ignore macos dot-underscore files

## `qos_net` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_net-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- Merge pull-request #621
- ensure timeout encompasses the entire proxy request
- introduce maximum timeout to proxy requests
- use passed-in max_connections value

## `qos_core` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_core-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- change BridgeConfig formatting to flat json representation
- Merge pull-request #621
- ensure timeout encompasses the entire proxy request
- introduce maximum timeout to proxy requests

## `qos_p256` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_p256-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- use github links instead of relative
- make spec.md valid rust doc
- r-n-o feedback and general clarifications
- Add formal specification for qos key set

## `qos_nsm` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_nsm-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- Deny missing rust docs
- Include pivot hashes in InvalidPivotHash error
- add expected/actual values to AttestError variants
- Integrate fuzz harnesses into main workspace

## `qos_hex` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_hex-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Fixed
- fix hex logic; deny not forbid unsafe

### Other
- Deny missing rust docs
- refactor bridge definition in Manifest
- clippy

## `qos_crypto` - [0.5.0](https://github.com/tkhq/qos/releases/tag/qos_crypto-v0.5.0) - 2026-02-28

### Added
- add release-plz for release automation and changelog generation

### Other
- Run fmt on all targets
- Integrate fuzz harnesses into main workspace
- clippy
- hoist lints and package info to workspace root

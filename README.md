# QuorumOS

QuorumOS is a trusted computation layer for hosting secure apps at modern cloud scale.

Fundamentally, the OS architecture is based on the first principle that a threshold of members from a set can deem an enclave trustworthy and execute root system calls.

This is a WIP.

## Submitting a PR

Before a PR can be merged it must:

Be formatted

```bash
cargo +nightly
```

Pass the linter

```bash
cargo clippy

# to fix some types of lints you can run
cargo clippy --fix
```

And pass all tests

```bash
cargo test
```

## System requirements

- openssl >= 1.1.0

## Key parts

### Enclave

- houses nitro server
- see `qos-core`

## Host

- EC2 instance where the nitro enclave lives inside
- has client for talking to nitro enclave
- has server for incoming request from outside world
- see `qos-host`

## End user

- anything making request to host
- see `qos-client`

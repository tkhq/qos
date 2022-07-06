# QuorumOS

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

## View the docs

In the root of this project run

```bash
cargo doc --open
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

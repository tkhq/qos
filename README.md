# QuorumOS

QuorumOS is a trusted computation layer for hosting secure apps at modern cloud scale.

Fundamentally, the OS architecture is based on the first principle that a threshold of members from a set can deem an enclave trustworthy and execute root system calls.

This is a WIP.

## Submitting a PR

Before a PR can be merged it must:

Be formatted

```bash
make lint
```

And pass all tests

```bash
make test-all
```

## View the docs

In the root of this project run

```bash
cargo doc --open
```

## Commands

Run tests for the full project:

```shell
cargo test -- --nocapture
```

Run a local "enclave":

```shell
cargo run --bin qos_core \
  -- \
  --usock ./dev.sock \
  --mock
```

Run the enclave host:

```shell
cargo run --bin qos-host \
  -- \
  --host-ip 127.0.0.1 \
  --host-port 3000 \
  --usock ./dev.sock
```

Run a command against a running "enclave" and host:

```shell
cargo run --bin qos-client \
  --manifest-path ./qos-client/Cargo.toml \
  describe-nsm \
  --host-ip 127.0.0.1 \
  --host-port 3000
```

## System requirements

- openssl >= 1.1.0

## Key parts

### Enclave

- houses nitro server
- see `qos_core`

## Host

- EC2 instance where the nitro enclave lives inside
- has client for talking to nitro enclave
- has server for incoming request from outside world
- see `qos-host`

## End user

- anything making request to host
- see `qos-client`

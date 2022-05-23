Quick start

```
# run tests
cargo test --all

# format code
cargo +nightly fmt
```

# System requirements

- openssl >= 1.1.0

# Key parts

## Enclave

- houses nitro server

## Host

- EC2 instance where the nitro enclave lives inside
- has client for talking to nitro enclave
- has server for incoming request from outside world

## End user

- Anything making request to host

# Decisions / Things to Revisit:

- Use Serde in `qos-core`. We've decided to do this right now for agility; but we should probably make our own simple macro or find a secure serialization lib (look into borsch?)

# TODO:

- Build crypto  - all public key + hashing logic. High level so we can swap. Bring in OpenSSL
- Pivot logic
- Cli for posting shards, nsm attestation flow
- Research flow for attestation - with nsm / nitro enclave docs

- Sanity check vsock - aws or qemu
- Run deployed aws attestation flow (save nsm responses for stubbing)
- Smart shamir logic in enclave, don't randomly reconstruct
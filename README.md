qiq mafs

```
# start server
maker server

# start client
make client

# make code pretttty
cargo +nightly fmt
```

# Enclave
- houses nitro server

# Host
- EC2 instance where the nitro enclave lives inside
- has client for talking to nitro enclave
- has server for incoming request from outside world 

# End user
- Anything making request to host

TODO:
- sanity check vsock - aws or qemu
- big: aws attestation flow - cannot be developed locally
- shamir logic
  - simple cli for posting shards
- no default features for all crates
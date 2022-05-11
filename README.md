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

### Decisions / Things to Revisit:
- Use Serde in `qos-core`. We've decided to do this right now for agility; but we should probably 
make our own simple macro.

TODO:
- zeke use end_to_end eq for protocol message
- sanity check vsock - aws or qemu
- big: aws attestation flow - cannot be developed locally
- shamir logic
  - simple cli for posting shards
- no default features for all crates
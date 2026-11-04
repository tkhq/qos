# Enclave randomness

QOS generates long-lived secrets inside the enclave: ephemeral keys, quorum
key shares, and application keys. All of them come from the kernel's CRNG.

## Entropy sources

- **NSM.** The kernel builds in the NSM driver (`CONFIG_NSM=y`). It registers
  the `nsm-hwrng` hardware RNG with quality 1000 when the device is probed,
  before init runs. The kernel selects the highest-quality hwrng and mixes its
  output into the input pool that seeds the CRNG. It counts each NSM byte as
  1000/1024 of full entropy (about 7.8 of 8 bits).
- **CPU and boot.** The kernel also mixes in RDRAND/RDSEED, interrupt timing,
  and jitter entropy, and trusts the CPU RNG by default.
- **Other hwrng drivers.** virtio-rng and TPM drivers are compiled in, but
  Nitro exposes neither device (`pci=off`), so NSM is the only hwrng.

## What QOS checks

During boot, `qos_aws::init_platform` calls `check_hwrng("nsm-hwrng")`. It
reads `/sys/class/misc/hw_random/rng_current`. If it can't read the file, or
the current hwrng is not `nsm-hwrng`, the enclave powers off. This check
proves that NSM feeds the pool. It does not prove that the CRNG is seeded. The
blocking behavior of `getrandom(2)` covers that.

## Kernel behavior

`getrandom(2)` blocks until the CRNG is initialized, then never blocks. The
CRNG is seeded early in boot, long before QOS generates keys.

## Getting randomness in Rust

Use `OsRng`, which calls `getrandom(2)`, for any secret:

```rust
use rand_core::{OsRng, TryRngCore};

let mut seed = [0u8; 32];
OsRng.try_fill_bytes(&mut seed).expect("OS randomness unavailable");
```

- Treat an `OsRng` error as fatal. Never fall back to another source.
- `rand::rng()` is a CSPRNG seeded from `OsRng`. It is fine for shuffles and
  nonces, but use `OsRng` directly for keys.
- Don't use seeded or non-cryptographic generators (`SmallRng`,
  `StdRng::seed_from_u64`) for secrets, and don't seed from time or PIDs.
- Don't call NSM `GetRandom` for key material. It bypasses kernel mixing, so
  the key depends on a single source.
- Don't open `/dev/random` or `/dev/urandom` directly. `getrandom(2)` needs no
  file descriptor and can't read before the CRNG is seeded.

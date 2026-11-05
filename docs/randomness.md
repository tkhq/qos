# Enclave randomness

Every secret QOS creates in the enclave comes from the Linux kernel's random
number generator (the CRNG). That includes ephemeral keys, quorum key shares,
and application keys.

## Entropy sources

The kernel mixes several sources into one pool and seeds the CRNG from it:

- **NSM.** The Nitro Security Module has a hardware RNG. The NSM driver is
  built into the kernel, so it is ready before init starts.
- **The CPU.** The RDRAND and RDSEED instructions.
- **Timing.** Interrupt timing and CPU jitter.

The kernel trusts the CPU's RNG by default. It can mark the CRNG ready from
the CPU alone, before any NSM output reaches it. On its own, the kernel adds
NSM output only at its next scheduled reseed. That is about a second away
early in boot and up to a minute away later. QOS doesn't rely on that timing.
Init forces the reseed at boot, as the next section describes.

## Boot checks

QOS guarantees that NSM output is in the CRNG before QOS starts. At boot,
init (`qos_aws::init_platform`) samples NSM directly, mixes the sample into
the kernel pool, and forces a reseed. It does these steps before it sends the
boot heartbeat to Nitro, and powers off the enclave if any step fails. A
failure therefore shows up as a failed enclave boot.

1. Check that the kernel's active hardware RNG is `nsm-hwrng` and that the
   kernel credits its output as entropy (quality 1000).
2. Read two 64-byte samples from `/dev/hwrng`, each from a separate NSM
   request. Check that they differ and are not one repeated byte. This
   catches a broken or stuck device. It does not detect subtle bias.
3. Wait for the CRNG to be ready, write the samples to `/dev/random`, and
   force a reseed (`RNDRESEEDCRNG`).

After step 3, the CRNG includes NSM output, whatever the boot timing was.

## Using randomness in Rust

Use `OsRng` for keys and other secrets. It calls `getrandom(2)`, which reads
from the CRNG.

```rust
use rand_core::{OsRng, TryRngCore};

let mut seed = [0u8; 32];
OsRng.try_fill_bytes(&mut seed).expect("OS randomness unavailable");
```

- Treat an `OsRng` error as fatal. Don't fall back to another source.
- Don't use seeded or non-cryptographic generators, such as `SmallRng` or
  `StdRng::seed_from_u64`, for secrets.
- Don't use NSM `GetRandom` directly for keys. It skips the kernel pool, so
  the key depends on a single source.

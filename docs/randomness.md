# Enclave randomness

QOS generates long-lived secrets inside the enclave: ephemeral keys, quorum
key shares, and application keys. All of them come from the kernel's CRNG.

## How the kernel CRNG works

Every entropy source mixes its bytes into the kernel's input pool, and the
kernel counts how many bits of entropy each source adds. When the pool has
256 bits, the kernel seeds the CRNG, a ChaCha20 stream that `getrandom(2)`
returns. Before that, `getrandom(2)` blocks. After that, it never blocks. The
kernel then reseeds the CRNG from the pool when it is next used after an
interval: half the uptime (at least one second) during the first two minutes,
then 60 seconds. Input that arrives after a seed reaches `getrandom(2)` output
at the next reseed.

## Entropy sources

- **CPU.** Very early in boot, the kernel mixes 512 bits from RDSEED (or
  RDRAND) into the pool, and it mixes in more at every reseed.
  The kernel credits that first input as entropy by default;
  `src/images/linux_nitro/hardening.cmdline` sets `random.trust_cpu=on` to
  make that choice explicit in the measured command line. So the CPU RNG alone
  seeds the CRNG, before any driver loads.
- **NSM.** The NSM driver is built into the kernel (`CONFIG_NSM=y`). When the
  kernel probes the NSM device, before init runs, the driver registers the
  `nsm-hwrng` hardware RNG with quality 1000. A kernel thread then reads it
  continuously and counts each byte as 1000/1024 of full entropy (about 7.8
  of 8 bits). NSM output reaches the CRNG from the first reseed after it
  arrives.
- **Interrupts and timers.** The kernel mixes in interrupt timing. If
  `getrandom(2)` would block, it also generates entropy from timer jitter.

Mixing more sources can't weaken the CRNG, even if one source is malicious.
Crediting a source only decides when the CRNG is first seeded.

The Nitro hypervisor gives the enclave only vsock and NSM over virtio-mmio.
`hardening.config` builds in no other hwrng or TPM driver, so NSM is the only
hwrng. This matters because the kernel selects the hwrng with the highest
quality, and drivers that set no quality default to 1024, which is higher
than NSM's 1000.

## What QOS enforces

- **At build time.** The `linux_nitro` build fails if the resolved config does
  not build in NSM or enables the virtio-rng, Intel, AMD, VIA, or TPM RNG
  drivers.
- **At boot.** `qos_aws::init_platform` calls `check_hwrng("nsm-hwrng")`. It
  reads `/sys/class/misc/hw_random/rng_current`. If it can't read the file,
  or the current hwrng is not `nsm-hwrng`, the enclave powers off.

The boot check proves that NSM is the selected hwrng, so the kernel's hwrng
thread feeds NSM output into the input pool. With `random.trust_cpu=on`, it
does not prove that NSM output is in the seed behind the first keys.

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

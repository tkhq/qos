# Enclave kernel hardening

The enclave kernel follows the Kernel Self Protection Project's
[recommended settings](https://github.com/KSPP/kspp.github.io/blob/04b2a2c36113730382a58eb46ee1f23adecaff41/Recommended_Settings.md)
for common and x86-64 options. Hardening does not replace timely kernel upgrades.

## Enforcement

- `src/images/linux_nitro/minimal.config` disables features the enclave does
  not use. The build fails if any come back.
- `src/images/linux_nitro/hardening.config` overrides the StageX baseline in
  `nitro.config`. The build fails if the resolved config drops any setting.
- `src/images/linux_nitro/hardening.cmdline` holds boot arguments with no config
  equivalent.
- `src/init/hardening.sysctl` holds runtime settings. Init applies and verifies
  them before platform setup; any error aborts boot.

Changing any of these changes the enclave measurements.

## Exceptions

KSPP options that were renamed, removed, or only apply to modules, EFI, or
other architectures are covered by their current equivalents or don't apply.

| KSPP recommendation | Decision |
| --- | --- |
| `RANDSTRUCT_FULL` | Not enabled: reproducible builds publish the seed, so the layout is public. |
| `kernel.perf_event_paranoid=3` | Uses `2`: `3` needs a distro patch. |
| `kernel.warn_limit=1` | Deferred: one benign `WARN` would reboot the enclave. Revisit once production shows no warnings. |
| `nosmt`, `SCHED_CORE` | Not applied: the enclave owns whole cores, so this would halve CPUs for no isolation gain. |
| IOMMU options | Not applied: `pci=off`, and Nitro exposes no DMA-capable device. |
| `pti=on` | Not applied: PTI stays on `auto`, which enables it on CPUs affected by Meltdown (such as Skylake in `m5`/`c5`) and skips it on CPUs that are not. |
| `slub_debug=ZF` | Not applied: expensive and overlaps freelist hardening, KFENCE, and allocation wiping. |
| SELinux, AppArmor, Landlock, etc. | Not enabled: the enclave has no policy for them to enforce. |
| `HW_RANDOM_TPM` | Not enabled: Nitro has no TPM, and NSM must be the only [hwrng](randomness.md). |

User namespaces, modules, kexec, 32-bit compatibility, and debug interfaces are
disabled; other namespaces remain.

## Validation

Before release, boot on real Nitro hardware and confirm NSM and its
[entropy source](randomness.md), attestation, key forwarding, pivot restarts,
and egress. Measure throughput and memory use. When upgrading the kernel,
re-review KSPP's list and the new kernel's defaults.

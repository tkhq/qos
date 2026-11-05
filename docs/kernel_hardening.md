# Enclave kernel hardening

The enclave kernel follows the Kernel Self Protection Project's
[recommended settings](https://github.com/KSPP/kspp.github.io/blob/04b2a2c36113730382a58eb46ee1f23adecaff41/Recommended_Settings.md)
for common and x86-64 options:

- `src/images/linux_nitro/hardening.config`: kernel config and built-in boot
  arguments. The build fails if Kconfig drops a setting.
- `src/init/hardening.rs`: sysctls. Boot aborts if one does not apply.

Changing any of these changes the enclave measurements.

## Skipped recommendations

Options that were renamed, removed, or only apply to modules, EFI, or other
architectures are covered by their current equivalents or don't apply.

| KSPP recommendation | Decision |
| --- | --- |
| `RANDSTRUCT_FULL` | Not enabled: reproducible builds publish the seed, so the layout is public. |
| `kernel.perf_event_paranoid=3` | Left at the default `2`: `3` needs a distro patch. |
| `kernel.warn_limit=1` | Deferred: one benign `WARN` would reboot the enclave. |
| `nosmt`, `SCHED_CORE` | Not applied: the enclave owns whole cores, so this would halve CPUs for no isolation gain. |
| IOMMU options | Not applied: `pci=off`, and Nitro exposes no DMA-capable device. |
| `pti=on` | Not applied: `auto` enables PTI only on CPUs affected by Meltdown. |
| `slub_debug=ZF` | Not applied: expensive and overlaps freelist hardening, KFENCE, and allocation wiping. |
| SELinux, AppArmor, Landlock, etc. | Not enabled: the enclave has no policy for them to enforce. |
| `HW_RANDOM_TPM` | Not enabled: Nitro has no TPM, and NSM must be the only [hwrng](randomness.md). |

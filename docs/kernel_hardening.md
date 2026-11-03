# Enclave kernel hardening

The enclave kernel uses Linux **6.18.60**, a kernel.org longterm release. See
[kernel maintenance](./kernel_maintenance.md) for its projected support window,
security-fix provenance, and upgrade procedure. Hardening does not replace timely
security updates.

The baseline is the Kernel Self Protection Project's
[recommended settings](https://github.com/KSPP/kspp.github.io/blob/04b2a2c36113730382a58eb46ee1f23adecaff41/Recommended_Settings.md),
reviewed on November 2, 2026. This document accounts for the common and x86-64
recommendations; other architectures do not apply to this image.

## Policy and enforcement

- `src/images/linux_nitro/nitro.config` preserves the upstream StageX baseline.
- `src/images/linux_nitro/hardening.config` overrides that baseline. The build
  checks every requested setting **after** `make olddefconfig`, failing if a
  dependency, toolchain limitation, or kernel upgrade drops an enabled control
  or re-enables a disabled one. The image exports the resolved `/linux.config`.
- `src/images/linux_nitro/hardening.cmdline` supplies the KSPP boot arguments.
  The kernel image exports `/linux.cmdline`; both enclave images and the prebuilt
  QEMU EIF builder consume it. It includes SLUB redzones/sanity checks, allocator
  wiping, forced PTI, SMT disabling, CPU mitigations, and KCFI. These can have
  significant workload-dependent performance and memory costs.
- `src/init/hardening.sysctl` supplies the runtime controls. Init writes and
  reads them back immediately after mounting `/proc`, before platform setup,
  serving requests, or launching the pivot. Errors abort boot. A leading `-`
  permits only a missing sysctl for an interface disabled at build time.

The public kernel artifact, initramfs, and command line change, so regenerate
and approve the enclave measurements before deployment.

## Disposition of conditional and historical recommendations

| KSPP recommendation | Disposition for this build |
| --- | --- |
| Common and x86-64 settings with current symbols | Requested in `hardening.config` and checked against the resolved config. Integrity checks such as `DEBUG_LIST` remain enabled. |
| `STRICT_DEVMEM`, `IO_STRICT_DEVMEM` | Inapplicable with `DEVMEM` disabled; no physical-memory access device is provided. |
| `DEBUG_RODATA`, `DEBUG_SET_MODULE_RONX` | Historical names; use `STRICT_KERNEL_RWX`. Module memory protections are inapplicable with modules disabled. |
| `DEBUG_CREDENTIALS`, `REFCOUNT_FULL` | Removed upstream. Current reference-count protection is part of the kernel implementation rather than this old selectable option. |
| `HARDENED_USERCOPY_FALLBACK`, `HARDENED_USERCOPY_PAGESPAN` | Historical options absent from this kernel; hardened usercopy remains required. |
| `PAGE_POISONING_ZERO`, `page_poison=1`, `slub_debug=P` | KSPP's pre-5.3 alternatives; use `init_on_alloc=1`, `init_on_free=1` and their config defaults instead. `slub_debug=ZF` is retained separately. |
| `MODULE_SIG`, `MODULE_SIG_FORCE`, `MODULE_SIG_ALL`, `MODULE_SIG_SHA512`, `MODULE_SIG_HASH`, `MODULE_SIG_KEY`, `STRICT_MODULE_RWX` | Inapplicable: `MODULES` is disabled, NSM is built in, and init loads no modules. No module-signing key is needed. The inherited, misspelled `nomodules` boot argument is removed; module loading is compiled out. |
| GCC plugins for latent entropy, struct initialization, stack erasure | This build uses Clang. Use `INIT_STACK_ALL_ZERO`, Clang RANDSTRUCT, and the current `KSTACK_ERASE` implementation. The GCC latent-entropy plugin has no Clang equivalent. |
| `AMD_IOMMU_V2` | Removed upstream; current AMD IOMMU support is enabled. PCI is disabled by the Nitro command line, so DMA/EFI/IOMMU controls have no exposed hardware to protect inside the enclave. They remain enabled where available. |
| `EFI_DISABLE_PCI_DMA`, `RESET_ATTACK_MITIGATION` | Inapplicable: EFI is disabled. Nitro uses the Linux boot protocol and supplies no EFI firmware services. Adding EFI code would not protect an enclave's memory across a hypervisor-managed reboot. |
| `CFI_CLANG` | Renamed upstream; enforce `CFI` with the existing Clang toolchain. |
| `UBSAN_SANITIZE_ALL` | Removed upstream; enabling UBSAN instruments kernel objects by default, except explicit per-object/subdirectory exclusions in the kernel build. |
| `RANDOM_TRUST_CPU`, `RANDOM_TRUST_BOOTLOADER` | Removed upstream; both now default on. Explicitly retain them with `random.trust_cpu=on random.trust_bootloader=on` boot arguments. |
| `vsyscall=none`, `vdso32=0` | Equivalent build-time restrictions are enforced: `X86_VSYSCALL_EMULATION`, `IA32_EMULATION`, and `COMPAT_VDSO` are disabled. Their boot parsers are also compiled out, so these redundant arguments would be unrecognized. |
| `STATIC_USERMODEHELPER` | Enabled with an empty path, disabling implicit usermode helpers. Init handles device and network setup directly; normal `exec` of the pivot and egress tools remains available. |
| `RANDSTRUCT_FULL` | Enabled with a public seed derived from the resolved config. Reproducing the same image must reproduce the same layouts. This provides configuration-to-configuration diversity, **not secret or per-boot layout randomization**; attackers can reproduce the layouts. KASLR separately randomizes runtime placement. |
| `kernel.perf_event_paranoid=3` | KSPP notes this needs a distro patch. This is upstream Linux, so use `2`, the strongest upstream restriction; privileged profiling is additionally constrained by confidentiality lockdown. |
| `kernel.modules_disabled`, `kernel.kexec_load_disabled`, `user.max_user_namespaces` | Corresponding features are disabled at build time. Their sysctls may be absent; if present they must accept the restrictive value. |
| `dev.tty.ldisc_autoload`, `dev.tty.legacy_tiocsti` | Corresponding defaults are disabled at build time. Both runtime controls must also accept and read back zero. |
| arm64, x86-32, ARM settings | Not applicable to the x86-64 image. |

User namespaces, `/proc/kcore`, kexec, hibernation, legacy executable formats,
32-bit compatibility, module loading, KUnit, debugfs, and function-error injection
are disabled. Seccomp and Landlock support are available; simply compiling them
does not install a workload-specific sandbox. SELinux compilation likewise does
not supply an application policy.

## Validation and upgrades

Build both enclave variants, run the QEMU end-to-end suite, and boot on real Nitro
hardware before release. Confirm NSM and its entropy source, attestation,
key forwarding, pivot execution/restarts, and network egress. On real hardware,
verify that KASLR and hardware-dependent mitigations actually activate; config
selection alone does not prove that they do. Measure throughput, latency, boot
time, and memory use with SLUB validation, allocation wiping, KFENCE, CFI,
and RANDSTRUCT enabled and SMT disabled.

When upgrading, compare KSPP's recommendations with this pinned baseline, review
new kernel defaults and removed symbols, and rerun the resolved-config checks.
[kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)
can additionally audit the resolved config, the running `/proc/cmdline`, and
runtime sysctls. Treat any additional recommendations as findings to review,
not evidence that every recommendation is relevant to an enclave.

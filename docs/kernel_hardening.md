# Enclave kernel hardening

The enclave kernel uses Linux **7.3.1**. This stable series requires regular
kernel upgrades. Hardening does not replace timely security updates.

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
- `src/images/linux_nitro/hardening.cmdline` supplies only boot arguments with
  no config equivalent: `page_alloc.shuffle=1`, which `SHUFFLE_PAGE_ALLOCATOR`
  needs to take effect. Arguments that repeat a config default are omitted.
  The kernel image exports `/linux.cmdline` for both enclave images; the prebuilt
  QEMU EIF builder stages this file directly, since it uses StageX's kernel.
- `src/init/hardening.sysctl` supplies runtime controls that `hardening.config`
  does not already fix. Init writes and reads them back immediately after
  mounting `/proc`, before platform setup, serving requests, or launching the
  pivot. Errors abort boot. Controls whose upstream default already matches
  stay listed, since no build check would catch a changed default.

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
| `PAGE_POISONING_ZERO`, `page_poison=1`, `slub_debug=P` | KSPP's pre-5.3 alternatives; use the `INIT_ON_ALLOC_DEFAULT_ON` and `INIT_ON_FREE_DEFAULT_ON` config defaults instead. |
| `MODULE_SIG`, `MODULE_SIG_FORCE`, `MODULE_SIG_ALL`, `MODULE_SIG_SHA512`, `MODULE_SIG_HASH`, `MODULE_SIG_KEY`, `STRICT_MODULE_RWX` | Inapplicable: `MODULES` is disabled, NSM is built in, and init loads no modules. No module-signing key is needed. The inherited, misspelled `nomodules` boot argument is removed; module loading is compiled out. |
| GCC plugins for latent entropy, struct initialization, stack erasure | This build uses Clang. Use `INIT_STACK_ALL_ZERO` and the current `KSTACK_ERASE` implementation; RANDSTRUCT is covered below. The GCC latent-entropy plugin has no Clang equivalent. |
| IOMMU options (`IOMMU_*`, `INTEL_IOMMU*`, `AMD_IOMMU*`, `iommu.strict`, `iommu.passthrough`) | Not requested: `pci=off`, and Nitro exposes no DMA-capable device for an IOMMU to confine. |
| `EFI_DISABLE_PCI_DMA`, `RESET_ATTACK_MITIGATION` | Inapplicable: EFI is disabled. Nitro uses the Linux boot protocol and supplies no EFI firmware services. Adding EFI code would not protect an enclave's memory across a hypervisor-managed reboot. |
| `RANDOM_KMALLOC_CACHES` | Renamed upstream; enforce `KMALLOC_PARTITION_CACHES` with `KMALLOC_PARTITION_TYPED`, Clang 22's type-based mode. It is the upstream default with that compiler and guarantees separation that the random mode only makes probable. |
| `CFI_CLANG`, `cfi=kcfi` | Renamed upstream; enforce `CFI` with the existing Clang toolchain. The boot mode is the upstream default: FineIBT where the CPU supports IBT, kCFI otherwise. |
| `UBSAN_SANITIZE_ALL` | Removed upstream; enabling UBSAN instruments kernel objects by default, except explicit per-object/subdirectory exclusions in the kernel build. |
| `RANDOM_TRUST_CPU`, `RANDOM_TRUST_BOOTLOADER` | Removed upstream; both now default on. |
| `vsyscall=none`, `vdso32=0` | Equivalent build-time restrictions are enforced: `X86_VSYSCALL_EMULATION`, `IA32_EMULATION`, and `COMPAT_VDSO` are disabled. Their boot parsers are also compiled out, so these redundant arguments would be unrecognized. |
| `STATIC_USERMODEHELPER` | Enabled with an empty path, disabling implicit usermode helpers. Init handles device and network setup directly; normal `exec` of the pivot and egress tools remains available. |
| `RANDSTRUCT_FULL` | Not enabled: reproducible builds require a public seed, so attackers can compute the layouts. KASLR separately randomizes runtime placement. |
| `kernel.perf_event_paranoid=3` | KSPP notes this needs a distro patch. This is upstream Linux, so use `2`, the strongest upstream restriction; privileged profiling is additionally constrained by confidentiality lockdown. |
| `kernel.modules_disabled`, `kernel.kexec_load_disabled`, `user.max_user_namespaces` | Corresponding features are disabled at build time, so these sysctls do not exist. |
| `kernel.dmesg_restrict`, `dev.tty.ldisc_autoload`, `dev.tty.legacy_tiocsti` | Their defaults come from `SECURITY_DMESG_RESTRICT`, `LDISC_AUTOLOAD`, and `LEGACY_TIOCSTI`, which the config check enforces. |
| `nosmt`, `mitigations=auto,nosmt`, `SCHED_CORE` | Not applied: the enclave owns whole cores, so disabling SMT would only separate enclave processes from each other, at up to half the CPUs. |
| `pti=on` | Not applied: the default enables PTI on CPUs affected by Meltdown. |
| `slub_debug=ZF` | Not applied: an expensive debugging aid that overlaps freelist hardening, KFENCE, and allocation wiping. Enabling it would also disable pointer hashing. |
| `HW_RANDOM_TPM`, `X86_USER_SHADOW_STACK` | Not requested: Nitro has no TPM, and the enclave binaries do not opt in to user shadow stacks. |
| SELinux, Smack, TOMOYO, AppArmor, Landlock | Not enabled: none protects anything without a policy or a program that uses it, and the enclave has neither. |
| arm64, x86-32, ARM settings | Not applicable to the x86-64 image. |

User namespaces, `/proc/kcore`, kexec, hibernation, legacy executable formats,
32-bit compatibility, module loading, KUnit, debugfs, and function-error injection
are disabled. Seccomp support is available; compiling it does not install a
workload-specific sandbox.

## Validation and upgrades

Build both enclave variants, run the QEMU end-to-end suite, and boot on real Nitro
hardware before release. Confirm NSM and its entropy source, attestation,
key forwarding, pivot execution/restarts, and network egress. On real hardware,
verify that KASLR and hardware-dependent mitigations actually activate; config
selection alone does not prove that they do. Measure throughput, latency, boot
time, and memory use with allocation wiping, KFENCE, and CFI enabled.

When upgrading, compare KSPP's recommendations with this pinned baseline, review
new kernel defaults and removed symbols, and rerun the resolved-config checks.
[kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)
can additionally audit the resolved config, the running `/proc/cmdline`, and
runtime sysctls. Treat any additional recommendations as findings to review,
not evidence that every recommendation is relevant to an enclave.

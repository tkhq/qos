# Enclave kernel maintenance

QoS builds Linux **6.18.60**, the latest kernel.org 6.18 longterm release as of
November 2, 2026. [kernel.org's release policy](https://www.kernel.org/category/releases.html)
projects support for the 6.18 series through **December 2028**. That is a projected
maintenance window, not a contractual emergency-patch SLA.

The source URL, SHA-256, and build images are pinned in
`src/images/linux_nitro/Containerfile`. The StageX `nitro.config` is the starting
point; `make olddefconfig` resolves it for this kernel. Review the resulting
`/linux.config`, since symbols vary between kernel versions.

CVE-2026-98432 is fixed in 6.18.56, according to the
[Linux CNA's CVE record](https://www.cve.org/CVERecord?id=CVE-2026-98432) and the
[6.18.56 changelog](https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18.56)
("ipv4: free inet_opt and ireq_opt after an RCU grace period"). The pinned
6.18.60 includes this fix.

## Update procedure

1. Track [kernel.org's supported releases](https://www.kernel.org/releases.json)
   and [kernel security announcements](https://subspace.kernel.org/lists.linux.dev.html).
   Review new 6.18 stable releases and relevant security fixes promptly. LTS
   support does not automatically update QoS's pinned source.
2. Verify the source against kernel.org's signed release/checksum information,
   update the version, URL, checksum, and build directory together, and review
   config changes and any hardening-policy failures.
3. Build both enclave images, run QEMU end-to-end tests, and validate NSM entropy,
   attestation, key forwarding, pivot behavior, and egress on real Nitro hardware.
   Regenerate and approve enclave measurements before deployment.
4. Upgrade to another supported longterm series before 6.18 reaches its projected
   end of support. Recheck upstream's support window periodically; it can change.

This repository does not define a responsible team's on-call response deadline.
If an emergency-patch guarantee is required, establish an internal ownership and
response SLA or obtain a supported vendor arrangement; upstream LTS alone does
not supply one.

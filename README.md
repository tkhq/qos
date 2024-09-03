# QuorumOS #

<https://github.com/tkhq/qos>

Click [here](./src/README.md) for the Rust code README.

## About ##

A minimal, immutable, and deterministic Linux unikernel build system targeting
various Trusted Execution Environments for use cases that require high security
and accountability.

This is intended as a reference repository which could serve as a boilerplate
to build your own hardened and immutable operating system images for high
security applications.

## Platforms ##

| Platform                   | Target  | Status   | Verified boot Method  |
|----------------------------|:-------:|:--------:|:---------------------:|
| Generic/Qemu               | generic | working  | Safeboot or Heads     |
| AWS Nitro Enclaves         | aws     | building | Nitro attestation API |
| GCP Confidential Compute   | gcp     | research | vTPM 2.0 attestation  |
| Azure Confidential VMs     | azure   | research | vTPM 2.0 attestation  |

## Features ##

 * Immutability
   * Root filesystem is a CPIO filesystem extracted to a RamFS at boot
 * Minimalism
   * < 5MB footprint
   * Nothing is included but a kernel and your target binary by default
   * Sample "hello world" included as a default reference
   * Debug builds include busybox init shim and drop to a shell
 * Determinism
   * Multiple people can build artifacts and get identical hashes
   * Allows one to prove distributed artifacts correspond to published sources
 * Hardening
   * No TCP/IP network support
     * Favor using a virtual socket or physical interface to a gateway system
   * Most unessesary kernel features are disabled at compile time
   * Follow [Kernel Self Protection Project](kspp) recommendations

[kspp]: https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project

## Trust ##

The main branch of this repo, which contains all binaries in the dist
directory, should always be signed by multiple people who have confirmed the
source code is what they expect, and results in the expected binaries via
reproducible builds.

We use [git-sig][gs] for this.

Please install it in order to follow our signing and verification steps.

Two libraries you may need to `brew install` first are `bash` in order to get to version 5+ and `gnu-getopt`.  After
installing `gnu-getopt` in order to get it to be the one that is automatically picked up on the PATH, follow the instructions
provided by `brew` in order to update your PATH.

### Verify ###

#### Signers

Please review that keys are authentic and from individuals you expect.

| Name             | PGP Fingerprint                                                                          |
|------------------|------------------------------------------------------------------------------------------|
| Jack Kearney     |[CADF 760B CCE7 8999 CEC1 372B 1784 24A6 721E E568](https://keyoxide.org/178424A6721EE568)|
| Lance Vick       |[6B61 ECD7 6088 748C 7059 0D55 E90A 4013 36C8 AAA9](https://keyoxide.org/E90A401336C8AAA9)|
| Zeke Mostov      |[D96C 422E 04DE 5D2E E0F7 E9E7 DBB0 DCA3 8D40 5491](https://keyoxide.org/DBB0DCA38D405491)|


You can import the keys of all signers with:

```
gpg --import keys/*
```

#### Signatures

Once you have public keys you trust locally pinned, you are able verify that
the artifacts and code we publish are validly signed.

We require a minimum of 2 signatures so you can use [git-sig][gs] as follows:

```
git sig verify --threshold 2
```

### Sign ###

We use git-sig for signing the repo and dist artifacts after you have completed
any code review and reproduced your own set of artifacts.

```
git sig add
```

Please make a PR to upload attestation signatures so that this trust can be
preserved for other consumers of these binaries that may lack the resources
to build for themselves.

### Release ###

Cut a new release to be attested/signed by others.

```
make VERSION=1.0.0 dist
```

## Development ##

### Requirements ###

 * 10GB+ free RAM
 * Docker 20+
 * GNU Make

### Examples ###

#### Build given target
```
make TARGET=generic
```

#### Boot generic image in Qemu
```
make run
```

#### Enter shell in toolchain environment
```
make toolchain-shell
```

#### Update toolchain dependency pins
```
make toolchain-update
```


### Release Process

 0. Determine the release semver version by consulting the [changelog](./CHANGELOG.MD).
 1. Create a branch for your release e.g.
    `git checkout -b release/v1.0.0`
 2. Run `make dist` as described in ["Release" section](#release)
 3. Commit the new dist folder `git commit -m "Release v1.0.0" -- dist/`
 4. Push up your branch to github, and make a pull request.
 5. You may also create and push a signed `-rcX` git tag where the number after `rc` doesn't already exist.
    `git tag -S v1.0.0-rc0 -m v1.0.0-rc0`
    `git push origin v1.0.0-rc0`
 6. Wait for others to replicate your build, see ["Verify" section](#verify)
 7. Once the release has enough `git sig` signatures, make the final tag and merge the pull request.
    `git tag -S v1.0.0 -m v1.0.0`
    `git push origin v1.0.0`


[gs]: https://codeberg.org/distrust/git-sig

### LFS setup

This repository externalises large files so that they do not bulk up the git repo itself.
This is done through a tool called `git-lfs`, which must be installed for it to work.
Additionally, we use a custom agent to store our LFS objects in S3 (rather than the default and more expensive Github LFS service).

In order to setup our s3 based lfs:

1) Install [tkinfra](https://github.com/tkhq/mono/tree/main/src/go/tkinfra)
2) Run `./scripts/setup-lfs.sh`

#### Troubleshooting

Our mono repo uses the same lfs configuration. For troubleshooting tips consult monos [LFS troubleshooting](https://github.com/tkhq/mono#troubleshooting-lfs) section.

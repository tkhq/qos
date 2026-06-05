# QoS Test Runner Specification

## Summary

We want one shared Rust library of tests that can run against multiple execution
strategies. A test describes behavior, such as starting a signed-echo app and
checking `/health` and `/echo`. Builders produce fresh artifacts. Host runners
run the host-side QoS process. Enclave runners run the enclave/app side.

The first shared test is:

1. start a signed-echo app,
2. wait for readiness,
3. call `/health`,
4. POST a message to `/echo`,
5. verify the returned signed payload and signature,
6. shut the app down.

The important split is:

- shared tests define what is tested,
- builders define how artifacts are produced and cached,
- host runners define where `qos_host` and boot orchestration run,
- enclave runners define where the enclave/app code runs,
- top-level test runners compose those pieces for specific use cases.

## Definitions

- Shared test: runner-agnostic Rust test logic. It can request an app, probe
  returned endpoints, verify responses, and report pass/fail.
- Builder: component that produces or locates host binaries, pivot binaries,
  rootfs/kernel inputs, container images, and metadata. It owns freshness and
  cache checks.
- Host runner: component that runs host-side code such as `qos_host`, boot
  client logic, and HTTP probing.
- Enclave runner: component that runs the enclave/app side, such as QEMU,
  Docker, or TVC.
- Runtime socket: the control-plane transport between a host runner and an
  enclave runner. Supported shapes are vsock, Unix socket, TCP, or an external
  control URL. Unix sockets only apply when both sides share the same kernel;
  QEMU guests and macOS hosts require vsock or an explicit TCP proxy/forward.
- Top-level runner: implementation of the shared test runner trait. It composes
  one builder, one host runner, and one enclave runner.
- Reproducible Plain QEMU: high-fidelity local QEMU runner that boots a
  StageX-built rootfs/pivot package with a normal QEMU kernel and user-networked
  TCP forwarding.
- Nested Nitro QEMU: experimental composition that boots an x86_64 Linux parent
  VM under QEMU, then runs Linux/x86_64 `qemu-system-x86_64 -M
  nitro-enclave`, `vhost-device-vsock`, and QoS host binaries inside that
  parent VM.
- Lightweight QEMU: QEMU runner that avoids StageX and uses local,
  non-reproducible cross-compiled artifacts for developer speed.
- Docker runner: runner that uses Docker for the app/enclave side, or optionally
  for a host-side compatibility layer.
- Vivo/TVC runner: external-platform runner that deploys through TVC and probes
  gateway endpoints.
- Artifact freshness: evidence that the runnable artifact corresponds to the
  current requested source/build configuration, or to an explicitly configured
  digest.
- Build key: stable cache key derived from source identity, build config,
  target, builder kind, and relevant environment inputs.

## Goals

- Provide one reusable Rust test library for runner-agnostic QoS app behavior.
- Support multiple top-level runners with different fidelity/cost profiles.
- Make builders first-class because reproducible StageX builds, local
  cross-compiles, Docker builds, and TVC image selection have different rules.
- Make artifact freshness explicit and auditable.
- Allow host-side code to run natively by default, with an explicit option for a
  containerized/VM host runner when needed for macOS or CI compatibility.
- Keep Mono/Vivo/TVC-specific implementation out of this repo while still
  supporting a TVC-backed runner elsewhere.
- Avoid rewriting existing integration tests as part of the first version.

## Non-goals

- Do not make existing integration tests use the new framework yet.
- Do not require every builder to be reproducible.
- Do not put Vivo/TVC CLI implementation in this repo.
- Do not use mocks as acceptance tests for runner correctness.

## Architecture

The shared test library should define small interfaces and data types:

- `TestRunner`: lifecycle trait used by shared tests.
- `ArtifactRequest`: high-level app request, initially `SignedEcho`.
- `BuildPlan`: normalized build request created from an `ArtifactRequest` and
  runner config.
- `BuildOutput`: host binaries, pivot bytes/path, image/rootfs/kernel identity, hashes,
  and builder metadata.
- `HostRunner`: starts/stops `qos_host` and boot/client orchestration.
- `EnclaveRunner`: starts/stops QEMU, Docker, or external app runtime.
- `StartAppSpec`: app name, QoS version, pivot path/args, health route, public
  routes, and metadata.
- `RunningApp`: opaque top-level app handle.
- `AppEndpoint`: concrete URLs the shared test can probe.
- `TestOutcome`: pass/fail outcome passed into cleanup.

The top-level runner flow should be:

1. Convert `ArtifactRequest` into a `BuildPlan`.
2. Ask the selected builder for a fresh `BuildOutput`.
3. Start the selected enclave runner with the enclave/app artifacts.
4. Start the selected host runner against the enclave endpoint.
5. Boot/provision the app using the host runner.
6. Return `AppEndpoint` to the shared test.
7. Stop host and enclave resources during cleanup.

The shared test library may verify signed-echo response semantics, but it must
not decide how to build, boot, bridge, containerize, publish, or tear down the
app.

## Runner Matrix

| Top-level runner | Builder | Enclave runner | Host runner | Purpose |
| --- | --- | --- | --- | --- |
| Reproducible Plain QEMU | StageX reproducible builder | Plain QEMU rootfs/kernel | Native host by default | Highest-fidelity local/CI test without Nitro-specific QEMU |
| Lightweight QEMU | Local cross-compile builder | Lightweight QEMU package | Native host by default | Fast dev loop without StageX |
| Nested Nitro QEMU | StageX or local cross-compile builder plus Rawhide parent bundle | `nitro-enclave` QEMU inside an x86_64 parent Linux QEMU VM | QEMU parent VM | Experimental local EIF/vsock path |
| Docker | Docker/local builder | Docker app runtime | Native or Docker host | Cheap Linux process/container test |
| Vivo/TVC | Digest/image selector or publisher | TVC deployment | Native TVC CLI/gateway probe | External platform E2E |

These runners are deliberately not equivalent. The reproducible QEMU runner
catches StageX packaging, init, rootfs, QEMU boot, control-plane, and pivot
execution failures. Lightweight QEMU and Docker are faster but lower fidelity.

## Builder Interface

Builders are in scope for this project. They should be separate from runners so
the same execution strategy can use different artifact strategies.

The builder interface should support:

- build plan normalization,
- cache lookup by build key,
- building when cache is missing or invalid,
- final artifact hash validation,
- returning structured build metadata.

Recommended trait shape:

- `fn build_key(&self, plan: &BuildPlan) -> Result<BuildKey, BuildError>`
- `async fn build(&self, plan: &BuildPlan) -> Result<BuildOutput, BuildError>`
- `fn validate(&self, output: &BuildOutput) -> Result<(), BuildError>`

`build()` may return a cached output only when `validate()` proves the output is
still present and matches the expected hashes.

Builder implementations:

- Native cargo builder: uses Cargo for host binaries and can use
  `cargo_bin_*`-style paths for tests, but should still verify hashes.
- Cross-compile builder: uses Cargo with explicit target triples and isolated
  target dirs for enclave-side binaries.
- StageX reproducible builder: uses pinned StageX/container inputs and records
  rootfs/kernel/pivot identity.
- Docker builder: builds or loads Docker images and records image IDs/digests.
- TVC image builder/selector: either publishes an image by digest or validates a
  configured digest.

## Host Runner Interface

Host runners control host-side execution. The default host runner is native:
`qos_host`, boot orchestration, and HTTP probing run as native macOS or Linux
binaries.

Host runner variants:

- Native host runner: preferred default. Runs `qos_host` and boot client logic
  on the developer/CI host.
- Docker host runner: optional compatibility path. Runs host-side QoS binaries
  in Docker when native host execution is not possible or not desired.
- QEMU host runner: optional compatibility path. Runs host-side QoS binaries in
  a VM while the test process remains native.
- TVC host runner: invokes TVC CLI and probes gateway URLs.

The top-level runner must record which host runner was used. A test result from
a Docker/VM host runner should not be presented as equivalent to a native-host
result.

For QEMU enclave runners, native host execution remains the default because it
is closest to the intended local/operator workflow. Docker/VM host runners are
escape hatches for macOS or CI environments that cannot provide native
vsock/QEMU support.

## Enclave Runner Interface

Enclave runners control the app/enclave execution environment.

Enclave runner variants:

- Reproducible Plain QEMU runner: boots the StageX-built rootfs/pivot package
  with a normal QEMU machine.
- Lightweight QEMU runner: boots a non-StageX local QEMU package.
- Docker enclave runner: runs the app/enclave approximation in Docker.
- TVC enclave runner: deploys the app through TVC.

The enclave runner should not build artifacts itself. It receives `BuildOutput`
from a builder and should fail if required artifacts are missing or hashes do not
match metadata.

## Host Execution Policy

Default policy:

- The Rust test process runs natively.
- `qos_host` runs natively.
- Boot orchestration runs natively, either through `qos_client` or linked
  services.
- HTTP probes originate from the native test process.

Alternative policy:

- A top-level runner may use a Docker or QEMU host runner when native host
  execution is not available.
- This is an explicit runner configuration, not an implicit fallback.
- The result metadata must include `host_runner = native | docker | qemu | tvc`.
- Preflight must explain why a requested host runner cannot run.

This gives macOS users a possible path even when the desired QEMU/vsock setup is
Linux-only, without making host execution ambiguous.

## Runtime Transports

The runner interfaces should model transport explicitly instead of assuming a
single local socket shape:

- Vsock: useful for future QEMU compositions that need to exercise a
  host/enclave control boundary close to production.
- TCP: acceptable for lightweight QEMU and Docker compositions where the app
  runtime is behind QEMU user networking or container port publishing.
- Unix socket: acceptable only for same-kernel local execution, such as a native
  local core or a same-container/same-VM composition.
- External URL: used by TVC or any service that exposes the control plane
  through a gateway/API.

The QEMU runners may use TCP host forwarding even when the host runner is
native. That is a deliberate local emulation transport for the first harness
implementation.

## Reproducible Plain QEMU Runner

The reproducible QEMU runner is the high-fidelity local runner for this harness.
It avoids Nitro-specific QEMU machine support and instead boots a normal QEMU
guest with a StageX-built rootfs and pivot:

1. StageX builder produces a fresh or cached plain QEMU package and signed-echo
   pivot.
2. Host builder produces native host binaries or confirms cached binaries.
3. QEMU enclave runner starts a normal QEMU machine with a pinned kernel and the
   built rootfs.
4. Host runner starts `qos_host` and connects to the QEMU guest through TCP host
   forwarding.
5. Host runner boots the guest with a manifest whose pivot hash matches the
   built signed-echo pivot.
6. Top-level runner returns endpoint URLs to the shared signed-echo test.
7. Cleanup stops host, QEMU, temp dirs, and logs according to the outcome.

Expected properties:

- Best signal for StageX-built guest binaries, rootfs packaging, `/init`,
  `qos_core`, `qos_host`, boot protocol, and pivot execution under QEMU.
- Slowest runner.
- Requires pinned StageX inputs and records StageX rootfs/kernel/pivot identity.
- Does not require a QEMU build with Nitro-enclave machine support.

For v1, `dangerous-dev-boot` is acceptable because the test is about runner/app
lifecycle, not quorum ceremony correctness. Standard boot can become a separate
test dimension later.

## Lightweight QEMU Runner

The lightweight QEMU runner exists for developer velocity. It avoids StageX and
does not claim reproducible PCR/build identity.

It should:

1. Native/cross builder compiles host binaries, enclave-side QoS/init/core
   pieces, and signed-echo pivot.
2. Builder packages those outputs into the minimal QEMU-bootable form required
   by the lightweight runner.
3. Lightweight QEMU enclave runner starts QEMU with that package.
4. Host runner starts `qos_host` and boots using the same manifest/pivot hash
   logic as the full runner.

The lightweight package can be an initramfs or a writable development rootfs,
depending on the available kernel. On macOS, a practical tested composition is:

- an aarch64 QEMU `virt` guest,
- a local non-StageX cross-compiled `qos_core` and `light_init`,
- a 9p-mounted rootfs when the selected kernel does not honor the generated
  initramfs,
- QEMU user networking with TCP host forwarding for the native host-to-core
  control plane and for the signed-echo app port.

That 9p/TCP composition is intentionally a fast development runner. It can prove
the shared test, local build freshness, boot orchestration, and pivot execution,
but it does not prove StageX reproducibility.

Expected properties:

- Faster than full QEMU.
- Useful on developer machines for app/test iteration.
- Non-reproducible by design.
- Still enforces local freshness through build keys and content hashes.
- Uses separate output dirs from the full QEMU runner.

## Nested Nitro QEMU Runner

The nested Nitro runner is an experimental local path for exercising an EIF with
QEMU's emulated `nitro-enclave` machine type. For now it only supports an
x86_64 parent VM and an x86_64 Nitro enclave guest. On non-x86 hosts, such as
macOS arm64, this runs through QEMU TCG rather than hardware acceleration.

The composition is:

1. The Rust test process runs on the developer or CI host.
2. Outer `qemu-system-x86_64` boots a Linux/x86_64 parent VM.
3. The parent VM boots a Fedora Rawhide root image containing:
   - the matching Rawhide kernel/initramfs used by outer QEMU,
   - Rawhide `qemu-system-x86_64` with `nitro-enclave` support,
   - Rawhide `vhost-device-vsock`,
   - `/init`, which mounts the harness 9p work share.
4. The harness 9p work share contains:
   - Linux/x86_64 `nested_parent_init`, `qos_host`, `qos_client`, and
     `qos_bridge`,
   - the StageX-built `nitro.eif`,
   - the x86_64 Linux signed-echo pivot.
5. Parent `/init` execs `nested_parent_init`, which starts
   `vhost-device-vsock` with a guest CID and
   `forward-listen` ports for the QoS core port and app port.
6. Parent init starts inner `qemu-system-x86_64 -M
   nitro-enclave,vsock=c,id=... -kernel /work/nitro.eif -chardev
   socket,id=c,path=...`.
7. Parent init starts `qos_host` against CID `1` by default, matching QEMU's
   documented vhost-user-vsock forwarding model.
8. Parent init runs `qos_client dangerous-dev-boot`, then starts `qos_bridge`.
9. The host test process probes the signed-echo app through outer QEMU user
   networking.

This runner requires an explicit Fedora Rawhide parent bundle. The repo builds
the parent init and QoS binaries, while the bundle supplies the parent VM root
image, Rawhide kernel, Rawhide initramfs, QEMU, and `vhost-device-vsock`. The
bundle is configured with `QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE` and must
contain `rootfs.ext4`, `vmlinuz`, and `initramfs.img`.

A developer can build the Rawhide parent bundle with:

```sh
make nested-nitro-rawhide-parent
export QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE="$PWD/target/qos-test-harness/nested-nitro/rawhide-parent"
```

The helper runs an amd64 Fedora Rawhide container, installs Rawhide
`kernel-core`, `kernel-modules-core`, `qemu-system-x86-core`, and
`vhost-device-vsock`, forces dracut to include the virtio, 9p, and vsock modules
needed by this topology, then packages a bootable ext4 parent root image. It
verifies that `qemu-system-x86_64 -machine help` lists `nitro-enclave` and that
`vhost-device-vsock --help` exposes `--forward-cid`.

Useful overrides:

- `QOS_NESTED_NITRO_RAWHIDE_IMAGE`, default `fedora:rawhide`.
- `QOS_NESTED_NITRO_RAWHIDE_ROOTFS_SIZE`, default `2G`.
- `QOS_NESTED_NITRO_RAWHIDE_PARENT_DIR` or
  `QOS_TEST_QEMU_NESTED_NITRO_PARENT_BUNDLE`, to choose the output directory.
- `QOS_NESTED_NITRO_RAWHIDE_QEMU_PACKAGES`, default
  `qemu-system-x86-core`.

`QOS_TEST_QEMU_NESTED_NITRO_OUTER_KERNEL` and
`QOS_TEST_QEMU_NESTED_NITRO_OUTER_INITRD` remain escape-hatch overrides, but the
normal path uses `vmlinuz` and `initramfs.img` from the Rawhide bundle.

Two builder styles are supported:

- StageX: builds the EIF via the existing StageX-style `Containerfile.qemu`,
  stages the x86_64 parent work directory, and records StageX as the builder
  kind.
- Local cross compile: builds `nested_parent_init`, `qos_host`, `qos_client`,
  `qos_bridge`, and `signed_echo` for `x86_64-unknown-linux-musl`, stages the
  same parent work directory, uses the existing EIF packaging step as a runtime
  input, and records local cross compile as the builder kind.

The builder is selected with `QOS_TEST_QEMU_NESTED_NITRO_BUILDER=stagex|cross`.
The default is `stagex`.

Important limitations:

- It is not a replacement for the plain QEMU runner.
- It is expected to be slow on non-x86 hosts because both QEMU layers may run
  under TCG.
- QEMU's emulated `nitro-enclave` machine is useful for local EIF/vsock testing,
  but it does not provide AWS-signed production attestation.
- The Rawhide parent bundle is part of the build key, so changing its root
  image, kernel, initramfs, QEMU, or `vhost-device-vsock` invalidates the staged
  work directory.

## Docker Runner

The Docker runner is a lower-fidelity runner for cheap Linux process testing.

Supported compositions:

- Docker enclave runner plus native host runner.
- Docker enclave runner plus Docker host runner.

The second option is useful for macOS or CI compatibility, but it should be
clearly labeled as lower fidelity than native-host QEMU. Docker results should
not be treated as evidence that QEMU rootfs/init behavior is correct.

## Vivo/TVC Runner

The Vivo/TVC runner is out of scope for this repo, but the shared interfaces
must support it.

That runner should:

1. Build/publish/select an image by digest.
2. Use the TVC CLI to create app/deployment/manifest/approval state.
3. Wait for TVC materialization and gateway readiness.
4. Construct gateway URLs for `/health` and `/echo`.
5. Probe those URLs using TVC-required auth/TLS/gateway behavior.
6. Delete or retain TVC resources based on the test outcome and runner config.

The shared test must not assume local process IDs, local ports, local filesystem
artifacts, or Docker/QEMU-specific metadata.

## Build Freshness And Caching

Freshness is a builder responsibility. The shared test asks for
`ArtifactRequest::SignedEcho`; the selected builder must produce a valid
`BuildOutput`.

General rules:

- Use explicit package/bin names instead of broad implicit workspace builds.
- Use runner-specific target/output dirs when artifact classes differ.
- Hash final runnable artifacts after build or cache lookup.
- Never identify a runnable artifact only by a mutable tag such as `latest`.
- Make the manifest pivot hash come from the exact bytes that will be booted.
- Fail if the manifest hash differs from the artifact placed into the runtime.

Cache rules:

- Builders should compute a `BuildKey` before building.
- If a matching build record exists and all recorded files still hash correctly,
  the builder may skip the expensive build/package step.
- If the workspace is clean, the key may include the git commit hash.
- If the workspace is dirty, the key must include a digest of relevant tracked
  diffs plus relevant untracked source files, or the builder must decline cache
  reuse.
- Build config must be part of the key: builder kind, runner kind, Cargo
  profile, target triple, feature set, env affecting compilation, Dockerfile or
  StageX input identity, and pivot/app selection.
- The cache record should be stored under a runner-owned output directory, not
  in Cargo metadata.

Recommended build record:

- build key,
- runner/builder names,
- workspace path,
- git commit and dirty flag,
- Cargo profile and target triple,
- host OS/arch,
- exact command summary,
- output file paths,
- SHA-256 of host binaries,
- SHA-256 of pivot bytes,
- image/kernel/rootfs digest if applicable,
- StageX base image digests if applicable,
- timestamp for diagnostics only, not identity.

Cargo freshness is useful but insufficient. Cargo tracks compiled binaries;
builders also package binaries into rootfs trees, initramfs, Docker layers, or
TVC deployments. Those packaging outputs need their own cache keys and hash
validation.

## Build Freshness By Builder

### StageX Reproducible Builder

Must rebuild or validate:

- native host binaries if this builder also owns them,
- signed-echo pivot,
- StageX-built plain QEMU package/rootfs,
- QEMU kernel and launch inputs.

The package/rootfs step must depend on all source files that affect the guest,
not only the Dockerfile. A generated build fingerprint is acceptable if it
captures the same inputs. Clean git commit keys can be used for cache lookup;
dirty trees need diff/untracked-source fingerprints or no cache reuse.

### Local Cross-Compile Builder

Must rebuild or validate:

- native host binaries,
- cross-compiled enclave/core/init pieces,
- signed-echo pivot,
- lightweight QEMU package/rootfs/initramfs.

It may use non-reproducible timestamps and local Cargo behavior, but it must
hash final runnable files and ensure the boot manifest uses the actual pivot
bytes.

### Docker Builder

Must rebuild or validate:

- native test/host binaries if used,
- app/enclave container image,
- host container image if using Docker host runner,
- image ID/digest loaded or run by Docker.

Content-derived tags are allowed as convenience names. The recorded identity is
the image ID or digest.

### TVC Image Builder/Selector

Must validate:

- image reference includes or resolves to a digest,
- TVC deployment uses that digest,
- expected pivot path and digest match runner config,
- created app/deployment IDs are captured for cleanup.

It cannot prove local Cargo freshness unless it also owns building and
publishing the image.

## Signed-Echo Artifact

The preferred v1 implementation is to add a repo-local signed-echo pivot binary.
That gives QEMU and Docker builders a buildable artifact whose freshness can be
enforced by Cargo/build keys.

The signed-echo pivot should:

- expose `/health` returning HTTP 200 when ready,
- expose `/echo` accepting a plain request body,
- return JSON with `time`, `message`, `signed_payload_hex`, `signature_hex`,
  and `public_key_hex`,
- sign `b"echo app signed at" || timestamp_be_u64 || message`,
- return a 130-byte QoS P-256 public key as hex,
- return a 64-byte raw P-256 ECDSA signature as hex.

For external runners, a configured image or binary is acceptable, but those
runners can only validate digest identity unless they also own the build.

## Preflight

Each builder, host runner, and enclave runner should expose preflight checks.

StageX builder:

- Docker/BuildKit available,
- pinned StageX base images present or pullable,
- required source/build inputs visible,
- output/cache directory writable.

Local cross builder:

- required Rust target/toolchain available,
- linker/cross tools available,
- output/cache directory writable.

QEMU enclave runner:

- QEMU binary available,
- selected machine, kernel, rootfs mode, and network device supported,
- KVM or non-KVM mode explicitly configured,
- required ports/socket paths available.

Native host runner:

- host binaries exist and hash-match `BuildOutput`,
- required ports available.

Docker host/enclave runner:

- Docker daemon reachable,
- target platform available,
- required ports available.

TVC runner:

- TVC CLI exists,
- credentials/config present,
- gateway/observer/API endpoints configured,
- image digest configured or build/publish path available.

## Cleanup And Diagnostics

All top-level runners must cleanup after a started app, even when the shared test
fails.

On pass:

- stop app/enclave/container/deployment,
- stop host runner resources,
- remove temp dirs and transient sockets,
- keep concise build/run metadata unless configured otherwise.

On fail:

- stop resources unless configured to keep them,
- preserve logs, build records, command lines, artifact hashes, endpoint URLs,
  and runner-specific IDs,
- include enough data to reproduce which exact host binaries, pivot bytes,
  kernel, image, rootfs, or TVC deployment was used.

Cleanup errors should not hide the original test error. The final error should
include both.

## Initial Implementation Order

1. Keep the shared harness small: trait, lifecycle DTOs, signed-echo shared
   test, signed-echo verifier, no fake-runner tests.
2. Add the builder interfaces and build records before implementing QEMU.
3. Add a repo-local signed-echo pivot binary.
4. Implement the local cross builder and lightweight QEMU runner first for dev
   velocity.
5. Implement the StageX builder and reproducible plain QEMU runner using the same
   top-level runner shape.
6. Add Docker host/enclave runner variants once QEMU boundaries are stable.
7. Implement Vivo/TVC runner outside this repo against the same shared test
   shape.

## Acceptance Criteria

- The signed-echo shared test can run unchanged against at least two top-level
  runner compositions.
- Builders can skip expensive work only when build records and output hashes
  prove cache validity.
- QEMU enclave runners run enclave/app code under QEMU.
- Host execution mode is explicit: native, Docker, QEMU, or TVC.
- Reproducible QEMU runner records StageX rootfs/kernel identity and does not
  reuse stale packages.
- Lightweight QEMU runner avoids StageX and records non-reproducible local
  artifact identity.
- Every runner records the exact pivot hash used in the boot manifest.
- Cleanup runs after every started app and preserves failure diagnostics.

# QOS Development Mode Guide

This guide explains how to run QOS locally in mock mode for development and debugging.

## Overview

Mock mode allows you to run QOS locally without an AWS Nitro enclave. It uses a mock NSM (Nitro Secure Module) that returns hardcoded attestation documents, making it ideal for rapid development and testing.

## Prerequisites

- Have your custom application binary ready

## Quick Start

```bash
# Terminal 1: Start enclave in mock mode
cargo run --bin qos_core --features mock -- --usock ./dev.sock --mock

# Terminal 2: Start host
cargo run --bin qos_host -- --host-ip 127.0.0.1 --host-port 3000 --usock ./dev.sock

# Terminal 3: Bootstrap with your app
cargo run --bin qos_client -- dangerous-dev-boot \
  --host-ip 127.0.0.1 --host-port 3000 \
  --pivot-path ./path/to/your/app \
  --restart-policy never --pivot-args "[]" \
  --unsafe-eph-path-override ./local-enclave/qos.ephemeral.key
```

## Manual Setup (Step by Step)

### Terminal 1: Start qos_core in Mock Mode

```bash
cargo run --bin qos_core --features mock -- --usock ./dev.sock --mock
```

**Important flags:**
- `--features mock`: Compiles with mock NSM support
- `--mock`: Enables mock mode at runtime
- `--usock ./dev.sock`: Unix socket for communication with qos_host

### Terminal 2: Start qos_host

```bash
cargo run --bin qos_host -- \
  --host-ip 127.0.0.1 \
  --host-port 3000 \
  --usock ./dev.sock
```

**Flags:**
- `--host-ip`: IP address to bind to (use 127.0.0.1 for local)
- `--host-port`: Port for HTTP API (commonly 3000 or 3001)
- `--usock`: Must match the socket path used by qos_core

### Terminal 3: Bootstrap with dangerous-dev-boot

```bash
cargo run --bin qos_client -- dangerous-dev-boot \
  --host-ip 127.0.0.1 \
  --host-port 3000 \
  --pivot-path ./path/to/your/app \
  --restart-policy never \
  --pivot-args "[]" \
  --unsafe-eph-path-override ./local-enclave/qos.ephemeral.key
```

**Key parameters:**
- `--host-ip` / `--host-port`: Must match qos_host configuration
- `--pivot-path`: Path to your custom application binary
- `--restart-policy`: `never` for debugging, `always` for production-like behavior
- `--pivot-args`: JSON array of command-line arguments for your app (e.g., `"[--port,8080]"`)
- `--unsafe-eph-path-override`: Points to the ephemeral key generated during boot

## What dangerous-dev-boot Does

The `dangerous-dev-boot` command is a development shortcut that automates the entire provisioning flow:

1. Generates a quorum key
2. Shards the key (N=2, K=2)
3. Creates a minimal manifest with mock PCR values
4. Sends BootStandardRequest (manifest + pivot binary)
5. Provisions both shares to reconstruct the quorum key
6. Your app starts running

**Never use in production** - this bypasses all security checks and uses weak security parameters.

## Understanding Mock Mode

### Mock NSM Behavior

The mock NSM:
- Returns a **hardcoded** attestation document (from `qos_nsm/src/static/mock_attestation_doc`)
- Uses **hardcoded PCR values** (all defined in `qos_nsm/src/mock.rs`)
- Uses a **fixed timestamp** (unless `mock_realtime` feature is enabled)
- Does not perform real cryptographic attestation

### Why --unsafe-eph-path-override?

The mock attestation document contains a **broken** ephemeral public key (PEM format, 800 bytes) instead of the expected DER format (65 bytes). This causes parsing errors.

The `--unsafe-eph-path-override` flag tells the client to:
1. **Ignore** the public key from the attestation document
2. **Read** the actual ephemeral key from the filesystem
3. **Use** that key for encrypting quorum shares

**The flow:**
1. qos_core generates a fresh ephemeral key during `BootStandardRequest`
2. qos_core writes private key to `./local-enclave/qos.ephemeral.key`
3. qos_core returns the (broken) mock attestation document
4. Client reads `./local-enclave/qos.ephemeral.key` for the real public key
5. Client encrypts shares correctly
6. Decryption succeeds

### Alternative: Skip the Override

If you prefer not to use `--unsafe-eph-path-override`, you can omit it entirely. The client will attempt to extract the public key from the attestation document. However, this may fail due to the PEM encoding issue.

## File System Layout

When running in mock mode, qos_core creates a `./local-enclave/` directory with:

```
./local-enclave/
├── qos.ephemeral.key    # Ephemeral key pair (generated during boot)
├── qos.manifest          # Approved manifest
├── qos.pivot.bin         # Your application binary
└── qos.quorum.key        # Quorum key (after provisioning)
```

## Common Issues

### DecryptionFailed Error

**Symptom:** `thread 'main' panicked at qos_client/src/cli/services.rs:1720:5: ProtocolErrorResponse(DecryptionFailed)`

**Cause:** Mismatch between the ephemeral key used for encryption and the one used for decryption.

**Solution:**
- Use `--unsafe-eph-path-override ./local-enclave/qos.ephemeral.key`

### EncodedPublicKeyTooLong Error

**Symptom:** `Ephemeral key not valid public key: EncodedPublicKeyTooLong`

**Cause:** The mock attestation document has a PEM-encoded public key (800 bytes) instead of DER format.

**Solution:** Use `--unsafe-eph-path-override ./local-enclave/qos.ephemeral.key`

### Socket Connection Refused

**Symptom:** Connection refused to `./dev.sock`

**Solutions:**
- Ensure qos_core is running first (Terminal 1)
- Check that both qos_core and qos_host use the same `--usock` path
- Verify the socket file exists: `ls -la ./dev.sock`

## Debugging Your Application

### Viewing Logs

qos_core and qos_host output logs to their respective terminals. Set `RUST_LOG` for more verbose logging:

```bash
RUST_LOG=debug cargo run --bin qos_core --features mock -- --usock ./dev.sock --mock
```

### Restarting After Changes

If you modify your application:

1. Stop all three terminals (Ctrl+C)
2. Rebuild your app: `cargo build --bin your_app` or `cargo build --release --bin your_app`
3. Clean up: `rm -rf ./local-enclave`
4. Restart from Terminal 1

### Connecting to Your Application

After successful provisioning, your application runs and can be accessed via:
- **HTTP API** (if your app exposes one): `curl http://localhost:YOUR_APP_PORT`
- **Unix socket** (if your app uses `sec_app.sock`): Located at `./local-enclave/sec_app.sock`

## Production Differences

Mock mode differs significantly from production:

| Aspect | Mock Mode | Production |
|--------|-----------|------------|
| Attestation | Hardcoded document | Real AWS Nitro attestation |
| PCR Values | All zeros or mock values | Real enclave measurements |
| Ephemeral Key | Generated fresh each boot | Generated fresh each boot |
| Verification | None | Full cryptographic verification |
| Security | **INSECURE** | Secure enclave isolation |

**Never deploy with the `mock` feature enabled in production environments.**

# Provision a yubikey with qos client

This playbook covers provisioning yubikey for use with qos manifest and share set.

## Background: Management Key Compatibility

The `qos_client` uses the [`yubikey`](https://crates.io/crates/yubikey) Rust crate (v0.8), which only supports **3DES** management keys. yubikeys with firmware 5.7+ ship with **AES192** as the default management key algorithm. If you attempt to run `provision-yubikey` against such a device you will see: `Error: GenerateSign(FailedToAuthWithMGM)`. 

_Note_: we hope that once a new version of the `yubikey` crate is released it will support AES192 and we can remove the step (1) to downgrade the management key algorithm to TDES.

You can confirm the algorithm your device is using:

```bash
ykman piv info
# Look for: Management key algorithm: AES192  ← incompatible
#       or: Management key algorithm: TDES    ← compatible
```

If your device reports `AES192`, make sure to follow step 1 of provisioning.


## Setup

### 1: Set Management Key to TDES

**What this does**: Downgrades the management key algorithm from AES192 to 3DES so that `qos_client` can authenticate with the yubikey. The key value is set to the well-known PIV default 3DES key, which is what `qos_client` expects.

```bash
ykman piv access change-management-key --algorithm TDES
```

When prompted:

- **Current management key**: press Enter to use the default
- **New management key**: `010203040506070801020304050607080102030405060708` (this is suggested as it is the yubikey default management key. It should be changed before using in production: see [step 4](#4-lock-the-management-key))

Verify the change:

```bash
ykman piv info
# Management key algorithm: TDES  ← expected
```

### 2: Set the PIN

**What this does**: Changes the PIV PIN from the factory default (`123456`) to a value you choose. The PIN is required every time `qos_client` performs a signing or key agreement operation.

First, disable shell history to avoid your PIN appearing in `~/.bash_history`:

```bash
unset HISTFILE
```

Then change the PIN:

```bash
qos_client yubikey-change-pin \
  --current-pin-path <(printf '%s' "123456") \
  --new-pin-path <(printf '%s' "YOUR_NEW_PIN")
```

Replace `YOUR_NEW_PIN` with your chosen PIN. PIN requirements: 6–8 characters.

Note: Do not write the PIN to a file on disk. The process substitution syntax `<(printf ...)` passes the value directly without touching the filesystem. With `HISTFILE` unset, the command will not be written to your shell history.

### 3: Provision the yubikey

**What this does**: Generates two P-256 keys on the yubikey (in the signing and key agreement slots) and writes the corresponding public key to disk. The private key never leaves the device.

```bash
qos_client provision-yubikey --pub-path ~/path/to/output.pub
```

When prompted, enter the PIN you set in Phase 2.

The file at `--pub-path` will contain the hex-encoded public key. Share this `.pub` file with the ceremony coordinator — never share the PIN or the device itself.

If you ever need to retrieve the public key from an already-provisioned yubikey:

```bash
qos_client yubikey-public
# or save to a file:
qos_client yubikey-public > ~/path/to/output.pub
```

Note: The PIN policy is set to `Always`, meaning the yubikey will require PIN entry (and a physical touch) for every cryptographic operation. This ensures the device cannot be used without your explicit authorization.

### 4: Lock the Management Key

**What this does**: Authenticates with the current management key (the default set in step 1), then sends a PIV `SET MANAGEMENT KEY` command to the device with a newly generated random value. The yubikey atomically replaces its stored management key in hardware. Because the new value is discarded immediately, no one can authenticate as management again — PIN changes, PUK changes, PIN retry counter resets, and key imports are all permanently blocked.

```bash
ykman piv access change-management-key \
  --management-key 010203040506070801020304050607080102030405060708 \
  --algorithm TDES --generate > /dev/null
```

Verify the default management key no longer works by running the same command, but this time you should observe the error: `ERROR: Authentication with management key failed.` If you see this error, the lock is confirmed.

Note: If you need to reset the yubikey after this step, you must perform a full PIV reset (`ykman piv reset`), which will destroy all keys and certificates on the device.

## Provisioning Multiple YubiKeys with the Same Key

If you need the same key on multiple yubikeys, use `advanced-provision-yubikey` instead of `provision-yubikey`.

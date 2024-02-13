# Quorum Key Resharding Guide

This guide covers how to reshard a quorum key using the qos_client CLI.

## Overview

Flow:

1) Generate the configuration for how to reshard the given quorum keys. This configuration is called the `ReshardInput`.
2) Boot the enclave in reshard mode using the `ReshardInput`.
3) A threshold of the _old_ share holders query the enclave for an attestation document.
4) A threshold of the _old_ share holders re-encrypt their shares to the enclaves ephemeral key and post those shares in a single message. The data structure used to group a users shares and their corresponding quorum keys is called the `ReshardProvisionInput`.
5) All of the _new_ share holders fetch the `ReshardOutput` to verify they can decrypt their shares.

## Steps

### 1 - Generate ReshardInput (Lead)

Generate the configuration for resharding the quorum keys.

```sh
qos_client generate-reshard-input \
  --qos-release-dir <read: path to a dir with the pcrs file and release.env> \
  --pcr3-preimage-path <read: path to the IAM role for the enclave> \
  --quorum-key-path-multiple <read: path to a quorum key to reshard; use this flag multiple times to specify multiple quorum key paths> \
  --old-share-set-dir <read: path to dir with old share set> \
  --new-share-set-dir <read: path to dir with new share set> \
  --reshard-input-path <write: path to the file to write the reshard input>
```

### 2 - Reshard Boot (Lead)

Post the reshard boot instruction with the reshard input.

```sh
qos_client boot-reshard \
  --reshard-input-path <read: path to reshard input> \
  --host-port 3001 \
  --host-ip localhost
```

### 3 - Get attestation doc (Old Share Holder)

Get the attestation doc from the enclave. The attestation doc contains a refference to the reshard input and the ephemeral key which shares will be encrypted.

```sh
qos_client get-reshard-attestation-doc \
  --attestation-doc-path <write: path to the file to write the attestation doc to> \
  --host-port 3001 \
  --host-ip localhost
```

### 4 - Re-encrypt share to ephemeral key (Old Share Holder)

Use the attestation doc to verify that the enclave is properly setup and running the expected code and re-encrypt relevant shares to the ephemeral key of the enclave. This step should be done on an airgapped machine as unencrypted shares will be exposed to memory.

For each quorum key being resharded, the user will need a separate directory with just the quorum key and their targeted share. Each directory must be organized like:

```
- quorum-share-dir
  - quorum_key.pub
  - my_alias.share
```

Note that the logic looks at the extension of the file to determine if its a share or the quorum key.

```sh
qos_client reshard-re-encrypt-share \
  --yubikey \
  --quorum-share-dir-multiple <read: path to directory to specify> \
  --attestation-doc-path <read: path to attestation doc> \
  --provision-input-path <write: path to the file to write this users provision input> \
  --reshard-input-path <read: path to reshard input> \
  --qos-release-dir <read: path to a dir with pcrs file and release.env> \
  --pcr3-preimage-path <read: path to the IAM role for the enclave> \
  --new-share-set-dir <read: path to dir new share set> \
  --old-share-set-dir <read: path to dir with old_share_set> \
  --alias <alias for share holder>
```

### 5 - Post reshard input (Old Share Holder)

Post the re-encrypted shares from last step in order to reconstruct the quorum keys.

```sh
qos_client reshard-post-share
  --provision-input-path <write: path to the file to write this users provision input> \
  --host-port 3001 \
  --host-ip localhost
```

### 6 - Get the new shares (New Share Holder)

```sh
qos_client get-reshard-output \
  --reshard-output-path <write: path to the file to write this users reshard output> \
  --host-port 3001 \
  --host-ip localhost
```

### 7 - Verify shares (New Share Holder)

Verify that we can decrypt our shares. This step should be done on an airgapped machine as the unencrypted share will be exposed to memory.

The new shares will be written to subdirectories generated within the given share dir. The subdirectories will be named with the first four bytes of the quorum key. Each subdirectory will contain a new share and the quorum key it targets. After running the command against an empty `share-dir` and two sharded quorum, keys, the layout would look like:

```sh
- share-dir
  - 04009fd6
    - quorum_key.pub
    - my_alias.share
  - 041acdf2
    - quorum_key.pub
    - my_alias.share
```

```sh
qos_client verify-reshard-output \
  --yubikey \
  --reshard-output-path <read: path to reshard output> \
  --share-dir <write: dir to write subdirs that contain a share and the targeted quorum key>
```

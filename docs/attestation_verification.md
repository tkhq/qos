# Verify an Attestation Document Against a Manifest

This procedure verifies that a QOS attestation document is authentic and binds
the expected manifest, enclave measurements, and ephemeral public key. It needs
the COSE_Sign1 document, the manifest (or its envelope), and a trusted copy of
the AWS Nitro Enclaves Root-G1 certificate.

Choose the expected attestation kind before starting: **setup** for a boot or
provisioning document, or **live** for a post-provision app document.

## Checklist

1. **Decode COSE_Sign1.** Accept an untagged four-item COSE_Sign1 array or CBOR
   tag 18. Require protected algorithm `-35` (ES384), and preserve the received
   `protected` and `payload` byte strings without re-encoding them.

2. **Decode the payload.** Require an AWS attestation map with non-empty
   `module_id`, `certificate`, and `cabundle`; `digest == SHA384`; a non-zero
   `timestamp`; and valid `pcrs`, `user_data`, and `public_key` byte strings.

3. **Verify the certificate path.** Ignore `cabundle[0]`, which is the
   document-supplied root. Validate pinned Root-G1 -> `cabundle[1..]` ->
   `certificate`, including signatures and validity windows, at the verifier's
   chosen validation time.

4. **Verify the COSE signature.** Use the P-384 public key from `certificate` to
   verify the raw 96-byte ECDSA signature over the SHA-384 digest of the encoded
   COSE `Sig_structure` defined below.

5. **Recompute the manifest hash.** Hash the manifest only, never its envelope:
   V2 uses SHA-256 over [QOS canonical JSON](../src/qos_json/SPEC.md); V1/V0 use
   SHA-256 over Borsh. Verify `user_data == manifest_hash` as raw bytes.

6. **Verify measured PCRs.** Require PCR0, PCR1, PCR2, and PCR3 to equal
   `manifest.enclave.pcr0..pcr3` byte-for-byte. Require every PCR index 0 through
   31 to be present.

7. **Validate the ephemeral key.** Require `public_key` to encode
   `encrypt_public || sign_public`: two uncompressed SEC1 P-256 points (65 bytes
   each, 130 bytes total). Use this exact 130-byte value in the next step.

8. **Verify the manifest commitment PCR.** Reconstruct the expected commitment
   from `manifest_hash` and `public_key` as defined below. Verify it equals PCR16
   for setup documents or PCR17 for live documents.

9. **Verify the manifest-only commitment.** Reconstruct PCR18 from
   `manifest_hash` as below; this does not replace step 8's key binding.

## Constants

| Item | Value |
|---|---|
| COSE signature | ES384 (`alg = -35`), ECDSA P-384/SHA-384, raw `r || s` |
| Certificate signatures | ECDSA P-384/SHA-384 |
| Manifest hash | SHA-256, 32 bytes |
| PCR digest and length | SHA-384, 48 bytes |
| Attestable PCR indexes | 0 through 31 |
| Setup commitment | PCR16, domain `qos-setup-manifest-pcr-commitment-v1` |
| Live commitment | PCR17, domain `qos-live-manifest-pcr-commitment-v1` |
| Manifest-only commitment | PCR18, domain `qos-manifest-pcr-commitment-v1` |
| Commitment PCR initial value | 48 zero bytes |
| Commitment hex | Lowercase, no `0x` prefix |
| Ephemeral public key | `encrypt_public || sign_public`, 65 + 65 bytes |
| Root-G1 SHA-256 fingerprint | `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (DER certificate) |

Download Root-G1 from
<https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip> or use
the [vendored certificate](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/static/aws_root_cert.pem).

## Constructions

### COSE `Sig_structure`

Encode this CBOR array with definite lengths, using the original byte strings:

```text
[
  "Signature1",
  protected,
  h'',
  payload
]
```

Compute `SHA384(encoded_array)` and verify the COSE signature as raw
`r || s`, where each scalar is a 48-byte big-endian integer. Convert to ASN.1
DER only when required by the cryptographic API.

### Manifest commitment PCR

Encode this UTF-8 canonical JSON with exactly the shown fields and no
whitespace:

```json
{"domain":"<domain>","ephemeralPublicKey":"<lowercase hex>","manifestHash":"<lowercase hex>"}
```

Then compute:

```text
commitment  = SHA384(preimage)
expectedPcr = SHA384((0x00 * 48) || commitment)
```

Compare `expectedPcr` with PCR16 (setup) or PCR17 (live). The reference
implementation is
[`expected_manifest_commitment_pcr`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L178-L186);
its encoding and output vectors are in
[`manifest_pcr_commitment_preimage_uses_qos_json`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L691-L702)
and
[`manifest_commitment_pcr_test_vectors`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L716-L764).

### Manifest-only commitment PCR

PCR18 applies the same two hashes to this canonical JSON:

```json
{"domain":"qos-manifest-pcr-commitment-v1","manifestHash":"<lowercase hex>"}
```

The key field is absent, not empty; the distinct domain separates PCR18 from
PCR16 and PCR17.

## Pitfalls

- Pin Root-G1 out of band; never trust `cabundle[0]` as a trust anchor.
- Choose certificate validation time explicitly; archived documents may require
  the document timestamp because Nitro leaf certificates are short-lived.
- Hash the schema-specific canonical manifest, not received JSON bytes or the
  manifest envelope.
- Do not confuse the 32-byte SHA-256 manifest hash with 48-byte SHA-384 PCRs.
- Hash the entire 130-byte public key, not only its encryption or signing half.
- Preserve the two commitment hash layers:
  `SHA384(zeros48 || SHA384(preimage))`.
- Do not mix setup PCR16/domain with live PCR17/domain.
- Treat COSE signatures as raw `r || s`; many APIs expect DER instead.

## Reference

- Full verification flow:
  [`attestation_doc_from_der`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L457-L476) and
  [`verify_attestation_doc_against_manifest`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L236-L256)
- Certificate path and COSE signature:
  [`verify_certificate_chain`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L479-L505) and
  [`verify_cose_sign1_sig`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L509-L554)
- Manifest, PCR, nonce, and key bindings:
  [`verify_attestation_doc_against_user_input`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L323-L404)
  and
  [`verify_attestation_doc_manifest_commitment`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/nitro/mod.rs#L193-L229)
- Manifest hashing:
  [`VersionedManifest::manifest_hash`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_core/src/protocol/services/boot/manifest.rs#L121-L127)
  and [QOS canonical JSON](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_json/SPEC.md)
- End-to-end fixtures:
  [`MOCK_NSM_ATTESTATION_DOCUMENT`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/mock.rs#L55-L56)
  and [`MockNsm`](https://github.com/tkhq/qos/blob/1cf9b652a4616fc081948328e2b9ad57675c1395/src/qos_nsm/src/mock.rs#L109-L111)

Manifest approval verification and proof retrieval are outside this procedure.

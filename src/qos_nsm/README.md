# `qos_nsm`

`qos_nsm` contains QOS types and provider implementations for the AWS Nitro
Secure Module (NSM) API. QOS uses this crate to request attestation documents,
parse Nitro attestation documents, and verify the document fields that bind a
running enclave to an approved manifest.

The main abstraction is `NsmProvider`. Production code uses `Nsm`, which sends
`NsmRequest` values to the AWS Nitro NSM driver. Tests and local development can
use mock providers that implement the same trait.

## Providers

- `Nsm`: the production provider. It sends `NsmRequest` values to the AWS Nitro
  NSM driver and returns `NsmResponse` values from the driver.
- `MockNsm`: a static test provider behind the `mock` feature. It returns the
  fixed attestation document embedded in this crate. This is useful for tests
  that need stable historical fixture data.
- `DynamicMockNsm`: a configurable test provider behind the `mock` feature. It
  creates a fresh, parseable COSE Sign1 attestation document for each
  attestation request and preserves the request's `user_data`, `nonce`, and
  `public_key` fields.

`DynamicMockNsm` supports local end-to-end tests for pivot applications that call
the attestation API, return app-level proofs, and include an attestation document
plus manifest in their response. Like a real NSM request, the ephemeral public
key must be supplied in `NsmRequest::Attestation`.

## Attestation Scope

The Nitro helpers in `nitro` expose two levels of parsing:

- `unsafe_attestation_doc_from_der` decodes the COSE payload into an
  `AttestationDoc` without certificate-chain or signature validation.
- `attestation_doc_from_der` performs AWS Nitro certificate-chain validation and
  verifies the COSE signature against the attestation document certificate.

Mock providers are only for local development and tests. In particular,
`DynamicMockNsm` creates documents that are useful for checking QOS protocol
fields such as manifest hash, PCRs, nonce, and ephemeral public key, but it does
not produce AWS Nitro PKI-signed documents.

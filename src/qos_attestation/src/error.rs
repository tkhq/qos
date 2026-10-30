//! Errors for attestation.

use qos_nsm::nitro::AttestError;

/// Errors from constructing inputs, attesting, verifying and caching.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	/// The NSM returned an error.
	#[error("NSM returned an error: {0}")]
	Nsm(String),
	/// The NSM returned a response that isn't an attestation document.
	#[error("unexpected NSM response: {0}")]
	UnexpectedNsmResponse(String),
	/// The document failed to parse, or its certificate chain or signature
	/// failed verification.
	#[error("attestation document could not be parsed or verified: {0}")]
	Document(#[source] AttestError),
	/// A certificate's validity period could not be read.
	#[error("failed to read certificate validity: {0}")]
	Certificate(String),
	/// The certificate chain expired at issuance or verification, or before
	/// serving.
	#[error("attestation document certificate chain is already expired")]
	Expired,
	/// A certificate was not yet valid at issuance or verification.
	#[error("attestation document certificate chain is not yet valid")]
	NotYetValid,
	/// Signed issuance falls after the supplied verification second.
	#[error("attestation document timestamp is in a future second")]
	FutureTimestamp,
	/// Reading the provider's trusted clock failed.
	#[error("failed to read NSM timestamp: {0}")]
	Clock(#[source] AttestError),
	/// The manifest, PCR0-3, live-key commitment, or nonce check failed.
	#[error("attestation document does not match the manifest: {0}")]
	Binding(#[source] AttestError),
	/// The document's public key differs from the expected live ephemeral key.
	#[error("attestation document attests a different public key")]
	PublicKeyMismatch,
	/// The manifest-only (PCR18) commitment check failed.
	#[error("manifest-only commitment check failed: {0}")]
	ManifestOnlyCommitment(#[source] AttestError),
	/// The blocking attestation task failed.
	#[error("attestation task failed: {0}")]
	Task(String),
}

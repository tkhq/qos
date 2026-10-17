//! Errors for self-attestation.

use qos_nsm::nitro::AttestError;

/// Errors from loading inputs, attesting, verifying and caching.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	/// The manifest file could not be read.
	#[error("failed to read manifest: {0}")]
	ManifestRead(#[source] std::io::Error),
	/// The manifest file is larger than the read limit.
	#[error("manifest is larger than {limit} bytes")]
	ManifestTooLarge {
		/// The limit, in bytes.
		limit: u64,
	},
	/// The manifest bytes are not a manifest envelope QOS understands.
	#[error("failed to decode manifest envelope: {0}")]
	ManifestDecode(String),
	/// The manifest schema can't be used for a boot proof.
	#[error("manifest {0} is not supported")]
	UnsupportedManifestVersion(&'static str),
	/// The ephemeral key could not be read.
	#[error("failed to read ephemeral key: {0}")]
	EphemeralKey(String),
	/// The key or manifest no longer matches the inputs pinned at startup.
	#[error("ephemeral key or manifest changed since startup")]
	InputsChanged,
	/// The NSM returned an error.
	#[error("NSM returned an error: {0}")]
	Nsm(String),
	/// The NSM returned a response that isn't an attestation document.
	#[error("unexpected NSM response: {0}")]
	UnexpectedNsmResponse(String),
	/// The document failed to parse, or its certificate chain or signature
	/// failed verification.
	#[error("attestation document failed verification: {0}")]
	Document(#[source] AttestError),
	/// A certificate's validity period could not be read.
	#[error("failed to read certificate validity: {0}")]
	Certificate(String),
	/// The document's certificate chain has already expired at the
	/// document's own timestamp.
	#[error("attestation document certificate chain is already expired")]
	Expired,
	/// The document doesn't attest the expected manifest, PCR0-3, live key
	/// commitment, or an empty nonce.
	#[error("attestation document does not match the manifest: {0}")]
	Binding(#[source] AttestError),
	/// The document attests a different public key than ours.
	#[error("attestation document attests a different public key")]
	PublicKeyMismatch,
	/// The manifest-only (PCR18) commitment is missing or wrong.
	#[error("manifest-only commitment check failed: {0}")]
	ManifestOnlyCommitment(#[source] AttestError),
	/// Loading inputs or attesting took longer than the call timeout.
	#[error("attestation timed out")]
	Timeout,
	/// An earlier timed-out attestation is still running.
	#[error("an earlier attestation is still in flight")]
	InFlight,
	/// The blocking attestation task failed.
	#[error("attestation task failed: {0}")]
	Task(String),
}

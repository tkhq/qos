//! Verification of the QuorumOS trust chain: an NSM attestation document and
//! an in-memory manifest or manifest envelope, checked against caller-supplied
//! trust and policy.
//!
//! [`verify_attestation_and_manifest`] verifies an attestation document
//! against a manifest. [`verify_attestation_and_manifest_envelope`] first
//! anchors and verifies the manifest envelope, then delegates to the manifest
//! verifier. Deserialization is deliberately left to callers. On success both
//! return authenticated attestation evidence, including the enclave's
//! ephemeral public key.

pub use qos_nsm::nitro::ManifestCommitmentKind;
use qos_nsm::nitro::{self, AttestError};
use qos_p256::{P256Error, P256Public};
use std::{
	fmt,
	time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

use crate::protocol::{
	ProtocolError,
	services::boot::{
		ManifestSet, ShareSet, VersionedManifest, VersionedManifestEnvelope,
	},
};

/// Errors from manifest and manifest-envelope verification, one per failure
/// class.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
	/// The manifest namespace name does not match the expected value.
	#[error(
		"manifest namespace name mismatch: expected {expected}, got {actual}"
	)]
	NamespaceNameMismatch {
		/// Expected namespace name.
		expected: String,
		/// Namespace name in the manifest.
		actual: String,
	},
	/// The manifest namespace nonce does not match the expected value.
	#[error(
		"manifest namespace nonce mismatch: expected {expected}, got {actual}"
	)]
	NonceMismatch {
		/// Expected namespace nonce.
		expected: u32,
		/// Namespace nonce in the manifest.
		actual: u32,
	},
	/// The manifest quorum key does not match the expected value.
	#[error("manifest quorum key mismatch: expected {expected}, got {actual}")]
	QuorumKeyMismatch {
		/// Expected quorum public key, hex encoded.
		expected: String,
		/// Quorum public key in the manifest, hex encoded.
		actual: String,
	},
	/// A manifest PCR does not match the expected value.
	#[error("manifest PCR{index} mismatch: expected {expected}, got {actual}")]
	PcrMismatch {
		/// PCR register index (0 through 3).
		index: u8,
		/// Expected PCR value, hex encoded.
		expected: String,
		/// PCR value in the manifest, hex encoded.
		actual: String,
	},
	/// The manifest pivot (app binary) hash does not match the expected
	/// value.
	#[error("manifest pivot hash mismatch: expected {expected}, got {actual}")]
	PivotHashMismatch {
		/// Expected pivot hash, hex encoded.
		expected: String,
		/// Pivot hash in the manifest, hex encoded.
		actual: String,
	},
	/// The manifest hash does not match the expected value.
	#[error("manifest hash mismatch: expected {expected}, got {actual}")]
	ManifestHashMismatch {
		/// Expected manifest hash, hex encoded.
		expected: String,
		/// Hash of the manifest in the envelope, hex encoded.
		actual: String,
	},
	/// The manifest set does not match the expected value.
	#[error("manifest set mismatch: expected {expected:?}, got {actual:?}")]
	ManifestSetMismatch {
		/// Expected manifest set.
		expected: ManifestSet,
		/// Manifest set in the manifest.
		actual: ManifestSet,
	},
	/// The share set does not match the expected value.
	#[error("share set mismatch: expected {expected:?}, got {actual:?}")]
	ShareSetMismatch {
		/// Expected share set.
		expected: ShareSet,
		/// Share set in the manifest.
		actual: ShareSet,
	},
	/// The attestation document could not be decoded or did not verify up to
	/// the root certificate authority.
	#[error("attestation document verification failed: {0}")]
	AttestationDoc(#[from] AttestError),
	/// The authenticated attestation document does not match the manifest,
	/// nonce policy, or manifest commitment PCR.
	#[error("attestation document does not match the manifest: {0}")]
	AttestationManifest(#[source] AttestError),
	/// The attestation document is older than the permitted freshness window.
	#[error(
		"attestation document is stale: timestamp {timestamp_ms}ms, earliest permitted {earliest_ms}ms"
	)]
	AttestationTooOld {
		/// Timestamp carried by the attestation document.
		timestamp_ms: u64,
		/// Earliest timestamp permitted by the freshness policy.
		earliest_ms: u64,
	},
	/// The attestation document is too far in the future.
	#[error(
		"attestation document is from the future: timestamp {timestamp_ms}ms, latest permitted {latest_ms}ms"
	)]
	AttestationFromFuture {
		/// Timestamp carried by the attestation document.
		timestamp_ms: u64,
		/// Latest timestamp permitted by the clock-skew policy.
		latest_ms: u64,
	},
	/// The system clock is before the Unix epoch.
	#[error("system clock is before the Unix epoch")]
	SystemTimeBeforeUnixEpoch,
	/// The current time cannot be represented in milliseconds.
	#[error("current time is outside the supported millisecond range")]
	SystemTimeOutOfRange,
	/// A configured freshness duration cannot be represented in milliseconds.
	#[error("attestation freshness duration is outside the supported range")]
	FreshnessDurationOutOfRange,
	/// The manifest-set approvals over the manifest hash did not verify.
	#[error("manifest set approval verification failed: {0}")]
	ManifestSetApprovals(#[from] ProtocolError),
	/// The attestation document carries no public key.
	#[error("attestation document is missing a public key")]
	MissingPublicKey,
	/// The attestation document public key is not a valid P-256 public key.
	#[error("failed to decode ephemeral public key: {0:?}")]
	EphemeralKeyDecode(P256Error),
	/// A caller-supplied manifest policy rejected the manifest.
	#[error("manifest policy rejected the manifest: {0}")]
	ManifestPolicy(String),
}

/// Policy for the nonce carried by an attestation document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoncePolicy {
	/// The attestation document must not contain a nonce.
	Absent,
	/// The attestation document must contain exactly these nonce bytes.
	Exact(Vec<u8>),
}

/// Certificate, freshness, nonce, and boot-phase policy for an attestation.
#[derive(Debug, Clone)]
pub struct AttestationPolicy<'a> {
	root_ca: &'a [u8],
	max_age: Duration,
	max_future_skew: Duration,
	nonce: NoncePolicy,
	commitment_kind: ManifestCommitmentKind,
}

impl<'a> AttestationPolicy<'a> {
	/// Create a policy that requires an absent nonce and permits no future
	/// clock skew.
	#[must_use]
	pub fn new(
		root_ca: &'a [u8],
		max_age: Duration,
		commitment_kind: ManifestCommitmentKind,
	) -> Self {
		Self {
			root_ca,
			max_age,
			max_future_skew: Duration::ZERO,
			nonce: NoncePolicy::Absent,
			commitment_kind,
		}
	}

	/// Permit attestation timestamps up to this far in the future.
	#[must_use]
	pub fn max_future_skew(mut self, max_future_skew: Duration) -> Self {
		self.max_future_skew = max_future_skew;
		self
	}

	/// Set the expected attestation nonce.
	#[must_use]
	pub fn nonce(mut self, nonce: NoncePolicy) -> Self {
		self.nonce = nonce;
		self
	}
}

/// Caller-owned trust anchor for a manifest envelope.
///
/// Envelope approvals are checked only after the embedded manifest is anchored
/// to one of these values. This prevents an envelope's self-described manifest
/// set from being its own root of trust.
#[derive(Debug, Clone, Copy)]
pub enum ManifestEnvelopeTrust<'a> {
	/// Trust exactly this manifest hash.
	ManifestHash([u8; 32]),
	/// Trust this manifest set, comparing members without regard to ordering.
	ManifestSet(&'a ManifestSet),
}

/// Authenticated evidence returned after manifest attestation verification.
pub struct VerifiedManifestAttestation {
	/// Ephemeral public key bound into the manifest commitment PCR.
	pub ephemeral_key: P256Public,
	/// Hash of the verified manifest.
	pub manifest_hash: [u8; 32],
	/// Boot phase whose commitment PCR was verified.
	pub commitment_kind: ManifestCommitmentKind,
	/// Timestamp carried by the authenticated attestation document.
	pub attestation_timestamp_ms: u64,
}

impl fmt::Debug for VerifiedManifestAttestation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VerifiedManifestAttestation")
			.field(
				"ephemeral_key",
				&qos_hex::encode(&self.ephemeral_key.to_bytes()),
			)
			.field("manifest_hash", &qos_hex::encode(&self.manifest_hash))
			.field("commitment_kind", &self.commitment_kind)
			.field("attestation_timestamp_ms", &self.attestation_timestamp_ms)
			.finish()
	}
}

/// Caller-defined policy for accepting a manifest.
pub trait ManifestPolicy {
	/// Check the manifest after it has been supplied or externally anchored.
	///
	/// # Errors
	///
	/// Returns a [`VerifyError`] describing why the policy rejected the
	/// manifest.
	fn verify(&self, manifest: &VersionedManifest) -> Result<(), VerifyError>;
}

/// Expected values to check the manifest against. Only supplied values are
/// compared. For direct manifest verification, the manifest itself is assumed
/// to come from a trusted caller. Envelope verification separately requires a
/// [`ManifestEnvelopeTrust`] value.
#[derive(Debug, Clone, Default)]
pub struct VerificationExpectations {
	namespace_name: Option<String>,
	nonce: Option<u32>,
	quorum_key: Option<Vec<u8>>,
	pcr0: Option<Vec<u8>>,
	pcr1: Option<Vec<u8>>,
	pcr2: Option<Vec<u8>>,
	pcr3: Option<Vec<u8>>,
	pivot_hash: Option<[u8; 32]>,
	manifest_hash: Option<[u8; 32]>,
	manifest_set: Option<ManifestSet>,
	share_set: Option<ShareSet>,
}

impl VerificationExpectations {
	/// Create an empty set of expectations.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Expect the manifest namespace name.
	#[must_use]
	pub fn namespace_name(mut self, name: &str) -> Self {
		self.namespace_name = Some(name.to_string());
		self
	}

	/// Expect the manifest namespace nonce.
	#[must_use]
	pub fn nonce(mut self, nonce: u32) -> Self {
		self.nonce = Some(nonce);
		self
	}

	/// Expect the manifest quorum public key bytes.
	#[must_use]
	pub fn quorum_key(mut self, quorum_key: Vec<u8>) -> Self {
		self.quorum_key = Some(quorum_key);
		self
	}

	/// Expect the manifest PCR0 value.
	#[must_use]
	pub fn pcr0(mut self, pcr0: Vec<u8>) -> Self {
		self.pcr0 = Some(pcr0);
		self
	}

	/// Expect the manifest PCR1 value.
	#[must_use]
	pub fn pcr1(mut self, pcr1: Vec<u8>) -> Self {
		self.pcr1 = Some(pcr1);
		self
	}

	/// Expect the manifest PCR2 value.
	#[must_use]
	pub fn pcr2(mut self, pcr2: Vec<u8>) -> Self {
		self.pcr2 = Some(pcr2);
		self
	}

	/// Expect the manifest PCR3 value.
	#[must_use]
	pub fn pcr3(mut self, pcr3: Vec<u8>) -> Self {
		self.pcr3 = Some(pcr3);
		self
	}

	/// Expect the manifest pivot (app binary) hash.
	#[must_use]
	pub fn pivot_hash(mut self, pivot_hash: [u8; 32]) -> Self {
		self.pivot_hash = Some(pivot_hash);
		self
	}

	/// Expect the manifest hash.
	#[must_use]
	pub fn manifest_hash(mut self, manifest_hash: [u8; 32]) -> Self {
		self.manifest_hash = Some(manifest_hash);
		self
	}

	/// Expect the manifest set: threshold and members must match, regardless
	/// of member ordering.
	#[must_use]
	pub fn manifest_set(mut self, manifest_set: ManifestSet) -> Self {
		self.manifest_set = Some(manifest_set);
		self
	}

	/// Expect the share set: threshold and members must match, regardless of
	/// member ordering.
	#[must_use]
	pub fn share_set(mut self, share_set: ShareSet) -> Self {
		self.share_set = Some(share_set);
		self
	}
}

impl ManifestPolicy for VerificationExpectations {
	fn verify(&self, manifest: &VersionedManifest) -> Result<(), VerifyError> {
		check_expectations(self, manifest, &manifest.manifest_hash())
	}
}

/// Verify an attestation document against a trusted in-memory manifest.
///
/// # Arguments
///
/// * `attestation_doc` - DER encoded COSE Sign1 attestation document from the
///   NSM.
/// * `manifest` - manifest to verify against the attestation document.
/// * `attestation_policy` - certificate trust, freshness, nonce, and boot-phase
///   requirements. Certificate validity and freshness are evaluated at the
///   current system time.
/// * `manifest_policy` - caller-defined requirements for the trusted manifest.
///
/// # Errors
///
/// Returns a [`VerifyError`] variant identifying the failed check.
pub fn verify_attestation_and_manifest(
	attestation_doc: &[u8],
	manifest: &VersionedManifest,
	attestation_policy: &AttestationPolicy<'_>,
	manifest_policy: &dyn ManifestPolicy,
) -> Result<VerifiedManifestAttestation, VerifyError> {
	verify_attestation_and_manifest_at_time(
		attestation_doc,
		manifest,
		attestation_policy,
		manifest_policy,
		current_time()?,
	)
}

fn verify_attestation_and_manifest_at_time(
	attestation_doc: &[u8],
	manifest: &VersionedManifest,
	attestation_policy: &AttestationPolicy<'_>,
	manifest_policy: &dyn ManifestPolicy,
	current_time: Duration,
) -> Result<VerifiedManifestAttestation, VerifyError> {
	let manifest_hash = manifest.manifest_hash();

	manifest_policy.verify(manifest)?;

	let doc = nitro::attestation_doc_from_der(
		attestation_doc,
		attestation_policy.root_ca,
		current_time.as_secs(),
	)?;
	check_attestation_freshness(
		doc.timestamp,
		current_time_ms(current_time)?,
		attestation_policy,
	)?;

	let enclave = manifest.enclave();
	let public_key =
		doc.public_key.as_deref().ok_or(VerifyError::MissingPublicKey)?;
	let expected_nonce = match &attestation_policy.nonce {
		NoncePolicy::Absent => None,
		NoncePolicy::Exact(nonce) => Some(nonce.as_slice()),
	};
	nitro::verify_attestation_doc_against_manifest_with_nonce(
		attestation_policy.commitment_kind,
		&doc,
		nitro::ManifestAttestationInput {
			manifest_hash: &manifest_hash,
			pcr0: &enclave.pcr0,
			pcr1: &enclave.pcr1,
			pcr2: &enclave.pcr2,
			pcr3: &enclave.pcr3,
		},
		expected_nonce,
	)
	.map_err(VerifyError::AttestationManifest)?;

	let ephemeral_key = P256Public::from_bytes(public_key)
		.map_err(VerifyError::EphemeralKeyDecode)?;

	Ok(VerifiedManifestAttestation {
		ephemeral_key,
		manifest_hash,
		commitment_kind: attestation_policy.commitment_kind,
		attestation_timestamp_ms: doc.timestamp,
	})
}

/// Verify an in-memory manifest envelope and attestation document.
///
/// The embedded manifest must first match the caller-owned `trust` anchor.
/// Manifest-set approvals are then checked before the manifest is passed to
/// [`verify_attestation_and_manifest`]. Deserialization is intentionally not
/// part of this function.
///
/// # Errors
///
/// Returns a [`VerifyError`] variant identifying the failed check.
pub fn verify_attestation_and_manifest_envelope(
	attestation_doc: &[u8],
	manifest_envelope: &VersionedManifestEnvelope,
	trust: ManifestEnvelopeTrust<'_>,
	attestation_policy: &AttestationPolicy<'_>,
	manifest_policy: &dyn ManifestPolicy,
) -> Result<VerifiedManifestAttestation, VerifyError> {
	verify_attestation_and_manifest_envelope_at_time(
		attestation_doc,
		manifest_envelope,
		trust,
		attestation_policy,
		manifest_policy,
		current_time()?,
	)
}

fn verify_attestation_and_manifest_envelope_at_time(
	attestation_doc: &[u8],
	manifest_envelope: &VersionedManifestEnvelope,
	trust: ManifestEnvelopeTrust<'_>,
	attestation_policy: &AttestationPolicy<'_>,
	manifest_policy: &dyn ManifestPolicy,
	current_time: Duration,
) -> Result<VerifiedManifestAttestation, VerifyError> {
	check_envelope_trust(manifest_envelope, trust)?;
	manifest_envelope.check_approvals()?;

	verify_attestation_and_manifest_at_time(
		attestation_doc,
		&manifest_envelope.clone().manifest(),
		attestation_policy,
		manifest_policy,
		current_time,
	)
}

fn current_time() -> Result<Duration, VerifyError> {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| VerifyError::SystemTimeBeforeUnixEpoch)
}

fn current_time_ms(current_time: Duration) -> Result<u64, VerifyError> {
	u64::try_from(current_time.as_millis())
		.map_err(|_| VerifyError::SystemTimeOutOfRange)
}

fn check_attestation_freshness(
	timestamp_ms: u64,
	current_time_ms: u64,
	policy: &AttestationPolicy<'_>,
) -> Result<(), VerifyError> {
	let max_age_ms = u64::try_from(policy.max_age.as_millis())
		.map_err(|_| VerifyError::FreshnessDurationOutOfRange)?;
	let max_future_skew_ms = u64::try_from(policy.max_future_skew.as_millis())
		.map_err(|_| VerifyError::FreshnessDurationOutOfRange)?;
	let earliest_ms = current_time_ms.saturating_sub(max_age_ms);
	if timestamp_ms < earliest_ms {
		return Err(VerifyError::AttestationTooOld {
			timestamp_ms,
			earliest_ms,
		});
	}
	let latest_ms = current_time_ms.saturating_add(max_future_skew_ms);
	if timestamp_ms > latest_ms {
		return Err(VerifyError::AttestationFromFuture {
			timestamp_ms,
			latest_ms,
		});
	}
	Ok(())
}

fn check_envelope_trust(
	envelope: &VersionedManifestEnvelope,
	trust: ManifestEnvelopeTrust<'_>,
) -> Result<(), VerifyError> {
	match trust {
		ManifestEnvelopeTrust::ManifestHash(expected) => {
			let actual = envelope.manifest_hash();
			if expected != actual {
				return Err(VerifyError::ManifestHashMismatch {
					expected: qos_hex::encode(&expected),
					actual: qos_hex::encode(&actual),
				});
			}
		}
		ManifestEnvelopeTrust::ManifestSet(expected) => {
			let actual = envelope.manifest_set();
			if !manifest_sets_equal(expected, actual) {
				return Err(VerifyError::ManifestSetMismatch {
					expected: expected.clone(),
					actual: actual.clone(),
				});
			}
		}
	}
	Ok(())
}

fn manifest_sets_equal(expected: &ManifestSet, actual: &ManifestSet) -> bool {
	let mut expected_members = expected.members.clone();
	let mut actual_members = actual.members.clone();
	expected_members.sort();
	actual_members.sort();
	expected.threshold == actual.threshold && expected_members == actual_members
}

fn share_sets_equal(expected: &ShareSet, actual: &ShareSet) -> bool {
	let mut expected_members = expected.members.clone();
	let mut actual_members = actual.members.clone();
	expected_members.sort();
	actual_members.sort();
	expected.threshold == actual.threshold && expected_members == actual_members
}

fn check_expectations(
	expectations: &VerificationExpectations,
	manifest: &VersionedManifest,
	manifest_hash: &[u8; 32],
) -> Result<(), VerifyError> {
	let namespace = manifest.namespace();
	if let Some(expected) = &expectations.namespace_name
		&& expected != &namespace.name
	{
		return Err(VerifyError::NamespaceNameMismatch {
			expected: expected.clone(),
			actual: namespace.name.clone(),
		});
	}
	if let Some(expected) = expectations.nonce
		&& expected != namespace.nonce
	{
		return Err(VerifyError::NonceMismatch {
			expected,
			actual: namespace.nonce,
		});
	}
	if let Some(expected) = &expectations.quorum_key
		&& expected != &namespace.quorum_key
	{
		return Err(VerifyError::QuorumKeyMismatch {
			expected: qos_hex::encode(expected),
			actual: qos_hex::encode(&namespace.quorum_key),
		});
	}

	let enclave = manifest.enclave();
	for (index, expected, actual) in [
		(0u8, &expectations.pcr0, &enclave.pcr0),
		(1, &expectations.pcr1, &enclave.pcr1),
		(2, &expectations.pcr2, &enclave.pcr2),
		(3, &expectations.pcr3, &enclave.pcr3),
	] {
		if let Some(expected) = expected
			&& expected != actual
		{
			return Err(VerifyError::PcrMismatch {
				index,
				expected: qos_hex::encode(expected),
				actual: qos_hex::encode(actual),
			});
		}
	}

	if let Some(expected) = expectations.pivot_hash
		&& &expected != manifest.pivot_hash()
	{
		return Err(VerifyError::PivotHashMismatch {
			expected: qos_hex::encode(&expected),
			actual: qos_hex::encode(manifest.pivot_hash()),
		});
	}
	if let Some(expected) = expectations.manifest_hash
		&& &expected != manifest_hash
	{
		return Err(VerifyError::ManifestHashMismatch {
			expected: qos_hex::encode(&expected),
			actual: qos_hex::encode(manifest_hash),
		});
	}

	if let Some(expected) = &expectations.manifest_set
		&& !manifest_sets_equal(expected, manifest.manifest_set())
	{
		return Err(VerifyError::ManifestSetMismatch {
			expected: expected.clone(),
			actual: manifest.manifest_set().clone(),
		});
	}
	if let Some(expected) = &expectations.share_set
		&& !share_sets_equal(expected, manifest.share_set())
	{
		return Err(VerifyError::ShareSetMismatch {
			expected: expected.clone(),
			actual: manifest.share_set().clone(),
		});
	}
	Ok(())
}

#[cfg(test)]
#[path = "verify/tests.rs"]
mod tests;

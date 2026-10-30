//! Request NSM attestations and verify signatures, certificate chains, and
//! caller-supplied expected boot inputs.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use qos_nsm::{
	NsmProvider,
	nitro::{self, ManifestAttestationInput, attestation_doc_from_der},
	types::{NsmRequest, NsmResponse},
};
use qos_p256::P256Public;
use x509_cert::{Certificate, der::Decode};

use crate::{AttestationInputs, Error};

/// Document bytes and metadata returned after verification against expected
/// inputs.
///
/// Certificate validity is checked at issuance and the supplied verification
/// time.
/// This result does not impose a maximum document age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestationDocument {
	document: Vec<u8>,
	timestamp_ms: u64,
	not_after_unix: u64,
	leaf_fingerprint: [u8; 32],
	verification_time_unix_ms: u64,
}

impl VerifiedAttestationDocument {
	/// Verify signed document bytes against a supplied root CA and expected boot
	/// inputs.
	///
	/// Checks the certificate chain and signature, the manifest hash and PCR0-3,
	/// the live-key commitment in PCR17, the manifest-only commitment in PCR18,
	/// the expected public key, and absence of a nonce.
	///
	/// Also requires the PCR17/PCR18 commitments written by QOS 0.15.0.
	///
	/// Certificate validity must hold at the supplied verification time and at
	/// issuance.
	/// `verification_time_unix_ms` is in milliseconds since the Unix epoch.
	/// Verification uses whole-second precision. Issuance may be anywhere within
	/// the supplied time's second, but cannot fall in a later second.
	/// Issuance rounds up for strict certificate expiry, and down for not-before.
	/// Use a trusted current time for current validity, or deliberately supply a
	/// historical time to verify historical evidence. No maximum age is imposed.
	///
	/// # Errors
	///
	/// Returns an error if parsing, certificate or signature verification fails;
	/// certificates are invalid at either time; issuance is in a later second;
	/// or any expected boot input or nonce check fails.
	pub fn verify_at(
		document: Vec<u8>,
		root_der: &[u8],
		inputs: &AttestationInputs,
		verification_time_unix_ms: u64,
	) -> Result<Self, Error> {
		let verification_seconds = verification_time_unix_ms / 1000;
		let VerifiedDocumentParts { document: doc, not_after_unix } =
			verify_document(&document, root_der, verification_seconds)?;
		check_binding(&doc, inputs)?;
		Ok(Self {
			document,
			timestamp_ms: doc.timestamp,
			not_after_unix,
			leaf_fingerprint: qos_crypto::sha_256(&doc.certificate),
			verification_time_unix_ms,
		})
	}

	/// Remaining certificate lifetime at the recorded verification time.
	/// Rounding the verification time up to a full second avoids extending the
	/// cache deadline.
	#[cfg(feature = "cache")]
	pub(crate) fn remaining_lifetime_at_verification(
		&self,
	) -> std::time::Duration {
		std::time::Duration::from_secs(
			self.not_after_unix
				.saturating_sub(self.verification_time_unix_ms.div_ceil(1000)),
		)
	}

	/// Original signed `COSE_Sign1` bytes supplied to the verifier.
	#[must_use]
	pub fn document(&self) -> &[u8] {
		&self.document
	}

	/// Verified document timestamp, in milliseconds since the Unix epoch.
	#[must_use]
	pub fn timestamp_ms(&self) -> u64 {
		self.timestamp_ms
	}

	/// Earliest expiry among the leaf, supplied intermediates, and root CA,
	/// in seconds since the Unix epoch.
	#[must_use]
	pub fn not_after_unix(&self) -> u64 {
		self.not_after_unix
	}

	/// SHA-256 of the leaf certificate's DER.
	#[must_use]
	pub fn leaf_fingerprint(&self) -> [u8; 32] {
		self.leaf_fingerprint
	}
}

/// Blocking attestation operations available on every [`NsmProvider`].
///
/// Import this trait to request nonce-free boot attestations or request and
/// verify them against expected boot inputs.
///
/// ```no_run
/// use qos_attestation::{AttestationInputs, Error, NsmProviderExt, VerifiedAttestationDocument};
/// use qos_nsm::NsmProvider;
///
/// fn check<P: NsmProvider + ?Sized>(
///     nsm: &P,
///     inputs: &AttestationInputs,
///     document: Vec<u8>,
///     trusted_root: &[u8],
/// ) -> Result<(), Error> {
///     let local = nsm.attest_and_verify(inputs)?;
///     let now = std::time::SystemTime::now()
///         .duration_since(std::time::UNIX_EPOCH)
///         .expect("clock is after the Unix epoch")
///         .as_millis()
///         .try_into()
///         .expect("Unix milliseconds fit in u64");
///     let supplied = VerifiedAttestationDocument::verify_at(document, trusted_root, inputs, now)?;
///     Ok(())
/// }
/// ```
pub trait NsmProviderExt: NsmProvider {
	/// Request unverified COSE bytes with `manifest_hash` as `user_data`, the
	/// supplied `public_key`, and no nonce. Blocks on one NSM request.
	///
	/// # Errors
	///
	/// Returns an error if the NSM returns an error or an unexpected response.
	fn request_attestation_doc(
		&self,
		manifest_hash: &[u8; 32],
		public_key: &P256Public,
	) -> Result<Vec<u8>, Error> {
		let request = NsmRequest::Attestation {
			user_data: Some(manifest_hash.to_vec()),
			nonce: None,
			public_key: Some(public_key.to_bytes()),
		};
		match self.nsm_process_request(request) {
			NsmResponse::Attestation { document } => Ok(document),
			NsmResponse::Error(code) => Err(Error::Nsm(format!("{code:?}"))),
			other => Err(Error::UnexpectedNsmResponse(format!("{other:?}"))),
		}
	}

	/// Request a nonce-free document for `inputs`, then verify it against
	/// [`NsmProvider::attestation_root_ca_der`] at the provider's trusted current
	/// time. Reads [`NsmProvider::timestamp_ms`] after requesting the document.
	/// Both operations block and may each make an NSM request.
	///
	/// # Errors
	///
	/// Returns an error if requesting the document or any verification check
	/// in [`VerifiedAttestationDocument::verify_at`] fails, or reading the clock fails.
	fn attest_and_verify(
		&self,
		inputs: &AttestationInputs,
	) -> Result<VerifiedAttestationDocument, Error> {
		let document = self.request_attestation_doc(
			&inputs.manifest_hash,
			&inputs.ephemeral_public_key,
		)?;
		let verification_time_unix_ms =
			self.timestamp_ms().map_err(Error::Clock)?;
		VerifiedAttestationDocument::verify_at(
			document,
			&self.attestation_root_ca_der(),
			inputs,
			verification_time_unix_ms,
		)
	}
}

impl<T: NsmProvider + ?Sized> NsmProviderExt for T {}

/// Parsed document after certificate and signature verification, before
/// checking the caller's expected boot inputs.
pub(crate) struct VerifiedDocumentParts {
	document: AttestationDoc,
	/// Earliest certificate expiry, in seconds since the Unix epoch.
	not_after_unix: u64,
}

struct CertificateValidity {
	not_before_unix: u64,
	not_after_unix: u64,
}

impl CertificateValidity {
	fn check(&self, earliest: u64, latest: u64) -> Result<(), Error> {
		if earliest < self.not_before_unix {
			return Err(Error::NotYetValid);
		}
		if latest >= self.not_after_unix {
			return Err(Error::Expired);
		}
		Ok(())
	}
}

pub(crate) fn verify_document(
	document: &[u8],
	root_der: &[u8],
	verification_time_unix_s: u64,
) -> Result<VerifiedDocumentParts, Error> {
	let doc =
		attestation_doc_from_der(document, root_der, verification_time_unix_s)
			.map_err(Error::Document)?;
	let validity = certificate_validity(&doc, root_der)?;
	// Valid at the supplied verification time.
	validity.check(verification_time_unix_s, verification_time_unix_s)?;
	// Valid at issuance.
	validity.check(doc.timestamp / 1000, doc.timestamp.div_ceil(1000))?;
	if doc.timestamp / 1000 > verification_time_unix_s {
		return Err(Error::FutureTimestamp);
	}
	Ok(VerifiedDocumentParts {
		document: doc,
		not_after_unix: validity.not_after_unix,
	})
}

/// Find the interval where the leaf, intermediates, and trusted root are all valid.
fn certificate_validity(
	doc: &AttestationDoc,
	root_der: &[u8],
) -> Result<CertificateValidity, Error> {
	doc.cabundle
		.iter()
		.skip(1)
		.chain([&doc.certificate])
		.map(|c| c.as_slice())
		.chain([root_der])
		.try_fold(
			CertificateValidity {
				not_before_unix: 0,
				not_after_unix: u64::MAX,
			},
			|bounds, der| {
				let cert = Certificate::from_der(der)
					.map_err(|e| Error::Certificate(e.to_string()))?;
				let validity = cert.tbs_certificate.validity;
				Ok(CertificateValidity {
					not_before_unix: bounds
						.not_before_unix
						.max(validity.not_before.to_unix_duration().as_secs()),
					not_after_unix: bounds
						.not_after_unix
						.min(validity.not_after.to_unix_duration().as_secs()),
				})
			},
		)
}

/// Compare parsed document fields with the caller's expected boot inputs.
///
/// Check the manifest hash, PCR0-3, live-key commitment (PCR17), manifest-only
/// commitment (PCR18), public key, and absence of a nonce. This function does
/// not verify the certificate chain or signature.
pub(crate) fn check_binding(
	doc: &AttestationDoc,
	inputs: &AttestationInputs,
) -> Result<(), Error> {
	// Check the manifest hash, PCR0-3, nonce, and PCR17 commitment to the
	// document's public key. QOS rotates to the live key before pivot startup.
	nitro::verify_attestation_doc_against_manifest_live(
		doc,
		ManifestAttestationInput {
			manifest_hash: &inputs.manifest_hash,
			pcr0: &inputs.pcr0,
			pcr1: &inputs.pcr1,
			pcr2: &inputs.pcr2,
			pcr3: &inputs.pcr3,
		},
	)
	.map_err(Error::Binding)?;

	// PCR17 binds the manifest to the document's public key.
	// Also require that key to match the caller's expected public key.
	match doc.public_key.as_ref() {
		Some(pub_key)
			if pub_key.as_slice() == inputs.ephemeral_public_key.to_bytes() => {}
		_ => return Err(Error::PublicKeyMismatch),
	}

	nitro::verify_attestation_doc_manifest_only_commitment(
		doc,
		&inputs.manifest_hash,
	)
	.map_err(Error::ManifestOnlyCommitment)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use qos_nsm::{
		mock::{
			MOCK_LEAF_CERT_DER, MOCK_NSM_ATTESTATION_DOCUMENT,
			MOCK_ROOT_CERT_DER, MOCK_SECONDS_SINCE_EPOCH, MockNsm,
		},
		nitro::{
			AWS_ROOT_CERT_PEM, cert_from_pem, unsafe_attestation_doc_from_der,
		},
	};
	use serde_bytes::ByteBuf;

	use super::*;
	use crate::tests::{
		ReplyNsm, bound_doc, enclave_mock_nsm, qemu_shaped_document,
		sample_inputs, signed_with_mock_key,
	};

	/// Request a signed mock document for the supplied manifest hash and key,
	/// without a nonce.
	fn mock_document(nsm: &MockNsm, inputs: &AttestationInputs) -> Vec<u8> {
		nsm.request_attestation_doc(
			&inputs.manifest_hash,
			&inputs.ephemeral_public_key,
		)
		.unwrap()
	}

	fn aws_root() -> Vec<u8> {
		cert_from_pem(AWS_ROOT_CERT_PEM).unwrap()
	}

	// Certificate-chain and signature checks with signed fixtures.

	#[test]
	fn aws_fixture_verifies_at_its_own_time() {
		let VerifiedDocumentParts { document: doc, not_after_unix } =
			verify_document(
				MOCK_NSM_ATTESTATION_DOCUMENT,
				&aws_root(),
				MOCK_SECONDS_SINCE_EPOCH,
			)
			.unwrap();
		assert!(not_after_unix > MOCK_SECONDS_SINCE_EPOCH);
		// The fixture leaf expires first, within about three hours of issuance.
		assert!(not_after_unix - doc.timestamp / 1000 <= 3 * 60 * 60 + 60);
		let leaf = not_after_of(&doc.certificate);
		assert_eq!(not_after_unix, leaf);
	}

	#[test]
	fn mock_nsm_doc_verifies_against_mock_root() {
		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let provider: &dyn NsmProvider = &nsm;
		let verified = provider.attest_and_verify(&inputs).unwrap();
		let doc = unsafe_attestation_doc_from_der(verified.document()).unwrap();
		assert_eq!(verified.timestamp_ms(), doc.timestamp);
		assert_eq!(verified.not_after_unix(), not_after_of(MOCK_LEAF_CERT_DER));
		assert_eq!(
			verified.leaf_fingerprint(),
			qos_crypto::sha_256(MOCK_LEAF_CERT_DER)
		);
	}

	#[test]
	fn verification_keeps_the_owned_document_allocation() {
		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let document = mock_document(&nsm, &inputs);
		let allocation = document.as_ptr();
		let verified = VerifiedAttestationDocument::verify_at(
			document,
			MOCK_ROOT_CERT_DER,
			&inputs,
			MOCK_SECONDS_SINCE_EPOCH * 1000,
		)
		.unwrap();
		assert_eq!(verified.document().as_ptr(), allocation);
	}

	#[test]
	fn tampered_and_truncated_docs_are_rejected() {
		let mut tampered = MOCK_NSM_ATTESTATION_DOCUMENT.to_vec();
		let last = tampered.len() - 1;
		tampered[last] ^= 1;
		assert!(matches!(
			verify_document(&tampered, &aws_root(), MOCK_SECONDS_SINCE_EPOCH),
			Err(Error::Document(_))
		));

		let truncated = &MOCK_NSM_ATTESTATION_DOCUMENT
			[..MOCK_NSM_ATTESTATION_DOCUMENT.len() / 2];
		assert!(matches!(
			verify_document(truncated, &aws_root(), MOCK_SECONDS_SINCE_EPOCH),
			Err(Error::Document(_))
		));
	}

	#[test]
	fn wrong_root_is_rejected() {
		assert!(matches!(
			verify_document(
				MOCK_NSM_ATTESTATION_DOCUMENT,
				MOCK_ROOT_CERT_DER,
				MOCK_SECONDS_SINCE_EPOCH
			),
			Err(Error::Document(_))
		));

		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let document = mock_document(&nsm, &inputs);
		assert!(matches!(
			VerifiedAttestationDocument::verify_at(
				document,
				&aws_root(),
				&inputs,
				MOCK_SECONDS_SINCE_EPOCH * 1000
			),
			Err(Error::Document(_))
		));
	}

	#[test]
	fn verification_uses_the_signed_timestamp_and_rounds_up_at_expiry() {
		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let mut doc =
			unsafe_attestation_doc_from_der(&mock_document(&nsm, &inputs))
				.unwrap();
		let expiry = not_after_of(MOCK_LEAF_CERT_DER);
		// A correctly signed document one full second before expiry is valid,
		// even though verification does not use the current wall clock.
		doc.timestamp = (expiry - 1) * 1000;
		let verified = VerifiedAttestationDocument::verify_at(
			signed_with_mock_key(&doc),
			MOCK_ROOT_CERT_DER,
			&inputs,
			(expiry - 1) * 1000,
		)
		.unwrap();
		assert_eq!(verified.timestamp_ms(), doc.timestamp);
		assert_eq!(verified.not_after_unix(), expiry);

		// The fractional second rounds up to expiry. At and after expiry must
		// also fail; every payload is re-signed to isolate timestamp handling.
		for timestamp in
			[(expiry - 1) * 1000 + 1, expiry * 1000, (expiry + 1) * 1000]
		{
			doc.timestamp = timestamp;
			assert!(
				matches!(
					VerifiedAttestationDocument::verify_at(
						signed_with_mock_key(&doc),
						MOCK_ROOT_CERT_DER,
						&inputs,
						(expiry - 1) * 1000
					),
					Err(Error::Expired
						| Error::Document(
							nitro::AttestError::InvalidCertChain(_)
						))
				),
				"timestamp {timestamp}"
			);
		}
	}

	#[test]
	fn verification_time_allows_history_without_an_age_limit() {
		let inputs = sample_inputs(1);
		let doc = mock_document(&enclave_mock_nsm(&inputs, true), &inputs);
		let expiry = not_after_of(MOCK_LEAF_CERT_DER);
		for time in [MOCK_SECONDS_SINCE_EPOCH, expiry - 1] {
			VerifiedAttestationDocument::verify_at(
				doc.clone(),
				MOCK_ROOT_CERT_DER,
				&inputs,
				time * 1000,
			)
			.unwrap();
		}
		for time in [expiry, expiry + 1] {
			assert!(
				VerifiedAttestationDocument::verify_at(
					doc.clone(),
					MOCK_ROOT_CERT_DER,
					&inputs,
					time * 1000
				)
				.is_err()
			);
		}
		assert!(
			VerifiedAttestationDocument::verify_at(
				doc.clone(),
				MOCK_ROOT_CERT_DER,
				&inputs,
				0
			)
			.is_err()
		);
		VerifiedAttestationDocument::verify_at(
			doc,
			MOCK_ROOT_CERT_DER,
			&inputs,
			MOCK_SECONDS_SINCE_EPOCH * 1000,
		)
		.unwrap();
	}

	#[test]
	fn issuance_respects_certificate_validity_and_verification_time() {
		let inputs = sample_inputs(1);
		let mut doc = unsafe_attestation_doc_from_der(&mock_document(
			&enclave_mock_nsm(&inputs, true),
			&inputs,
		))
		.unwrap();
		let before = Certificate::from_der(MOCK_LEAF_CERT_DER)
			.unwrap()
			.tbs_certificate
			.validity
			.not_before
			.to_unix_duration()
			.as_secs();
		doc.timestamp = before * 1000 - 1;
		assert!(matches!(
			VerifiedAttestationDocument::verify_at(
				signed_with_mock_key(&doc),
				MOCK_ROOT_CERT_DER,
				&inputs,
				MOCK_SECONDS_SINCE_EPOCH * 1000
			),
			Err(Error::NotYetValid)
		));
		for millis in [0, 1, 999] {
			doc.timestamp = MOCK_SECONDS_SINCE_EPOCH * 1000 + millis;
			VerifiedAttestationDocument::verify_at(
				signed_with_mock_key(&doc),
				MOCK_ROOT_CERT_DER,
				&inputs,
				MOCK_SECONDS_SINCE_EPOCH * 1000 + 1,
			)
			.unwrap();
		}
		doc.timestamp = (MOCK_SECONDS_SINCE_EPOCH + 1) * 1000;
		assert!(matches!(
			VerifiedAttestationDocument::verify_at(
				signed_with_mock_key(&doc),
				MOCK_ROOT_CERT_DER,
				&inputs,
				MOCK_SECONDS_SINCE_EPOCH * 1000
			),
			Err(Error::FutureTimestamp)
		));
	}

	struct ClockNsm {
		document: Vec<u8>,
		time: Option<u64>,
		events: std::sync::Mutex<Vec<&'static str>>,
	}

	impl NsmProvider for ClockNsm {
		fn nsm_process_request(&self, _: NsmRequest) -> NsmResponse {
			self.events.lock().unwrap().push("document");
			NsmResponse::Attestation { document: self.document.clone() }
		}

		fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
			self.events.lock().unwrap().push("clock");
			self.time.ok_or(nitro::AttestError::InvalidTimeStamp)
		}

		fn attestation_root_ca_der(&self) -> Vec<u8> {
			MOCK_ROOT_CERT_DER.to_vec()
		}
	}

	#[test]
	fn provider_reads_trusted_clock_after_the_bound_request() {
		let inputs = sample_inputs(1);
		let document = mock_document(&enclave_mock_nsm(&inputs, true), &inputs);
		for time in [
			Some(MOCK_SECONDS_SINCE_EPOCH * 1000),
			Some(not_after_of(MOCK_LEAF_CERT_DER) * 1000),
			None,
		] {
			let nsm = ClockNsm {
				document: document.clone(),
				time,
				events: std::sync::Mutex::new(Vec::new()),
			};
			let result = nsm.attest_and_verify(&inputs);
			assert_eq!(*nsm.events.lock().unwrap(), ["document", "clock"]);
			match time {
				None => assert!(matches!(result, Err(Error::Clock(_)))),
				Some(time) if time == MOCK_SECONDS_SINCE_EPOCH * 1000 => {
					result.unwrap();
				}
				Some(_) => assert!(result.is_err()),
			}
		}
	}

	// Expected manifest, PCR, public-key, and nonce checks.

	#[test]
	fn wrong_key_is_rejected() {
		let inputs = sample_inputs(1);
		let mut doc = bound_doc(&inputs, true);
		// Changing only the document's public key leaves PCR17 committed to
		// the original key, so the commitment check fails first.
		doc.public_key = Some(ByteBuf::from(
			sample_inputs(2).ephemeral_public_key.to_bytes(),
		));
		assert!(matches!(check_binding(&doc, &inputs), Err(Error::Binding(_))));

		// A document whose PCR17 matches another key still fails the
		// comparison with inputs.ephemeral_public_key.
		let mut other = inputs.clone();
		other.ephemeral_public_key = sample_inputs(2).ephemeral_public_key;
		assert!(matches!(
			check_binding(&bound_doc(&other, true), &inputs),
			Err(Error::PublicKeyMismatch)
		));
	}

	#[test]
	fn wrong_manifest_hash_is_rejected() {
		let inputs = sample_inputs(1);
		let mut expected = inputs.clone();
		expected.manifest_hash = [0xee; 32];
		assert!(matches!(
			check_binding(&bound_doc(&inputs, true), &expected),
			Err(Error::Binding(nitro::AttestError::DifferentUserData { .. }))
		));
	}

	#[test]
	fn changed_pcr0_to_pcr3_are_rejected() {
		let inputs = sample_inputs(1);
		for index in 0..4usize {
			let mut doc = bound_doc(&inputs, true);
			doc.pcrs.insert(index, ByteBuf::from(vec![0xab; 48]));
			assert!(
				matches!(check_binding(&doc, &inputs), Err(Error::Binding(_))),
				"PCR{index}"
			);
		}
	}

	#[test]
	fn live_commitment_is_required_even_with_a_setup_commitment() {
		let inputs = sample_inputs(1);
		let mut missing = bound_doc(&inputs, true);
		missing.pcrs.insert(17, ByteBuf::from(vec![0; 48]));
		let mut setup = missing.clone();
		let commitment =
			nitro::expected_manifest_commitment_pcr::<nitro::Setup>(
				&inputs.manifest_hash,
				&inputs.ephemeral_public_key.to_bytes(),
			)
			.unwrap();
		setup.pcrs.insert(16, ByteBuf::from(commitment.to_vec()));
		for (case, doc) in [("unprovisioned", missing), ("setup key", setup)] {
			assert!(
				matches!(
					check_binding(&doc, &inputs),
					Err(Error::Binding(nitro::AttestError::DifferentPcr {
						index: 17,
						..
					}))
				),
				"{case}"
			);
		}
	}

	#[test]
	fn nonce_is_rejected() {
		let inputs = sample_inputs(1);
		let mut doc = bound_doc(&inputs, true);
		doc.nonce = Some(ByteBuf::from(vec![1]));
		assert!(matches!(
			check_binding(&doc, &inputs),
			Err(Error::Binding(
				nitro::AttestError::UnexpectedAttestationDocNonce
			))
		));
	}

	#[test]
	fn genuine_doc_for_other_inputs_is_rejected() {
		let inputs = sample_inputs(1);
		let other_inputs = sample_inputs(2);
		let nsm = enclave_mock_nsm(&other_inputs, true);
		let document = mock_document(&nsm, &other_inputs);
		VerifiedAttestationDocument::verify_at(
			document.clone(),
			MOCK_ROOT_CERT_DER,
			&other_inputs,
			MOCK_SECONDS_SINCE_EPOCH * 1000,
		)
		.unwrap();
		assert!(matches!(
			VerifiedAttestationDocument::verify_at(
				document,
				MOCK_ROOT_CERT_DER,
				&inputs,
				MOCK_SECONDS_SINCE_EPOCH * 1000
			),
			Err(Error::Binding(nitro::AttestError::DifferentUserData { .. }))
		));
	}

	// Mandatory manifest-only commitment check in PCR18.

	#[test]
	fn pcr18_commitment_is_required() {
		let inputs = sample_inputs(1);
		let without = enclave_mock_nsm(&inputs, false);
		assert!(matches!(
			without.attest_and_verify(&inputs),
			Err(Error::ManifestOnlyCommitment(
				nitro::AttestError::DifferentPcr { index: 18, .. }
			))
		));

		let mut wrong = bound_doc(&inputs, true);
		wrong.pcrs.insert(18, ByteBuf::from(vec![0xcd; 48]));
		assert!(matches!(
			check_binding(&wrong, &inputs),
			Err(Error::ManifestOnlyCommitment(
				nitro::AttestError::DifferentPcr { index: 18, .. }
			))
		));

		let mut missing = bound_doc(&inputs, true);
		missing.pcrs.remove(&18);
		assert!(matches!(
			check_binding(&missing, &inputs),
			Err(Error::Binding(nitro::AttestError::MissingPcr { index: 18 }))
		));
	}

	// NSM errors and unexpected response types.

	#[test]
	fn nsm_errors_are_typed() {
		let inputs = sample_inputs(1);
		let nsm = ReplyNsm(NsmResponse::Error(
			qos_nsm::types::NsmErrorCode::InternalError,
		));
		assert!(matches!(nsm.attest_and_verify(&inputs), Err(Error::Nsm(_))));
		let nsm = ReplyNsm(NsmResponse::LockPCRs);
		assert!(matches!(
			nsm.attest_and_verify(&inputs),
			Err(Error::UnexpectedNsmResponse(_))
		));
	}

	// Earliest expiry across the leaf, intermediates, and root CA.

	#[test]
	fn not_after_is_the_earliest_including_an_intermediate() {
		let fixture = verify_document(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&aws_root(),
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.unwrap()
		.document;
		let short_lived = fixture.certificate.clone();

		// Put a shorter-lived fixture certificate in the intermediate list.
		// This tests expiry parsing, not whether the certificates form a valid
		// chain.
		let mut doc = bound_doc(&sample_inputs(1), false);
		doc.certificate = ByteBuf::from(MOCK_LEAF_CERT_DER.to_vec());
		doc.cabundle = vec![
			ByteBuf::from(MOCK_ROOT_CERT_DER.to_vec()),
			short_lived.clone(),
		];
		let earliest = certificate_validity(&doc, MOCK_ROOT_CERT_DER)
			.map(|v| v.not_after_unix)
			.unwrap();
		assert_eq!(earliest, not_after_of(&short_lived));
		assert!(earliest < not_after_of(MOCK_LEAF_CERT_DER));
	}

	#[test]
	fn not_after_uses_the_supplied_root_and_ignores_the_embedded_root() {
		let fixture =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();
		let shorter_root = fixture.certificate;
		let mut doc = bound_doc(&sample_inputs(1), true);
		doc.certificate = ByteBuf::from(MOCK_LEAF_CERT_DER.to_vec());
		doc.cabundle = vec![ByteBuf::from(MOCK_ROOT_CERT_DER.to_vec())];
		assert!(not_after_of(&shorter_root) < not_after_of(MOCK_LEAF_CERT_DER));
		assert_eq!(
			certificate_validity(&doc, &shorter_root)
				.map(|v| v.not_after_unix)
				.unwrap(),
			not_after_of(&shorter_root)
		);

		// The first bundle entry is replaced by the trusted root, even if it
		// expires earlier or cannot be decoded as a certificate.
		for embedded_root in [shorter_root, ByteBuf::from(vec![0])] {
			doc.cabundle[0] = embedded_root;
			assert_eq!(
				certificate_validity(&doc, MOCK_ROOT_CERT_DER)
					.map(|v| v.not_after_unix)
					.unwrap(),
				not_after_of(MOCK_LEAF_CERT_DER)
			);
		}
	}

	#[test]
	fn not_after_rejects_malformed_leaf_intermediate_and_supplied_root() {
		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let original =
			unsafe_attestation_doc_from_der(&mock_document(&nsm, &inputs))
				.unwrap();
		for position in ["leaf", "intermediate", "root"] {
			let mut doc = original.clone();
			let mut root = MOCK_ROOT_CERT_DER.to_vec();
			match position {
				"leaf" => doc.certificate = ByteBuf::from(vec![0]),
				"intermediate" => doc.cabundle[1] = ByteBuf::from(vec![0]),
				"root" => root = vec![0],
				_ => unreachable!(),
			}
			assert!(
				matches!(
					certificate_validity(&doc, &root).map(|v| v.not_after_unix),
					Err(Error::Certificate(_))
				),
				"{position}"
			);
		}
	}

	// QEMU's placeholder certificates and signature are rejected with either
	// root.

	#[test]
	fn default_verification_rejects_a_qemu_shaped_doc() {
		let inputs = sample_inputs(1);
		let document = qemu_shaped_document(&inputs, true);
		for root in [aws_root(), MOCK_ROOT_CERT_DER.to_vec()] {
			assert!(matches!(
				VerifiedAttestationDocument::verify_at(
					document.clone(),
					&root,
					&inputs,
					MOCK_SECONDS_SINCE_EPOCH * 1000
				),
				Err(Error::Document(_))
			));
		}
	}

	fn not_after_of(der: &[u8]) -> u64 {
		Certificate::from_der(der)
			.unwrap()
			.tbs_certificate
			.validity
			.not_after
			.to_unix_duration()
			.as_secs()
	}
}

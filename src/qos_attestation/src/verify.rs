//! Attest through the NSM and verify the document against our own inputs.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use qos_nsm::{
	NsmProvider,
	nitro::{
		self, ManifestAttestationInput, attestation_doc_from_der,
		unsafe_attestation_doc_from_der,
	},
	types::{NsmRequest, NsmResponse},
};
use x509_cert::{Certificate, der::Decode};

use crate::{AttestationInputs, Error};

/// Whether to require the manifest-only (PCR18) commitment.
///
/// There is deliberately no default. QOS writes PCR18 from 0.15.0, so
/// `Required` should typically be chosen. `NotChecked` is for enclaves on older
/// QOS releases, where `Required` would never pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestOnlyCommitment {
	/// The document must carry the PCR18 commitment to the manifest.
	Required,
	/// PCR18 is not checked.
	NotChecked,
}

/// Checks applied to every document on top of the chain and binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyPolicy {
	/// The PCR18 policy.
	pub manifest_only: ManifestOnlyCommitment,
}

/// An attestation document that passed verification against its inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
	/// The `COSE_Sign1` bytes, as returned by the NSM.
	pub document: Vec<u8>,
	/// The inputs the document is bound to.
	pub inputs: AttestationInputs,
	/// The document's signed timestamp, in milliseconds.
	pub timestamp_ms: u64,
	/// The earliest `notAfter` across the certificates the chain was
	/// verified through, in seconds since the Unix epoch.
	pub not_after_unix: u64,
	/// SHA-256 of the leaf certificate's DER.
	pub leaf_fingerprint: [u8; 32],
}

/// Request a document from the NSM and verify it against `inputs`.
///
/// The request carries the manifest hash as `user_data`, our ephemeral key
/// as `public_key`, and no nonce, the same as QOS's own post-boot request.
/// The trust anchor is [`NsmProvider::attestation_root_ca_der`]. This makes
/// one NSM call, which blocks.
///
/// # Errors
///
/// Returns an error if the NSM call fails or the document fails any check
/// in [`verify_self_attestation`].
pub fn attest_self<P: NsmProvider + ?Sized>(
	nsm: &P,
	inputs: &AttestationInputs,
	policy: &VerifyPolicy,
) -> Result<VerifiedAttestation, Error> {
	let document = request_document(nsm, inputs)?;
	verify_self_attestation(
		&document,
		&nsm.attestation_root_ca_der(),
		inputs,
		policy,
	)
}

/// Verify document bytes against `root_der` and `inputs`.
///
/// This proves the document was valid **at its own timestamp**: the chain
/// is checked at the document's signed time, not at the current time. It
/// does not prove the document is fresh. Callers that need freshness should
/// compare [`VerifiedAttestation::not_after_unix`] with their own clock.
///
/// # Errors
///
/// Returns an error if the document doesn't parse, its chain or signature
/// doesn't verify against `root_der`, it is already expired, it doesn't bind
/// to `inputs`, or it fails `policy`.
pub fn verify_self_attestation(
	document: &[u8],
	root_der: &[u8],
	inputs: &AttestationInputs,
	policy: &VerifyPolicy,
) -> Result<VerifiedAttestation, Error> {
	let (doc, not_after_unix) = verify_document(document, root_der)?;
	check_binding(&doc, inputs, *policy)?;
	Ok(VerifiedAttestation {
		document: document.to_vec(),
		inputs: inputs.clone(),
		timestamp_ms: doc.timestamp,
		not_after_unix,
		leaf_fingerprint: qos_crypto::sha_256(&doc.certificate),
	})
}

/// Like [`verify_self_attestation`], but skips the certificate chain, the
/// signature and expiry, keeping every binding and policy check.
///
/// For emulated NSMs such as QEMU's, which don't sign documents. The
/// result has `not_after_unix == u64::MAX`, since there is no chain to
/// expire.
///
/// # Errors
///
/// Returns an error if the document doesn't parse, doesn't bind to
/// `inputs`, or fails `policy`.
#[cfg(feature = "unsafe-verifier")]
pub fn unsafe_verify_self_attestation_skip_chain(
	document: &[u8],
	inputs: &AttestationInputs,
	policy: &VerifyPolicy,
) -> Result<VerifiedAttestation, Error> {
	let doc =
		unsafe_attestation_doc_from_der(document).map_err(Error::Document)?;
	check_binding(&doc, inputs, *policy)?;
	Ok(VerifiedAttestation {
		document: document.to_vec(),
		inputs: inputs.clone(),
		timestamp_ms: doc.timestamp,
		not_after_unix: u64::MAX,
		leaf_fingerprint: qos_crypto::sha_256(&doc.certificate),
	})
}

pub(crate) fn request_document<P: NsmProvider + ?Sized>(
	nsm: &P,
	inputs: &AttestationInputs,
) -> Result<Vec<u8>, Error> {
	let request = NsmRequest::Attestation {
		user_data: Some(inputs.manifest_hash.to_vec()),
		nonce: None,
		public_key: Some(inputs.ephemeral_public_key.clone()),
	};
	match nsm.nsm_process_request(request) {
		NsmResponse::Attestation { document } => Ok(document),
		NsmResponse::Error(code) => Err(Error::Nsm(format!("{code:?}"))),
		other => Err(Error::UnexpectedNsmResponse(format!("{other:?}"))),
	}
}

/// Verify the chain and signature at the document's own timestamp, and
/// return the parsed document with its earliest `notAfter`.
pub(crate) fn verify_document(
	document: &[u8],
	root_der: &[u8],
) -> Result<(AttestationDoc, u64), Error> {
	let timestamp_ms = unsafe_attestation_doc_from_der(document)
		.map_err(Error::Document)?
		.timestamp;
	// Round up so a document is never treated as valid past `notAfter`.
	let validation_time = timestamp_ms.div_ceil(1000);
	let doc = attestation_doc_from_der(document, root_der, validation_time)
		.map_err(Error::Document)?;
	let not_after_unix = earliest_not_after(&doc, root_der)?;
	if not_after_unix <= validation_time {
		return Err(Error::Expired);
	}
	Ok((doc, not_after_unix))
}

/// The earliest `notAfter` over the leaf, the intermediates and the trust
/// anchor, which are the certificates the chain is verified through. The
/// first `cabundle` entry is skipped because verification uses `root_der`
/// in its place.
pub(crate) fn earliest_not_after(
	doc: &AttestationDoc,
	root_der: &[u8],
) -> Result<u64, Error> {
	let intermediates = doc.cabundle.iter().skip(1).map(|c| c.as_slice());
	std::iter::once(doc.certificate.as_slice())
		.chain(intermediates)
		.chain(std::iter::once(root_der))
		.map(not_after)
		.try_fold(u64::MAX, |earliest, next| Ok(earliest.min(next?)))
}

fn not_after(der: &[u8]) -> Result<u64, Error> {
	let cert = Certificate::from_der(der)
		.map_err(|e| Error::Certificate(e.to_string()))?;
	Ok(cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs())
}

/// Check that a parsed document attests our manifest, PCR0-3, live key
/// commitment and key, with no nonce, then apply `policy`.
pub(crate) fn check_binding(
	doc: &AttestationDoc,
	inputs: &AttestationInputs,
	policy: VerifyPolicy,
) -> Result<(), Error> {
	// The live (PCR17) check, because a pivot only ever holds the live key.
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

	// PCR17 binds whichever key the document carries, so also require ours.
	let doc_key = doc.public_key.as_ref().map(|k| k.as_slice());
	if doc_key != Some(inputs.ephemeral_public_key.as_slice()) {
		return Err(Error::PublicKeyMismatch);
	}

	match policy.manifest_only {
		ManifestOnlyCommitment::Required => {
			nitro::verify_attestation_doc_manifest_only_commitment(
				doc,
				&inputs.manifest_hash,
			)
			.map_err(Error::ManifestOnlyCommitment)?;
		}
		ManifestOnlyCommitment::NotChecked => {}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use qos_nsm::{
		mock::{
			MOCK_LEAF_CERT_DER, MOCK_NSM_ATTESTATION_DOCUMENT,
			MOCK_ROOT_CERT_DER, MOCK_SECONDS_SINCE_EPOCH, MockNsm,
		},
		nitro::{AWS_ROOT_CERT_PEM, cert_from_pem},
	};
	use serde_bytes::ByteBuf;

	use super::*;
	use crate::test_support::{
		RecordingNsm, bound_doc, enclave_mock_nsm, qemu_shaped_document,
		sample_inputs, setup_key_doc,
	};

	const REQUIRED: VerifyPolicy =
		VerifyPolicy { manifest_only: ManifestOnlyCommitment::Required };
	const NOT_CHECKED: VerifyPolicy =
		VerifyPolicy { manifest_only: ManifestOnlyCommitment::NotChecked };

	fn aws_root() -> Vec<u8> {
		cert_from_pem(AWS_ROOT_CERT_PEM).unwrap()
	}

	// Doc is genuine.

	#[test]
	fn aws_fixture_verifies_at_its_own_time() {
		let (doc, not_after) =
			verify_document(MOCK_NSM_ATTESTATION_DOCUMENT, &aws_root())
				.unwrap();
		assert!(not_after > MOCK_SECONDS_SINCE_EPOCH);
		// The leaf lives about 3 hours, and it expires before anything else.
		assert!(not_after - doc.timestamp / 1000 <= 3 * 60 * 60 + 60);
		let leaf = not_after_of(&doc.certificate);
		assert_eq!(not_after, leaf);
	}

	#[test]
	fn mock_nsm_doc_verifies_against_mock_root() {
		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, true);
		let verified = attest_self(&nsm, &inputs, &REQUIRED).unwrap();
		assert_eq!(verified.inputs, inputs);
		assert_eq!(verified.not_after_unix, not_after_of(MOCK_LEAF_CERT_DER));
		assert_eq!(
			verified.leaf_fingerprint,
			qos_crypto::sha_256(MOCK_LEAF_CERT_DER)
		);
	}

	#[test]
	fn tampered_and_truncated_docs_are_rejected() {
		let mut tampered = MOCK_NSM_ATTESTATION_DOCUMENT.to_vec();
		let last = tampered.len() - 1;
		tampered[last] ^= 1;
		assert!(matches!(
			verify_document(&tampered, &aws_root()),
			Err(Error::Document(_))
		));

		let truncated = &MOCK_NSM_ATTESTATION_DOCUMENT
			[..MOCK_NSM_ATTESTATION_DOCUMENT.len() / 2];
		assert!(matches!(
			verify_document(truncated, &aws_root()),
			Err(Error::Document(_))
		));
	}

	#[test]
	fn wrong_root_is_rejected() {
		assert!(matches!(
			verify_document(MOCK_NSM_ATTESTATION_DOCUMENT, MOCK_ROOT_CERT_DER),
			Err(Error::Document(_))
		));

		let inputs = sample_inputs(1);
		let nsm = enclave_mock_nsm(&inputs, false);
		let document = request_document(&nsm, &inputs).unwrap();
		assert!(matches!(
			verify_self_attestation(
				&document,
				&aws_root(),
				&inputs,
				&NOT_CHECKED
			),
			Err(Error::Document(_))
		));
	}

	#[test]
	fn validation_after_expiry_is_rejected() {
		// The chain check itself, a day after the fixture's leaf expired.
		let err = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&aws_root(),
			MOCK_SECONDS_SINCE_EPOCH + 24 * 60 * 60,
		)
		.unwrap_err();
		assert!(matches!(err, nitro::AttestError::InvalidCertChain(_)));
	}

	// Binding.

	#[test]
	fn correct_manifest_and_live_key_bind() {
		let inputs = sample_inputs(1);
		check_binding(&bound_doc(&inputs, true), &inputs, REQUIRED).unwrap();
		check_binding(&bound_doc(&inputs, false), &inputs, NOT_CHECKED)
			.unwrap();
	}

	#[test]
	fn wrong_key_is_rejected() {
		let inputs = sample_inputs(1);
		let mut doc = bound_doc(&inputs, false);
		// A different key in the doc breaks the PCR17 commitment first.
		doc.public_key =
			Some(ByteBuf::from(sample_inputs(2).ephemeral_public_key));
		assert!(matches!(
			check_binding(&doc, &inputs, NOT_CHECKED),
			Err(Error::Binding(_))
		));

		// A doc that is self-consistent for another key fails our key check.
		let mut other = inputs.clone();
		other.ephemeral_public_key = sample_inputs(2).ephemeral_public_key;
		assert!(matches!(
			check_binding(&bound_doc(&other, false), &inputs, NOT_CHECKED),
			Err(Error::PublicKeyMismatch)
		));
	}

	#[test]
	fn wrong_manifest_hash_is_rejected() {
		let inputs = sample_inputs(1);
		let mut expected = inputs.clone();
		expected.manifest_hash = [0xee; 32];
		assert!(matches!(
			check_binding(&bound_doc(&inputs, false), &expected, NOT_CHECKED),
			Err(Error::Binding(nitro::AttestError::DifferentUserData { .. }))
		));
	}

	#[test]
	fn changed_pcr0_to_pcr3_are_rejected() {
		let inputs = sample_inputs(1);
		for index in 0..4usize {
			let mut doc = bound_doc(&inputs, false);
			doc.pcrs.insert(index, ByteBuf::from(vec![0xab; 48]));
			assert!(
				matches!(
					check_binding(&doc, &inputs, NOT_CHECKED),
					Err(Error::Binding(_))
				),
				"PCR{index}"
			);
		}
	}

	#[test]
	fn missing_live_commitment_is_rejected() {
		let inputs = sample_inputs(1);
		let mut doc = bound_doc(&inputs, false);
		doc.pcrs.insert(17, ByteBuf::from(vec![0; 48]));
		assert!(matches!(
			check_binding(&doc, &inputs, NOT_CHECKED),
			Err(Error::Binding(nitro::AttestError::DifferentPcr {
				index: 17,
				..
			}))
		));
	}

	#[test]
	fn nonce_is_rejected() {
		let inputs = sample_inputs(1);
		let mut doc = bound_doc(&inputs, false);
		doc.nonce = Some(ByteBuf::from(vec![1]));
		assert!(matches!(
			check_binding(&doc, &inputs, NOT_CHECKED),
			Err(Error::Binding(
				nitro::AttestError::UnexpectedAttestationDocNonce
			))
		));
	}

	#[test]
	fn setup_key_doc_is_rejected() {
		let inputs = sample_inputs(1);
		assert!(matches!(
			check_binding(&setup_key_doc(&inputs), &inputs, NOT_CHECKED),
			Err(Error::Binding(_))
		));
	}

	#[test]
	fn genuine_doc_for_other_inputs_is_rejected() {
		// The original cache's blocking bug: a genuine, verifiable doc that
		// attests nothing we asked for.
		let inputs = sample_inputs(1);
		let unrelated = MockNsm::new();
		let document = request_document(&unrelated, &sample_inputs(2)).unwrap();
		assert!(
			verify_self_attestation(
				&document,
				MOCK_ROOT_CERT_DER,
				&inputs,
				&NOT_CHECKED
			)
			.is_err()
		);
		assert!(
			verify_self_attestation(
				MOCK_NSM_ATTESTATION_DOCUMENT,
				&aws_root(),
				&inputs,
				&NOT_CHECKED
			)
			.is_err()
		);
	}

	// PCR18 policy.

	#[test]
	fn pcr18_required_needs_the_commitment() {
		let inputs = sample_inputs(1);
		let with = enclave_mock_nsm(&inputs, true);
		attest_self(&with, &inputs, &REQUIRED).unwrap();

		let without = enclave_mock_nsm(&inputs, false);
		assert!(matches!(
			attest_self(&without, &inputs, &REQUIRED),
			Err(Error::ManifestOnlyCommitment(_))
		));
		attest_self(&without, &inputs, &NOT_CHECKED).unwrap();

		let mut wrong = bound_doc(&inputs, true);
		wrong.pcrs.insert(18, ByteBuf::from(vec![0xcd; 48]));
		assert!(matches!(
			check_binding(&wrong, &inputs, REQUIRED),
			Err(Error::ManifestOnlyCommitment(_))
		));
	}

	// NSM request.

	#[test]
	fn nsm_request_carries_hash_and_key_and_no_nonce() {
		let inputs = sample_inputs(1);
		let nsm = RecordingNsm::new(enclave_mock_nsm(&inputs, false));
		attest_self(&nsm, &inputs, &NOT_CHECKED).unwrap();

		let requests = nsm.requests();
		assert_eq!(requests.len(), 1);
		let NsmRequest::Attestation { user_data, nonce, public_key } =
			&requests[0]
		else {
			panic!("expected an attestation request");
		};
		assert_eq!(user_data.as_deref(), Some(&inputs.manifest_hash[..]));
		assert_eq!(public_key.as_ref(), Some(&inputs.ephemeral_public_key));
		assert_eq!(nonce, &None);
	}

	#[test]
	fn nsm_errors_are_typed() {
		let inputs = sample_inputs(1);
		let nsm = RecordingNsm::replying(NsmResponse::Error(
			qos_nsm::types::NsmErrorCode::InternalError,
		));
		assert!(matches!(
			attest_self(&nsm, &inputs, &NOT_CHECKED),
			Err(Error::Nsm(_))
		));
		let nsm = RecordingNsm::replying(NsmResponse::LockPCRs);
		assert!(matches!(
			attest_self(&nsm, &inputs, &NOT_CHECKED),
			Err(Error::UnexpectedNsmResponse(_))
		));
	}

	// not_after.

	#[test]
	fn not_after_is_the_earliest_including_an_intermediate() {
		let (fixture, _) =
			verify_document(MOCK_NSM_ATTESTATION_DOCUMENT, &aws_root())
				.unwrap();
		let short_lived = fixture.certificate.clone();

		// A long-lived leaf with a short-lived intermediate behind it.
		let mut doc = bound_doc(&sample_inputs(1), false);
		doc.certificate = ByteBuf::from(MOCK_LEAF_CERT_DER.to_vec());
		doc.cabundle = vec![
			ByteBuf::from(MOCK_ROOT_CERT_DER.to_vec()),
			short_lived.clone(),
		];
		let earliest = earliest_not_after(&doc, MOCK_ROOT_CERT_DER).unwrap();
		assert_eq!(earliest, not_after_of(&short_lived));
		assert!(earliest < not_after_of(MOCK_LEAF_CERT_DER));
	}

	// unsafe-verifier: the default path never accepts an unsigned document,
	// with or without the feature.

	#[test]
	fn default_verification_rejects_a_qemu_shaped_doc() {
		let inputs = sample_inputs(1);
		let document = qemu_shaped_document(&inputs, true);
		for root in [aws_root(), MOCK_ROOT_CERT_DER.to_vec()] {
			assert!(matches!(
				verify_self_attestation(&document, &root, &inputs, &REQUIRED),
				Err(Error::Document(_))
			));
		}
	}

	#[cfg(feature = "unsafe-verifier")]
	#[test]
	fn skip_chain_accepts_a_bound_qemu_shaped_doc() {
		let inputs = sample_inputs(1);
		let document = qemu_shaped_document(&inputs, true);
		let verified = unsafe_verify_self_attestation_skip_chain(
			&document, &inputs, &REQUIRED,
		)
		.unwrap();
		assert_eq!(verified.inputs, inputs);
		assert_eq!(verified.not_after_unix, u64::MAX);
		assert_eq!(verified.document, document);
	}

	#[cfg(feature = "unsafe-verifier")]
	#[test]
	fn skip_chain_still_checks_every_binding() {
		use crate::test_support::signed_with_zeros;

		let inputs = sample_inputs(1);
		let skip = |document: &[u8], policy: &VerifyPolicy| {
			unsafe_verify_self_attestation_skip_chain(document, &inputs, policy)
		};

		let other_key = {
			let mut other = inputs.clone();
			other.ephemeral_public_key = sample_inputs(2).ephemeral_public_key;
			qemu_shaped_document(&other, false)
		};
		assert!(matches!(
			skip(&other_key, &NOT_CHECKED),
			Err(Error::PublicKeyMismatch)
		));

		let other_manifest = {
			let mut other = inputs.clone();
			other.manifest_hash = [0xee; 32];
			qemu_shaped_document(&other, false)
		};
		assert!(matches!(
			skip(&other_manifest, &NOT_CHECKED),
			Err(Error::Binding(_))
		));

		let with_nonce = {
			let mut doc = nitro::unsafe_attestation_doc_from_der(
				&qemu_shaped_document(&inputs, false),
			)
			.unwrap();
			doc.nonce = Some(ByteBuf::from(vec![1]));
			signed_with_zeros(&doc)
		};
		assert!(matches!(
			skip(&with_nonce, &NOT_CHECKED),
			Err(Error::Binding(
				nitro::AttestError::UnexpectedAttestationDocNonce
			))
		));

		assert!(matches!(
			skip(&qemu_shaped_document(&inputs, false), &REQUIRED),
			Err(Error::ManifestOnlyCommitment(_))
		));
	}

	fn not_after_of(der: &[u8]) -> u64 {
		not_after(der).unwrap()
	}
}

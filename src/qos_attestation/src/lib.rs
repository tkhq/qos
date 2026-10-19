//! QOS attestation.
//!
//! - [`inputs`]: construct expected boot inputs from a public key and manifest.
//! - [`verify`]: standalone chain, signature and boot-input verification.
//! - `cache` (opt-in feature): keep one nonce-free boot attestation available
//!   until certificate expiry, with one background task refreshing it.
//!
//! The cache verifies every document against fixed boot inputs and the provider
//! root. Consumers retain the manifest bytes in memory and serve the verified
//! document's `.document()` bytes without calling the NSM per response. Its
//! timestamp describes issuance, not the response carrying it. Call
//! [`qos_nsm::NsmProvider`] directly for fresh or nonce-bound documents.
//!
//! Consumers own logging and process supervision. They should exit if cache
//! startup fails or the returned refresh task resolves, and arrange supervision
//! such as QOS's `RestartPolicy::Always`. Poisoned cache locks panic; discard
//! that cache instance rather than retrying access.
//!
//! A boot proof's manifest bytes are public: they include pivot args and,
//! for v2 manifests, the pivot environment. Never put secrets there.

mod error;
pub mod inputs;
pub mod verify;

#[cfg(feature = "cache")]
pub mod cache;

pub use error::Error;
pub use inputs::AttestationInputs;
pub use verify::{NsmProviderExt, VerifiedAttestationDocument};

#[cfg(test)]
mod tests {
	//! Test fixtures shared by the modules' unit tests.

	use std::collections::BTreeMap;

	use aws_nitro_enclaves_cose::{
		CoseSign1,
		crypto::{
			Hash, MessageDigest, SignatureAlgorithm, SigningPrivateKey,
			SigningPublicKey,
		},
		error::CoseError,
		header_map::HeaderMap,
	};
	use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
	use p384::ecdsa::{
		Signature, SigningKey,
		signature::hazmat::{PrehashSigner, PrehashVerifier},
	};
	use qos_nsm::{
		NsmProvider,
		mock::MockNsm,
		nitro::{self, AttestError},
		types::{NsmRequest, NsmResponse},
	};
	use qos_p256::P256Pair;
	use serde_bytes::ByteBuf;

	use crate::AttestationInputs;

	/// Deterministic inputs; different `n` give different keys, hashes and PCRs.
	pub(crate) fn sample_inputs(n: u8) -> AttestationInputs {
		let pcr = |i: u8| vec![n.wrapping_mul(4).wrapping_add(i); 48];
		AttestationInputs {
			ephemeral_public_key: P256Pair::from_master_seed(&[n; 32].into())
				.unwrap()
				.public_key(),
			manifest_hash: [n; 32],
			pcr0: pcr(0),
			pcr1: pcr(1),
			pcr2: pcr(2),
			pcr3: pcr(3),
		}
	}

	fn live_commitment(inputs: &AttestationInputs) -> Vec<u8> {
		nitro::expected_manifest_commitment_pcr::<nitro::Live>(
			&inputs.manifest_hash,
			&inputs.ephemeral_public_key.to_bytes(),
		)
		.unwrap()
		.to_vec()
	}

	fn manifest_only_commitment(inputs: &AttestationInputs) -> Vec<u8> {
		nitro::expected_manifest_only_commitment_pcr(&inputs.manifest_hash)
			.unwrap()
			.to_vec()
	}

	/// A mock NSM in the state QOS leaves it in after booting with `inputs`:
	/// PCR0-3 measured, the live commitment in PCR17 and, if asked, the
	/// manifest-only commitment in PCR18.
	pub(crate) fn enclave_mock_nsm(
		inputs: &AttestationInputs,
		pcr18: bool,
	) -> MockNsm {
		let nsm = MockNsm::new()
			.with_pcr(0, inputs.pcr0.clone())
			.with_pcr(1, inputs.pcr1.clone())
			.with_pcr(2, inputs.pcr2.clone())
			.with_pcr(3, inputs.pcr3.clone())
			.with_pcr(17, live_commitment(inputs));
		if pcr18 {
			nsm.with_pcr(18, manifest_only_commitment(inputs))
		} else {
			nsm
		}
	}

	fn unsigned_doc(inputs: &AttestationInputs) -> AttestationDoc {
		let mut pcrs = BTreeMap::new();
		for index in 0..usize::from(nitro::ATTESTABLE_PCR_COUNT) {
			pcrs.insert(index, ByteBuf::from(vec![0u8; nitro::PCR_SHA384_LEN]));
		}
		for index in [16, 17, 18] {
			pcrs.insert(
				index,
				ByteBuf::from(nitro::MANIFEST_COMMITMENT_INITIAL_PCR.to_vec()),
			);
		}
		for (index, pcr) in
			[&inputs.pcr0, &inputs.pcr1, &inputs.pcr2, &inputs.pcr3]
				.into_iter()
				.enumerate()
		{
			pcrs.insert(index, ByteBuf::from(pcr.clone()));
		}
		AttestationDoc {
			module_id: "test-module".into(),
			digest: Digest::SHA384,
			timestamp: 1,
			pcrs,
			certificate: ByteBuf::new(),
			cabundle: vec![],
			public_key: Some(ByteBuf::from(
				inputs.ephemeral_public_key.to_bytes(),
			)),
			user_data: Some(ByteBuf::from(inputs.manifest_hash.to_vec())),
			nonce: None,
		}
	}

	/// A parsed, unsigned document that binds correctly to `inputs`.
	pub(crate) fn bound_doc(
		inputs: &AttestationInputs,
		pcr18: bool,
	) -> AttestationDoc {
		let mut doc = unsigned_doc(inputs);
		doc.pcrs.insert(17, ByteBuf::from(live_commitment(inputs)));
		if pcr18 {
			doc.pcrs
				.insert(18, ByteBuf::from(manifest_only_commitment(inputs)));
		}
		doc
	}

	/// An NSM that returns a fixed response.
	pub(crate) struct ReplyNsm(pub(crate) NsmResponse);

	impl NsmProvider for ReplyNsm {
		fn nsm_process_request(&self, _: NsmRequest) -> NsmResponse {
			self.0.clone()
		}

		fn timestamp_ms(&self) -> Result<u64, AttestError> {
			Ok(qos_nsm::mock::MOCK_SECONDS_SINCE_EPOCH * 1000)
		}
	}

	/// A document shaped like QEMU's: it binds correctly, but its signature,
	/// certificate and CA bundle are all zero bytes, so no root can verify it.
	pub(crate) fn qemu_shaped_document(
		inputs: &AttestationInputs,
		pcr18: bool,
	) -> Vec<u8> {
		let mut doc = bound_doc(inputs, pcr18);
		doc.timestamp = 1_800_000_000_000;
		doc.certificate = ByteBuf::from(vec![0; 64]);
		doc.cabundle = vec![ByteBuf::from(vec![0; 64])];
		signed_with_zeros(&doc)
	}

	pub(crate) fn signed_with_zeros(doc: &AttestationDoc) -> Vec<u8> {
		CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &ZeroSigner)
			.unwrap()
			.as_bytes(false)
			.unwrap()
	}

	/// Sign a document with the test key matching `MOCK_LEAF_CERT_DER`.
	pub(crate) fn signed_with_mock_key(doc: &AttestationDoc) -> Vec<u8> {
		let signer = MockSigner(mock_signing_key());
		CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &signer)
			.unwrap()
			.as_bytes(false)
			.unwrap()
	}

	pub(crate) fn mock_signing_key() -> SigningKey {
		SigningKey::from_slice(&[
			0xe5, 0xaa, 0x61, 0x18, 0xb2, 0x86, 0xc0, 0xf9, 0xb9, 0x1a, 0x5f,
			0x0b, 0x43, 0x52, 0xb0, 0x03, 0xf6, 0x01, 0x62, 0xda, 0x9d, 0xa3,
			0xad, 0x11, 0x39, 0x1d, 0xa2, 0x5f, 0x18, 0xc9, 0xef, 0x58, 0xd7,
			0x52, 0x39, 0xc7, 0x6b, 0x04, 0x3c, 0x64, 0xa2, 0x0c, 0xd8, 0xca,
			0x63, 0x66, 0x95, 0xb5,
		])
		.unwrap()
	}

	struct MockSigner(SigningKey);

	impl SigningPrivateKey for MockSigner {
		fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
			let signature: Signature = self
				.0
				.sign_prehash(digest)
				.map_err(|error| CoseError::SignatureError(Box::new(error)))?;
			Ok(signature.to_vec())
		}
	}

	impl SigningPublicKey for MockSigner {
		fn get_parameters(
			&self,
		) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
			Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
		}

		fn verify(
			&self,
			digest: &[u8],
			signature: &[u8],
		) -> Result<bool, CoseError> {
			let signature = Signature::from_slice(signature)
				.map_err(|error| CoseError::SignatureError(Box::new(error)))?;
			self.0
				.verifying_key()
				.verify_prehash(digest, &signature)
				.map(|()| true)
				.map_err(|error| CoseError::SignatureError(Box::new(error)))
		}
	}

	struct ZeroSigner;

	impl SigningPrivateKey for ZeroSigner {
		fn sign(&self, _digest: &[u8]) -> Result<Vec<u8>, CoseError> {
			Ok(vec![0; 96])
		}
	}

	impl SigningPublicKey for ZeroSigner {
		fn get_parameters(
			&self,
		) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
			Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
		}

		fn verify(
			&self,
			_digest: &[u8],
			_signature: &[u8],
		) -> Result<bool, CoseError> {
			Ok(false)
		}
	}

	struct Sha2;

	impl Hash for Sha2 {
		fn hash(
			digest: MessageDigest,
			data: &[u8],
		) -> Result<Vec<u8>, CoseError> {
			use sha2::Digest as _;
			match digest {
				MessageDigest::Sha256 => {
					Ok(sha2::Sha256::digest(data).to_vec())
				}
				MessageDigest::Sha384 => {
					Ok(sha2::Sha384::digest(data).to_vec())
				}
				MessageDigest::Sha512 => {
					Ok(sha2::Sha512::digest(data).to_vec())
				}
			}
		}
	}
}

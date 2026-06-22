//! Mocks for external attest endpoints. Only for testing.

use std::collections::{BTreeMap, BTreeSet};

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
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_bytes::ByteBuf;

use crate::{
	nitro,
	nsm::NsmProvider,
	types::{NsmDigest, NsmErrorCode, NsmRequest, NsmResponse},
};

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// The `user_data` for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT: &str =
	"a2ec4272c44690b2dc32ed89d4bdd266ec2b0e753dff2f25f08b5d2a15cfe2e6";

/// A valid time to validated the cert chain against in
/// [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_SECONDS_SINCE_EPOCH: u64 = 1_657_117_192;

/// Value of the `timestamp` field in the [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_ATTESTATION_DOC_TIMESTAMP: u64 = 1_657_117_102_484;

/// PCR index 0 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR0: &str = "f8bb0133c427bc49aa39f6811a01077ce9ab7e635fa1f5439c9c8bf99754f8230e41b09426b0e595eebdc4d6ed4bc3b6";

/// PCR index 1 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR1: &str = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";

/// PCR index 2 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR2: &str = "c185515d78cb90a2dc1fa49ea232fb44645acd18652c96dd05a92b9c5dbfa36d61d7c7d9e71d51de38de914cd00214bb";

/// PCR index 3 for [`MOCK_NSM_ATTESTATION_DOCUMENT`].
pub const MOCK_PCR3: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
// This was generate using the `gen_att_doc` script in `integration`.
pub const MOCK_NSM_ATTESTATION_DOCUMENT: &[u8] =
	include_bytes!("./static/mock_attestation_doc");

const MOCK_MODULE_ID: &str = "mock_module_id";
const MOCK_NSM_VERSION_MAJOR: u16 = 1;
const MOCK_NSM_VERSION_MINOR: u16 = 2;
const MOCK_NSM_VERSION_PATCH: u16 = 14;
const MOCK_MAX_PCRS: u16 = 1024;
const MOCK_LOCKED_PCRS: [u16; 3] = [90, 91, 92];
const MOCK_EXTEND_PCR_RESPONSE: [u8; 4] = [3, 4, 7, 4];
const MOCK_RANDOM_RESPONSE: [u8; 4] = [4, 2, 0, 69];

/// Mock Nitro Secure Module endpoint that should only ever be used for testing.
pub struct MockNsm;
impl NsmProvider for MockNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation {
				user_data: _,
				nonce: _,
				public_key: _,
			} => NsmResponse::Attestation {
				document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
			},
			NsmRequest::DescribeNSM => NsmResponse::DescribeNSM {
				version_major: MOCK_NSM_VERSION_MAJOR,
				version_minor: MOCK_NSM_VERSION_MINOR,
				version_patch: MOCK_NSM_VERSION_PATCH,
				module_id: MOCK_MODULE_ID.to_string(),
				max_pcrs: MOCK_MAX_PCRS,
				locked_pcrs: BTreeSet::from(MOCK_LOCKED_PCRS),
				digest: NsmDigest::SHA256,
			},
			NsmRequest::ExtendPCR { index: _, data: _ } => {
				NsmResponse::ExtendPCR {
					data: MOCK_EXTEND_PCR_RESPONSE.to_vec(),
				}
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: MOCK_RANDOM_RESPONSE.to_vec() }
			}
			NsmRequest::LockPCR { index: _ } => NsmResponse::LockPCR,
			NsmRequest::LockPCRs { range: _ } => NsmResponse::LockPCRs,
			NsmRequest::DescribePCR { index: _ } => NsmResponse::DescribePCR {
				lock: false,
				data: MOCK_EXTEND_PCR_RESPONSE.to_vec(),
			},
		}
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		{
			#[cfg(not(feature = "mock_realtime"))]
			{
				Ok(MOCK_ATTESTATION_DOC_TIMESTAMP)
			}
			#[cfg(feature = "mock_realtime")]
			{
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|time| {
						let ms = time.as_millis();
						u64::try_from(ms)
							.map_err(|_| nitro::AttestError::InvalidTimeStamp)
					})
					.map_err(|_| nitro::AttestError::InvalidTimeStamp)?
			}
		}
	}
}

/// A configurable mock Nitro Secure Module endpoint for local tests.
///
/// Unlike [`MockNsm`], this provider creates a fresh attestation document for
/// each [`NsmRequest::Attestation`] request. The generated document preserves
/// the request's `user_data`, `nonce`, and `public_key` fields.
///
/// This mock produces a parseable COSE Sign1 attestation document. It is for
/// local development and tests only, and it does not produce an attestation
/// document signed by the AWS Nitro PKI.
#[derive(Clone, Debug)]
pub struct DynamicMockNsm {
	module_id: String,
	timestamp_ms: u64,
	pcrs: BTreeMap<usize, ByteBuf>,
	signing_key: P384PrivateKey,
}

impl DynamicMockNsm {
	/// Create a dynamic mock NSM with the same default PCRs and timestamp as
	/// [`MockNsm`].
	#[must_use]
	pub fn new() -> Self {
		Self {
			module_id: MOCK_MODULE_ID.to_string(),
			timestamp_ms: MOCK_ATTESTATION_DOC_TIMESTAMP,
			pcrs: default_pcrs(),
			signing_key: P384PrivateKey::deterministic(),
		}
	}

	/// Configure the timestamp embedded in generated attestation documents.
	#[must_use]
	pub fn with_timestamp_ms(mut self, timestamp_ms: u64) -> Self {
		self.timestamp_ms = timestamp_ms;
		self
	}

	/// Configure the module ID embedded in generated attestation documents.
	#[must_use]
	pub fn with_module_id(mut self, module_id: impl Into<String>) -> Self {
		self.module_id = module_id.into();
		self
	}

	/// Configure a PCR value embedded in generated attestation documents.
	#[must_use]
	pub fn with_pcr(mut self, index: usize, data: Vec<u8>) -> Self {
		self.pcrs.insert(index, ByteBuf::from(data));
		self
	}

	fn attestation(
		&self,
		user_data: Option<Vec<u8>>,
		nonce: Option<Vec<u8>>,
		public_key: Option<Vec<u8>>,
	) -> NsmResponse {
		let doc = AttestationDoc {
			module_id: self.module_id.clone(),
			digest: Digest::SHA384,
			timestamp: self.timestamp_ms,
			pcrs: self.pcrs.clone(),
			certificate: ByteBuf::from(vec![1]),
			cabundle: vec![ByteBuf::from(vec![1])],
			public_key: public_key.map(ByteBuf::from),
			user_data: user_data.map(ByteBuf::from),
			nonce: nonce.map(ByteBuf::from),
		};

		match CoseSign1::new::<MockSha2>(
			&doc.to_binary(),
			&HeaderMap::new(),
			&self.signing_key,
		)
		.and_then(|cose| cose.as_bytes(true))
		{
			Ok(document) => NsmResponse::Attestation { document },
			Err(_) => NsmResponse::Error(NsmErrorCode::InternalError),
		}
	}
}

impl Default for DynamicMockNsm {
	fn default() -> Self {
		Self::new()
	}
}

impl NsmProvider for DynamicMockNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation { user_data, nonce, public_key } => {
				self.attestation(user_data, nonce, public_key)
			}
			NsmRequest::DescribeNSM => NsmResponse::DescribeNSM {
				version_major: MOCK_NSM_VERSION_MAJOR,
				version_minor: MOCK_NSM_VERSION_MINOR,
				version_patch: MOCK_NSM_VERSION_PATCH,
				module_id: self.module_id.clone(),
				max_pcrs: MOCK_MAX_PCRS,
				locked_pcrs: BTreeSet::from(MOCK_LOCKED_PCRS),
				digest: NsmDigest::SHA384,
			},
			NsmRequest::DescribePCR { index } => {
				let Some(data) = self.pcrs.get(&usize::from(index)) else {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				};
				NsmResponse::DescribePCR { lock: true, data: data.to_vec() }
			}
			NsmRequest::ExtendPCR { index: _, data: _ } => {
				NsmResponse::Error(NsmErrorCode::InvalidOperation)
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: MOCK_RANDOM_RESPONSE.to_vec() }
			}
			NsmRequest::LockPCR { index: _ } => NsmResponse::LockPCR,
			NsmRequest::LockPCRs { range: _ } => NsmResponse::LockPCRs,
		}
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		Ok(self.timestamp_ms)
	}
}

fn default_pcrs() -> BTreeMap<usize, ByteBuf> {
	BTreeMap::from([
		(0, ByteBuf::from(qos_hex::decode(MOCK_PCR0).expect("valid PCR0"))),
		(1, ByteBuf::from(qos_hex::decode(MOCK_PCR1).expect("valid PCR1"))),
		(2, ByteBuf::from(qos_hex::decode(MOCK_PCR2).expect("valid PCR2"))),
		(3, ByteBuf::from(qos_hex::decode(MOCK_PCR3).expect("valid PCR3"))),
	])
}

#[derive(Clone, Debug)]
struct P384PrivateKey(p384::SecretKey);

impl P384PrivateKey {
	fn deterministic() -> Self {
		let secret = qos_hex::decode(
			"55c6aa815a31741bc37f0ffddea73af2397bad640816ef22bfb689efc1b6cc682a73f7e5a657248e3abad500e46d5afc",
		)
		.expect("valid deterministic p384 secret");
		Self(p384::SecretKey::from_slice(&secret).expect("valid p384 secret"))
	}
}

impl SigningPrivateKey for P384PrivateKey {
	fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
		use p384::ecdsa::signature::hazmat::PrehashSigner as _;

		let signer = SigningKey::from(&self.0);
		signer
			.sign_prehash(digest)
			.map(|sig: Signature| sig.to_vec())
			.map_err(|e| CoseError::SignatureError(Box::new(e)))
	}
}

impl SigningPublicKey for P384PrivateKey {
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
		use p384::ecdsa::signature::hazmat::PrehashVerifier as _;

		let signature_wrapped = Signature::try_from(signature)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))?;

		let verifier = VerifyingKey::from(self.0.public_key());
		verifier
			.verify_prehash(digest, &signature_wrapped)
			.map(|()| true)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))
	}
}

struct MockSha2;
impl Hash for MockSha2 {
	fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
		use sha2::Digest as _;

		match digest {
			MessageDigest::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
			MessageDigest::Sha384 => Ok(sha2::Sha384::digest(data).to_vec()),
			MessageDigest::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::nitro::{
		unsafe_attestation_doc_from_der,
		verify_attestation_doc_against_user_input,
	};

	fn hex_pcr(value: &str) -> Vec<u8> {
		qos_hex::decode(value).unwrap()
	}

	#[test]
	fn dynamic_mock_nsm_embeds_attestation_request_fields() {
		let user_data = vec![1, 2, 3, 4];
		let nonce = vec![5, 6, 7, 8];
		let public_key = vec![9, 10, 11, 12];
		let nsm = DynamicMockNsm::new();

		let response = nsm.nsm_process_request(NsmRequest::Attestation {
			user_data: Some(user_data.clone()),
			nonce: Some(nonce.clone()),
			public_key: Some(public_key.clone()),
		});

		let NsmResponse::Attestation { document } = response else {
			panic!("expected attestation response");
		};
		let doc = unsafe_attestation_doc_from_der(&document).unwrap();
		assert_eq!(doc.user_data.unwrap().as_slice(), user_data);
		assert_eq!(doc.nonce.unwrap().as_slice(), nonce);
		assert_eq!(doc.public_key.as_ref().unwrap().as_slice(), public_key);
	}

	#[test]
	fn dynamic_mock_nsm_field_verification_matches_request_inputs() {
		let public_key = vec![9, 10, 11, 12];
		let user_data =
			qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap();
		let nsm = DynamicMockNsm::new();

		let response = nsm.nsm_process_request(NsmRequest::Attestation {
			user_data: Some(user_data.clone()),
			nonce: None,
			public_key: Some(public_key.clone()),
		});

		let NsmResponse::Attestation { document } = response else {
			panic!("expected attestation response");
		};
		let doc = unsafe_attestation_doc_from_der(&document).unwrap();
		assert_eq!(doc.public_key.as_ref().unwrap().as_slice(), public_key);
		verify_attestation_doc_against_user_input(
			&doc,
			&user_data,
			&hex_pcr(MOCK_PCR0),
			&hex_pcr(MOCK_PCR1),
			&hex_pcr(MOCK_PCR2),
			&hex_pcr(MOCK_PCR3),
		)
		.unwrap();
	}
}

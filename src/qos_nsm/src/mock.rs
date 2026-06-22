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
use p384::{
	PublicKey,
	ecdsa::{
		Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashSigner,
	},
};
use serde_bytes::ByteBuf;

use crate::{
	nitro,
	nsm::NsmProvider,
	types::{NsmDigest, NsmErrorCode, NsmRequest, NsmResponse},
};

#[cfg(test)]
use crate::nitro::{
	unsafe_attestation_doc_from_der, verify_attestation_doc_against_user_input,
};

#[cfg(test)]
fn hex_pcr(pcr: &str) -> Vec<u8> {
	qos_hex::decode(pcr).unwrap()
}

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

const DYNAMIC_MOCK_MODULE_ID: &str = "dynamic_mock_module_id";
const DYNAMIC_MOCK_CERTIFICATE: &[u8] = b"dynamic mock certificate";
const DYNAMIC_MOCK_CA_BUNDLE: &[u8] = b"dynamic mock ca bundle";
const DYNAMIC_MOCK_P384_SECRET: &[u8; 48] = &[
	0x55, 0xc6, 0xaa, 0x81, 0x5a, 0x31, 0x74, 0x1b, 0xc3, 0x7f, 0x0f, 0xfd,
	0xde, 0xa7, 0x3a, 0xf2, 0x39, 0x7b, 0xad, 0x64, 0x08, 0x16, 0xef, 0x22,
	0xbf, 0xb6, 0x89, 0xef, 0xc1, 0xb6, 0xcc, 0x68, 0x2a, 0x73, 0xf7, 0xe5,
	0xa6, 0x57, 0x24, 0x8e, 0x3a, 0xba, 0xd5, 0x00, 0xe4, 0x6d, 0x5a, 0xfc,
];

/// Mock Nitro Secure Module endpoint that creates parseable attestation docs.
#[derive(Clone, Debug)]
pub struct DynamicMockNsm {
	module_id: String,
	timestamp_ms: u64,
	pcrs: BTreeMap<usize, ByteBuf>,
	signing_key: [u8; 48],
}

impl DynamicMockNsm {
	/// Create a new dynamic mock NSM provider.
	///
	/// # Panics
	///
	/// Panics if this crate's hardcoded mock PCR constants are invalid hex.
	#[must_use]
	pub fn new() -> Self {
		Self {
			module_id: DYNAMIC_MOCK_MODULE_ID.to_string(),
			timestamp_ms: MOCK_ATTESTATION_DOC_TIMESTAMP,
			pcrs: BTreeMap::from([
				(0, ByteBuf::from(qos_hex::decode(MOCK_PCR0).unwrap())),
				(1, ByteBuf::from(qos_hex::decode(MOCK_PCR1).unwrap())),
				(2, ByteBuf::from(qos_hex::decode(MOCK_PCR2).unwrap())),
				(3, ByteBuf::from(qos_hex::decode(MOCK_PCR3).unwrap())),
			]),
			signing_key: *DYNAMIC_MOCK_P384_SECRET,
		}
	}

	/// Set the timestamp included in generated attestation documents.
	#[must_use]
	pub fn with_timestamp_ms(mut self, timestamp_ms: u64) -> Self {
		self.timestamp_ms = timestamp_ms;
		self
	}

	/// Set the module id included in generated attestation documents.
	#[must_use]
	pub fn with_module_id(mut self, module_id: impl Into<String>) -> Self {
		self.module_id = module_id.into();
		self
	}

	/// Set a PCR value included in generated attestation documents.
	#[must_use]
	pub fn with_pcr(mut self, index: usize, value: impl Into<Vec<u8>>) -> Self {
		self.pcrs.insert(index, ByteBuf::from(value.into()));
		self
	}

	fn attestation_document(
		&self,
		user_data: Option<Vec<u8>>,
		nonce: Option<Vec<u8>>,
		public_key: Option<Vec<u8>>,
	) -> Vec<u8> {
		let doc = AttestationDoc {
			module_id: self.module_id.clone(),
			digest: Digest::SHA384,
			timestamp: self.timestamp_ms,
			pcrs: self.pcrs.clone(),
			certificate: ByteBuf::from(DYNAMIC_MOCK_CERTIFICATE.to_vec()),
			cabundle: vec![ByteBuf::from(DYNAMIC_MOCK_CA_BUNDLE.to_vec())],
			public_key: public_key.map(ByteBuf::from),
			user_data: user_data.map(ByteBuf::from),
			nonce: nonce.map(ByteBuf::from),
		};
		let key = P384PrivateKey::new(self.signing_key);
		CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &key)
			.expect("dynamic mock attestation document is signable")
			.as_bytes(false)
			.expect("dynamic mock attestation document is serializable")
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
				NsmResponse::Attestation {
					document: self
						.attestation_document(user_data, nonce, public_key),
				}
			}
			NsmRequest::DescribeNSM => NsmResponse::DescribeNSM {
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: self.module_id.clone(),
				max_pcrs: 1024,
				locked_pcrs: BTreeSet::from([90, 91, 92]),
				digest: NsmDigest::SHA384,
			},
			NsmRequest::ExtendPCR { index: _, data: _ } => {
				NsmResponse::Error(NsmErrorCode::InvalidOperation)
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: vec![4, 2, 0, 69] }
			}
			NsmRequest::LockPCR { index: _ } => NsmResponse::LockPCR,
			NsmRequest::LockPCRs { range: _ } => NsmResponse::LockPCRs,
			NsmRequest::DescribePCR { index } => {
				self.pcrs.get(&usize::from(index)).map_or(
					NsmResponse::Error(NsmErrorCode::InvalidIndex),
					|pcr| NsmResponse::DescribePCR {
						lock: false,
						data: pcr.to_vec(),
					},
				)
			}
		}
	}

	fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
		Ok(self.timestamp_ms)
	}
}

struct P384PrivateKey {
	secret: p384::SecretKey,
}

impl P384PrivateKey {
	fn new(secret: [u8; 48]) -> Self {
		Self { secret: p384::SecretKey::from_slice(&secret).unwrap() }
	}
}

impl SigningPrivateKey for P384PrivateKey {
	fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
		let signer = SigningKey::from(&self.secret);
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
		let verifier =
			VerifyingKey::from(PublicKey::from(self.secret.public_key()));
		verifier
			.verify_prehash(digest, &signature_wrapped)
			.map(|()| true)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))
	}
}

struct Sha2;
impl Hash for Sha2 {
	fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
		use sha2::Digest as _;

		match digest {
			MessageDigest::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
			MessageDigest::Sha384 => Ok(sha2::Sha384::digest(data).to_vec()),
			MessageDigest::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
		}
	}
}

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
				version_major: 1,
				version_minor: 2,
				version_patch: 14,
				module_id: "mock_module_id".to_string(),
				max_pcrs: 1024,
				locked_pcrs: BTreeSet::from([90, 91, 92]),
				digest: NsmDigest::SHA256,
			},
			NsmRequest::ExtendPCR { index: _, data: _ } => {
				NsmResponse::ExtendPCR { data: vec![3, 4, 7, 4] }
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: vec![4, 2, 0, 69] }
			}
			NsmRequest::LockPCR { index: _ } => NsmResponse::LockPCR,
			NsmRequest::LockPCRs { range: _ } => NsmResponse::LockPCRs,
			NsmRequest::DescribePCR { index: _ } => {
				NsmResponse::DescribePCR { lock: false, data: vec![3, 4, 7, 4] }
			}
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

#[cfg(test)]
mod dynamic_mock_nsm_tests {
	use serde_bytes::ByteBuf;

	use super::*;

	#[test]
	fn dynamic_mock_nsm_embeds_attestation_request_fields() {
		let user_data = vec![1, 2, 3];
		let nonce = vec![4, 5, 6];
		let public_key = vec![7; 65];
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
		assert_eq!(doc.user_data, Some(ByteBuf::from(user_data)));
		assert_eq!(doc.nonce, Some(ByteBuf::from(nonce)));
		assert_eq!(doc.public_key, Some(ByteBuf::from(public_key)));
	}

	#[test]
	fn dynamic_mock_nsm_field_verification_matches_request_inputs() {
		let user_data =
			qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap();
		let nsm = DynamicMockNsm::new();

		let response = nsm.nsm_process_request(NsmRequest::Attestation {
			user_data: Some(user_data.clone()),
			nonce: None,
			public_key: None,
		});

		let NsmResponse::Attestation { document } = response else {
			panic!("expected attestation response");
		};

		let doc = unsafe_attestation_doc_from_der(&document).unwrap();

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

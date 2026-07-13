//! Mocks for external attest endpoints. Only for testing.

use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Mutex,
};

use aws_nitro_enclaves_cose::{
	CoseSign1,
	crypto::{
		MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
	},
	error::CoseError,
	header_map::HeaderMap,
};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use p384::ecdsa::{
	Signature, SigningKey, VerifyingKey,
	signature::hazmat::{PrehashSigner as _, PrehashVerifier as _},
};
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

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// DER encoded root CA of the mock NSM PKI. Attestation documents signed by
/// [`MockNsm`] chain up to this root. See
/// `src/static/mock_pki/generate.py` for how the fixtures are generated.
pub const MOCK_ROOT_CERT_DER: &[u8] =
	include_bytes!("./static/mock_pki/root.der");

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// DER encoded intermediate CA of the mock NSM PKI.
pub const MOCK_INTERMEDIATE_CERT_DER: &[u8] =
	include_bytes!("./static/mock_pki/intermediate.der");

/// DO NOT USE IN PRODUCTION - ONLY FOR TESTS.
/// DER encoded end entity certificate of the mock NSM PKI. [`MockNsm`] signs
/// attestation documents with the associated P-384 key.
pub const MOCK_LEAF_CERT_DER: &[u8] =
	include_bytes!("./static/mock_pki/leaf.der");

/// Hex encoded P-384 secret scalar for [`MOCK_LEAF_CERT_DER`].
const MOCK_LEAF_P384_SECRET_HEX: &str =
	include_str!("./static/mock_pki/leaf_p384_secret.hex");

const MOCK_MODULE_ID: &str = "mock_module_id";

#[derive(Debug)]
struct MockNsmState {
	max_pcrs: u16,
	pcrs: BTreeMap<u16, Vec<u8>>,
	locked_pcrs: BTreeSet<u16>,
}

impl Default for MockNsmState {
	fn default() -> Self {
		let mut pcrs = BTreeMap::new();
		for index in [
			nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
			nitro::LIVE_MANIFEST_COMMITMENT_PCR_INDEX,
		] {
			pcrs.insert(index, nitro::MANIFEST_COMMITMENT_INITIAL_PCR.to_vec());
		}

		Self {
			max_pcrs: nitro::ATTESTABLE_PCR_COUNT,
			pcrs,
			locked_pcrs: BTreeSet::new(),
		}
	}
}

/// Mock Nitro Secure Module endpoint that should only ever be used for testing.
#[derive(Debug, Default)]
pub struct MockNsm {
	state: Mutex<MockNsmState>,
}

impl MockNsm {
	/// Create a new mock Nitro Secure Module endpoint.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Seed a PCR register with a value, e.g. mock measurements for
	/// PCR{0, 1, 2, 3}. This is the mock analog of the image measurements a
	/// real Nitro enclave boots with.
	///
	/// # Panics
	///
	/// Panics if `index` is not an attestable PCR index or `value` does not
	/// have a valid PCR length (32, 48, or 64 bytes; real Nitro PCRs are 48
	/// byte SHA384 values). Only for tests.
	#[must_use]
	pub fn with_pcr(self, index: u16, value: Vec<u8>) -> Self {
		assert!(
			index < nitro::ATTESTABLE_PCR_COUNT,
			"PCR{index} is not an attestable PCR index"
		);
		assert!(
			[32, 48, 64].contains(&value.len()),
			"PCR{index} seed value must be a 32, 48, or 64 byte PCR"
		);

		{
			let mut state = self.state.lock().unwrap();
			state.pcrs.insert(index, value);
		}
		self
	}

	/// Build a mock attestation document over the current PCR bank and the
	/// attestation request inputs, then sign it with the mock NSM PKI leaf
	/// key ([`MOCK_LEAF_CERT_DER`]).
	fn signed_attestation_document(
		&self,
		user_data: Option<Vec<u8>>,
		nonce: Option<Vec<u8>>,
		public_key: Option<Vec<u8>>,
	) -> Vec<u8> {
		let pcrs = {
			let state = self.state.lock().unwrap();
			(0..nitro::ATTESTABLE_PCR_COUNT)
				.map(|index| {
					let pcr =
						state.pcrs.get(&index).cloned().unwrap_or_else(|| {
							vec![0u8; nitro::PCR_SHA384_LEN]
						});
					(usize::from(index), ByteBuf::from(pcr))
				})
				.collect()
		};

		let attestation_doc = AttestationDoc {
			module_id: MOCK_MODULE_ID.to_string(),
			digest: Digest::SHA384,
			timestamp: self
				.timestamp_ms()
				.expect("mock timestamp is always available. qed."),
			pcrs,
			certificate: ByteBuf::from(MOCK_LEAF_CERT_DER.to_vec()),
			cabundle: vec![
				ByteBuf::from(MOCK_ROOT_CERT_DER.to_vec()),
				ByteBuf::from(MOCK_INTERMEDIATE_CERT_DER.to_vec()),
			],
			public_key: public_key.map(ByteBuf::from),
			user_data: user_data.map(ByteBuf::from),
			nonce: nonce.map(ByteBuf::from),
		};

		CoseSign1::new::<nitro::Sha2>(
			&attestation_doc.to_binary(),
			&HeaderMap::new(),
			&MockLeafKey::new(),
		)
		.expect("mock attestation document is signable. qed.")
		.as_bytes(false)
		.expect("mock attestation document is serializable. qed.")
	}
}

/// The mock NSM PKI leaf key used to sign mock attestation documents.
struct MockLeafKey(p384::SecretKey);

impl MockLeafKey {
	fn new() -> Self {
		let secret = qos_hex::decode(MOCK_LEAF_P384_SECRET_HEX.trim())
			.expect("mock leaf secret fixture is valid hex. qed.");
		Self(
			p384::SecretKey::from_slice(&secret)
				.expect("mock leaf secret fixture is a P-384 scalar. qed."),
		)
	}
}

impl SigningPrivateKey for MockLeafKey {
	fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
		let signer = SigningKey::from(&self.0);
		signer
			.sign_prehash(digest)
			.map(|sig: Signature| sig.to_vec())
			.map_err(|e| CoseError::SignatureError(Box::new(e)))
	}
}

impl SigningPublicKey for MockLeafKey {
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
		let signature_wrapped = Signature::try_from(signature)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))?;
		let verifier = VerifyingKey::from(self.0.public_key());
		verifier
			.verify_prehash(digest, &signature_wrapped)
			.map(|()| true)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))
	}
}

impl NsmProvider for MockNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation { user_data, nonce, public_key } => {
				NsmResponse::Attestation {
					document: self.signed_attestation_document(
						user_data, nonce, public_key,
					),
				}
			}
			NsmRequest::DescribeNSM => {
				let state = self.state.lock().unwrap();
				NsmResponse::DescribeNSM {
					version_major: 1,
					version_minor: 2,
					version_patch: 14,
					module_id: MOCK_MODULE_ID.to_string(),
					max_pcrs: state.max_pcrs,
					locked_pcrs: state.locked_pcrs.clone(),
					digest: NsmDigest::SHA384,
				}
			}
			NsmRequest::ExtendPCR { index, data } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				if state.locked_pcrs.contains(&index) {
					return NsmResponse::Error(NsmErrorCode::ReadOnlyIndex);
				}

				let current = state
					.pcrs
					.entry(index)
					.or_insert_with(|| vec![0u8; nitro::PCR_SHA384_LEN]);
				let extended =
					nitro::pcr_extend_sha384(current, &data).unwrap().to_vec();
				current.clone_from(&extended);
				NsmResponse::ExtendPCR { data: extended }
			}
			NsmRequest::GetRandom => {
				NsmResponse::GetRandom { random: vec![4, 2, 0, 69] }
			}
			NsmRequest::LockPCR { index } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				state.locked_pcrs.insert(index);
				NsmResponse::LockPCR
			}
			NsmRequest::LockPCRs { range } => {
				let mut state = self.state.lock().unwrap();
				if range > state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				state.locked_pcrs.extend(0..range);
				NsmResponse::LockPCRs
			}
			NsmRequest::DescribePCR { index } => {
				let mut state = self.state.lock().unwrap();
				if index >= state.max_pcrs {
					return NsmResponse::Error(NsmErrorCode::InvalidIndex);
				}
				let lock = state.locked_pcrs.contains(&index);
				let data = state
					.pcrs
					.entry(index)
					.or_insert_with(|| vec![0u8; nitro::PCR_SHA384_LEN])
					.clone();
				NsmResponse::DescribePCR { lock, data }
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

	fn attestation_root_ca_der(&self) -> Vec<u8> {
		MOCK_ROOT_CERT_DER.to_vec()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mock_nsm_tracks_pcr_state() {
		let nsm = MockNsm::new();

		let NsmResponse::DescribePCR { lock: initial_lock, data: initial_data } =
			nsm.nsm_process_request(NsmRequest::DescribePCR { index: 5 })
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(!initial_lock);
		assert_eq!(initial_data, vec![0u8; nitro::PCR_SHA384_LEN]);

		let NsmResponse::ExtendPCR { data: extended_data } = nsm
			.nsm_process_request(NsmRequest::ExtendPCR {
				index: 5,
				data: b"mock-state-check".to_vec(),
			})
		else {
			panic!("unexpected ExtendPCR response");
		};
		assert_ne!(extended_data, initial_data);

		assert!(matches!(
			nsm.nsm_process_request(NsmRequest::LockPCR { index: 5 }),
			NsmResponse::LockPCR
		));

		let NsmResponse::DescribePCR { lock: locked, data: locked_data } =
			nsm.nsm_process_request(NsmRequest::DescribePCR { index: 5 })
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(locked);
		assert_eq!(locked_data, extended_data);

		assert!(matches!(
			nsm.nsm_process_request(NsmRequest::ExtendPCR {
				index: 5,
				data: b"after-lock".to_vec(),
			}),
			NsmResponse::Error(NsmErrorCode::ReadOnlyIndex)
		));
	}

	fn attestation_document(nsm: &MockNsm) -> Vec<u8> {
		let NsmResponse::Attestation { document } =
			nsm.nsm_process_request(NsmRequest::Attestation {
				user_data: Some(vec![1, 2, 3]),
				nonce: None,
				public_key: Some(vec![7; 65]),
			})
		else {
			panic!("unexpected Attestation response");
		};
		document
	}

	#[test]
	fn mock_nsm_attestation_doc_preserves_request_fields() {
		let nsm = MockNsm::new();
		let user_data = vec![1, 2, 3];
		let nonce = vec![4, 5, 6];
		let public_key = vec![7; 65];

		let NsmResponse::Attestation { document } =
			nsm.nsm_process_request(NsmRequest::Attestation {
				user_data: Some(user_data.clone()),
				nonce: Some(nonce.clone()),
				public_key: Some(public_key.clone()),
			})
		else {
			panic!("unexpected Attestation response");
		};

		let doc = nitro::unsafe_attestation_doc_from_der(&document).unwrap();
		assert_eq!(doc.user_data, Some(ByteBuf::from(user_data)));
		assert_eq!(doc.nonce, Some(ByteBuf::from(nonce)));
		assert_eq!(doc.public_key, Some(ByteBuf::from(public_key)));
		assert_eq!(doc.module_id, MOCK_MODULE_ID);
		assert_eq!(doc.timestamp, nsm.timestamp_ms().unwrap());
	}

	#[test]
	fn mock_nsm_attestation_doc_verifies_against_mock_root() {
		let nsm = MockNsm::new();
		let document = attestation_document(&nsm);

		let doc = nitro::attestation_doc_from_der(
			&document,
			MOCK_ROOT_CERT_DER,
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.unwrap();

		assert_eq!(doc.user_data, Some(ByteBuf::from(vec![1, 2, 3])));
		assert_eq!(doc.public_key, Some(ByteBuf::from(vec![7; 65])));
	}

	#[test]
	fn mock_nsm_attestation_doc_fails_against_aws_root() {
		let nsm = MockNsm::new();
		let document = attestation_document(&nsm);

		let aws_root = nitro::cert_from_pem(nitro::AWS_ROOT_CERT_PEM).unwrap();
		assert!(
			nitro::attestation_doc_from_der(
				&document,
				&aws_root,
				MOCK_SECONDS_SINCE_EPOCH,
			)
			.is_err()
		);
	}

	#[test]
	fn mock_nsm_attestation_doc_contains_all_attestable_pcrs() {
		let nsm = MockNsm::new();
		let document = attestation_document(&nsm);

		let doc = nitro::unsafe_attestation_doc_from_der(&document).unwrap();
		for index in 0..nitro::ATTESTABLE_PCR_COUNT {
			assert!(doc.pcrs.contains_key(&usize::from(index)));
		}
	}

	#[test]
	fn mock_nsm_attestation_doc_reflects_seeded_and_extended_pcrs() {
		let seeded_pcr0 = vec![42u8; nitro::PCR_SHA384_LEN];
		let nsm = MockNsm::new().with_pcr(0, seeded_pcr0.clone());

		let NsmResponse::ExtendPCR { data: extended } = nsm
			.nsm_process_request(NsmRequest::ExtendPCR {
				index: nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
				data: b"commitment".to_vec(),
			})
		else {
			panic!("unexpected ExtendPCR response");
		};

		let document = attestation_document(&nsm);
		let doc = nitro::unsafe_attestation_doc_from_der(&document).unwrap();

		assert_eq!(
			doc.pcrs.get(&0),
			Some(&ByteBuf::from(seeded_pcr0)),
			"seeded PCR0 should be reflected in the attestation doc"
		);
		assert_eq!(
			doc.pcrs
				.get(&usize::from(nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX)),
			Some(&ByteBuf::from(extended)),
			"extended PCR should be reflected in the attestation doc"
		);
	}

	#[test]
	fn mock_nsm_attestation_root_is_the_mock_root() {
		assert_eq!(
			MockNsm::new().attestation_root_ca_der(),
			MOCK_ROOT_CERT_DER.to_vec()
		);
	}

	#[test]
	fn default_attestation_root_is_the_aws_nitro_root() {
		struct AwsDefault;
		impl NsmProvider for AwsDefault {
			fn nsm_process_request(&self, _: NsmRequest) -> NsmResponse {
				unimplemented!()
			}
			fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
				unimplemented!()
			}
		}

		assert_eq!(
			AwsDefault.attestation_root_ca_der(),
			nitro::cert_from_pem(nitro::AWS_ROOT_CERT_PEM).unwrap()
		);
	}
}

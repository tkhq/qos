//! Request-aware mock Nitro Secure Module endpoint. Only for testing.

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
use p384::{
	SecretKey,
	ecdsa::{
		Signature, SigningKey, VerifyingKey,
		signature::hazmat::{PrehashSigner, PrehashVerifier},
	},
};
use serde_bytes::ByteBuf;

use crate::{
	mock,
	nsm::NsmProvider,
	types::{NsmErrorCode, NsmRequest, NsmResponse},
};

const MODULE_ID: &str = "mocknsm_module_id";
const TIMESTAMP_MS: u64 = 1;
const CERTIFICATE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
const CA_BUNDLE_CERT: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x02];

/// Mock Nitro Secure Module endpoint that mirrors attestation request fields.
pub struct MockNsm;

impl NsmProvider for MockNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation { user_data, nonce, public_key } => {
				match attestation_doc_der(user_data, nonce, public_key) {
					Ok(document) => NsmResponse::Attestation { document },
					Err(_) => NsmResponse::Error(NsmErrorCode::InternalError),
				}
			}
			request => mock::MockNsm.nsm_process_request(request),
		}
	}

	fn timestamp_ms(&self) -> Result<u64, crate::nitro::AttestError> {
		mock::MockNsm.timestamp_ms()
	}
}

/// Builds a request-aware mock attestation document.
#[must_use]
pub fn attestation_doc(
	user_data: Option<Vec<u8>>,
	nonce: Option<Vec<u8>>,
	public_key: Option<Vec<u8>>,
) -> AttestationDoc {
	AttestationDoc {
		module_id: MODULE_ID.to_owned(),
		digest: Digest::SHA384,
		timestamp: TIMESTAMP_MS,
		pcrs: mock_pcrs(),
		certificate: ByteBuf::from(CERTIFICATE.to_vec()),
		cabundle: vec![ByteBuf::from(CA_BUNDLE_CERT.to_vec())],
		public_key: public_key.map(ByteBuf::from),
		user_data: user_data.map(ByteBuf::from),
		nonce: nonce.map(ByteBuf::from),
	}
}

/// Encodes a request-aware mock attestation document as COSE Sign1 bytes.
///
/// # Errors
///
/// Returns a COSE error if the deterministic mock document cannot be signed or
/// serialized.
pub fn attestation_doc_der(
	user_data: Option<Vec<u8>>,
	nonce: Option<Vec<u8>>,
	public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, CoseError> {
	let doc = attestation_doc(user_data, nonce, public_key);
	let private = mock_private_key();
	let cose_sign1 =
		CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &private)?;
	cose_sign1.as_bytes(true)
}

fn mock_pcrs() -> BTreeMap<usize, ByteBuf> {
	BTreeMap::from([
		(0, zero_pcr()),
		(1, zero_pcr()),
		(2, zero_pcr()),
		(3, zero_pcr()),
	])
}

fn zero_pcr() -> ByteBuf {
	ByteBuf::from(vec![0; 48])
}

fn mock_private_key() -> P384PrivateKey {
	let secret = [
		0x55, 0xc6, 0xaa, 0x81, 0x5a, 0x31, 0x74, 0x1b, 0xc3, 0x7f, 0x0f, 0xfd,
		0xde, 0xa7, 0x3a, 0xf2, 0x39, 0x7b, 0xad, 0x64, 0x08, 0x16, 0xef, 0x22,
		0xbf, 0xb6, 0x89, 0xef, 0xc1, 0xb6, 0xcc, 0x68, 0x2a, 0x73, 0xf7, 0xe5,
		0xa6, 0x57, 0x24, 0x8e, 0x3a, 0xba, 0xd5, 0x00, 0xe4, 0x6d, 0x5a, 0xfc,
	];

	P384PrivateKey(
		SecretKey::from_slice(&secret).expect("valid mock P-384 key"),
	)
}

struct P384PrivateKey(SecretKey);

impl SigningPrivateKey for P384PrivateKey {
	fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
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
		let signature_wrapped = Signature::try_from(signature)
			.map_err(|e| CoseError::SignatureError(Box::new(e)))?;
		let verifier = VerifyingKey::from(self.0.public_key());

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

//! Logic for decoding and validating the Nitro Secure Module Attestation
//! Document.

use aws_nitro_enclaves_cose::{
	crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPublicKey},
	error::CoseError,
	CoseSign1,
};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use p384::{
	ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
	PublicKey,
};
use serde_bytes::ByteBuf;

mod error;
mod syntactic_validation;

pub use error::AttestError;

pub use crate::types;

/// Signing algorithms we expect the certificates to use. Any other
/// algorithms will be considered invalid. NOTE: this list was deduced just
/// by trial and error and thus its unclear if it should include more types.
static AWS_NITRO_CERT_SIG_ALG: &[&webpki::SignatureAlgorithm] =
	&[&webpki::ECDSA_P384_SHA384];

/// AWS Nitro root CA certificate.
///
/// This should be validated against the checksum:
/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`. This
/// checksum and the certificate should be manually verified against
/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html/>.
pub const AWS_ROOT_CERT_PEM: &[u8] =
	std::include_bytes!("./static/aws_root_cert.pem");

/// Extract a DER encoded certificate from bytes representing a PEM encoded
/// certificate.
pub fn cert_from_pem(pem: &[u8]) -> Result<Vec<u8>, AttestError> {
	let (_, doc) =
		x509_cert::der::Document::from_pem(&String::from_utf8_lossy(pem))
			.map_err(|_| AttestError::PemDecodingError)?;
	Ok(doc.to_vec())
}

/// Verify that `attestation_doc` matches the specified parameters.
///
/// To learn more about the attestation document fields see:
/// <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#22-attestation-document-specification/>.
///
/// # Arguments
///
/// * `attestation_doc` - the attestation document to verify.
/// * `user_data` - expected value of the `user_data` field.
/// * `pcr0` - expected value of PCR index 0.
/// * `pcr1` - expected value of PCR index 1.
/// * `pcr2` - expected value of PCR index 3.
///
/// # Panics
///
/// Panics if any part of verification fails.
pub fn verify_attestation_doc_against_user_input(
	attestation_doc: &AttestationDoc,
	user_data: &[u8],
	pcr0: &[u8],
	pcr1: &[u8],
	pcr2: &[u8],
	pcr3: &[u8],
) -> Result<(), AttestError> {
	if user_data
		!= attestation_doc
			.user_data
			.as_ref()
			.ok_or(AttestError::MissingUserData)?
			.to_vec()
	{
		return Err(AttestError::DifferentUserData);
	}

	// nonce is none
	if attestation_doc.nonce.is_some() {
		return Err(AttestError::UnexpectedAttestationDocNonce);
	}

	if pcr0
		!= attestation_doc
			.pcrs
			.get(&0)
			.ok_or(AttestError::MissingPcr0)?
			.clone()
			.into_vec()
	{
		return Err(AttestError::DifferentPcr0);
	}

	// pcr1 matches
	if pcr1
		!= attestation_doc
			.pcrs
			.get(&1)
			.ok_or(AttestError::MissingPcr1)?
			.clone()
			.into_vec()
	{
		return Err(AttestError::DifferentPcr1);
	}

	// pcr2 matches
	if pcr2
		!= attestation_doc
			.pcrs
			.get(&2)
			.ok_or(AttestError::MissingPcr2)?
			.clone()
			.into_vec()
	{
		return Err(AttestError::DifferentPcr2);
	}

	// pcr3 matches
	if pcr3
		!= attestation_doc
			.pcrs
			.get(&3)
			.ok_or(AttestError::MissingPcr3)?
			.clone()
			.into_vec()
	{
		return Err(AttestError::DifferentPcr3);
	}

	Ok(())
}

/// Extract the DER encoded `AttestationDoc` from the nitro secure module
/// (nsm) provided COSE Sign1 structure.
///
/// WARNING: This will not perform any validation of the attestation doc and
/// should not be used directly in production; instead use
/// [`attestation_doc_from_der`].
///
/// # Arguments
///
/// * `cose_sign1_der` - the DER encoded COSE Sign1 structure containing the
///   attestation document payload.
pub fn unsafe_attestation_doc_from_der(
	cose_sign1_der: &[u8],
) -> Result<AttestationDoc, AttestError> {
	let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
		.map_err(|_| AttestError::InvalidCOSESign1Structure)?;

	let raw_attestation_doc = cose_sign1
		.get_payload::<Sha2>(None)
		.map_err(|_| AttestError::InvalidCOSESign1Structure)?;

	AttestationDoc::from_binary(&raw_attestation_doc[..]).map_err(Into::into)
}

/// Extract the DER encoded `AttestationDoc` from the nitro secure module
/// (nsm) provided COSE Sign1 structure. This function will verify the the
/// root certificate authority via the CA bundle and verify that the end
/// entity certificate signed the COSE Sign1 structure.
///
/// While this does some basic verification, it is up to the user to verify
///
/// # Arguments
///
/// * `cose_sign1_der` - the DER encoded COSE Sign1 structure containing the
///   attestation document payload.
/// * `root_cert` - the DER encoded root certificate. This should be a hardcoded
///   root certificate from amazon and its authenticity should be validated out
///   of band.
/// * `validation_time` - a moment in time that the certificates should be
///   valid. This is measured in seconds since the unix epoch. Most likely this
///   will be the current time.
pub fn attestation_doc_from_der(
	cose_sign1_der: &[u8],
	root_cert: &[u8],
	validation_time: u64, // seconds since unix epoch
) -> Result<AttestationDoc, AttestError> {
	let attestation_doc = unsafe_attestation_doc_from_der(cose_sign1_der)?;
	let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
		.map_err(|_| AttestError::InvalidCOSESign1Structure)?;

	syntactic_validation::module_id(&attestation_doc.module_id)?;
	syntactic_validation::digest(attestation_doc.digest)?;
	syntactic_validation::pcrs(&attestation_doc.pcrs)?;
	syntactic_validation::cabundle(&attestation_doc.cabundle)?;
	syntactic_validation::timestamp(attestation_doc.timestamp)?;
	syntactic_validation::public_key(&attestation_doc.public_key)?;
	syntactic_validation::user_data(&attestation_doc.user_data)?;
	syntactic_validation::nonce(&attestation_doc.nonce)?;

	verify_certificate_chain(
		&attestation_doc.cabundle,
		root_cert,
		&attestation_doc.certificate,
		validation_time,
	)?;
	verify_cose_sign1_sig(&attestation_doc.certificate, &cose_sign1)?;
	Ok(attestation_doc)
}

/// Verify the certificate chain against the root & end entity certificates.
fn verify_certificate_chain(
	cabundle: &[ByteBuf],
	root_cert: &[u8],
	end_entity_certificate: &[u8],
	validation_time: u64,
) -> Result<(), AttestError> {
	// Bundle starts with root certificate - we want to replace the root
	// with our hardcoded known certificate, so we remove the root
	// (first element). Ordering is: root cert .. intermediate certs ..
	// end entity cert.
	let intermediate_certs: Vec<_> =
		cabundle[1..].iter().map(|x| x.as_slice()).collect();

	let anchor = vec![webpki::TrustAnchor::try_from_cert_der(root_cert)?];
	let anchors = webpki::TlsServerTrustAnchors(&anchor);

	let cert = webpki::EndEntityCert::try_from(end_entity_certificate)?;
	cert.verify_is_valid_tls_server_cert(
		AWS_NITRO_CERT_SIG_ALG,
		&anchors,
		&intermediate_certs,
		webpki::Time::from_seconds_since_unix_epoch(validation_time),
	)
	.map_err(AttestError::InvalidCertChain)?;

	Ok(())
}

// Check that cose sign1 structure is signed with the key in the end
// entity certificate.
fn verify_cose_sign1_sig(
	end_entity_certificate: &[u8],
	cose_sign1: &CoseSign1,
) -> Result<(), AttestError> {
	use x509_cert::der::Decode;

	let ee_cert =
		x509_cert::certificate::Certificate::from_der(end_entity_certificate)
			.map_err(|_| AttestError::FailedToParseCert)?;

	// Expect v3
	if ee_cert.tbs_certificate.version != x509_cert::certificate::Version::V3 {
		return Err(AttestError::InvalidEndEntityCert);
	}

	let pub_key =
		ee_cert.tbs_certificate.subject_public_key_info.subject_public_key;
	let key = PublicKey::from_sec1_bytes(pub_key)
		.map_err(|_| AttestError::FailedDecodeKeyFromCert)?;
	let key_wrapped = P384PubKey(key);

	// Verify the signature against the extracted public key
	let is_valid_sig = cose_sign1
		.verify_signature::<Sha2>(&key_wrapped)
		.map_err(|_| AttestError::InvalidCOSESign1Signature)?;
	if is_valid_sig {
		Ok(())
	} else {
		Err(AttestError::InvalidCOSESign1Signature)
	}
}

struct P384PubKey(p384::PublicKey);
impl SigningPublicKey for P384PubKey {
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

		let verifier = VerifyingKey::from(self.0);
		verifier
			.verify_prehash(digest, &signature_wrapped)
			.map(|_| true)
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

#[cfg(test)]
mod test {
	use aws_nitro_enclaves_cose::{
		crypto::SigningPrivateKey, header_map::HeaderMap,
	};
	use p384::{ecdsa::SigningKey, SecretKey};

	use super::*;
	use crate::mock::{
		MOCK_NSM_ATTESTATION_DOCUMENT, MOCK_PCR0, MOCK_PCR1, MOCK_PCR2,
		MOCK_PCR3, MOCK_SECONDS_SINCE_EPOCH,
		MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT,
	};

	// Public domain work: Pride and Prejudice by Jane Austen, taken from https://www.gutenberg.org/files/1342/1342.txt
	const TEXT: &[u8] = b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife.";

	struct P384PrivateKey(p384::SecretKey);
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
			let signature_wrapped = Signature::try_from(signature)
				.map_err(|e| CoseError::SignatureError(Box::new(e)))?;

			let verifier = VerifyingKey::from(self.0.public_key());
			verifier
				.verify_prehash(digest, &signature_wrapped)
				.map(|_| true)
				.map_err(|e| CoseError::SignatureError(Box::new(e)))
		}
	}

	fn generate_p384() -> (P384PrivateKey, P384PubKey) {
		// Taken from aws-nitro-enclaves-cose tests
		let secret = hex_literal::hex!(
			"55c6aa815a31741bc37f0ffddea73af2397bad640816ef22bfb689efc1b6cc68
		2a73f7e5a657248e3abad500e46d5afc"
		);
		let private = p384::SecretKey::from_be_bytes(&secret).unwrap();
		let public = private.public_key();

		(P384PrivateKey(private), P384PubKey(public))
	}

	#[test]
	fn cose_sign1_ec384_validate() {
		let (_, ec_public) = generate_p384();

		// Taken from aws-nitro-enclaves-cose tests
		let cose_doc = CoseSign1::from_bytes(&[
			0x84, /* Protected: {1: -35} */
			0x44, 0xA1, 0x01, 0x38, 0x22, /* Unprotected: {4: '11'} */
			0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
			0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
			0x72, 0x75, 0x74, 0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72,
			0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20, 0x61, 0x63, 0x6B, 0x6E, 0x6F,
			0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20, 0x74, 0x68,
			0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65,
			0x20, 0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73,
			0x73, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20,
			0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20, 0x66, 0x6F, 0x72, 0x74,
			0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20, 0x62,
			0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F,
			0x66, 0x20, 0x61, 0x20, 0x77, 0x69, 0x66, 0x65,
			0x2E, /* signature - length 48 x 2 */
			0x58, 0x60, /* R: */
			0xCD, 0x42, 0xD2, 0x76, 0x32, 0xD5, 0x41, 0x4E, 0x4B, 0x54, 0x5C,
			0x95, 0xFD, 0xE6, 0xE3, 0x50, 0x5B, 0x93, 0x58, 0x0F, 0x4B, 0x77,
			0x31, 0xD1, 0x4A, 0x86, 0x52, 0x31, 0x75, 0x26, 0x6C, 0xDE, 0xB2,
			0x4A, 0xFF, 0x2D, 0xE3, 0x36, 0x4E, 0x9C, 0xEE, 0xE9, 0xF9, 0xF7,
			0x95, 0xA0, 0x15, 0x15, /* S: */
			0x5B, 0xC7, 0x12, 0xAA, 0x28, 0x63, 0xE2, 0xAA, 0xF6, 0x07, 0x8A,
			0x81, 0x90, 0x93, 0xFD, 0xFC, 0x70, 0x59, 0xA3, 0xF1, 0x46, 0x7F,
			0x64, 0xEC, 0x7E, 0x22, 0x1F, 0xD1, 0x63, 0xD8, 0x0B, 0x3B, 0x55,
			0x26, 0x25, 0xCF, 0x37, 0x9D, 0x1C, 0xBB, 0x9E, 0x51, 0x38, 0xCC,
			0xD0, 0x7A, 0x19, 0x31,
		])
		.unwrap();

		// Accepts valid key
		assert!(cose_doc.verify_signature::<Sha2>(&ec_public).is_ok());
		assert_eq!(
			cose_doc.get_payload::<Sha2>(Some(&ec_public)).unwrap(),
			TEXT
		);

		// Rejects incorrect key
		let random_private = SecretKey::random(rand::rngs::OsRng);
		let random_public = random_private.public_key();

		assert!(cose_doc
			.verify_signature::<Sha2>(&P384PubKey(random_public))
			.is_err());

		assert!(cose_doc
			.get_payload::<Sha2>(Some(&P384PubKey(random_public)))
			.is_err());
	}

	#[test]
	fn attestation_doc_from_der_works_with_valid_payload() {
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		assert!(attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.is_ok());
	}

	#[test]
	fn attestation_doc_from_der_time_is_late() {
		let day_after = MOCK_SECONDS_SINCE_EPOCH + 86400;
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		let err_result = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			day_after,
		);

		match err_result {
			Err(AttestError::InvalidCertChain(webpki::Error::CertExpired)) => {}
			_ => panic!("{err_result:?}"),
		};
	}

	#[test]
	fn attestation_doc_from_der_time_is_early() {
		let day_before = MOCK_SECONDS_SINCE_EPOCH - 86400;
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		let err_result = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			day_before,
		);

		match err_result {
			Err(AttestError::InvalidCertChain(
				webpki::Error::CertNotValidYet,
			)) => {}
			_ => panic!("{err_result:?}"),
		};
	}

	#[test]
	fn attestation_doc_from_der_corrupt_cabundle() {
		let (private, _) = generate_p384();
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		let attestation_doc = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.unwrap();

		{
			let mut corrupt = attestation_doc.clone();
			// Remove the end entity cert
			corrupt.cabundle.pop();

			let corrupt_cose_sign1 = CoseSign1::new::<Sha2>(
				&corrupt.to_binary(),
				&HeaderMap::new(),
				&private,
			)
			.unwrap();

			let corrupt_document1 = corrupt_cose_sign1.as_bytes(true).unwrap();
			let err_result = attestation_doc_from_der(
				&corrupt_document1,
				&root_cert[..],
				MOCK_SECONDS_SINCE_EPOCH,
			);

			match err_result {
				Err(AttestError::InvalidCertChain(
					webpki::Error::UnknownIssuer,
				)) => {}
				_ => panic!("{err_result:?}"),
			};
		}

		{
			let mut corrupt = attestation_doc.clone();
			// Remove the root certificate, causing the verification flow to
			// think the 2nd intermediate cert is the 1st
			corrupt.cabundle.remove(0);

			let corrupt_cose_sign1 = CoseSign1::new::<Sha2>(
				&corrupt.to_binary(),
				&HeaderMap::new(),
				&private,
			)
			.unwrap();

			let corrupt_document1 = corrupt_cose_sign1.as_bytes(true).unwrap();
			let err_result = attestation_doc_from_der(
				&corrupt_document1,
				&root_cert[..],
				MOCK_SECONDS_SINCE_EPOCH,
			);

			match err_result {
				Err(AttestError::InvalidCertChain(
					webpki::Error::UnknownIssuer,
				)) => {}
				_ => panic!("{err_result:?}"),
			};
		}

		{
			let valid = attestation_doc;
			// Don't pop anything, just want to sanity check that we get a
			// corrupt signature on the cose sign1 structure.

			let corrupt_cose_sign1 = CoseSign1::new::<Sha2>(
				&valid.to_binary(),
				&HeaderMap::new(),
				&private,
			)
			.unwrap();

			let corrupt_document1 = corrupt_cose_sign1.as_bytes(true).unwrap();
			let err_result = attestation_doc_from_der(
				&corrupt_document1,
				&root_cert[..],
				MOCK_SECONDS_SINCE_EPOCH,
			);

			match err_result {
				Err(AttestError::InvalidCOSESign1Signature) => {}
				_ => panic!("{err_result:?}"),
			};
		}
	}

	#[test]
	fn attestation_doc_from_der_corrupt_end_entity_certificate() {
		let (private, _) = generate_p384();
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		let mut attestation_doc = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.unwrap();

		// Corrupt the end entity certificate
		attestation_doc.certificate.pop();
		attestation_doc.certificate.push(0xff);

		let corrupt_cose_sign1 = CoseSign1::new::<Sha2>(
			&attestation_doc.to_binary(),
			&HeaderMap::new(),
			&private,
		)
		.unwrap();

		let corrupt_document1 = corrupt_cose_sign1.as_bytes(true).unwrap();
		let err_result = attestation_doc_from_der(
			&corrupt_document1,
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		);

		match err_result {
			Err(AttestError::InvalidCertChain(
				webpki::Error::UnknownIssuer,
			)) => {}
			_ => panic!("{err_result:?}"),
		};
	}

	#[test]
	fn attestation_doc_from_der_bad_sign1_sig() {
		let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();
		let (private, _) = generate_p384();
		let document =
			CoseSign1::from_bytes(MOCK_NSM_ATTESTATION_DOCUMENT).unwrap();

		let unprotected = document.get_unprotected();
		let (_protected, payload) =
			document.get_protected_and_payload::<Sha2>(None).unwrap();

		// Sign the document with a private key that isn't in the end entity
		// certificate

		let corrupt_document =
			CoseSign1::new::<Sha2>(&payload, unprotected, &private).unwrap();
		let err_result = attestation_doc_from_der(
			&corrupt_document.as_bytes(true).unwrap(),
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		);

		match err_result {
			Err(AttestError::InvalidCOSESign1Signature) => {}
			_ => panic!("{err_result:?}"),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_works() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();
		// Accepts valid inputs
		assert!(verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.is_ok());
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_invalid_user_data() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&[255; 32],
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.unwrap_err();

		match err {
			AttestError::DifferentUserData => (),
			_ => panic!(),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_some_nonce() {
		let mut attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		// Set the nonce to Some
		attestation_doc.nonce = Some(ByteBuf::default());

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.unwrap_err();

		match err {
			AttestError::UnexpectedAttestationDocNonce => (),
			_ => panic!(),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_invalid_pcr0() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&[255; 48],
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.unwrap_err();

		match err {
			AttestError::DifferentPcr0 => (),
			_ => panic!(),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_invalid_pcr1() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&[255; 48],
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.unwrap_err();

		match err {
			AttestError::DifferentPcr1 => (),
			_ => panic!(),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_invalid_pcr2() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&[255; 48],
			&qos_hex::decode(MOCK_PCR3).unwrap(),
		)
		.unwrap_err();

		match err {
			AttestError::DifferentPcr2 => (),
			_ => panic!(),
		}
	}

	#[test]
	fn verify_attestation_doc_against_user_input_panics_invalid_pcr3() {
		let attestation_doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();

		let err = verify_attestation_doc_against_user_input(
			&attestation_doc,
			&qos_hex::decode(MOCK_USER_DATA_NSM_ATTESTATION_DOCUMENT).unwrap(),
			&qos_hex::decode(MOCK_PCR0).unwrap(),
			&qos_hex::decode(MOCK_PCR1).unwrap(),
			&qos_hex::decode(MOCK_PCR2).unwrap(),
			&[255; 48],
		)
		.unwrap_err();

		match err {
			AttestError::DifferentPcr3 => (),
			_ => panic!(),
		}
	}

	// #[test]
	// fn attestation_doc_from_der_corrupt_root_certificate() {
	// 	let root_cert =
	// 		openssl::x509::X509::from_pem(AWS_ROOT_CERT_PEM).unwrap();

	// 	// Build a root certificate with no extensions;
	// 	let mut builder = openssl::x509::X509Builder::new().unwrap();
	// 	builder.set_subject_name(root_cert.subject_name()).unwrap();
	// 	builder.set_not_before(root_cert.not_before()).unwrap();
	// 	builder.set_not_after(root_cert.not_after()).unwrap();
	// 	builder.set_version(root_cert.version()).unwrap();
	// 	builder.set_serial_number(root_cert.serial_number()).unwrap();
	// 	builder.set_issuer_name(root_cert.issuer_name()).unwrap();
	// 	builder.set_subject_name(root_cert.subject_name()).unwrap();
	// 	builder.set_pubkey(&root_cert.public_key().unwrap()).unwrap();

	// 	let corrupt_root_cert = builder.build().to_der().unwrap();
	// 	let err_result = attestation_doc_from_der(
	// 		MOCK_NSM_ATTESTATION_DOCUMENT,
	// 		&corrupt_root_cert[..],
	// 		MOCK_SECONDS_SINCE_EPOCH,
	// 	);

	// 	match err_result {
	// 		Err(AttestError::WebPki(
	// 			webpki::Error::MissingOrMalformedExtensions,
	// 		)) => {}
	// 		_ => panic!("{:?}", err_result),
	// 	}
	// }
}

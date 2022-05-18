//! Attestation verification logic

#[derive(Debug)]
pub enum AttestError {
	WebPki(webpki::Error),
	InvalidCertChain(webpki::Error),
	OpenSSLError(openssl::error::ErrorStack),

	Nsm(aws_nitro_enclaves_nsm_api::api::Error),
	InvalidEndEntityCert,
	InvalidCOSESign1Signature,
	InvalidCOSESign1Structure,
	InvalidDigest,
	InvalidModuleId,
	InvalidPcr,
	InvalidCABundle,
	InvalidTimeStamp,
	InvalidPubKey,
	InvalidBytes,
}

impl From<webpki::Error> for AttestError {
	fn from(e: webpki::Error) -> Self {
		Self::WebPki(e)
	}
}

impl From<openssl::error::ErrorStack> for AttestError {
	fn from(_: openssl::error::ErrorStack) -> Self {
		Self::OpenSSLError(openssl::error::ErrorStack::get())
	}
}

impl From<aws_nitro_enclaves_nsm_api::api::Error> for AttestError {
	fn from(e: aws_nitro_enclaves_nsm_api::api::Error) -> Self {
		Self::Nsm(e)
	}
}

pub mod nitro {
	use aws_nitro_enclaves_cose::CoseSign1;
	use aws_nitro_enclaves_nsm_api::api::AttestationDoc;

	use super::AttestError;

	/// Signing algorithms we expect the certificates to use. Any other
	/// algorithms will be considered invalid. NOTE: this list was deduced just
	/// by trial and error and thus its unclear if it should include more types.
	static AWS_NITRO_CERT_SIG_ALG: &[&webpki::SignatureAlgorithm] =
		&[&webpki::ECDSA_P384_SHA384];

	/// Corresponds to `MockNsm` attestation document response. This time is
	/// valid for the mock and should only be used for testing.
	pub(crate) const MOCK_SECONDS_SINCE_EPOCH: u64 = 1652756400;

	/// AWS Nitro root CA certificate.
	/// This should be validated against the below checksum:
	/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`
	pub(crate) const AWS_ROOT_CERT: &'static [u8] =
		std::include_bytes!("./aws_root_cert.pem");

	/// Extract a DER encoded certificate from bytes representing a PEM encoded
	/// certificate.
	pub(crate) fn cert_from_pem(pem: &[u8]) -> Result<Vec<u8>, AttestError> {
		Ok(openssl::x509::X509::from_pem(pem)?.to_der()?)
	}

	/// Extract the DER encoded `AttestationDoc` from the nsm provided
	/// attestation document. This function will verify the the root certificate
	/// authority via the CA bundle and that verify "target" (aka "end entity")
	/// certificate signed the COSE Sign1 message.
	///
	/// # Arguments
	///
	/// * `bytes` - the DER encoded COSE Sign1 structure containing the
	///   attestation document.
	/// * `root_cert` - the DER encoded root certificate. This should be a
	///   hardcoded root certificate from amazon and its authenticity should be
	///   validated out of band.
	/// * `validation_time` - a moment in time that the certificates should be
	///   valid. This is measured in seconds since the unix epoch. Most likely
	///   this will be the current time.
	pub fn attestation_doc_from_der(
		bytes: &[u8],
		root_cert: &[u8],
		validation_time: u64, // seconds since unix epoch
	) -> Result<AttestationDoc, AttestError> {
		let cose_sign1 = CoseSign1::from_bytes(&bytes[..])
			.map_err(|_| AttestError::InvalidCOSESign1Structure)?;
		let attestation_doc = {
			let raw_attestation_doc = cose_sign1
				.get_payload(None)
				.map_err(|_| AttestError::InvalidCOSESign1Structure)?;

			AttestationDoc::from_binary(&raw_attestation_doc[..])?
		};

		// Syntactical validation

		syntactic_validation::module_id(&attestation_doc.module_id)?;
		syntactic_validation::digest(attestation_doc.digest)?;
		syntactic_validation::pcrs(&attestation_doc.pcrs)?;
		syntactic_validation::cabundle(&attestation_doc.cabundle)?;
		syntactic_validation::timestamp(attestation_doc.timestamp)?;
		syntactic_validation::public_key(&attestation_doc.public_key)?;
		syntactic_validation::user_data(&attestation_doc.user_data)?;
		syntactic_validation::nonce(&attestation_doc.nonce)?;

		// Semantic validation

		// CA bundle verification, in other words verify certificate chain with
		// the root certificate
		{
			// Bundle starts with root certificate - we want to replace the root
			// with our hardcoded known certificate, so we remove the root
			// (first element). Ordering is: root cert .. intermediate certs ..
			// end entity cert.
			let intermediate_certs: Vec<_> = attestation_doc.cabundle[1..]
				.into_iter()
				.map(|x| x.as_slice())
				.collect();

			// The root CA
			let anchors =
				vec![webpki::TrustAnchor::try_from_cert_der(root_cert)?];
			let anchors = webpki::TlsServerTrustAnchors(&anchors);

			let time =
				webpki::Time::from_seconds_since_unix_epoch(validation_time);

			let cert_raw: &[u8] = attestation_doc.certificate.as_ref();
			let cert = webpki::EndEntityCert::try_from(cert_raw)?;

			// TODO: double check this is the correct verification
			cert.verify_is_valid_tls_server_cert(
				AWS_NITRO_CERT_SIG_ALG,
				&anchors,
				&intermediate_certs,
				time,
			)
			.map_err(|e| AttestError::InvalidCertChain(e))?;
		}

		// Check that cose sign1 structure is signed with the key in the end
		// entity certificate.
		{
			let ee_cert =
				openssl::x509::X509::from_der(&attestation_doc.certificate)?;

			// Expect v3 (0 corresponds to v1 etc.)
			if ee_cert.version() != 2 {
				return Err(AttestError::InvalidEndEntityCert);
			}

			let ee_cert_pub_key = ee_cert.public_key()?;

			// Verify the signature against the extracted public key
			if !cose_sign1
				.verify_signature(&ee_cert_pub_key)
				.map_err(|_| AttestError::InvalidCOSESign1Signature)?
			{
				return Err(AttestError::InvalidCOSESign1Signature);
			}
		}

		Ok(attestation_doc)
	}

	mod syntactic_validation {
		use std::collections::BTreeMap;

		use aws_nitro_enclaves_nsm_api::api::Digest;
		use serde_bytes::ByteBuf;

		use super::*;

		/// Mandatory field
		pub(super) fn module_id(id: &String) -> Result<(), AttestError> {
			if id.len() < 1 {
				Err(AttestError::InvalidModuleId)
			} else {
				Ok(())
			}
		}
		/// Mandatory field
		pub(super) fn pcrs(
			pcrs: &BTreeMap<usize, ByteBuf>,
		) -> Result<(), AttestError> {
			let is_valid_pcr_count = pcrs.len() > 0 && pcrs.len() <= 32;

			let is_valid_index_and_len = pcrs.iter().all(|(idx, pcr)| {
				let is_valid_idx = *idx <= 32;
				let is_valid_pcr_len = [32, 48, 64].contains(&pcr.len());
				is_valid_idx && is_valid_pcr_len
			});

			if !is_valid_index_and_len || !is_valid_pcr_count {
				Err(AttestError::InvalidPcr)
			} else {
				Ok(())
			}
		}
		/// Mandatory field
		pub(super) fn cabundle(
			cabundle: &Vec<ByteBuf>,
		) -> Result<(), AttestError> {
			let is_valid_len = cabundle.len() > 0;
			let is_valid_entries = cabundle
				.iter()
				.all(|cert| cert.len() >= 1 || cert.len() <= 1024);

			if !is_valid_len || !is_valid_entries {
				Err(AttestError::InvalidCABundle)
			} else {
				Ok(())
			}
		}
		/// Mandatory field
		pub(super) fn digest(d: Digest) -> Result<(), AttestError> {
			if d != Digest::SHA384 {
				Err(AttestError::InvalidDigest)
			} else {
				Ok(())
			}
		}
		/// Mandatory field
		pub(super) fn timestamp(t: u64) -> Result<(), AttestError> {
			if t == 0 {
				Err(AttestError::InvalidTimeStamp)
			} else {
				Ok(())
			}
		}
		/// Optional field
		pub(super) fn public_key(
			pub_key: &Option<ByteBuf>,
		) -> Result<(), AttestError> {
			if let Some(key) = pub_key {
				(key.len() >= 1 && key.len() <= 1024)
					.then(|| ())
					.ok_or(AttestError::InvalidPubKey)?
			}

			Ok(())
		}
		/// Optional field
		pub(super) fn user_data(
			data: &Option<ByteBuf>,
		) -> Result<(), AttestError> {
			bytes_512(data)
		}
		/// Optional field
		pub(super) fn nonce(n: &Option<ByteBuf>) -> Result<(), AttestError> {
			bytes_512(n)
		}

		fn bytes_512(val: &Option<ByteBuf>) -> Result<(), AttestError> {
			if let Some(val) = val {
				(val.len() <= 512)
					.then(|| ())
					.ok_or(AttestError::InvalidBytes)?
			}

			Ok(())
		}
	}

	#[cfg(test)]
	mod test {
		use aws_nitro_enclaves_cose::header_map::HeaderMap;
		use openssl::pkey::{PKey, Private, Public};
		use qos_core::protocol::MOCK_NSM_ATTESTATION_DOCUMENT;

		use super::{AttestError, *};

		/// Taken from aws-nitro-enclaves-cose-0.4.0
		/// Randomly generate SECP521R1/P-512 key to use for validating signing
		/// internally
		fn generate_ec512_test_key() -> (PKey<Private>, PKey<Public>) {
			let alg = openssl::ec::EcGroup::from_curve_name(
				openssl::nid::Nid::SECP521R1,
			)
			.unwrap();
			let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
			let ec_public = openssl::ec::EcKey::from_public_key(
				&alg,
				ec_private.public_key(),
			)
			.unwrap();
			(
				PKey::from_ec_key(ec_private).unwrap(),
				PKey::from_ec_key(ec_public).unwrap(),
			)
		}

		#[test]
		fn attestation_doc_from_der_time_is_late() {
			let day_after = MOCK_SECONDS_SINCE_EPOCH + 86400;
			let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
			let err_result = attestation_doc_from_der(
				MOCK_NSM_ATTESTATION_DOCUMENT,
				&root_cert[..],
				day_after,
			);

			match err_result {
				Err(AttestError::InvalidCertChain(
					webpki::Error::CertExpired,
				)) => {}
				_ => panic!("{:?}", err_result),
			};
		}

		#[test]
		fn attestation_doc_from_der_time_is_early() {
			let day_before = MOCK_SECONDS_SINCE_EPOCH - 86400;
			let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
			let err_result = attestation_doc_from_der(
				MOCK_NSM_ATTESTATION_DOCUMENT,
				&root_cert[..],
				day_before,
			);

			match err_result {
				Err(AttestError::InvalidCertChain(
					webpki::Error::CertNotValidYet,
				)) => {}
				_ => panic!("{:?}", err_result),
			};
		}

		#[test]
		fn attestation_doc_from_der_corrupt_cabundle() {
			let (private, _) = generate_ec512_test_key();
			let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
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

				let corrupt_cose_sign1 = CoseSign1::new(
					&corrupt.to_binary(),
					&HeaderMap::new(),
					&private,
				)
				.unwrap();

				let corrupt_document1 =
					corrupt_cose_sign1.as_bytes(true).unwrap();
				let err_result = attestation_doc_from_der(
					&corrupt_document1,
					&root_cert[..],
					MOCK_SECONDS_SINCE_EPOCH,
				);

				match err_result {
					Err(AttestError::InvalidCertChain(
						webpki::Error::UnknownIssuer,
					)) => {}
					_ => panic!("{:?}", err_result),
				};
			}

			{
				let mut corrupt = attestation_doc.clone();
				// Remove the root certificate, causing the verification flow to
				// think the 2nd intermediate cert is the 1st
				corrupt.cabundle.remove(0);

				let corrupt_cose_sign1 = CoseSign1::new(
					&corrupt.to_binary(),
					&HeaderMap::new(),
					&private,
				)
				.unwrap();

				let corrupt_document1 =
					corrupt_cose_sign1.as_bytes(true).unwrap();
				let err_result = attestation_doc_from_der(
					&corrupt_document1,
					&root_cert[..],
					MOCK_SECONDS_SINCE_EPOCH,
				);

				match err_result {
					Err(AttestError::InvalidCertChain(
						webpki::Error::UnknownIssuer,
					)) => {}
					_ => panic!("{:?}", err_result),
				};
			}

			{
				let valid = attestation_doc.clone();
				// Don't pop anything, just want to sanity check that we get a
				// corrupt signature on the cose sign1 structure.

				let corrupt_cose_sign1 = CoseSign1::new(
					&valid.to_binary(),
					&HeaderMap::new(),
					&private,
				)
				.unwrap();

				let corrupt_document1 =
					corrupt_cose_sign1.as_bytes(true).unwrap();
				let err_result = attestation_doc_from_der(
					&corrupt_document1,
					&root_cert[..],
					MOCK_SECONDS_SINCE_EPOCH,
				);

				match err_result {
					Err(AttestError::InvalidCOSESign1Signature) => {}
					_ => panic!("{:?}", err_result),
				};
			}
		}

		#[test]
		// fn attestation_doc_from_der_corrupt_end_entity_certificate() {
		// 	let (private, _) = generate_ec512_test_key();
		// 	let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
		// 	let attestation_doc = attestation_doc_from_der(
		// 		MOCK_NSM_ATTESTATION_DOCUMENT,
		// 		&root_cert[..],
		// 		MOCK_SECONDS_SINCE_EPOCH,
		// 	)
		// 	.unwrap();

		// 	let (r, mut cert) = x509_parser::parse_x509_certificate(
		// 		&attestation_doc.certificate,
		// 	)
		// 	.unwrap();
		// 	assert_eq!(r.len(), 0);

		// 	let mut corrupt_pub_key = cert
		// 		.tbs_certificate
		// 		.subject_pki
		// 		.subject_public_key
		// 		.data
		// 		.to_vec();

		// 	// Modify the pubkey by swapping out some random bytes.
		// 	corrupt_pub_key.pop();
		// 	corrupt_pub_key.push(0xff);
		// 	cert.tbs_certificate.subject_pki.subject_public_key.data =
		// 		&corrupt_pub_key;

		// 	// attestation_doc.certificate = cert.
		// }
		#[test]
		fn attestation_doc_from_der_bad_sign1_sig() {}

		#[test]
		fn attestation_doc_from_der_corrupt_root_certificate() {}
	}
}

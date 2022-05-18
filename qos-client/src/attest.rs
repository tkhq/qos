//! Attestation verification logic

#[derive(Debug)]
pub enum AttestError {
	InvalidCertChain,
	WebPki(webpki::Error),
	OpenSSLError(openssl::error::ErrorStack),
	InvalidPem,
	PEMError(x509_parser::prelude::PEMError),
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

impl From<x509_parser::prelude::PEMError> for AttestError {
	fn from(e: x509_parser::prelude::PEMError) -> Self {
		Self::PEMError(e)
	}
}

pub mod nitro {
	use aws_nitro_enclaves_cose::CoseSign1;
	use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
	use openssl::{
		bn::BigNumContext,
		ec::{EcGroup, EcKey, EcPoint},
		nid::Nid,
	};
	use x509_parser::pem::Pem;

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
		let mut pem_iter = Pem::iter_from_buffer(pem);
		let root_cert = pem_iter.next().ok_or(AttestError::InvalidPem)??;
		// Ensure there is only one cert in the given PEM
		pem_iter.next().is_none().then(|| ()).ok_or(AttestError::InvalidPem)?;

		Ok(root_cert.contents)
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
	/// TODO: convert expects into Errors - this shouldn't panic
	pub fn attestation_doc_from_der(
		bytes: Vec<u8>,
		root_cert: &[u8],
		validation_time: u64, // seconds since unix epoch
	) -> Result<AttestationDoc, AttestError> {
		let cose_sign1 = CoseSign1::from_bytes(&bytes[..]).unwrap();
		let raw_attestation_doc = cose_sign1.get_payload(None).unwrap();
		let attestation_doc =
			AttestationDoc::from_binary(&raw_attestation_doc[..])
				.expect("Attestation doc could not be decoded.");

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
			// (first element)
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
			.map_err(|_| AttestError::InvalidCertChain)?;
		}

		// Check that cose sign1 structure is signed with the key in the end
		// entity certificate.
		{
			let (remaining_input, certificate) =
				x509_parser::parse_x509_certificate(
					&attestation_doc.certificate,
				)
				.expect("Could not parse target certificate");

			// Basic checks
			assert!(
				remaining_input.len() == 0,
				"certificate was not valid DER encoding"
			);
			assert!(
				certificate.tbs_certificate.version()
					== x509_parser::x509::X509Version::V3,
				"Wrong certificate version"
			);

			// Get the public key the cose sign1 object was signed with
			// https://github.com/briansmith/webpki/issues/85
			let extracted_key = {
				let pub_key = certificate
					.tbs_certificate
					.subject_pki
					.subject_public_key
					.data;

				let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
				let mut ctx = BigNumContext::new().unwrap();
				let point =
					EcPoint::from_bytes(&group, &pub_key, &mut ctx).unwrap();
				let ec_key = EcKey::from_public_key(&group, &point).unwrap();

				openssl::pkey::PKey::try_from(ec_key).expect(
					"EC Key could not be converted to open ssl primitive",
				)
			};

			// Verify the signature against the extracted public key
			assert!(
				cose_sign1
					.verify_signature(&extracted_key)
					.expect("Error with cose signature verification."),
				"Could not verify attestation document with target certificate"
			);
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
				let is_valid_idx = *idx > 0 && *idx <= 32;
				let is_valid_pcr_len = [32, 48, 64].contains(&pcr.len());
				!is_valid_idx || !is_valid_pcr_len
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
			let is_valid_entries =
				cabundle.iter().all(|cert| cert.len() < 1 || cert.len() > 1024);

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
}

#[cfg(test)]
mod test {
	mod nitro {
		#[test]
		fn attestation_doc_from_der_time_is_late() {}

		#[test]
		fn attestation_doc_from_der_time_is_early() {}

		#[test]
		fn attestation_doc_from_der_corrupt_cabundle() {}

		#[test]
		fn attestation_doc_from_der_corrupt_target_certificate() {}

		#[test]
		fn attestation_doc_from_der_bad_sign1_sig() {}

		#[test]
		fn attestation_doc_from_der_corrupt_root_certificate() {}
	}
}

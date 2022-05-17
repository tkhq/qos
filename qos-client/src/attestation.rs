//! Attestation verification logic

#[derive(Debug)]
pub enum AttestationError {}

pub mod nitro {
	use aws_nitro_enclaves_cose::CoseSign1;
	use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
	use openssl::{
		bn::BigNumContext,
		ec::{EcGroup, EcKey, EcPoint},
		nid::Nid,
	};
	use x509_parser::pem::Pem;

	use super::AttestationError;

	// TODO: find out the exact algo we need and just use that
	static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
		// &webpki::ECDSA_P256_SHA256,
		// &webpki::ECDSA_P256_SHA384,
		// &webpki::ECDSA_P384_SHA256,
		&webpki::ECDSA_P384_SHA384,
		// &webpki::ED25519,
		// #[cfg(feature = "alloc")]
		// &webpki::RSA_PKCS1_2048_8192_SHA256,
		// #[cfg(feature = "alloc")]
		// &webpki::RSA_PKCS1_2048_8192_SHA384,
		// #[cfg(feature = "alloc")]
		// &webpki::RSA_PKCS1_2048_8192_SHA512,
		// #[cfg(feature = "alloc")]
		// &webpki::RSA_PKCS1_3072_8192_SHA384,
	];

	// Corresponds to `MockNsm` attestation document response
	pub(crate) const MOCK_SECONDS_SINCE_EPOCH: u64 = 1652756400;

	// aws root cert checksum:
	// 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
	pub(crate) const AWS_ROOT_CERT: &'static [u8] =
		std::include_bytes!("./aws_root_cert.pem");

	pub(crate) fn root_cert_from_pem(pem: &[u8]) -> Vec<u8> {
		let mut pem_iter = Pem::iter_from_buffer(pem);
		let root_cert = pem_iter
			.next()
			.expect("Hardcoded aws root cert should be valid PEM")
			.expect("Hardcoded aws root cert should be valid PEM");
		assert!(
			pem_iter.next().is_none(),
			"More then 1 cert detected in hardcoded aws root"
		);

		root_cert.contents
	}

	/// Extract the DER encoded `AttestationDoc` from the nsm provided
	/// attestation document. This function will verify the the root certificate
	/// authority via the CA bundle and that verify "target" (aka "end entity")
	/// certificate signed the COSE Sign1 message.
	pub fn attestation_doc_from_der(
		bytes: Vec<u8>,
		root_cert: &[u8],
		validation_time: u64, // seconds since unix epoch
	) -> Result<AttestationDoc, AttestationError> {
		let cose_sign1 = CoseSign1::from_bytes(&bytes[..]).unwrap();
		let raw_attestation_doc = cose_sign1.get_payload(None).unwrap();
		let attestation_doc =
			AttestationDoc::from_binary(&raw_attestation_doc[..])
				.expect("Attestation doc could not be decoded.");

		// TODO: [now] basic syntactical validation as per nsm api docs

		// CA bundle verification aka verify certificate chain with the root certificate
		{
			// Bundle starts with root certificate - we want to replace the root
			// with our hardcoded known certificate, so we remove the root
			// (first element)
			let intermediate_certs: Vec<_> = attestation_doc.cabundle[1..]
				.into_iter()
				.map(|x| x.as_slice())
				.collect();

			let anchor = webpki::TrustAnchor::try_from_cert_der(root_cert)
				.expect("Could not decode DER cabundle root");
			let anchors = vec![anchor];
			let anchors = webpki::TlsServerTrustAnchors(&anchors);

			// let second_since_epoch = std::time::SystemTime::now()
			// 	.duration_since(std::time::SystemTime::UNIX_EPOCH)
			// 	.unwrap().as_secs()

			let time =
				webpki::Time::from_seconds_since_unix_epoch(validation_time);

			let ee_raw: &[u8] = attestation_doc.certificate.as_ref();
			let cert = webpki::EndEntityCert::try_from(ee_raw)
				.expect("Could not decode target cert");

			cert.verify_is_valid_tls_server_cert(
				ALL_SIGALGS,
				&anchors,
				&intermediate_certs,
				time,
			)
			.expect("Invalid CA bundle");
		}

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
		/// Mandatory field
		fn module_id() {
			todo!()
		}
		/// Mandatory field
		fn pcrs() {
			todo!()
		}
		/// Mandatory field
		fn cabundle() {
			todo!()
		}
		/// Mandatory field
		fn digest() {
			todo!()
		}
		/// Mandatory field
		fn timestamp() {
			todo!()
		}
		/// Optional field
		fn public_key() {
			todo!()
		}
		/// Optional field
		fn user_data() {
			todo!()
		}
		/// Optional field
		fn nonce() {
			todo!()
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

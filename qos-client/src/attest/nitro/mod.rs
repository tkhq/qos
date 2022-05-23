//! Logic for decoding and validating the Nitro Secure Module Attestation
//! Document.

use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use serde_bytes::ByteBuf;

use super::AttestError;

mod syntactic_validation;

/// Version 3 for the X509 certificate format (0 corresponds to v1 etc.)
const X509_V3: i32 = 2;

/// Signing algorithms we expect the certificates to use. Any other
/// algorithms will be considered invalid. NOTE: this list was deduced just
/// by trial and error and thus its unclear if it should include more types.
static AWS_NITRO_CERT_SIG_ALG: &[&webpki::SignatureAlgorithm] =
	&[&webpki::ECDSA_P384_SHA384];

/// Corresponds to `MockNsm` attestation document response. This time is
/// valid for the mock and should only be used for testing.
pub(crate) const MOCK_SECONDS_SINCE_EPOCH: u64 = 1652756400;

/// AWS Nitro root CA certificate.
///
/// This should be validated against the checksum:
/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`. This
/// checksum and the certificate should be manually verified against
/// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html.
pub(crate) const AWS_ROOT_CERT: &'static [u8] =
	std::include_bytes!("./static/aws_root_cert.pem");

/// Extract a DER encoded certificate from bytes representing a PEM encoded
/// certificate.
pub(crate) fn cert_from_pem(pem: &[u8]) -> Result<Vec<u8>, AttestError> {
	Ok(openssl::x509::X509::from_pem(pem)?.to_der()?)
}

/// Extract the DER encoded `AttestationDoc` from the nitro secure module
/// (nsm) provided COSE Sign1 structure. This function will verify the the
/// root certificate authority via the CA bundle and verify that the end
/// entity certificate signed the COSE Sign1 structure.
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
	let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
		.map_err(|_| AttestError::InvalidCOSESign1Structure)?;
	let attestation_doc = {
		let raw_attestation_doc = cose_sign1
			.get_payload(None)
			.map_err(|_| AttestError::InvalidCOSESign1Structure)?;

		AttestationDoc::from_binary(&raw_attestation_doc[..])?
	};

	syntactic_validation::module_id(&attestation_doc.module_id)?;
	syntactic_validation::digest(attestation_doc.digest)?;
	syntactic_validation::pcrs(&attestation_doc.pcrs)?;
	syntactic_validation::cabundle(&attestation_doc.cabundle)?;
	syntactic_validation::timestamp(attestation_doc.timestamp)?;
	syntactic_validation::public_key(&attestation_doc.public_key)?;
	syntactic_validation::user_data(&attestation_doc.user_data)?;
	syntactic_validation::nonce(&attestation_doc.nonce)?;

	// TODO: Ensure verification conforms exactly to section 3.2.3.*
	// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#32-syntactical-validation
	verify_certificate_chain(
		&attestation_doc.cabundle,
		root_cert,
		&attestation_doc.certificate,
		validation_time,
	)?;
	verify_cose_sign1_sig(&attestation_doc.certificate, &cose_sign1)?;

	aws_spec_verify_cert_chain_x509_parse(
		&attestation_doc.cabundle,
		root_cert,
		&attestation_doc.certificate,
		validation_time,
	)?;

	aws_spec_verify_certs_only_openssl(
		&attestation_doc.cabundle,
		root_cert,
		&attestation_doc.certificate,
		validation_time,
	)?;

	// TODO:
	// Additional validation for
	// - timestamp is reasonable
	// - nonce, user data, public key match user provided data
	// - module id is what we expect
	// - pcr validation

	Ok(attestation_doc)
}

/// Verify the certificate chain against the root & end entity certificates.
fn verify_certificate_chain(
	cabundle: &Vec<ByteBuf>,
	root_cert: &[u8],
	end_entity_certificate: &[u8],
	validation_time: u64,
) -> Result<(), AttestError> {
	// Bundle starts with root certificate - we want to replace the root
	// with our hardcoded known certificate, so we remove the root
	// (first element). Ordering is: root cert .. intermediate certs ..
	// end entity cert.
	let intermediate_certs: Vec<_> =
		cabundle[1..].into_iter().map(|x| x.as_slice()).collect();

	let anchor = vec![webpki::TrustAnchor::try_from_cert_der(root_cert)?];
	let anchors = webpki::TlsServerTrustAnchors(&anchor);

	let cert = webpki::EndEntityCert::try_from(end_entity_certificate)?;
	cert.verify_is_valid_tls_server_cert(
		AWS_NITRO_CERT_SIG_ALG,
		&anchors,
		&intermediate_certs,
		webpki::Time::from_seconds_since_unix_epoch(validation_time),
	)
	.map_err(|e| AttestError::InvalidCertChain(e))?;

	Ok(())
}

/// Verification of the cert chain that requires the x509 parse library.
/// Includes verifying the basic constraints and key usage.
fn aws_spec_verify_cert_chain_x509_parse(
	cabundle: &Vec<ByteBuf>,
	root_cert: &[u8],
	end_entity_certificate: &[u8],
	_validation_time: u64,
) -> Result<(), AttestError> {
	use x509_parser::prelude::{FromDer, X509Certificate};

	// End entity cert verification
	{
		let (_, ee_cert) =
			X509Certificate::from_der(end_entity_certificate).unwrap();
		let ee_basic_constraints =
			ee_cert.basic_constraints().unwrap().unwrap().value;

		//  Basic constraint validation as specified in section 3.2.3.2.
		let is_not_ca = !ee_basic_constraints.ca;
		let is_none_path_len =
			ee_basic_constraints.path_len_constraint.is_none();

		// Key usage extension validation as specified in 3.2.3.3
		let is_marked_digital_signature =
			ee_cert.key_usage().unwrap().unwrap().value.digital_signature();

		(is_none_path_len && is_not_ca && is_marked_digital_signature)
			.then(|| ())
			.ok_or(AttestError::InvalidEndEntityCert)?;
	}

	// Root cert verification
	{
		let (_, root) = X509Certificate::from_der(root_cert).unwrap();
		let root_is_marked_key_cert_sign =
			root.key_usage().unwrap().unwrap().value.key_cert_sign();
		root_is_marked_key_cert_sign
			.then(|| ())
			.ok_or(AttestError::InvalidRootCert)?;
	}

	// Intermediate certificate verification
	cabundle
		.iter()
		.map(|encoded| {
			let (_, cert) = X509Certificate::from_der(encoded).unwrap();
			cert
		})
		.enumerate()
		// Reverse it so the first certificate is the one right before the end
		// entity and thus has the shortest path length.
		.rev()
		.all(|(idx, cert)| {
			// Key usage extension validation as specified in 3.2.3.3
			let is_marked_key_cert_sign =
				cert.key_usage().unwrap().unwrap().value.key_cert_sign();

			//  Basic constraint validation as specified in section 3.2.3.2.
			let basic_constraints =
				cert.basic_constraints().unwrap().unwrap().value;
			let is_correct_path_len_constraint = if basic_constraints.ca {
				true
			} else {
				if let Some(path_len) = basic_constraints.path_len_constraint {
					path_len as usize >= idx
				} else {
					false
				}
			};

			is_marked_key_cert_sign && is_correct_path_len_constraint
		})
		.then(|| ())
		.ok_or(AttestError::InvalidIntermediateCerts)?;

	Ok(())
}

/// Do all the verification we can with just the rust openssl library.
/// Includes verifying the time and name of the certificates.
fn aws_spec_verify_certs_only_openssl(
	cabundle: &Vec<ByteBuf>,
	root_cert: &[u8],
	end_entity_certificate: &[u8],
	validation_time: u64,
) -> Result<(), AttestError> {
	use openssl::{asn1::Asn1Time, nid::Nid, x509::X509};

	let asn1_time = Asn1Time::from_unix(validation_time as i64).unwrap();
	let verify_time = |cert: &X509| {
		*cert.not_after() > asn1_time && *cert.not_before() < asn1_time
	};

	// End entity cert verification
	{
		let end_entity_cert = X509::from_der(end_entity_certificate).unwrap();
		let verify_name = |cert: &X509| {
			cert.subject_name().entries().all(|field| {
				let data = field.data().as_utf8().unwrap().to_string();
				match field.object().nid() {
					Nid::COMMONNAME => {
						/* nitro module id  .. region */
						true
					}
					Nid::ORGANIZATIONNAME => data == "Amazon".to_string(),
					Nid::ORGANIZATIONALUNITNAME => data == "AWS".to_string(),
					Nid::COUNTRYNAME => data == "US".to_string(),
					Nid::STATEORPROVINCENAME => {
						data == "Washington".to_string()
					}
					Nid::LOCALITYNAME => data == "Seattle".to_string(),
					_ => {
						// /* "unexpected x509 subject name" */
						false
					}
				}
			})
		};

		(verify_time(&end_entity_cert) && verify_name(&end_entity_cert))
			.then(|| ())
			.ok_or(AttestError::InvalidEndEntityCert)?;
	}

	// Root cert verification
	{
		let root_cert = X509::from_der(root_cert).unwrap();
		let verify_name = |cert: &X509| {
			cert.subject_name().entries().all(|field| {
				let data = field.data().as_utf8().unwrap().to_string();
				match field.object().nid() {
					Nid::COMMONNAME => data == "aws.nitro-enclaves",
					Nid::ORGANIZATIONNAME => data == "Amazon".to_string(),
					Nid::ORGANIZATIONALUNITNAME => data == "AWS".to_string(),
					Nid::COUNTRYNAME => data == "US".to_string(),
					Nid::STATEORPROVINCENAME => {
						data == "Washington".to_string()
					}
					Nid::LOCALITYNAME => data == "Seattle".to_string(),
					_ => {
						/* "unexpected x509 subject name" */
						false
					}
				}
			})
		};

		(verify_time(&root_cert) && verify_name(&root_cert))
			.then(|| ())
			.ok_or(AttestError::InvalidRootCert)?;
	}

	// Intermediate cert verification
	cabundle
		.iter()
		.map(|encoded_cert| {
			openssl::x509::X509::from_der(encoded_cert).unwrap()
		})
		.all(|cert| verify_time(&cert))
		.then(|| ())
		.ok_or(AttestError::InvalidIntermediateCerts)?;

	Ok(())
}

// Check that cose sign1 structure is signed with the key in the end
// entity certificate.
fn verify_cose_sign1_sig(
	end_entity_certificate: &[u8],
	cose_sign1: &CoseSign1,
) -> Result<(), AttestError> {
	let ee_cert = openssl::x509::X509::from_der(end_entity_certificate)?;

	// Expect v3
	if ee_cert.version() != X509_V3 {
		return Err(AttestError::InvalidEndEntityCert)
	}

	let ee_cert_pub_key = ee_cert.public_key()?;

	// Verify the signature against the extracted public key
	let is_valid_sig = cose_sign1
		.verify_signature(&ee_cert_pub_key)
		.map_err(|_| AttestError::InvalidCOSESign1Signature)?;
	if !is_valid_sig {
		Err(AttestError::InvalidCOSESign1Signature)
	} else {
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use aws_nitro_enclaves_cose::header_map::HeaderMap;
	use openssl::pkey::{PKey, Private, Public};
	use qos_core::protocol::MOCK_NSM_ATTESTATION_DOCUMENT;

	use super::*;

	/// Taken from aws-nitro-enclaves-cose-0.4.0
	/// Randomly generate SECP521R1/P-512 key to use for validating signing
	/// internally
	fn generate_ec512_test_key() -> (PKey<Private>, PKey<Public>) {
		let alg =
			openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1)
				.unwrap();
		let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
		let ec_public =
			openssl::ec::EcKey::from_public_key(&alg, ec_private.public_key())
				.unwrap();
		(
			PKey::from_ec_key(ec_private).unwrap(),
			PKey::from_ec_key(ec_public).unwrap(),
		)
	}

	#[test]
	fn attestation_doc_from_der_works_with_valid_payload() {
		let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
		// TODO: verify each field on doc is as expected
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
		let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
		let err_result = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			day_after,
		);

		match err_result {
			Err(AttestError::InvalidCertChain(webpki::Error::CertExpired)) => {}
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
				_ => panic!("{:?}", err_result),
			};
		}

		{
			let valid = attestation_doc.clone();
			// Don't pop anything, just want to sanity check that we get a
			// corrupt signature on the cose sign1 structure.

			let corrupt_cose_sign1 =
				CoseSign1::new(&valid.to_binary(), &HeaderMap::new(), &private)
					.unwrap();

			let corrupt_document1 = corrupt_cose_sign1.as_bytes(true).unwrap();
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
	fn attestation_doc_from_der_corrupt_end_entity_certificate() {
		let (private, _) = generate_ec512_test_key();
		let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
		let mut attestation_doc = attestation_doc_from_der(
			MOCK_NSM_ATTESTATION_DOCUMENT,
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		)
		.unwrap();

		// Corrupt the end entity certificate
		attestation_doc.certificate.pop();
		attestation_doc.certificate.push(0xff);

		let corrupt_cose_sign1 = CoseSign1::new(
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
			_ => panic!("{:?}", err_result),
		};
	}

	#[test]
	fn attestation_doc_from_der_bad_sign1_sig() {
		let root_cert = cert_from_pem(AWS_ROOT_CERT).unwrap();
		let (private, _) = generate_ec512_test_key();
		let document =
			CoseSign1::from_bytes(MOCK_NSM_ATTESTATION_DOCUMENT).unwrap();

		let unprotected = document.get_unprotected();
		let (_protected, payload) =
			document.get_protected_and_payload(None).unwrap();

		// Sign the document with a private key that isn't in the end entity
		// certificate

		let corrupt_document =
			CoseSign1::new(&payload, unprotected, &private).unwrap();
		let err_result = attestation_doc_from_der(
			&corrupt_document.as_bytes(true).unwrap(),
			&root_cert[..],
			MOCK_SECONDS_SINCE_EPOCH,
		);

		match err_result {
			Err(AttestError::InvalidCOSESign1Signature) => {}
			_ => panic!("{:?}", err_result),
		}
	}

	// #[test]
	// fn attestation_doc_from_der_corrupt_root_certificate() {
	// 	let root_cert =
	// 		openssl::x509::X509::from_pem(AWS_ROOT_CERT).unwrap();

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

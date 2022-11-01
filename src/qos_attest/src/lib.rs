//! Attestation specific logic

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

pub mod nitro;

/// Attestation error.
#[derive(Debug)]
pub enum AttestError {
	/// `webpki::Error` wrapper.
	WebPki(webpki::Error),
	/// Invalid certificate chain.
	InvalidCertChain(webpki::Error),
	/// `openssl::error::ErrorStack` wrapper.
	/// `aws_nitro_enclaves_nsm_api::api::Error` wrapper.
	Nsm(aws_nitro_enclaves_nsm_api::api::Error),
	/// Invalid end entity certificate. In the case of Nitro this means the
	/// NSM's certificate was invalid.
	InvalidEndEntityCert,
	/// Invalid COSE Sign1 structure signature. In the case of Nitro this means
	/// the end entitys signature of the attestation doc was invalid.
	InvalidCOSESign1Signature,
	/// Invalid COSE Sign1 structure.
	InvalidCOSESign1Structure,
	/// Invalid hash digest.
	InvalidDigest,
	/// Invalid NSM module id.
	InvalidModuleId,
	/// Invalid PCR.
	InvalidPcr,
	/// Invalid certificate authority bundle.
	InvalidCABundle,
	/// Invalid time.
	InvalidTimeStamp,
	/// Invalid public key.
	InvalidPubKey,
	/// Invalid bytes.
	InvalidBytes,
	/// The NSM returned an unexpected response when querried
	UnexpectedNsmResponse(qos_core::protocol::attestor::types::NsmResponse),
	/// Error while decoding PEM.
	PemDecodingError,
}

impl From<webpki::Error> for AttestError {
	fn from(e: webpki::Error) -> Self {
		Self::WebPki(e)
	}
}

impl From<aws_nitro_enclaves_nsm_api::api::Error> for AttestError {
	fn from(e: aws_nitro_enclaves_nsm_api::api::Error) -> Self {
		Self::Nsm(e)
	}
}

/// Get the current time based on the NSM attestation document.
pub fn current_time(
	nsm: &dyn qos_core::protocol::attestor::NsmProvider,
) -> Result<u64, AttestError> {
	let nsm_request =
		qos_core::protocol::attestor::types::NsmRequest::Attestation {
			user_data: None,
			nonce: None,
			public_key: None,
		};
	let fd = nsm.nsm_init();
	let nsm_response = nsm.nsm_process_request(fd, nsm_request);
	let nsm_response = match nsm_response {
		qos_core::protocol::attestor::types::NsmResponse::Attestation {
			document,
		} => document,
		resp => return Err(AttestError::UnexpectedNsmResponse(resp)),
	};
	let attestation_document =
		nitro::unsafe_attestation_doc_from_der(&nsm_response)?;

	Ok(attestation_document.timestamp)
}

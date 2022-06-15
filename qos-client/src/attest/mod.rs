//! Attestation specific logic

pub mod nitro;

/// Attestation error.
#[derive(Debug)]
pub enum AttestError {
	/// `webpki::Error` wrapper.
	WebPki(webpki::Error),
	/// Invalid certificate chain.
	InvalidCertChain(webpki::Error),
	/// `openssl::error::ErrorStack` wrapper.
	OpenSSLError(openssl::error::ErrorStack),
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

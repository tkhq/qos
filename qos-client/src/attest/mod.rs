//! Attestation verification logic

pub mod nitro;

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

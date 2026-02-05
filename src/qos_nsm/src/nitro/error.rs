//! Attestation specific logic

use crate::types;

/// Attestation error.
#[derive(Debug)]
pub enum AttestError {
	/// `webpki::Error` wrapper.
	WebPki(webpki::Error),
	/// Invalid certificate chain.
	InvalidCertChain(webpki::Error),
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
	UnexpectedNsmResponse(types::NsmResponse),
	/// Error while decoding PEM.
	PemDecodingError,
	/// Error trying to decode the public key in a cert.
	FailedDecodeKeyFromCert,
	/// Error while trying to parse a cert.
	FailedToParseCert,
	/// User data is missing in the attestation doc.
	MissingUserData,
	/// User data (normally manifest hash) does not match the attestation doc.
	DifferentUserData {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// The attestation doc has a nonce when none was expected.
	UnexpectedAttestationDocNonce,
	/// The attestation doc does not contain a pcr0.
	MissingPcr0,
	/// The pcr0 in the attestation doc does not match.
	DifferentPcr0 {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// The attestation doc does not have a pcr1.
	MissingPcr1,
	/// The attestation doc has a different pcr1.
	DifferentPcr1 {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// The attestation doc does not have a pcr2.
	MissingPcr2,
	/// The attestation doc has a different pcr2.
	DifferentPcr2 {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// The attestation doc does not have a pcr3.
	MissingPcr3,
	/// The attestation doc has a different pcr3.
	DifferentPcr3 {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
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

impl std::fmt::Display for AttestError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::WebPki(e) => write!(f, "webpki error: {e}"),
			Self::InvalidCertChain(e) => {
				write!(f, "invalid certificate chain: {e}")
			}
			Self::Nsm(e) => write!(f, "NSM error: {e:?}"),
			Self::InvalidEndEntityCert => {
				write!(f, "invalid end entity certificate")
			}
			Self::InvalidCOSESign1Signature => {
				write!(f, "invalid COSE Sign1 signature")
			}
			Self::InvalidCOSESign1Structure => {
				write!(f, "invalid COSE Sign1 structure")
			}
			Self::InvalidDigest => write!(f, "invalid hash digest"),
			Self::InvalidModuleId => write!(f, "invalid NSM module ID"),
			Self::InvalidPcr => write!(f, "invalid PCR"),
			Self::InvalidCABundle => {
				write!(f, "invalid certificate authority bundle")
			}
			Self::InvalidTimeStamp => write!(f, "invalid timestamp"),
			Self::InvalidPubKey => write!(f, "invalid public key"),
			Self::InvalidBytes => write!(f, "invalid bytes"),
			Self::UnexpectedNsmResponse(resp) => {
				write!(f, "unexpected NSM response: {resp:?}")
			}
			Self::PemDecodingError => write!(f, "error decoding PEM"),
			Self::FailedDecodeKeyFromCert => {
				write!(f, "failed to decode public key from certificate")
			}
			Self::FailedToParseCert => write!(f, "failed to parse certificate"),
			Self::MissingUserData => {
				write!(f, "user data missing in attestation document")
			}
			Self::DifferentUserData { expected, actual } => {
				write!(
					f,
					"different user data: expected {expected}, got {actual}"
				)
			}
			Self::UnexpectedAttestationDocNonce => {
				write!(f, "unexpected nonce in attestation document")
			}
			Self::MissingPcr0 => {
				write!(f, "PCR0 missing in attestation document")
			}
			Self::DifferentPcr0 { expected, actual } => {
				write!(f, "different PCR0: expected {expected}, got {actual}")
			}
			Self::MissingPcr1 => {
				write!(f, "PCR1 missing in attestation document")
			}
			Self::DifferentPcr1 { expected, actual } => {
				write!(f, "different PCR1: expected {expected}, got {actual}")
			}
			Self::MissingPcr2 => {
				write!(f, "PCR2 missing in attestation document")
			}
			Self::DifferentPcr2 { expected, actual } => {
				write!(f, "different PCR2: expected {expected}, got {actual}")
			}
			Self::MissingPcr3 => {
				write!(f, "PCR3 missing in attestation document")
			}
			Self::DifferentPcr3 { expected, actual } => {
				write!(f, "different PCR3: expected {expected}, got {actual}")
			}
		}
	}
}

impl std::error::Error for AttestError {}

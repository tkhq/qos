//! A sample secure application.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	handles::Handles, protocol::services::boot::ManifestEnvelope,
	server::Routable,
};

/// Possible errors for this application
#[derive(
	Debug, Clone, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum AppError {
	/// Error serializing an message.
	Serialization,
	/// Error parsing an message.
	Parsing,
	/// `qos_core::protocol::ProtocolError` wrapper.
	Protocol(qos_core::protocol::ProtocolError),
	/// `borsh::maybestd::io::Error` wrapper.
	BorshIO,
	/// Error executing cryptographic functions.
	Crypto,
	/// Received an invalid request.
	InvalidRequest,
}

impl From<qos_core::protocol::ProtocolError> for AppError {
	fn from(e: qos_core::protocol::ProtocolError) -> Self {
		Self::Protocol(e)
	}
}

impl From<borsh::maybestd::io::Error> for AppError {
	fn from(_: borsh::maybestd::io::Error) -> Self {
		Self::BorshIO
	}
}

impl From<qos_crypto::CryptoError> for AppError {
	fn from(_: qos_crypto::CryptoError) -> Self {
		Self::Crypto
	}
}

/// Endpoints for this app.
#[derive(
	Debug, Clone, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum AppMsg {
	/// Request an echo.
	EchoReq {
		/// Data to echo.
		data: String,
	},
	/// Successful echo response. Contains the data sent in in
	/// [`Self::EchoReq`].
	EchoResp {
		/// Data sent in the echo request.
		data: String,
	},

	/// Request the data in files QOS writes.
	ReadQOSFilesReq,
	/// Response to read QOS files request.
	ReadQOSFilesResp {
		/// PEM encoded ephemeral key.
		ephemeral_key: Vec<u8>,
		/// PEM encoded quorum key.
		quorum_key: Vec<u8>,
		/// Borsh encoded manifest envelope.
		manifest_envelope: Box<ManifestEnvelope>,
	},

	/// Error response.
	Error {
		/// Information about the error.
		err: AppError,
	},
}

/// Request router for the app.
pub struct AppProcessor {
	handles: Handles,
}

impl AppProcessor {
	/// Create a new instance of [`Self`].
	#[must_use]
	pub fn new(handles: Handles) -> Self {
		Self { handles }
	}
}

impl Routable for AppProcessor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		macro_rules! ok {
			( $e:expr ) => {
				match $e {
					Ok(x) => x,
					Err(error) => {
						return AppMsg::Error { err: AppError::from(error) }
							.try_to_vec()
							.expect("Has valid borsh encoding")
					}
				}
			};
		}

		let request = ok!(AppMsg::try_from_slice(&request));

		let response = match request {
			AppMsg::EchoReq { data } => AppMsg::EchoResp { data },
			AppMsg::ReadQOSFilesReq => {
				let ephemeral_pair = ok!(self.handles.get_ephemeral_key());
				let quorum_pair = ok!(self.handles.get_quorum_key());

				AppMsg::ReadQOSFilesResp {
					ephemeral_key: ok!(ephemeral_pair.public_key_pem()),
					quorum_key: ok!(quorum_pair.public_key_pem()),
					manifest_envelope: Box::new(ok!(self
						.handles
						.get_manifest_envelope())),
				}
			}
			AppMsg::EchoResp { .. }
			| AppMsg::ReadQOSFilesResp { .. }
			| AppMsg::Error { .. } => AppMsg::Error { err: AppError::InvalidRequest },
		};

		ok!(response.try_to_vec())
	}
}

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	handles::Handles, protocol::services::boot::ManifestEnvelope,
	server::Routable,
};

pub enum AppError {
	
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

	/// Ping request.
	PingReq,
	/// Successful ping response.
	PingResp,

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
		msg: String,
	},
}

/// Request router for the app.
pub struct AppProcessor {
	handles: Handles,
}

impl AppProcessor {
	/// Create a new instance of [`Self`].
	pub fn new(handles: Handles) -> Self {
		Self { handles }
	}
}

impl Routable for AppProcessor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		macro_rules! ok {
			( $e:expr, $encoded_err:expr ) => {
				match $e {
					Ok(x) => x,
					/// TODO: make the app error be able to impl From for all error types we encounter
					/// here. Then we can return the actual error nested in an app err.
					Err(_) => return $encoded_err,
				}
			};
		}
		let parsing_err =
			AppMsg::Error { msg: "Error parsing request.".to_string() }
				.try_to_vec()
				.expect("Valid app msg");
		let serialize_err =
			AppMsg::Error { msg: "Failed to serialize `AppMsg`".to_string() }
				.try_to_vec()
				.expect("Valid app msg");
		let eph_err =
			AppMsg::Error { msg: "Failed to get eph key".to_string() }
				.try_to_vec()
				.expect("Valid app msg");

		let request = ok!(AppMsg::try_from_slice(&request), parsing_err);

		let response = match request {
			AppMsg::EchoReq { data } => AppMsg::EchoResp { data },
			AppMsg::PingReq => AppMsg::PingResp,
			AppMsg::ReadQOSFilesReq => {
				let ephemeral_pair = ok!(
					self
					   .handles
					   .get_ephemeral_key(),
					eph_err
				);
				let quorum_pair = ok!(
					self.handles.get_
				)

				AppMsg::ReadQOSFilesResp {
				   ephemeral_key:
						ephemeral_pair
						.public_key_pem()
						.unwrap(),
				   quorum_key: self
					   .handles
					   .get_quorum_key()
					   .unwrap()
					   .public_key_pem()
					   .unwrap(),
				   manifest_envelope: Box::new(
					   self.handles.get_manifest_envelope().unwrap(),
				   ),
			}
			},
			x => AppMsg::Error { msg: format!("{:?}", x) },
		};


		ok!(response.try_to_vec(), serialize_err)
	}
}

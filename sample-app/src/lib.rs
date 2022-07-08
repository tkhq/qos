use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::server::Routable;

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
	/// Error response.
	Error {
		/// Information about the error.
		msg: String,
	},
}

/// Request router for the app.
pub struct AppProcessor;
impl Routable for AppProcessor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		let request = match AppMsg::try_from_slice(&request) {
			Ok(request) => request,
			Err(_) => {
				let e = AppMsg::Error {
					msg: "Could not deserialize request to AppMsg".to_string(),
				};
				return e
					.try_to_vec()
					.expect("Valid AppMsg can always be serialized");
			}
		};

		let response = match request {
			AppMsg::EchoReq { data } => AppMsg::EchoResp { data },
			AppMsg::PingReq => AppMsg::PingResp,
			x => AppMsg::Error { msg: format!("{:?}", x) },
		};

		match response.try_to_vec() {
			Ok(response) => response,
			Err(e) => {
				let e = AppMsg::Error { msg: format!("{:?}", e) };
				e.try_to_vec().expect("Valid AppMsg can always be serialized")
			}
		}
	}
}

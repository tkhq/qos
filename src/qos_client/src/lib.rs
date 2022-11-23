//! CLI Client for interacting with `QuorumOS` enclave and host.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

pub mod cli;
#[cfg(feature = "smartcard")]
pub mod yubikey;

/// Host HTTP request helpers.
pub mod request {
	use std::io::Read;

	use borsh::{BorshDeserialize, BorshSerialize};
	use qos_core::protocol::msg::ProtocolMsg;

	const MAX_SIZE: u64 = u32::MAX as u64;

	/// Post a [`qos_core::protocol::msg::ProtocolMsg`] to the given host `url`.
	pub fn post(url: &str, msg: &ProtocolMsg) -> Result<ProtocolMsg, String> {
		let mut buf: Vec<u8> = vec![];

		let response = ureq::post(url)
			.send_bytes(
				&msg.try_to_vec()
					.expect("ProtocolMsg can always be serialized. qed."),
			)
			.map_err(|e| format!("post err: {:?}", e))?;

		response.into_reader().take(MAX_SIZE).read_to_end(&mut buf).map_err(
			|_| {
				"qos_client::request::post: reading response bytes error"
					.to_string()
			},
		)?;

		let decoded_response =
			ProtocolMsg::try_from_slice(&buf).map_err(|_| {
				"qos_client::request::post: deserialization error".to_string()
			})?;

		Ok(decoded_response)
	}

	/// Get the resource at the given host `url`.
	///
	/// # Panics
	///
	/// Panics if the http request fails.
	pub fn get(url: &str) -> Result<String, String> {
		ureq::get(url)
			.call()
			.unwrap()
			.into_string()
			.map_err(|_| format!("GET `{:?}` failed", url))
	}
}

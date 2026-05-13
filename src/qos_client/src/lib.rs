//! CLI Client for interacting with `QuorumOS` enclave and host.

pub mod cli;
#[cfg(feature = "smartcard")]
pub mod yubikey;

/// Host HTTP request helpers.
pub mod request {
	use std::io::Read;

	use qos_core::protocol::msg::{ProtocolMsg, ProtocolMsgEncoding};

	const MAX_SIZE: u64 = u32::MAX as u64;
	const ERROR_BODY_PREFIX_LIMIT: usize = 256;

	/// Post a [`qos_core::protocol::msg::ProtocolMsg`] to the given host `url`.
	///
	/// # Errors
	///
	/// Returns an error string if the HTTP request fails, the response
	/// cannot be read, or deserialization fails.
	///
	pub fn post(url: &str, msg: &ProtocolMsg) -> Result<ProtocolMsg, String> {
		post_wire(url, msg, ProtocolMsgEncoding::Json)
	}

	/// Post a [`qos_core::protocol::msg::ProtocolMsg`] using legacy Borsh
	/// wire encoding.
	///
	/// # Errors
	///
	/// Returns an error string if the HTTP request fails, the response
	/// cannot be read, or deserialization fails.
	pub fn post_borsh(
		url: &str,
		msg: &ProtocolMsg,
	) -> Result<ProtocolMsg, String> {
		post_wire(url, msg, ProtocolMsgEncoding::Borsh)
	}

	fn post_wire(
		url: &str,
		msg: &ProtocolMsg,
		encoding: ProtocolMsgEncoding,
	) -> Result<ProtocolMsg, String> {
		let mut buf: Vec<u8> = vec![];

		let response = ureq::post(url)
			.send_bytes(&msg.to_wire(encoding).map_err(|e| {
				format!("protocol message serialization error: {e:?}")
			})?)
			.map_err(|e| match e {
				ureq::Error::Status(code, r) => {
					let body = r.into_string();
					format!(
						"http_post error: [url: {url}, status: {code}, body: {body:?}]"
					)
				}
				ureq::Error::Transport(e) => {
					format!("http_post error: transport error: {e}")
				}
			})?;

		response.into_reader().take(MAX_SIZE).read_to_end(&mut buf).map_err(
			|e| {
				format!(
					"http_post error: failed to read response to buffer {e:?}"
				)
			},
		)?;

		let decoded_response = ProtocolMsg::from_wire_any(&buf).map_err(|e| {
			let body_prefix = String::from_utf8_lossy(
				&buf[..std::cmp::min(buf.len(), ERROR_BODY_PREFIX_LIMIT)],
			);
			format!(
				"http_post error: deserialization error: {e:?}; body prefix: {body_prefix:?}"
			)
		})?;

		Ok(decoded_response)
	}

	/// Get the resource at the given host `url`.
	///
	/// # Errors
	///
	/// Returns an error string if the response body cannot be read.
	///
	/// # Panics
	///
	/// Panics if the http request fails.
	pub fn get(url: &str) -> Result<String, String> {
		ureq::get(url)
			.call()
			.unwrap()
			.into_string()
			.map_err(|_| format!("GET `{url:?}` failed"))
	}
}

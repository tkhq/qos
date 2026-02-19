//! CLI Client for interacting with `QuorumOS` enclave and host.

/// Crate version, sourced from `Cargo.toml`.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit SHA at build time, set by `build.rs`.
pub const GIT_SHA: &str = env!("GIT_SHA");

pub mod cli;
#[cfg(feature = "smartcard")]
pub mod yubikey;

/// Host HTTP request helpers.
pub mod request {
	use std::io::Read;

	use borsh::BorshDeserialize;
	use qos_core::protocol::msg::ProtocolMsg;

	const MAX_SIZE: u64 = u32::MAX as u64;

	/// Post a [`qos_core::protocol::msg::ProtocolMsg`] to the given host `url`.
	///
	/// # Panics
	/// Panics if the `msg` cannot be Borsh serialized.
	/// Should never happen in practice because all protocol messages are
	/// Borsh-serializable.
	pub fn post(url: &str, msg: &ProtocolMsg) -> Result<ProtocolMsg, String> {
		let mut buf: Vec<u8> = vec![];

		let response = ureq::post(url)
			.send_bytes(
				&borsh::to_vec(msg)
					.expect("ProtocolMsg can always be serialized. qed."),
			)
			.map_err(|e| match e {
				ureq::Error::Status(code, r) => {
					let body = r.into_string();
					format!("http_post error: [url: {url}, status: {code}, body: {body:?}]")
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

		let decoded_response =
			ProtocolMsg::try_from_slice(&buf).map_err(|e| {
				format!("http_post error: deserialization error: {e:?}")
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
			.map_err(|_| format!("GET `{url:?}` failed"))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn git_sha_is_valid() {
		assert_eq!(
			GIT_SHA.len(),
			8,
			"expected 8 char short SHA, got {GIT_SHA:?}"
		);
		assert!(
			GIT_SHA.chars().all(|c| c.is_ascii_hexdigit()),
			"expected hex characters, got {GIT_SHA:?}"
		);
	}
}

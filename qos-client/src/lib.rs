pub(crate) mod attest;
pub mod cli;

pub mod request {
	use std::io::Read;

	use qos_core::protocol::{ProtocolMsg, Serialize};

	const MAX_SIZE: u64 = u32::MAX as u64;

	pub fn post(url: &str, msg: ProtocolMsg) -> Result<ProtocolMsg, String> {
		let mut buf: Vec<u8> = vec![];

		let response = ureq::post(url)
			.send_bytes(&msg.serialize())
			.map_err(|e| format!("post err: {:?}", e))?;

		response
			.into_reader()
			.take(MAX_SIZE)
			.read_to_end(&mut buf)
			.map_err(|_| "send response error".to_string())?;

		let pr = ProtocolMsg::deserialize(&mut buf)
			.map_err(|_| "send response error".to_string())?;

		Ok(pr)
	}

	pub fn get(url: &str) -> Result<String, String> {
		ureq::get(url)
			.call()
			.unwrap()
			.into_string()
			.map_err(|_| format!("GET `{:?}` failed", url))
	}
}

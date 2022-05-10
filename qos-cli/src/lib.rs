use qos_core::protocol::{ProtocolMsg, Serialize};
use std::io::Read;

const MAX_SIZE: u64 = u32::MAX as u64;

pub fn post(url: &str, msg: ProtocolMsg) -> Result<ProtocolMsg, String> {
	let mut buf: Vec<u8> = vec![];

	println!("About to post...");
	let response = ureq::post(url)
		.send_bytes(&msg.serialize())
		.map_err(|e| format!("post err: {:?}", e))?;

	println!("Just posted...");
	response
		.into_reader()
		.take(MAX_SIZE)
		.read_to_end(&mut buf)
		.map_err(|_| "send response error".to_string())?;

	let pr = ProtocolMsg::deserialize(&mut buf)
		.map_err(|_| "send response error".to_string())?;

	Ok(pr)
}

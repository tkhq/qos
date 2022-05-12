use std::io::Read;

use qos_core::protocol::{Echo, NsmRequest, ProtocolMsg, Serialize};

const MAX_SIZE: u64 = u32::MAX as u64;

struct EnclaveOptions {
	cid: Option<u32>,
	port: Option<u32>,
	usock: Option<String>,
}

struct CLIOptions {}

// fn parse_args(args: Vec<String>) -> CLIOptions {
// 	let mut options = CLIOptions::new();
// }

enum HostCmd {
	Hello,
	Echo,
	NsmDescribe,
}

fn run_cmd(cmd: HostCmd, url: &str) {
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");
	match cmd {
		HostCmd::Hello => {
			ureq::get(&health_url).call().unwrap().into_string().unwrap();
		}
		HostCmd::Echo => {
			let data = b"Hello, world!".to_vec();
			match request::post(
				&message_url,
				ProtocolMsg::EchoRequest(Echo { data }),
			)
			.unwrap()
			{
				ProtocolMsg::EchoResponse(Echo { data }) => {
					println!("EchoResponse: {:?}", String::from_utf8(data))
				}
				_ => {
					println!("Unknown request...")
				}
			}
		}
		HostCmd::NsmDescribe => {
			match request::post(
				&message_url,
				ProtocolMsg::NsmRequest(NsmRequest::DescribeNSM),
			)
			.unwrap()
			{
				ProtocolMsg::NsmResponse(resp) => {
					println!("NsmRepsonse: {:?}", resp)
				}
				_ => {
					println!("Unknown request...")
				}
			}
		}
	}
}

pub mod request {
	use super::*;
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

	fn get(url: &str) -> Result<String, String> {
		ureq::get(url)
			.call()
			.unwrap()
			.into_string()
			.map_err(|_| format!("GET `{:?}` failed", url))
	}
}

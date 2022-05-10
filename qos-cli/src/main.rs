#![forbid(unsafe_code)]

use std::io::Read;

use qos_cli;
use qos_core::protocol::{Echo, ProtocolMsg, Serialize};

const MAX_SIZE: u64 = u32::MAX as u64;

fn main() {
	let url = "http://127.0.0.1:3000";
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");

	let _body: String =
		ureq::get(&health_url).call().unwrap().into_string().unwrap();

	let data = b"Hello, world!".to_vec();
	let request = ProtocolMsg::EchoRequest(Echo { data });
	match qos_cli::post(&message_url, request).unwrap() {
		ProtocolMsg::EchoResponse(_) => {
			println!("EchoResponse")
		}
		_ => {
			println!("Unknown request...")
		}
	}
}

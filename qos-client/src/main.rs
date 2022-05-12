#![forbid(unsafe_code)]

use qos_core::protocol::{NsmRequest, ProtocolMsg};

fn main() {
	let url = "http://127.0.0.1:3000";
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");

	let _body: String =
		ureq::get(&health_url).call().unwrap().into_string().unwrap();

	println!("Health response: {:?}", _body);

	let request = ProtocolMsg::NsmRequest(NsmRequest::DescribeNSM);
	match qos_client::request::post(&message_url, request).unwrap() {
		ProtocolMsg::EchoResponse(_) => {
			println!("EchoResponse")
		}
		ProtocolMsg::NsmResponse(r) => {
			println!("NSM Response: {:?}", r);
		}
		_ => {
			println!("Unknown...");
		}
	}
}

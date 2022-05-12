#![forbid(unsafe_code)]

use aws_nitro_enclaves_nsm_api as nsm;
use qos_cli;
use qos_core::protocol::ProtocolMsg;

fn main() {
	let url = "http://127.0.0.1:3000";
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");

	let _body: String =
		ureq::get(&health_url).call().unwrap().into_string().unwrap();

	println!("Health response: {:?}", _body);

	let request = ProtocolMsg::NsmRequest(nsm::api::Request::DescribeNSM);
	match qos_cli::post(&message_url, request).unwrap() {
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

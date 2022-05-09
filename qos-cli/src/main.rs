use qos_core::protocol::{EchoRequest, ProtocolRequest, Serialize};
use std::io::Read;

const MAX_SIZE: u64 = u32::MAX as u64;

fn main() {
	let url = "http:127.0.0.1:3000";
	let body: String = ureq::get(&format!("{}/{}", url, "health"))
		.call()
		.unwrap()
		.into_string()
		.unwrap();

	let data = b"Hello, world!".to_vec();
	let request = ProtocolRequest::Echo(EchoRequest { data });
	let response = ureq::post(&format!("{}/{}", url, "message"))
		.send_bytes(&request.serialize())
		.unwrap();

	let mut buf: Vec<u8> = vec![];
	response.into_reader().take(MAX_SIZE).read_to_end(&mut buf).unwrap();

	println!("{:?}", buf);

	let pr = ProtocolRequest::deserialize(&mut buf).unwrap();
	match pr {
		ProtocolRequest::Echo(_) => {
			println!("Echo")
		}
		_ => {
			println!("Unknown request...")
		}
	}
}

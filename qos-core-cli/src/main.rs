#![forbid(unsafe_code)]

use std::env;

use qos_core::{
	client::Client,
	io::SocketAddress,
	protocol::{Echo, ProtocolMsg},
	server::{MockNsm, Server},
};

pub fn main() {
	let args: Vec<String> = env::args().collect();

	match args.get(1).map(|a| a.as_str()) {
		Some("server") => run_server(),
		Some("client") => run_client(),
		Some(_) | None => println!("Unknown command..."),
	};
}

fn run_client() {
	let addr = SocketAddress::new_unix("./dev.sock");
	let client = Client::new(addr);
	let data = b"Hello, world!".to_vec();
	let request = ProtocolMsg::EchoRequest(Echo { data });
	let response = client.send(request).unwrap();
	match response {
		ProtocolMsg::EchoResponse(er) => {
			println!("{}", String::from_utf8(er.data).unwrap());
		}
		_ => {
			println!("Unhandled...")
		}
	}
}

fn run_server() {
	let addr = SocketAddress::new_unix("./dev.sock");
	Server::<MockNsm>::listen(addr).unwrap();
}

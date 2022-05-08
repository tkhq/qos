use std::env;

use crate::protocol::{ProtocolRequest, Serialize};
mod io;
mod protocol;
mod server;

pub fn main() {
	let args: Vec<String> = env::args().collect();

	match args.get(1).map(|a| a.as_str()) {
		Some("server") => run_server(),
		Some("client") => run_client(),
		Some(_) | None => println!("Unknown command..."),
	};
}

fn run_client() {
	let addr = io::stream::SocketAddress::Unix(
		nix::sys::socket::UnixAddr::new("./dev.sock").unwrap(),
	);
	let client = io::stream::Stream::connect(&addr).unwrap();

	let data = b"Hello, world!".to_vec();
	println!("Payload: {:?}", data);

	let payload = protocol::EchoRequest { data };
	let request = ProtocolRequest::Echo(payload);

	client.send(&request.serialize()).unwrap();
	let result = client.recv().unwrap();

	println!("Result: {:?}", result);
}

fn run_server() {
	let addr = io::stream::SocketAddress::Unix(
		nix::sys::socket::UnixAddr::new("./dev.sock").unwrap(),
	);
	server::Server::listen(addr).unwrap();
}

use std::env;

use crate::protocol::{ProtocolRequest, Serialize};
mod client;
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
	let client = client::Client::new(addr);
	let data = b"Hello, world!".to_vec();
	let request = ProtocolRequest::Echo(protocol::EchoRequest { data });
	let response = client.send(request).unwrap();
	match response {
		ProtocolRequest::Echo(er) => {
			println!("{}", String::from_utf8(er.data).unwrap());
		}
		_ => {
			println!("Unhandled...")
		}
	}
}

fn run_server() {
	let addr = io::stream::SocketAddress::Unix(
		nix::sys::socket::UnixAddr::new("./dev.sock").unwrap(),
	);
	server::Server::listen(addr).unwrap();
}

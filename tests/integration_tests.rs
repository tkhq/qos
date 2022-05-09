#[cfg(test)]
mod test {
	use nix::sys::socket::UnixAddr;
	use qos::{io::stream::SocketAddress, protocol::ProtocolRequest, *};

	#[test]
	fn smoke_test() {
		assert_eq!(1, 1);
	}

	#[test]
	fn client_server() {
		let addr = SocketAddress::Unix(UnixAddr::new("./dev.sock").unwrap());
		let addr2 = addr.clone();
		let _ = std::thread::spawn(move || {
			server::Server::listen(addr2).unwrap();
		});

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
}

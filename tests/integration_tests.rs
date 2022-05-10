use nix::sys::socket::UnixAddr;
use qos::{
	client::Client,
	io::SocketAddress,
	protocol::{EchoRequest, ProtocolRequest},
	server::Server,
};

#[test]
fn smoke_test() {
	assert_eq!(1, 1);
}

#[test]
fn client_server() {
	// Ensure concurrent tests are not attempting to listen at the same
	// address
	let addr = SocketAddress::Unix(
		UnixAddr::new("./integration_tests_client_server.sock").unwrap(),
	);

	let addr2 = addr.clone();
	// Note that thread handle gets detached on drop
	let _ = std::thread::spawn(move || {
		Server::listen(addr2).unwrap();
	});

	let client = Client::new(addr);
	let data = b"Hello, world!".to_vec();
	let request = ProtocolRequest::Echo(EchoRequest { data });
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

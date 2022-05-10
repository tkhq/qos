use qos_core::{
	client::Client,
	io::SocketAddress,
	protocol::{Echo, ProtocolMsg},
	server::Server,
};

#[test]
fn client_server() {
	// Ensure concurrent tests are not attempting to listen at the same
	// address
	let addr =
		SocketAddress::new_unix("./integration_tests_client_server.sock");
	let addr2 = addr.clone();
	// Note that thread handle gets detached on drop
	let _ = std::thread::spawn(move || {
		Server::listen(addr2).unwrap();
	});

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

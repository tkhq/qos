use std::io::Read;

use qos_core::{
	io::SocketAddress,
	protocol::{Echo, ProtocolMsg, Serialize},
	server::Server,
};
use qos_host::HostServer;

const MAX_SIZE: u64 = u32::MAX as u64;

// TODO: Fix flakey test...
#[tokio::test]
async fn end_to_end() {
	let enclave_addr = SocketAddress::new_unix("./end_to_end.sock");
	let enclave_addr2 = enclave_addr.clone();
	let ip = [127, 0, 0, 1];
	let port = 3000;
	let url =
		format!("http://{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port);

	// Spawn enclave
	std::thread::spawn(move || {
		Server::listen(enclave_addr).unwrap();
	});

	std::thread::spawn(move || {
		let host = HostServer::new(enclave_addr2, ip, port);

		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();

		rt.block_on(host.serve())
	});

	// Test health endpoint
	let body: String = ureq::get(&format!("{}/{}", url, "health"))
		.call()
		.unwrap()
		.into_string()
		.unwrap();

	assert_eq!(body, "Ok!");

	// Test message endpoint
	let data = b"Hello, world!".to_vec();
	let request = ProtocolMsg::EchoRequest(Echo { data: data.clone() });
	let response = ureq::post(&format!("{}/{}", url, "message"))
		.send_bytes(&request.serialize())
		.unwrap();

	let mut buf: Vec<u8> = vec![];
	response.into_reader().take(MAX_SIZE).read_to_end(&mut buf).unwrap();

	let pr = ProtocolMsg::deserialize(&mut buf).unwrap();

	assert_eq!(pr, ProtocolMsg::EchoResponse(Echo { data }));
}

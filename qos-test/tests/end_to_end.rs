use std::fs::remove_file;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use qos_cli;
use qos_core::{
	io::SocketAddress,
	protocol::{Echo, ProtocolMsg, ProvisionRequest, Serialize},
	server::Server,
};
use qos_crypto;
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
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");

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

	std::thread::sleep(std::time::Duration::from_secs(1));

	// Test health endpoint
	let body: String =
		ureq::get(&health_url).call().unwrap().into_string().unwrap();
	assert_eq!(body, "Ok!");

	// Test message endpoint
	let data = b"Hello, world!".to_vec();
	let request = ProtocolMsg::EchoRequest(Echo { data: data.clone() });
	let response = qos_cli::post(&message_url, request).unwrap();
	assert_eq!(response, ProtocolMsg::EchoResponse(Echo { data }));

	// Test reconstruction
	let secret = b"This is extremely secret".to_vec();
	let n = 6;
	let k = 3;
	let all_shares = qos_crypto::shares_generate(&secret, n, k);

	let s1 = all_shares[0].clone();
	let r1 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s1 });
	let response = qos_cli::post(&message_url, r1).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	let s2 = all_shares[1].clone();
	let r2 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s2 });
	let response = qos_cli::post(&message_url, r2).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	let s3 = all_shares[2].clone();
	let r3 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s3 });
	let response = qos_cli::post(&message_url, r3).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	let path = Path::new(qos_core::server::SECRET_FILE);
	assert!(!path.exists());

	let rr = ProtocolMsg::ReconstructRequest;
	let response = qos_cli::post(&message_url, rr).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	assert!(path.exists());
	let mut content = Vec::new();
	let mut file = File::open(qos_core::server::SECRET_FILE).unwrap();
	file.read_to_end(&mut content).unwrap();

	assert_eq!(content, secret);

	// Delete file
	std::fs::remove_file(path).unwrap();
}

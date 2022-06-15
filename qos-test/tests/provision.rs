use std::{fs::File, io::Read, path::Path};

use qos_client;
use qos_core::{
	io::SocketAddress,
	protocol::{Echo, Executor, MockNsm, ProtocolMsg, Provision},
	server::SocketServer,
};
use qos_crypto;
use qos_host::HostServer;

#[tokio::test]
async fn provision_e2e() {
	let usock = "./provisions_e2e.sock";
	let enclave_addr = SocketAddress::new_unix(usock);
	let enclave_addr2 = enclave_addr.clone();
	let ip = [127, 0, 0, 1];
	let port = 3002;
	let url =
		format!("http://{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port);
	let health_url = format!("{}/{}", url, "health");
	let message_url = format!("{}/{}", url, "message");

	let pivot_file = "./end-to-end.pivot".to_string();
	let secret_file = "./end-to-end.secret".to_string();
	let ephemeral_file = "./end-to-end.ephemeral".to_string();

	// Spawn enclave
	let pivot_file2 = pivot_file.clone();
	let secret_file2 = secret_file.clone();
	let ephemeral_file2 = ephemeral_file.clone();
	std::thread::spawn(move || {
		let attestor = MockNsm {};
		let executor = Executor::new(
			Box::new(attestor),
			secret_file2,
			pivot_file2,
			ephemeral_file2,
		);

		SocketServer::listen(enclave_addr, executor).unwrap()
	});

	std::thread::spawn(move || {
		let host = HostServer::new(enclave_addr2, ip, port);

		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();

		rt.block_on(host.serve())
	});

	// Enclave + host need time to bind before serving requests...
	std::thread::sleep(std::time::Duration::from_secs(1));

	// Test health endpoint
	let body: String =
		ureq::get(&health_url).call().unwrap().into_string().unwrap();
	assert_eq!(body, "Ok!");

	// Test message endpoint
	let data = b"Hello, world!".to_vec();
	let request = ProtocolMsg::EchoRequest(Echo { data: data.clone() });
	let response = qos_client::request::post(&message_url, request).unwrap();
	let expected = ProtocolMsg::EchoResponse(Echo { data });
	assert_eq!(expected, response);

	// Test reconstruction
	let secret = b"This is extremely secret".to_vec();
	let n = 6;
	let k = 3;
	let all_shares = qos_crypto::shares_generate(&secret, n, k);

	let s1 = all_shares[0].clone();
	let r1 = ProtocolMsg::ProvisionRequest(Provision { share: s1 });
	let response = qos_client::request::post(&message_url, r1).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let s2 = all_shares[1].clone();
	let r2 = ProtocolMsg::ProvisionRequest(Provision { share: s2 });
	let response = qos_client::request::post(&message_url, r2).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let s3 = all_shares[2].clone();
	let r3 = ProtocolMsg::ProvisionRequest(Provision { share: s3 });
	let response = qos_client::request::post(&message_url, r3).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let path = Path::new(&secret_file);
	assert!(!path.exists());

	let rr = ProtocolMsg::ReconstructRequest;
	let response = qos_client::request::post(&message_url, rr).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	assert!(path.exists());
	let mut content = Vec::new();
	let mut file = File::open(&secret_file).unwrap();
	file.read_to_end(&mut content).unwrap();

	assert_eq!(content, secret);

	// Delete file
	std::fs::remove_file(path).unwrap();
	std::fs::remove_file(usock).unwrap();
}

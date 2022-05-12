use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use qos_cli;
use qos_core::{
	io::SocketAddress,
	protocol::{
		Echo, Executor, MockNsm, NsmRequest, NsmResponse, ProtocolMsg,
		ProvisionRequest, NsmDigest,
	},
	server::SocketServer,
};
use qos_crypto;
use qos_host::HostServer;

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
		let attestor = MockNsm {};
		let executor = Executor::new(attestor);

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
	let response = qos_cli::post(&message_url, request).unwrap();
	let expected = ProtocolMsg::EchoResponse(Echo { data });
	assert_eq!(expected, response);

	// Test reconstruction
	let secret = b"This is extremely secret".to_vec();
	let n = 6;
	let k = 3;
	let all_shares = qos_crypto::shares_generate(&secret, n, k);

	let s1 = all_shares[0].clone();
	let r1 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s1 });
	let response = qos_cli::post(&message_url, r1).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let s2 = all_shares[1].clone();
	let r2 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s2 });
	let response = qos_cli::post(&message_url, r2).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let s3 = all_shares[2].clone();
	let r3 = ProtocolMsg::ProvisionRequest(ProvisionRequest { share: s3 });
	let response = qos_cli::post(&message_url, r3).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	let path = Path::new(qos_core::protocol::SECRET_FILE);
	assert!(!path.exists());

	let rr = ProtocolMsg::ReconstructRequest;
	let response = qos_cli::post(&message_url, rr).unwrap();
	let expected = ProtocolMsg::SuccessResponse;
	assert_eq!(expected, response);

	assert!(path.exists());
	let mut content = Vec::new();
	let mut file = File::open(qos_core::protocol::SECRET_FILE).unwrap();
	file.read_to_end(&mut content).unwrap();

	assert_eq!(content, secret);

	// Delete file
	std::fs::remove_file(path).unwrap();

	// Test NSM connection
	let request = ProtocolMsg::NsmRequest(NsmRequest::DescribeNSM);
	let response = qos_cli::post(&message_url, request).unwrap();
	let expected = ProtocolMsg::NsmResponse(NsmResponse::DescribeNSM {
		version_major: 1,
		version_minor: 2,
		version_patch: 14,
		module_id: "mock_module_id".to_string(),
		max_pcrs: 1024,
		locked_pcrs: BTreeSet::from([90, 91, 92]),
		digest: NsmDigest::SHA256,
	});
	assert_eq!(response, expected);
}

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use openssl::rsa::Rsa;
use qos_core::{
	io::SocketAddress,
	protocol::{Executor, Load, MockNsm, ProtocolMsg, SignatureWithPubKey},
	server::SocketServer,
};
use qos_crypto::{RsaPair, RsaPub};
use qos_host::HostServer;

#[test]
fn load_e2e() {
	let mut base_path = std::env::current_dir().unwrap();
	base_path.push("mock");
	// ensure the base path exists
	std::fs::create_dir_all(base_path.clone()).unwrap();

	let make_path = |n: usize| {
		let mut path = base_path.clone();
		path.push(format!("rsa_public_{}.mock.pem", n.to_string()));
		path
	};

	//
	// Part 1 - create signatures
	//
	let executable = b"vape nation".to_vec();
	let key_range = 0..5;
	let pairs: Vec<_> = key_range
		.clone()
		.map(|_| {
			//TO
			let pair: RsaPair = Rsa::generate(4096).unwrap().into();
			pair
		})
		.collect();

	let paths: Vec<_> = pairs
		.iter()
		.enumerate()
		.map(|(i, pair)| {
			let path = make_path(i);
			let pub_pem = pair.public_key_pem().unwrap();
			let rsa_pub = RsaPub::from_pem(&pub_pem[..]).unwrap();
			// Write the key to the given path
			rsa_pub.write_pem_file(&path).unwrap();

			path
		})
		.collect();

	let signatures: Vec<_> = pairs
		.iter()
		.enumerate()
		.map(|(i, pair)| SignatureWithPubKey {
			signature: pair.sign_sha256(&mut executable.clone()[..]).unwrap(),
			path: paths[i].to_string_lossy().into_owned(),
		})
		.collect();

	//
	// Part 2 - start up services
	//
	let enclave_addr = SocketAddress::new_unix("./rsa_verify_payload.sock");
	let enclave_addr2 = enclave_addr.clone();
	let ip = Ipv4Addr::from([127, 0, 0, 1]);
	let port = 3001; // Use a unique port so we don't collide with other tests
	let socket_addr = SocketAddrV4::new(ip, port);
	let message_url = format!("http://{}/message", socket_addr.to_string());
	let pivot_file = "./verification.pivot".to_string();
	let secret_file = "./verification.secret".to_string();

	// Spawn enclave
	let pivot_file2 = pivot_file.clone();
	let secret_file2 = secret_file.clone();
	std::thread::spawn(move || {
		let attestor = MockNsm {};
		let executor =
			Executor::new(Box::new(attestor), secret_file2, pivot_file2);

		SocketServer::listen(enclave_addr, executor).unwrap()
	});

	std::thread::spawn(move || {
		let host = HostServer::new(enclave_addr2, SocketAddr::V4(socket_addr));

		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();

		rt.block_on(host.serve())
	});

	// Enclave + host need time to bind before serving requests...
	std::thread::sleep(std::time::Duration::from_secs(1));

	//
	// Part 3 - make request
	//
	let load_request =
		ProtocolMsg::LoadRequest(Load { executable, signatures });
	let response =
		qos_client::request::post(&message_url, load_request).unwrap();
	assert_eq!(response, ProtocolMsg::SuccessResponse);

	//
	// Part 4 - clean up the generated keys
	//
	std::fs::remove_file(&pivot_file).unwrap();
	for path in paths {
		std::fs::remove_file(path).unwrap()
	}
}

use std::{
	fs,
	io::{BufRead, BufReader, Write},
	process::{Command, Stdio},
};

use borsh::de::BorshDeserialize;
use integration::{
	PivotSocketStressMsg, LOCAL_HOST, PCR3_PRE_IMAGE_PATH,
	PIVOT_SOCKET_STRESS_PATH, QOS_DIST_DIR,
};
use qos_core::protocol::{
	services::{
		boot::{
			Approval, BridgeConfig, Manifest, ManifestSet, Namespace,
			PivotConfig, RestartPolicy, ShareSet,
		},
		genesis::{GenesisMemberOutput, GenesisOutput},
	},
	ProtocolPhase, QosHash,
};
use qos_crypto::sha_256;
use qos_host::EnclaveInfo;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
};

#[tokio::test]
async fn qos_host_bridge_works() {
	const PIVOT_HASH_PATH: &str = "/tmp/qos_host_bridge-pivot-hash.txt";

	let host_port = qos_test_primitives::find_free_port().unwrap();
	let app_host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp: PathWrapper = "/tmp/qos_host_bridge".into();
	let _: PathWrapper = PIVOT_HASH_PATH.into();
	fs::create_dir_all(&*tmp).unwrap();

	let usock_path = "/tmp/qos_host_bridge/qos_host_bridge.sock".to_owned();
	let usock: PathWrapper = usock_path.clone().into();
	let secret_path: PathWrapper =
		"/tmp/qos_host_bridge/qos_host_bridge.secret".into();
	let pivot_path: PathWrapper =
		"/tmp/qos_host_bridge/qos_host_bridge.pivot".into();
	let manifest_path: PathWrapper =
		"/tmp/qos_host_bridge/qos_host_bridge.manifest".into();
	let eph_path: PathWrapper =
		"/tmp/qos_host_bridge/ephemeral_key.secret".into();

	let boot_dir: PathWrapper = "/tmp/qos_host_bridge/boot-dir".into();
	fs::create_dir_all(&*boot_dir).unwrap();
	let attestation_dir: PathWrapper =
		"/tmp/qos_host_bridge/attestation-dir".into();
	fs::create_dir_all(&*attestation_dir).unwrap();
	let attestation_doc_path = format!("{}/attestation_doc", &*attestation_dir);

	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";

	let namespace = "quit-coding-to-vape";

	let personal_dir = |user: &str| format!("{all_personal_dir}/{user}-dir");

	let user1 = "user1";
	let user2 = "user2";
	let user3 = "user3";

	// -- Create pivot-build-fingerprints.txt
	let pivot = fs::read(PIVOT_SOCKET_STRESS_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let pivot_hash = qos_hex::encode_to_vec(&mock_pivot_hash);
	std::fs::write(PIVOT_HASH_PATH, pivot_hash).unwrap();

	// -- CLIENT create manifest.
	let pivot_app_sock_path =
		usock_path + "." + &app_host_port.to_string() + ".appsock";
	let pivot_args = format!("[{pivot_app_sock_path}]");
	let cli_manifest_path = format!("{}/manifest", &*boot_dir);

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-manifest",
			"--nonce",
			"2",
			"--namespace",
			namespace,
			"--restart-policy",
			"never",
			"--pivot-hash-path",
			PIVOT_HASH_PATH,
			"--qos-release-dir",
			QOS_DIST_DIR,
			"--pcr3-preimage-path",
			PCR3_PRE_IMAGE_PATH,
			"--manifest-path",
			&cli_manifest_path,
			"--pivot-args",
			&pivot_args,
			"--manifest-set-dir",
			"./mock/keys/manifest-set",
			"--share-set-dir",
			"./mock/keys/share-set",
			"--patch-set-dir",
			"./mock/keys/manifest-set",
			"--quorum-key-path",
			"./mock/namespaces/quit-coding-to-vape/quorum_key.pub",
			"--bridge-config",
			&format!("[{{\"type\": \"server\", \"port\": {app_host_port}, \"host\": \"0.0.0.0\"}}]"),
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check the manifest written to file
	let manifest: Manifest =
		serde_json::from_slice(&fs::read(&cli_manifest_path).unwrap()).unwrap();

	let genesis_output = {
		let contents =
			fs::read("./mock/boot-e2e/genesis-dir/genesis_output").unwrap();
		GenesisOutput::try_from_slice(&contents).unwrap()
	};
	// For simplicity sake, we use the same keys for the share set and manifest
	// set.
	let mut members: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.cloned()
		.map(|GenesisMemberOutput { share_set_member, .. }| share_set_member)
		.collect();
	members.sort();

	let namespace_field = Namespace {
		name: namespace.to_string(),
		nonce: 2,
		quorum_key: genesis_output.quorum_key,
	};
	assert_eq!(manifest.namespace, namespace_field);
	let pivot = PivotConfig {
		hash: mock_pivot_hash,
		restart: RestartPolicy::Never,
		args: vec![pivot_app_sock_path.to_string()],
		debug_mode: false,
		bridge_config: vec![BridgeConfig::Server {
			port: app_host_port,
			host: "0.0.0.0".into(),
		}],
	};
	assert_eq!(manifest.pivot, pivot);
	let manifest_set = ManifestSet { threshold: 2, members: members.clone() };
	assert_eq!(manifest.manifest_set, manifest_set);
	let share_set = ShareSet { threshold: 2, members };
	assert_eq!(manifest.share_set, share_set);

	// -- CLIENT make sure each user can run `approve-manifest`
	for alias in [user1, user2, user3] {
		let approval_path = format!(
			"{}/{}-{}-{}.approval",
			&*boot_dir, alias, namespace, manifest.namespace.nonce,
		);

		let secret_path = format!("{}/{}.secret", &personal_dir(alias), alias);

		let mut child = Command::new("../target/debug/qos_client")
			.args([
				"approve-manifest",
				"--secret-path",
				&*secret_path,
				"--manifest-path",
				&cli_manifest_path,
				"--manifest-approvals-dir",
				&*boot_dir,
				"--pcr3-preimage-path",
				PCR3_PRE_IMAGE_PATH,
				"--pivot-hash-path",
				PIVOT_HASH_PATH,
				"--qos-release-dir",
				QOS_DIST_DIR,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--share-set-dir",
				"./mock/keys/share-set",
				"--patch-set-dir",
				"./mock/keys/manifest-set",
				"--quorum-key-path",
				"./mock/namespaces/quit-coding-to-vape/quorum_key.pub",
				"--alias",
				alias,
			])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.unwrap();

		let mut stdin = child.stdin.take().expect("Failed to open stdin");

		let mut stdout = {
			let stdout = child.stdout.as_mut().unwrap();
			let stdout_reader = BufReader::new(stdout);
			stdout_reader.lines()
		};

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct namespace name: quit-coding-to-vape? (y/n)"
		);
		stdin.write_all("y\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct namespace nonce: 2? (y/n)"
		);
		// On purpose, try to input a bad value, neither yes or no
		stdin
			.write_all("maybe\n".as_bytes())
			.expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Please answer with either \"yes\" (y) or \"no\" (n)"
		);
		// Try the longer option ("yes" rather than "y")
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct pivot restart policy: RestartPolicy::Never? (y/n)"
		);
		stdin.write_all("y\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Are these the correct pivot args:"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			&format!("[\"/tmp/qos_host_bridge/qos_host_bridge.sock.{app_host_port}.appsock\"]?")
		);
		assert_eq!(&stdout.next().unwrap().unwrap(), "(y/n)");
		stdin.write_all("y\n".as_bytes()).expect("Failed to write to stdin");

		// Wait for the command to write the approval and exit
		assert!(child.wait().unwrap().success());

		// Read in the generated approval to check it was created correctly
		let approval: Approval =
			serde_json::from_slice(&fs::read(approval_path).unwrap()).unwrap();
		let personal_pair = P256Pair::from_hex_file(format!(
			"{}/{}.secret",
			personal_dir(alias),
			alias,
		))
		.unwrap();

		let signature = personal_pair.sign(&manifest.qos_hash()).unwrap();
		assert_eq!(approval.signature, signature);

		assert_eq!(approval.member.alias, alias);
		assert_eq!(
			approval.member.pub_key,
			personal_pair.public_key().to_bytes(),
		);
	}

	// -- ENCLAVE start enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				&*usock,
				"--quorum-file",
				&*secret_path,
				"--pivot-file",
				&*pivot_path,
				"--ephemeral-file",
				&*eph_path,
				"--mock",
				"--manifest-file",
				&*manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// -- HOST start host
	let mut host_child_process: ChildWrapper =
		Command::new("../target/debug/qos_host")
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				&*usock,
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(host_port);

	// -- CLIENT generate the manifest envelope
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-manifest-envelope",
			"--manifest-approvals-dir",
			&*boot_dir,
			"--manifest-path",
			&cli_manifest_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT broadcast boot standard instruction
	let manifest_envelope_path = format!("{}/manifest_envelope", &*boot_dir,);
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-standard",
			"--manifest-envelope-path",
			&manifest_envelope_path,
			"--pivot-path",
			PIVOT_SOCKET_STRESS_PATH,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--pcr3-preimage-path",
			"./mock/pcr3-preimage.txt",
			"--unsafe-skip-attestation",
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// For each user, post a share,
	for user in [&user1, &user2] {
		// Get attestation doc and manifest
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"get-attestation-doc",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--attestation-doc-path",
				&*attestation_doc_path,
				"--manifest-envelope-path",
				"/tmp/dont_care"
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		let share_path = format!("{}/{}.share", &personal_dir(user), user);
		let secret_path = format!("{}/{}.secret", &personal_dir(user), user);
		let eph_wrapped_share_path: PathWrapper =
			format!("{}/{}.eph_wrapped.share", &*tmp, user).into();
		let approval_path: PathWrapper =
			format!("{}/{}.attestation.approval", &*tmp, user).into();
		// Encrypt share to ephemeral key
		let mut child = Command::new("../target/debug/qos_client")
			.args([
				"proxy-re-encrypt-share",
				"--share-path",
				&share_path,
				"--secret-path",
				&secret_path,
				"--attestation-doc-path",
				&*attestation_doc_path,
				"--eph-wrapped-share-path",
				&eph_wrapped_share_path,
				"--approval-path",
				&approval_path,
				"--manifest-envelope-path",
				&manifest_envelope_path,
				"--pcr3-preimage-path",
				PCR3_PRE_IMAGE_PATH,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				&*eph_path,
			])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.unwrap();

		let mut stdin = child.stdin.take().expect("Failed to open stdin");

		let mut stdout = {
			let stdout = child.stdout.as_mut().unwrap();
			let stdout_reader = BufReader::new(stdout);
			stdout_reader.lines()
		};

		// Skip over a log message
		stdout.next();

		// Answer prompts with yes
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct namespace name: quit-coding-to-vape? (y/n)"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct namespace nonce: 2? (y/n)"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
				&stdout.next().unwrap().unwrap(),
				"Does this AWS IAM role belong to the intended organization: arn:aws:iam::123456789012:role/Webserver? (y/n)"
			);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"The following manifest set members approved:"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		// Check that it finished successfully
		assert!(child.wait().unwrap().success());

		// Post the encrypted share
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"post-share",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--eph-wrapped-share-path",
				&eph_wrapped_share_path,
				"--approval-path",
				&approval_path,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
	}

	let enclave_info_url =
		format!("http://{LOCAL_HOST}:{host_port}/qos/enclave-info");
	let enclave_info: EnclaveInfo =
		ureq::get(&enclave_info_url).call().unwrap().into_json().unwrap();
	assert_eq!(enclave_info.phase, ProtocolPhase::QuorumKeyProvisioned);

	// Give the enclave time to start the pivot
	tokio::time::sleep(std::time::Duration::from_secs(2)).await;

	// Wait for the qos_host app bridge to run
	qos_test_primitives::wait_until_port_is_bound(app_host_port);

	// send a PivotSocketStressMsg to check if the  bridge works all the way
	let bridge_addr = format!("127.0.0.1:{app_host_port}");
	let mut tcp_stream = TcpStream::connect(&bridge_addr).await.unwrap();

	let msg = PivotSocketStressMsg::OkRequest(42);
	let msg_bytes = borsh::to_vec(&msg).unwrap();
	let mut header = (msg_bytes.len() as u64).to_le_bytes();

	// send the header/length
	tcp_stream.write_all(&header).await.unwrap();
	// send the msg
	tcp_stream.write_all(&msg_bytes).await.unwrap();

	// receive the reply header
	assert_eq!(8, tcp_stream.read_exact(&mut header).await.unwrap());
	let reply_size = usize::from_le_bytes(header);
	let mut reply_bytes = vec![0u8; reply_size];
	// receive the reply msg
	assert_eq!(
		reply_size,
		tcp_stream.read_exact(&mut reply_bytes).await.unwrap()
	);
	// decode the reply msg
	let reply: PivotSocketStressMsg = borsh::from_slice(&reply_bytes).unwrap();

	match reply {
		PivotSocketStressMsg::OkResponse(val) => assert_eq!(val, 42),
		_ => panic!("invalid pivot response"),
	}

	// test qos_host restart keeping the bridge up via the envelope logic
	// kill the original
	host_child_process.0.kill().expect("unable to kill qos_host");
	drop(host_child_process);

	// -- HOST restart host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/qos_host")
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				&*usock,
			])
			.spawn()
			.unwrap()
			.into();

	// Wait for the qos_host app bridge to run
	qos_test_primitives::wait_until_port_is_bound(app_host_port);

	// send a PivotSocketStressMsg to check if the  bridge works all the way
	let bridge_addr = format!("127.0.0.1:{app_host_port}");
	let mut tcp_stream = TcpStream::connect(&bridge_addr).await.unwrap();

	let msg = PivotSocketStressMsg::OkRequest(42);
	let msg_bytes = borsh::to_vec(&msg).unwrap();
	let mut header = (msg_bytes.len() as u64).to_le_bytes();

	// send the header/length
	tcp_stream.write_all(&header).await.unwrap();
	// send the msg
	tcp_stream.write_all(&msg_bytes).await.unwrap();

	// receive the reply header
	assert_eq!(8, tcp_stream.read_exact(&mut header).await.unwrap());
	let reply_size = usize::from_le_bytes(header);
	let mut reply_bytes = vec![0u8; reply_size];
	// receive the reply msg
	assert_eq!(
		reply_size,
		tcp_stream.read_exact(&mut reply_bytes).await.unwrap()
	);
	// decode the reply msg
	let reply: PivotSocketStressMsg = borsh::from_slice(&reply_bytes).unwrap();

	match reply {
		PivotSocketStressMsg::OkResponse(val) => assert_eq!(val, 42),
		_ => panic!("invalid pivot response"),
	}
}

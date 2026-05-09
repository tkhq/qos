use std::{
	fs,
	io::{BufRead, BufReader, Write},
	path::PathBuf,
	process::{Command, Stdio},
};

use borsh::de::BorshDeserialize;
use integration::{
	wait_for_tcp_sock, PivotSocketStressMsg, LOCAL_HOST, PCR3_PRE_IMAGE_PATH,
	PIVOT_SOCKET_STRESS_PATH, QOS_DIST_DIR,
};
use qos_core::protocol::{
	services::{
		boot::{
			Approval, BridgeConfig, ManifestSet, ManifestV1, Namespace,
			PivotConfigV1, RestartPolicy, ShareSet,
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

#[tokio::test(flavor = "multi_thread")]
async fn qos_bridge_works() {
	const PIVOT_HASH_PATH: &str = "/tmp/qos_host_bridge-pivot-hash.txt";

	let host_port = qos_test_primitives::find_free_port().unwrap();
	let app_host_port = qos_test_primitives::find_free_port().unwrap();
	let app_host_port_override = qos_test_primitives::find_free_port().unwrap();
	let tmp = PathWrapper::from("/tmp/qos_host_bridge");
	let _ = PathWrapper::from(PIVOT_HASH_PATH);
	fs::create_dir_all(&tmp).unwrap();

	let usock_path = "/tmp/qos_host_bridge/qos_host_bridge.sock".to_owned();
	let usock = PathWrapper::from(usock_path.clone());
	let secret_path =
		PathWrapper::from("/tmp/qos_host_bridge/qos_host_bridge.secret");
	let pivot_path =
		PathWrapper::from("/tmp/qos_host_bridge/qos_host_bridge.pivot");
	let manifest_path =
		PathWrapper::from("/tmp/qos_host_bridge/qos_host_bridge.manifest");
	let eph_path =
		PathWrapper::from("/tmp/qos_host_bridge/ephemeral_key.secret");

	let boot_dir = PathWrapper::from("/tmp/qos_host_bridge/boot-dir");
	fs::create_dir_all(&boot_dir).unwrap();
	let attestation_dir =
		PathWrapper::from("/tmp/qos_host_bridge/attestation-dir");
	fs::create_dir_all(&attestation_dir).unwrap();
	let attestation_doc_path = attestation_dir.join("attestation_doc");

	let all_personal_dir = PathBuf::from("./mock/boot-e2e/all-personal-dir");

	let namespace = "quit-coding-to-vape";

	let personal_dir =
		|user: &str| all_personal_dir.join(format!("{user}-dir"));

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
	let cli_manifest_path = boot_dir.join("manifest");

	assert!(Command::new(integration::QOS_CLIENT_PATH)
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
			cli_manifest_path.to_str().unwrap(),
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
			&format!("[{{\"type\": \"server\", \"port\": \"{app_host_port}\", \"host\": \"0.0.0.0\"}}]"),
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check the manifest written to file
	let manifest: ManifestV1 =
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
	let pivot = PivotConfigV1 {
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
		let approval_path = boot_dir.join(format!(
			"{}-{}-{}.approval",
			alias, namespace, manifest.namespace.nonce,
		));

		let secret_path = personal_dir(alias).join(format!("{alias}.secret"));

		let mut child = Command::new(integration::QOS_CLIENT_PATH)
			.args([
				"approve-manifest",
				"--secret-path",
				secret_path.to_str().unwrap(),
				"--manifest-path",
				cli_manifest_path.to_str().unwrap(),
				"--manifest-approvals-dir",
				boot_dir.to_str().unwrap(),
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
		let personal_pair = P256Pair::from_hex_file(
			personal_dir(alias).join(format!("{alias}.secret",)),
		)
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
		Command::new(integration::QOS_CORE_PATH)
			.args([
				"--usock",
				usock.to_str().unwrap(),
				"--quorum-file",
				secret_path.to_str().unwrap(),
				"--pivot-file",
				pivot_path.to_str().unwrap(),
				"--ephemeral-file",
				eph_path.to_str().unwrap(),
				"--mock",
				"--manifest-file",
				manifest_path.to_str().unwrap(),
			])
			.spawn()
			.unwrap()
			.into();

	// -- HOST start host
	let mut _host_child_process: ChildWrapper =
		Command::new(integration::QOS_HOST_PATH)
			.args([
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				usock.to_str().unwrap(),
				"--socket-timeout",
				"15000",
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(host_port);

	let control_url = format!("http://localhost:{host_port}/qos");
	// -- BRIDGE start bridge
	let mut bridge_child_process: ChildWrapper =
		Command::new(integration::QOS_BRIDGE_PATH)
			.args([
				"--host-port-override",
				&app_host_port_override.to_string(),
				"--usock",
				usock.to_str().unwrap(),
				"--control-url",
				&control_url,
			])
			.spawn()
			.unwrap()
			.into();

	// -- CLIENT generate the manifest envelope
	assert!(Command::new(integration::QOS_CLIENT_PATH)
		.args([
			"generate-manifest-envelope",
			"--manifest-approvals-dir",
			boot_dir.to_str().unwrap(),
			"--manifest-path",
			cli_manifest_path.to_str().unwrap(),
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT broadcast boot standard instruction
	let manifest_envelope_path = boot_dir.join("manifest_envelope");
	assert!(Command::new(integration::QOS_CLIENT_PATH)
		.args([
			"boot-standard",
			"--manifest-envelope-path",
			manifest_envelope_path.to_str().unwrap(),
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
		assert!(Command::new(integration::QOS_CLIENT_PATH)
			.args([
				"get-attestation-doc",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--attestation-doc-path",
				attestation_doc_path.to_str().unwrap(),
				"--manifest-envelope-path",
				"/tmp/dont_care"
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		let share_path = personal_dir(user).join(format!("{user}.share"));
		let secret_path = personal_dir(user).join(format!("{user}.secret"));
		let eph_wrapped_share_path =
			PathWrapper::from(tmp.join(format!("{user}.eph_wrapped.share")));
		let approval_path = PathWrapper::from(
			tmp.join(format!("{user}.attestation.approval",)),
		);
		// Encrypt share to ephemeral key
		let mut child = Command::new(integration::QOS_CLIENT_PATH)
			.args([
				"proxy-re-encrypt-share",
				"--share-path",
				share_path.to_str().unwrap(),
				"--secret-path",
				secret_path.to_str().unwrap(),
				"--attestation-doc-path",
				attestation_doc_path.to_str().unwrap(),
				"--eph-wrapped-share-path",
				eph_wrapped_share_path.to_str().unwrap(),
				"--approval-path",
				approval_path.to_str().unwrap(),
				"--manifest-envelope-path",
				manifest_envelope_path.to_str().unwrap(),
				"--pcr3-preimage-path",
				PCR3_PRE_IMAGE_PATH,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				eph_path.to_str().unwrap(),
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
		assert!(Command::new(integration::QOS_CLIENT_PATH)
			.args([
				"post-share",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--eph-wrapped-share-path",
				eph_wrapped_share_path.to_str().unwrap(),
				"--approval-path",
				approval_path.to_str().unwrap(),
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
	let bridge_addr = format!("127.0.0.1:{app_host_port_override}");
	wait_for_tcp_sock(&bridge_addr).await;

	// send a PivotSocketStressMsg to check if the  bridge works all the way
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

	// test qos_bridge restart after enclave is up
	bridge_child_process.kill().expect("unable to kill qos_host");
	drop(bridge_child_process);

	// -- BRIDGE restart bridge
	let _bridge_child_process: ChildWrapper =
		Command::new(integration::QOS_BRIDGE_PATH)
			.args([
				"--host-port-override",
				&app_host_port_override.to_string(),
				"--usock",
				usock.to_str().unwrap(),
				"--control-url",
				&control_url,
			])
			.spawn()
			.unwrap()
			.into();

	// Wait for the qos_bridge app bridge to run
	let bridge_addr = format!("127.0.0.1:{app_host_port_override}");
	wait_for_tcp_sock(&bridge_addr).await;

	// send a PivotSocketStressMsg to check if the  bridge works all the way
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

use std::{
	fs,
	io::{BufRead, BufReader, Write},
	path::{Path, PathBuf},
	process::{Command, Stdio},
};

use borsh::de::BorshDeserialize;
use integration::{
	LOCAL_HOST, PCR3_PRE_IMAGE_PATH, PIVOT_OK2_PATH, PIVOT_OK2_SUCCESS_FILE,
	QOS_DIST_DIR,
};
use qos_core::protocol::{
	services::{
		boot::{
			Approval, ManifestSet, ManifestV1, Namespace, PivotConfigV1,
			RestartPolicy, ShareSet,
		},
		genesis::{GenesisMemberOutput, GenesisOutput},
	},
	ProtocolPhase, QosHash,
};
use qos_crypto::sha_256;
use qos_host::EnclaveInfo;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test(flavor = "multi_thread")]
async fn standard_boot_e2e() {
	const PIVOT_HASH_PATH: &str = "/tmp/standard_boot_e2e-pivot-hash.txt";

	let host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp = PathWrapper::from("/tmp/boot-e2e");
	let _ = PathWrapper::from(PIVOT_OK2_SUCCESS_FILE);
	let _ = PathWrapper::from(PIVOT_HASH_PATH);
	fs::create_dir_all(&*tmp).unwrap();

	let usock = PathWrapper::from(tmp.join("boot_e2e.sock"));
	let secret_path = PathWrapper::from(tmp.join("boot_e2e.secret"));
	let pivot_path = PathWrapper::from(tmp.join("boot_e2e.pivot"));
	let manifest_path = PathWrapper::from(tmp.join("boot_e2e.manifest"));
	let eph_path = PathWrapper::from(tmp.join("ephemeral_key.secret"));

	let boot_dir = tmp.join("boot-dir");
	fs::create_dir_all(&boot_dir).unwrap();
	let attestation_dir = tmp.join("attestation-dir");
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
	let pivot = fs::read(PIVOT_OK2_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let pivot_hash = qos_hex::encode_to_vec(&mock_pivot_hash);
	std::fs::write(PIVOT_HASH_PATH, pivot_hash).unwrap();

	// -- CLIENT create manifest.
	let msg = "testing420";
	let pivot_args = format!("[--msg,{msg}]");
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
			"./mock/namespaces/quit-coding-to-vape/quorum_key.pub"
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
		args: vec!["--msg".to_string(), msg.to_string()],
		..Default::default()
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
			"[\"--msg\", \"testing420\"]?"
		);
		assert_eq!(&stdout.next().unwrap().unwrap(), "(y/n)");
		stdin.write_all("y\n".as_bytes()).expect("Failed to write to stdin");

		// Wait for the command to write the approval and exit
		assert!(child.wait().unwrap().success());

		// Read in the generated approval to check it was created correctly
		let approval: Approval =
			serde_json::from_slice(&fs::read(approval_path).unwrap()).unwrap();
		let personal_pair = P256Pair::from_hex_file(
			personal_dir(alias).join(format!("{alias}.secret")),
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
				&*usock,
				"--socket-timeout",
				"15000",
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(host_port);

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
			PIVOT_OK2_PATH,
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
	// and sanity check the pivot has not yet executed.
	assert!(!Path::new(PIVOT_OK2_SUCCESS_FILE).exists());
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
		let approval_path =
			PathWrapper::from(tmp.join(format!("{user}.attestation.approval")));
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

	// Check that the pivot executed
	let contents = std::fs::read(PIVOT_OK2_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);

	fs::remove_file(PIVOT_OK2_SUCCESS_FILE).unwrap();
}

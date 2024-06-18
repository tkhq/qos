use std::{
	collections::HashMap,
	fs,
	io::{BufRead, BufReader, Write},
	path::Path,
	process::{Command, Stdio},
};

use integration::{LOCAL_HOST, PCR3_PRE_IMAGE_PATH, QOS_DIST_DIR};
use qos_crypto::n_choose_k;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test]
async fn reshard_e2e() {
	let tmp: PathWrapper = "/tmp/reshard_e2e".into();
	drop(fs::create_dir_all(&*tmp));
	let _eph_path: PathWrapper = "/tmp/reshard_e2e/eph.secret".into();
	let usock: PathWrapper = "/tmp/reshard_e2e/usock.sock".into();
	let secret_path: PathWrapper = "/tmp/reshard_e2e/quorum.secret".into();
	let attestation_doc_path: PathWrapper = "/tmp/reshard_e2e/att_doc".into();
	let reshard_input_path: PathWrapper =
		"/tmp/reshard_e2e/reshard_input.json".into();
	let reshard_output_path: PathWrapper =
		"/tmp/reshard_e2e/reshard_output.json".into();
	let eph_path: PathWrapper = "/tmp/reshard_e2e/ephemeral_key.secret".into();

	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";
	let personal_dir = |user: &str| format!("{all_personal_dir}/{user}-dir");
	let user1 = "user1";
	let user2 = "user2";

	let host_port = qos_test_primitives::find_free_port().unwrap();

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				&*usock,
				"--quorum-file",
				&*secret_path,
				"--pivot-file",
				"/tmp/reshard_e2e/never_write_pivot_file",
				"--ephemeral-file",
				&*eph_path,
				"--mock",
				"--manifest-file",
				"/tmp/reshard_e2e/never_write_manifest",
			])
			.spawn()
			.unwrap()
			.into();

	// Start Host
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

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-reshard-input",
			"--qos-release-dir",
			QOS_DIST_DIR,
			"--pcr3-preimage-path",
			PCR3_PRE_IMAGE_PATH,
			"--quorum-key-path-multiple",
			"./mock/namespaces/quit-coding-to-vape/quorum_key.pub",
			"--old-share-set-dir",
			"./mock/keys/share-set",
			"--new-share-set-dir",
			"./mock/keys/new-share-set",
			"--reshard-input-path",
			&*reshard_input_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	qos_test_primitives::wait_until_port_is_bound(host_port);

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-reshard",
			"--reshard-input-path",
			&*reshard_input_path,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"get-reshard-attestation-doc",
			"--attestation-doc-path",
			&*attestation_doc_path,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	for user in [&user1, &user2] {
		let secret_path = format!("{}/{}.secret", &personal_dir(user), user);
		let provision_input_path =
			format!("{}/{}.provision_input.json", &*tmp, user);
		let quorum_share_dir1 = format!("./mock/reshard/{}/qkey1", user);

		let mut child = Command::new("../target/debug/qos_client")
			.args([
				"reshard-re-encrypt-share",
				"--secret-path",
				&secret_path,
				"--quorum-share-dir-multiple",
				&*quorum_share_dir1,
				"--attestation-doc-path",
				&*attestation_doc_path,
				"--provision-input-path",
				&*provision_input_path,
				"--reshard-input-path",
				&*reshard_input_path,
				"--qos-release-dir",
				QOS_DIST_DIR,
				"--pcr3-preimage-path",
				PCR3_PRE_IMAGE_PATH,
				"--new-share-set-dir",
				"./mock/keys/new-share-set",
				"--old-share-set-dir",
				"./mock/keys/share-set",
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
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"**WARNING:** Skipping attestation document verification.",
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Does this AWS IAM role belong to the intended organization: arn:aws:iam::123456789012:role/Webserver? (yes/no)",
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Does this new share set look correct? (yes/no)"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"040ee9045f3718bd1345dccf88693c993626d08448fdeba8ecaf1b867f4d0572d439852ef460963a9e8fab08864a55994c0779216b44a165b4eaced98722ed3778041646e59014eaec046b2636d3943f446282363c26cf995320d5944b8b4d7af0aa588c208c13ded5c86c3e9a31af687c4027d4636173f405503e7b1baeeee7eaa5"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"04c82672b2f8c4d520c5c7cda207b4a05f433e4db7f0daed9bbde6f54d42814af5aeabec191d2dda32ba4cdc6616aa3fda0a6711affa0d42efbe11144043028622044810d6d24626abfe6c31e884e674c870a2197c9e9cd80786b2fd3a087e2c38cad8376d9b7086901915d261ecb92bde5a757d27bbf1a20904120ff079b8a8ef71"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"049872acc56bca90eea07e1e1185e3015be3b7295b4ba484299702489bf4858b1374928b335d3405a16221ec240e80817fbfd783c7052446a31bd1821a9a10ff9c0469361a228e22e7cad34774a50f7cd8f97e7d6542f3903bf9d14647302691ef9195ae2c08ec62dcd0e845bc75e94ef8b9fa45925199a2f7d94d00981d6d2e0d85"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"0442993076a3b8345cb58b860477bce9db21bb6caceae8df298860410594ea08d4fc2ffec944fd7623a893b57037e0f20c44ff8eee6eff03110717efb9269181ed04bb495296212027597e2eb93ffbba07f0c41ae3018409b9ad2177e87b53a2729806f52ad6d0f6399ca3d37edddc81a687cd2a0a9f8aab914d76be2930ff8f5bba"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Is this the correct reconstruction threshold for the new share set: 3? (yes/no)"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"Are these the correct quorum keys to reshard? (yes/no)"
		);
		assert_eq!(
			&stdout.next().unwrap().unwrap(),
			"04c9434ba0a681ee7c21e17c7ce4f668360803686b198774c9362dac090f9995eeb68961319370969bd0d657167d9cfce13a7466ec47aba9845fbfc4fe9277866d04043daa777f57c1ebef21ff3eb71e00a681921da56186ac96b5d3b06b645c88c512fe8072d12971ce1f9592ef6bafd98b4982f8cf73cb6e80c8f6424294e54c71"
		);
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		assert_eq!(
			stdout.next().unwrap().unwrap(),
			format!("Reshard provision input written to: /tmp/reshard_e2e/{}.provision_input.json", user),
		);
		assert!(child.wait().unwrap().success());

		// Post the encrypted shares and approval over reshard input
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"reshard-post-share",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--provision-input-path",
				&*provision_input_path,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
	}

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"get-reshard-output",
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--reshard-output-path",
			&reshard_output_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let secret_path_fn = |user: &str| {
		format!("./mock/new-share-set-secrets/reshard-{}.secret", user)
	};

	type Share = Vec<u8>;
	type QuorumPubKey = Vec<u8>;
	let mut seen_shares = HashMap::<QuorumPubKey, Vec<Share>>::new();
	for user in ["1", "2", "3", "4"] {
		let secret_path = secret_path_fn(user);
		let share_dir: PathWrapper =
			format!("{}/{}/quorum_shares", &*tmp, user).into();
		fs::create_dir_all(&*share_dir).unwrap();
		let pair = P256Pair::from_hex_file(&secret_path).unwrap();

		assert!(Command::new("../target/debug/qos_client")
			.args([
				"verify-reshard-output",
				"--reshard-output-path",
				&reshard_output_path,
				"--secret-path",
				&secret_path,
				"--share-dir",
				&share_dir,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		for entry in fs::read_dir(&*share_dir).unwrap() {
			let path = entry.unwrap().path();

			if path.is_dir() {
				let mut quorum_key = None;
				let mut share = None;
				for inner_entry in fs::read_dir(&*path).unwrap() {
					let inner_path = inner_entry.unwrap().path();
					if inner_path.is_file() {
						let split_name = split_file_name(&inner_path);
						let buf = fs::read(inner_path).unwrap();

						if split_name.first().unwrap() == "quorum_key" {
							quorum_key = Some(buf)
						} else if split_name.last().unwrap() == "share" {
							share = Some(buf)
						}
					}
				}

				let share = share.unwrap();
				let decrypted_share = pair.decrypt(&share).unwrap();
				let quorum_key_pub_bytes =
					qos_hex::decode_from_vec(quorum_key.unwrap()).unwrap();
				seen_shares
					.entry(quorum_key_pub_bytes)
					.or_default()
					.push(decrypted_share)
			}
		}
	}

	for (pub_key, shares) in seen_shares.iter() {
		for combo in n_choose_k::combinations(
			shares, 3, /* new share set threshold */
		) {
			let secret: [u8; 32] =
				qos_crypto::shamir::shares_reconstruct(&combo)
					.unwrap()
					.try_into()
					.unwrap();

			let quorum_key = P256Pair::from_master_seed(&secret).unwrap();
			assert_eq!(*pub_key, quorum_key.public_key().to_bytes());
		}
	}
}

fn split_file_name(p: &Path) -> Vec<String> {
	let file_name =
		p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();
	file_name.split('.').map(String::from).collect()
}

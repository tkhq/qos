use std::{
	fs,
	io::{self, BufRead},
	path::Path,
	process::Command,
};

use borsh::de::BorshDeserialize;
use integration::{LOCAL_HOST, PCR3_PRE_IMAGE_PATH, QOS_DIST_DIR};
use qos_core::protocol::services::genesis::GenesisOutput;
use qos_crypto::{sha_512, shamir::shares_reconstruct};
use qos_nsm::nitro::unsafe_attestation_doc_from_der;
use qos_p256::{P256Pair, P256Public};
use qos_test_primitives::ChildWrapper;
use rand::{seq::SliceRandom, thread_rng};

// We don't use DR for dev; the keys are checked in and hold no value.
const DR_KEY_PUBLIC_PATH: &str = "./mock/mock_p256_dr.pub";
const DR_KEY_PRIVATE_PATH: &str = "./mock/mock_p256_dr.secret.keep";

/// This test is also a utility script to generate new quorum keys encrypted to existing "dev" operator in our dev environment.
/// Useful when we create new enclave applications.
#[tokio::test]
async fn dev_genesis() {
	let host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp = Path::new("/tmp/dev-genesis");
	if tmp.exists() {
        fs::remove_dir_all(tmp).unwrap();
    }
	fs::create_dir_all(tmp).unwrap();
	
	let tmp_dir = |file: &str| -> String { format!("{}/{file}", tmp.to_str().unwrap()) };

	let usock = tmp_dir("dev_genesis.sock");
	let secret_path = tmp_dir("dev_genesis.secret");
	let pivot_path = tmp_dir("dev_genesis.pivot");
	let manifest_path = tmp_dir("manifest.manifest");

	let all_personal_dir = tmp_dir("all-personal-dir");
	let genesis_dir = tmp_dir("genesis-dir");

	let attestation_doc_path =
		format!("{}/genesis_attestation_doc", genesis_dir);
	let genesis_output_path = format!("{}/genesis_output", genesis_dir);
	let dr_wrapped_quorum_key_path =
		format!("{}/dr_wrapped_quorum_key", genesis_dir);
	let dr_artifacts_path = format!("{}/genesis_dr_artifacts", genesis_dir);

	let dev_fixture_dev_pub = |user: &str| format!("fixtures/dev/dev-users/{}.pub", user);
	let dev_fixture_dev_secret = |user: &str| format!("fixtures/dev/dev-users/{}.secret.keep", user);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", &*all_personal_dir, user);
	let get_key_paths =
		|user: &str| (format!("{user}.secret"), format!("{user}.pub"));

	let threshold = 2;
	let dev1 = "1";
	let dev2 = "2";

	// Make the genesis dir
	fs::create_dir_all(Path::new(&genesis_dir)).unwrap();

	// Move the setup keys to the genesis dir - this will be the Genesis Set
	for dev_user in [dev1, dev2] {
		fs::copy(
			Path::new(&dev_fixture_dev_pub(&dev_user)),
			Path::new(&genesis_dir).join(&get_key_paths(dev_user).1)
		).unwrap();

		// Create the personal dir folder
		fs::create_dir_all(personal_dir(dev_user)).unwrap();
	}

	let quorum_threshold_path =
		Path::new(&genesis_dir).join("quorum_threshold");
	fs::write(quorum_threshold_path, b"2\n").unwrap();

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
				"--mock",
				"--manifest-file",
				&*manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// -- HOST start host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/qos_host")
			.args([
				"--host-port",
				&*host_port.to_string(),
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

	// -- CLIENT Run boot genesis, creating a genesis set from the setup keys in
	// the genesis dir
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-genesis",
			"--share-set-dir",
			&*genesis_dir,
			"--namespace-dir",
			&*genesis_dir,
			"--host-ip",
			LOCAL_HOST,
			"--host-port",
			&*host_port.to_string(),
			"--qos-release-dir",
			QOS_DIST_DIR,
			"--pcr3-preimage-path",
			PCR3_PRE_IMAGE_PATH,
			"--dr-key-path",
			DR_KEY_PUBLIC_PATH,
			"--unsafe-skip-attestation"
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- Check files generated from the genesis boot
	drop(unsafe_attestation_doc_from_der(
		&fs::read(&*attestation_doc_path).unwrap(),
	));
	let genesis_output = GenesisOutput::try_from_slice(
		&fs::read(&*genesis_output_path).unwrap(),
	)
	.unwrap();

	// -- Recreate the quorum key from the encrypted shares.
	let mut decrypted_shares: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.map(|member| {
			let alias = &member.share_set_member.alias;

			let share_key_path = dev_fixture_dev_secret(&alias);

			let share_pair = P256Pair::from_hex_file(share_key_path).unwrap();

			// Decrypt the share with the personal key
			let plain_text_share =
				share_pair.decrypt(&member.encrypted_quorum_key_share).unwrap();

			assert_eq!(sha_512(&plain_text_share), member.share_hash);

			plain_text_share
		})
		.collect();

	// Try recovering from a random permutation
	decrypted_shares.shuffle(&mut thread_rng());
	let master_secret: [u8; qos_p256::MASTER_SEED_LEN] =
		shares_reconstruct(&decrypted_shares[0..threshold])
			.unwrap()
			.try_into()
			.unwrap();
	let reconstructed = P256Pair::from_master_seed(&master_secret).unwrap();
	assert!(
		reconstructed.public_key()
			== P256Public::from_bytes(&genesis_output.quorum_key).unwrap()
	);

	// -- CLIENT make sure each user can run `after-genesis` against their
	// member output and decrypt their share with their share key.
	for user in [&dev1, &dev2] {
		let share_path = format!("{}/{}.share", &personal_dir(user), user);
		let secret_path = dev_fixture_dev_secret(&user);
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"after-genesis",
				"--secret-path",
				&secret_path,
				"--share-path",
				&share_path,
				"--alias",
				user,
				"--namespace-dir",
				&genesis_dir,
				"--qos-release-dir",
				QOS_DIST_DIR,
				"--pcr3-preimage-path",
				"./mock/pcr3-preimage.txt",
				"--unsafe-skip-attestation"
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		let user_key_pair = P256Pair::from_hex_file(secret_path).unwrap();

		// Check the share is encrypted to personal key
		let share =
			user_key_pair.decrypt(&fs::read(share_path).unwrap()).unwrap();
		// Cross check that the share belongs `decrypted_shares`, which we
		// created out of band in this test.
		assert!(decrypted_shares.contains(&share));
	}

	// Check that we can use the DR key to decrypt the quorum key
	let dr_key_pair = P256Pair::from_hex_file(DR_KEY_PRIVATE_PATH).unwrap();

	let dr_wrapped_quorum_key = fs::read(dr_wrapped_quorum_key_path).unwrap();
	let master_seed: [u8; 32] = dr_key_pair
		.decrypt(&dr_wrapped_quorum_key)
		.unwrap()
		.try_into()
		.unwrap();
	let pair = P256Pair::from_master_seed(&master_seed).unwrap();
	assert!(pair == reconstructed);

	let dr_artifacts_contents = fs::File::open(dr_artifacts_path).unwrap();
	assert_eq!(io::BufReader::new(dr_artifacts_contents).lines().count(), 4);

	// Check that we can verify the dr artifacts.
	let reconstructed_path = tmp_dir("reconstructed_quorum_master_seed_hex");
	reconstructed.to_hex_file(&*reconstructed_path).unwrap();
	assert!(Command::new("../target/debug/qos_client")
		.arg("verify-genesis")
		.arg("--namespace-dir")
		.arg(&*genesis_dir)
		.arg("--master-seed-path")
		.arg(&*reconstructed_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
}

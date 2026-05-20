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
use qos_test_primitives::{ChildWrapper, PathWrapper};
use rand::{rng, seq::SliceRandom};

const DR_KEY_PUBLIC_PATH: &str = "./mock/mock_p256_dr.pub";
const DR_KEY_PRIVATE_PATH: &str = "./mock/mock_p256_dr.secret.keep";

#[tokio::test(flavor = "multi_thread")]
async fn genesis_e2e() {
	let host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp_dir = PathWrapper::from("/tmp/genesis-e2e");
	fs::create_dir_all(&*tmp_dir).unwrap();

	let usock = tmp_dir.join("genesis_e2e.sock");
	let secret_path = tmp_dir.join("genesis_e2e.secret");
	let pivot_path = tmp_dir.join("genesis_e2e.pivot");
	let manifest_path = tmp_dir.join("manifest.manifest");

	let all_personal_dir = tmp_dir.join("all-personal-dir");
	let genesis_dir = tmp_dir.join("genesis-dir");

	let attestation_doc_path = genesis_dir.join("genesis_attestation_doc");
	let genesis_output_path = genesis_dir.join("genesis_output");
	let dr_wrapped_quorum_key_path = genesis_dir.join("dr_wrapped_quorum_key");
	let dr_artifacts_path = genesis_dir.join("genesis_dr_artifacts");

	let personal_dir =
		|user: &str| all_personal_dir.join(format!("{user}-dir"));
	let get_key_paths =
		|user: &str| (format!("{user}.secret"), format!("{user}.pub"));

	let threshold = 2;
	let user1 = "user1";
	let (user1_private_share_key, user1_public_share_key) =
		get_key_paths(user1);

	let user2 = "user2";
	let (user2_private_share_key, user2_public_share_key) =
		get_key_paths(user2);

	let user3 = "user3";
	let (user3_private_share_key, user3_public_share_key) =
		get_key_paths(user3);

	// -- CLIENT Create 3 setup keys
	// Make sure the directory keys are getting written to already exist.
	for (user, private, public) in [
		(&user1, &user1_private_share_key, &user1_public_share_key),
		(&user2, &user2_private_share_key, &user2_public_share_key),
		(&user3, &user3_private_share_key, &user3_public_share_key),
	] {
		fs::create_dir_all(personal_dir(user)).unwrap();
		let master_seed_path = personal_dir(user).join(private);
		let public_path = personal_dir(user).join(public);
		assert!(
			Command::new(integration::QOS_CLIENT_PATH)
				.args([
					"generate-file-key",
					"--master-seed-path",
					master_seed_path.to_str().unwrap(),
					"--pub-path",
					public_path.to_str().unwrap(),
				])
				.spawn()
				.unwrap()
				.wait()
				.unwrap()
				.success()
		);
		assert!(Path::new(&*personal_dir(user)).join(public).is_file());
		assert!(Path::new(&*personal_dir(user)).join(private).is_file());
	}

	// Make the genesis dir
	fs::create_dir_all(&*genesis_dir).unwrap();
	// Move the setup keys to the genesis dir - this will be the Genesis Set
	for (user, public) in [
		(&user1, &user1_public_share_key),
		(&user2, &user2_public_share_key),
		(&user3, &user3_public_share_key),
	] {
		let from = Path::new(&*personal_dir(user)).join(public);
		let to = Path::new(&*genesis_dir).join(public);
		fs::copy(from, to).unwrap();
	}
	let quorum_threshold_path =
		Path::new(&*genesis_dir).join("quorum_threshold");
	fs::write(quorum_threshold_path, b"2\n").unwrap();

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
				&*host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				usock.to_str().unwrap(),
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(host_port);

	// -- CLIENT Run boot genesis, creating a genesis set from the setup keys in
	// the genesis dir
	assert!(
		Command::new(integration::QOS_CLIENT_PATH)
			.args([
				"boot-genesis",
				"--share-set-dir",
				genesis_dir.to_str().unwrap(),
				"--namespace-dir",
				genesis_dir.to_str().unwrap(),
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
			.success()
	);

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

			let (private_share_key, _) = get_key_paths(alias);
			let share_key_path =
				Path::new(&*personal_dir(alias)).join(private_share_key);

			let share_pair = P256Pair::from_hex_file(share_key_path).unwrap();

			// Decrypt the share with the personal key
			let plain_text_share =
				share_pair.decrypt(&member.encrypted_quorum_key_share).unwrap();

			assert_eq!(sha_512(&plain_text_share[..]), member.share_hash);

			plain_text_share
		})
		.collect();

	// Try recovering from a random permutation
	decrypted_shares.shuffle(&mut rng());
	let master_secret: [u8; qos_p256::MASTER_SEED_LEN] =
		shares_reconstruct(&decrypted_shares[0..threshold]).unwrap()[..]
			.try_into()
			.unwrap();
	let reconstructed = P256Pair::from_master_seed(&master_secret).unwrap();
	assert!(
		reconstructed.public_key()
			== P256Public::from_bytes(&genesis_output.quorum_key).unwrap()
	);

	// -- CLIENT make sure each user can run `after-genesis` against their
	// member output and decrypt their share with their share key.
	for user in [&user1, &user2, &user3] {
		let share_path = personal_dir(user).join(format!("{user}.share"));
		let secret_path = personal_dir(user).join(format!("{user}.secret"));
		assert!(
			Command::new(integration::QOS_CLIENT_PATH)
				.args([
					"after-genesis",
					"--secret-path",
					secret_path.to_str().unwrap(),
					"--share-path",
					share_path.to_str().unwrap(),
					"--alias",
					user,
					"--namespace-dir",
					genesis_dir.to_str().unwrap(),
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
				.success()
		);

		let share_key_path =
			Path::new(&personal_dir(user)).join(format!("{user}.secret"));
		let share_path =
			Path::new(&personal_dir(user)).join(format!("{user}.share"));
		let share_key_pair = P256Pair::from_hex_file(share_key_path).unwrap();

		// Check the share is encrypted to personal key
		let share =
			share_key_pair.decrypt(&fs::read(share_path).unwrap()).unwrap();
		// Cross check that the share belongs `decrypted_shares`, which we
		// created out of band in this test.
		assert!(
			decrypted_shares
				.iter()
				.any(|decrypted_share| decrypted_share.as_slice() == &share[..])
		);
	}

	// Check that we can use the DR key to decrypt the quorum key
	let dr_key_pair = P256Pair::from_hex_file(DR_KEY_PRIVATE_PATH).unwrap();

	let dr_wrapped_quorum_key = fs::read(dr_wrapped_quorum_key_path).unwrap();
	let master_seed: [u8; 32] =
		dr_key_pair.decrypt(&dr_wrapped_quorum_key).unwrap()[..]
			.try_into()
			.unwrap();
	let pair = P256Pair::from_master_seed(&master_seed).unwrap();
	assert!(pair == reconstructed);

	let dr_artifacts_contents = fs::File::open(dr_artifacts_path).unwrap();
	assert_eq!(io::BufReader::new(dr_artifacts_contents).lines().count(), 4);

	// Check that we can verify the dr artifacts.
	let reconstructed_path =
		tmp_dir.join("reconstructed_quorum_master_seed_hex");
	reconstructed.to_hex_file(&reconstructed_path).unwrap();
	assert!(
		Command::new(integration::QOS_CLIENT_PATH)
			.arg("verify-genesis")
			.arg("--namespace-dir")
			.arg(genesis_dir)
			.arg("--master-seed-path")
			.arg(reconstructed_path)
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);
}

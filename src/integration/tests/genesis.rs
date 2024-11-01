use std::{
	fs,
	io::{self, BufRead},
	path::Path,
	process::Command,
};

use borsh::de::BorshDeserialize;
use integration::{LOCAL_HOST, QOS_DIST_DIR};
use qos_core::protocol::services::genesis::GenesisOutput;
use qos_crypto::{sha_512, shamir::{shares_reconstruct, shares_generate}};
use qos_nsm::nitro::unsafe_attestation_doc_from_der;
use qos_p256::{derive_secret, encrypt::P256EncryptPair, P256Pair, P256Public, P256_ENCRYPT_DERIVE_PATH};
use qos_test_primitives::{ChildWrapper, PathWrapper};
use rand::{seq::SliceRandom, thread_rng};

const DR_KEY_PUBLIC_PATH: &str = "./mock/mock_p256_dr.pub";
const DR_KEY_PRIVATE_PATH: &str = "./mock/mock_p256_dr.secret.keep";

#[tokio::test]
async fn genesis_e2e() {
	let host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp: PathWrapper = "/tmp/genesis-e2e".into();
	fs::create_dir_all(&*tmp).unwrap();
	let tmp_dir =
		|file: &str| -> PathWrapper { format!("{}/{file}", &*tmp).into() };

	let usock = tmp_dir("genesis_e2e.sock");
	let secret_path = tmp_dir("genesis_e2e.secret");
	let pivot_path = tmp_dir("genesis_e2e.pivot");
	let manifest_path = tmp_dir("manifest.manifest");

	let all_personal_dir = tmp_dir("all-personal-dir");
	let genesis_dir = tmp_dir("genesis-dir");

	let attestation_doc_path =
		format!("{}/genesis_attestation_doc", &*genesis_dir);
	let genesis_output_path = format!("{}/genesis_output", &*genesis_dir);
	let dr_wrapped_quorum_key_path =
		format!("{}/dr_wrapped_quorum_key", &*genesis_dir);
	let dr_artifacts_path = format!("{}/genesis_dr_artifacts", &*genesis_dir);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", &*all_personal_dir, user);
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
		let master_seed_path = format!("{}/{}", personal_dir(user), private);
		let public_path = format!("{}/{}", personal_dir(user), public);
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"generate-file-key",
				"--master-seed-path",
				&master_seed_path,
				"--pub-path",
				&public_path,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
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
			"./mock/pcr3-preimage.txt",
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

			let (private_share_key, _) = get_key_paths(alias);
			let share_key_path =
				Path::new(&*personal_dir(alias)).join(private_share_key);

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
		shares_reconstruct(&decrypted_shares[0..threshold]).try_into().unwrap();
	let reconstructed = P256Pair::from_master_seed(&master_secret).unwrap();
	assert!(
		reconstructed.public_key()
			== P256Public::from_bytes(&genesis_output.quorum_key).unwrap()
	);

	// -- CLIENT make sure each user can run `after-genesis` against their
	// member output and decrypt their share with their share key.
	for user in [&user1, &user2, &user3] {
		let share_path = format!("{}/{}.share", &personal_dir(user), user);
		let secret_path = format!("{}/{}.secret", &personal_dir(user), user);
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


#[test]
fn dothething() {
	// FAIL
	let sharepath = "/Users/lthibault/Desktop/reshard-2024-09-19/1.share";
	let master_seed_path = "/Users/lthibault/Desktop/reshard-2024-09-19/personal/user1-dir/user1.secret";

	// PASS
	// let sharepath = "/Users/lthibault/tkhq/code/namespaces/preprod/evm-parser/dev.share";
	// let master_seed_path = "/Users/lthibault/tkhq/code/keys/deployment/preprod/evm-parser/manifest-set/dev.secret";

	let b = fs::read(sharepath).unwrap();
	let master_seed_hex_bytes = fs::read(master_seed_path).unwrap();
	let master_seed_utf8 = std::str::from_utf8(&master_seed_hex_bytes).unwrap();
	let master_seed = qos_hex::decode(master_seed_utf8).unwrap();
	let encryption_pair_secret = derive_secret(&master_seed.try_into().unwrap(), P256_ENCRYPT_DERIVE_PATH).unwrap();
	let pair = P256EncryptPair::from_bytes(&encryption_pair_secret).unwrap();


	let encrypt_keypair_bytes = fs::read(master_seed_path).unwrap();
	let encrypt_keypair_utf8 = std::str::from_utf8(&encrypt_keypair_bytes).unwrap();
	let encrypt_keypair = qos_hex::decode(encrypt_keypair_utf8).unwrap();
	let direct_pair = P256EncryptPair::from_bytes(&encrypt_keypair).unwrap();
	// let direct_pair = P256EncryptPair::from_bytes(&encryption_pair_secret).expect("I puked");
	
	let result = pair.decrypt(&b).expect("failed to decrypt result");
	println!("{:?}", result);
	
	let direct_result = direct_pair.decrypt(&b).expect("failed to decrypt direct_result");
	println!("{:?}", direct_result);
}

fn assert_can_decrypt(sharepath: String, user_secret_path: String) {
	let b = fs::read(sharepath).unwrap();
	let master_seed_hex_bytes = fs::read(user_secret_path).unwrap();
	let master_seed_utf8 = std::str::from_utf8(&master_seed_hex_bytes).unwrap();
	let master_seed = qos_hex::decode(master_seed_utf8).unwrap();
	let encryption_pair_secret = derive_secret(&master_seed.try_into().unwrap(), P256_ENCRYPT_DERIVE_PATH).unwrap();
	let pair = P256EncryptPair::from_bytes(&encryption_pair_secret).unwrap();
	
	let result = pair.decrypt(&b).unwrap();
	println!("{:?}", result)
}

// REMOVE ME.  This is a hacky sanity check.
#[test]
fn qos_client_and_generate_are_equivalent() {
	let user = files_for_user("some-user".to_string());
	user.must_generate_and_save_user_dir();
	
	let secret_from_code = fs::read(user.secret_key_path()).unwrap();
	assert_eq!(secret_from_code.len(), 64);
	
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-file-key",
			"--master-seed-path",
			&user.secret_key_path(),
			"--pub-path",
			&user.public_key_path(),
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
		
		// HACK:  if it's different, it was overwritten by the qos_client command,
		// so it's at least saving to the same path.
		assert_ne!(secret_from_code, fs::read(user.secret_key_path()).unwrap());
		// From there, we just want to make sure the data has the correct shape.
		assert_eq!(secret_from_code.len(), 64);
}

#[tokio::test]
async fn preprod_reshard() {
	// Step 0:  two new dev keys
	let user1 = files_for_user("user1".to_string());
	let user2 = files_for_user("user2".to_string());

	for u in [user1.clone(), user2.clone()] {
		u.must_generate_and_save_user_dir();
		assert!(Path::new(&u.public_key_path()).is_file());
		assert!(Path::new(&u.secret_key_path()).is_file());
	}
	
	// Step 1:  load dev secret
	let dev_secret_utf8_bytes = read_dev_secret();
	let dev_secret_hex_bytes = qos_hex::decode(std::str::from_utf8(&dev_secret_utf8_bytes).unwrap()).unwrap();
	let dev_key = P256Pair::from_master_seed(&dev_secret_hex_bytes.clone().try_into().unwrap()).unwrap();
	
	// Step 2:  for each quorum key that we want to reshard...
	let encrypted_evm_parser_dev_share = fs::read("/Users/lthibault/tkhq/code/namespaces/preprod/evm-parser/dev.share").unwrap();
	let decrypted_evm_parser_dev_share = dev_key.decrypt(&encrypted_evm_parser_dev_share).unwrap();
	
	let reconstructed = shares_reconstruct(&[decrypted_evm_parser_dev_share]);
	let pk = P256Pair::from_master_seed(&reconstructed.clone().try_into().unwrap()).unwrap().public_key();
	println!("{}", qos_hex::encode(&pk.to_bytes()));

	// Step 4: Shard the master seed into 2 partitions (shares)
	let threshold = 2;
	let new_shares = shares_generate(&reconstructed, threshold, 2); // (threshold, total)


	// Step 5: Encrypt and save the new shares to files in /tmp/
    let user1_share_path = "/tmp/1_reshard.share";
    let user2_share_path = "/tmp/2_reshard.share";

    // Load the key pairs for user1 and user2
    let user1_key_pair = P256Pair::from_hex_file(format!("{}/{}", user1.personal_dir(), user1.private_share_key)).unwrap();
    let user2_key_pair = P256Pair::from_hex_file(format!("{}/{}", user2.personal_dir(), user2.private_share_key)).unwrap();

    // Encrypt the shares
    let encrypted_share_user1 = user1_key_pair.public_key().encrypt(&new_shares[0]).unwrap();
    let encrypted_share_user2 = user2_key_pair.public_key().encrypt(&new_shares[1]).unwrap();

    // Save the encrypted shares
    fs::write(&user1_share_path, &encrypted_share_user1).unwrap();
    fs::write(&user2_share_path, &encrypted_share_user2).unwrap();
	for (u, share_path) in [(user1, user1_share_path), (user2, user2_share_path)] {
		assert_can_decrypt(
			share_path.to_string(),
			u.secret_key_path());
	}

    // Verify that the encrypted shares were successfully saved
    assert!(Path::new(&user1_share_path).is_file());
    assert!(Path::new(&user2_share_path).is_file());

    println!("Encrypted share for user1 saved to: {}", user1_share_path);
    println!("Encrypted share for user2 saved to: {}", user2_share_path);
}

#[derive(Clone)]
struct UserFiles {
	name: String,
	private_share_key: String,
	public_share_key: String,
}

fn files_for_user(name: String) -> UserFiles {
	let get_key_paths =
		|user: &str| (format!("{user}.secret"), format!("{user}.pub"));

	let (private_share_key, public_share_key) = get_key_paths(&name);
	
	return UserFiles {
		 name: name,
		 private_share_key: private_share_key,
		 public_share_key: public_share_key
	}
}

impl UserFiles {
	fn must_generate_and_save_user_dir(&self) {
		// See qos_client::src::cli::services::generate_file_key
		let share_key_pair =
			P256Pair::generate().expect("unable to generate P256 keypair");
	
		// Write the personal key secret
		write_with_msg(
			self.secret_key_path().as_ref(),
			&share_key_pair.to_master_seed_hex(),
			"Master Seed",
		);

		// Write the setup key public key
		write_with_msg(
			self.public_key_path().as_ref(),
			&share_key_pair.public_key().to_hex_bytes(),
			"File Key Public",
		);

		// let user_keypair = P256Pair::generate().expect("unable to generate P256 keypair");
		// let user_master_seed_hex= user_keypair.to_master_seed_hex();

		// fs::create_dir_all(self.personal_dir()).unwrap();
		// fs::write(self.secret_path(), &user_master_seed_hex).unwrap();
		// fs::write(self.public_path(), qos_hex::encode(&user_keypair.public_key().to_bytes())).unwrap();
	}

	fn secret_key_path(&self) -> String {
		return format!("{}/{}", self.personal_dir(), self.private_share_key);
	}

	fn public_key_path(&self) -> String {
		return format!("{}/{}", self.personal_dir(), self.public_share_key);
	}

	fn personal_dir(&self) -> String {
		return format!("/tmp/personal/{}-dir", self.name)
	}
}

fn read_dev_secret() -> Vec<u8> {
	let path = "/Users/lthibault/tkhq/code/keys/deployment/preprod/evm-parser/manifest-set/dev.secret";  // picked arbitrarily; should all be the same
	return fs::read(path).unwrap();  // this key decrypts dev shares
}

/// Write `buf` to the file specified by `path` and write to stdout that
/// `item_name` was written to `path`.
/// 
/// Copied from qos_client::src::cli::servies
fn write_with_msg(path: &Path, buf: &[u8], item_name: &str) {
	let path_str = path.as_os_str().to_string_lossy();
	fs::write(path, buf).unwrap_or_else(|_| {
		panic!("Failed writing {} to file", path_str.clone())
	});
	println!("{item_name} written to: {path_str}");
}

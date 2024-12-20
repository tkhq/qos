//! Utility script to reshard old dev shares into 2 pieces.
//! This lets us test "true" quorum settings instead of relying on a 1-out-of-1
//! quorum.
use std::{
	fs,
	path::Path,
	process::Command,
	time::{SystemTime, UNIX_EPOCH},
};

use qos_crypto::shamir::shares_generate;
use qos_p256::{
	derive_secret, encrypt::P256EncryptPair, P256Pair, P256_ENCRYPT_DERIVE_PATH,
};

// Note: the dev secret can also be found in our keys repo
// (tkhq/keys:deployment/preprod/evm-parser/manifest-set/dev.secret)
// This secret is not security sensitive since it belongs to our dev/preprod
// environment I've also chosen to commit the old encrypted shares and quorum
// public keys because they're useful anchors for this tests. The quorum public
// keys and old dev shares for each enclaves are committed in
// ./fixtures/preprod/$ENCLAVE_NAME/
const OLD_DEV_SECRET_PATH: &str = "./fixtures/preprod/old_dev.secret.keep";

#[test]
fn preprod_reshard_ceremony() {
	// Global setup: our test will write to a new folder in `/tmp`
	let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let tmp_dir =
		format!("/tmp/preprod-reshard-{}", unix_timestamp.as_millis());
	fs::create_dir_all(&tmp_dir).unwrap();

	let tmp_path = |file: &str| -> String { format!("{}/{file}", tmp_dir) };

	let dev_users_dir = tmp_path("dev-users");
	fs::create_dir_all(dev_users_dir.clone()).unwrap();

	let enclaves_dir = tmp_path("enclaves");
	fs::create_dir_all(enclaves_dir.clone()).unwrap();

	let user_dir = |user: &str| format!("{}/{}", dev_users_dir, user);
	let enclave_dir = |enclave: &str| format!("{}/{}", enclaves_dir, enclave);
	let get_key_paths =
		|user: &str| (format!("{user}.secret"), format!("{user}.pub"));

	let user1 = "1";
	let (user1_private_path, user1_public_path) = get_key_paths(user1);

	let user2 = "2";
	let (user2_private_path, user2_public_path) = get_key_paths(user2);

	// Generate user directories and keys
	for (user, private, public) in [
		(&user1, &user1_private_path, &user1_public_path),
		(&user2, &user2_private_path, &user2_public_path),
	] {
		fs::create_dir_all(user_dir(user)).unwrap();

		let master_seed_path = format!("{}/{}", user_dir(user), private);
		let public_path = format!("{}/{}", user_dir(user), public);
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

		// Assert both public and private key paths now exist
		assert!(Path::new(&*user_dir(user)).join(public).is_file());
		assert!(Path::new(&*user_dir(user)).join(private).is_file());
	}

	// Load previous dev secret (1/1 setting)
	let dev_secret_utf8_bytes = fs::read(OLD_DEV_SECRET_PATH).unwrap();
	let dev_secret_hex_bytes =
		qos_hex::decode(std::str::from_utf8(&dev_secret_utf8_bytes).unwrap())
			.unwrap();
	let dev_key = P256Pair::from_master_seed(
		&dev_secret_hex_bytes.clone().try_into().unwrap(),
	)
	.unwrap();

	// For each of the enclaves...
	for enclave_name in [
		"ump",
		"evm-parser",
		"notarizer",
		"signer",
		"tls-fetcher",
		"deploy-test",
	] {
		// Decrypt the old dev share and assert that the resulting quorum key
		// has the right public key. Decrypted dev shares are _basically_ master
		// seeds. They're just have a "01" prefix because it's the one and only
		// "share" in a 1/1 SSS sharing.
		let encrypted_old_dev_share = fs::read(format!(
			"./fixtures/preprod/{}/old_dev.share.keep",
			enclave_name
		))
		.unwrap();
		let mut decrypted_dev_share =
			dev_key.decrypt(&encrypted_old_dev_share).unwrap();
		let removed_byte = decrypted_dev_share.remove(0);
		assert_eq!(removed_byte, 1);

		let pk = P256Pair::from_master_seed(
			&decrypted_dev_share.clone().try_into().unwrap(),
		)
		.unwrap()
		.public_key();
		let expected_quorum_public_key = fs::read(format!(
			"./fixtures/preprod/{}/quorum_key.pub",
			enclave_name
		))
		.unwrap();
		assert_eq!(
			qos_hex::encode(&pk.to_bytes()),
			std::str::from_utf8(&expected_quorum_public_key).unwrap()
		);

		// Now we have the proper quorum key, we're ready to shard it in two
		// pieces, to our two new users.
		let new_shares = shares_generate(&decrypted_dev_share, 2, 2).unwrap(); // (threshold, total)
		assert_eq!(new_shares.len(), 2);

		for (user, share) in
			[(&user1, &new_shares[0]), (&user2, &new_shares[1])]
		{
			// Load the key pair for this user
			let user_secret_path =
				format!("{}/{}.secret", user_dir(user), user);
			let user_key_pair =
				P256Pair::from_hex_file(user_secret_path.clone()).unwrap();
			// Encrypt the new share to it
			let encrypted_share =
				user_key_pair.public_key().encrypt(share).unwrap();

			// And write the resulting file
			fs::create_dir_all(enclave_dir(enclave_name)).unwrap();
			let encrypted_share_path =
				format!("{}/{}.share", enclave_dir(enclave_name), user);
			fs::write(encrypted_share_path.clone(), encrypted_share).unwrap();

			// Just to make sure: can the user decrypt the share we just created
			// with their secret?
			assert_can_decrypt(user_secret_path, encrypted_share_path);
		}
	}

	println!("success, reshard complete. Outputs are in {}", tmp_dir);
}

// Helper function to assert a given user secret (1st arg) can decrypt a share
// (2nd arg)
fn assert_can_decrypt(user_secret_path: String, sharepath: String) {
	let share = fs::read(sharepath).unwrap();
	let master_seed_hex_bytes = fs::read(user_secret_path).unwrap();
	let master_seed_utf8 = std::str::from_utf8(&master_seed_hex_bytes).unwrap();
	let master_seed = qos_hex::decode(master_seed_utf8).unwrap();
	let encryption_pair_secret = derive_secret(
		&master_seed.try_into().unwrap(),
		P256_ENCRYPT_DERIVE_PATH,
	)
	.unwrap();
	let pair = P256EncryptPair::from_bytes(&encryption_pair_secret).unwrap();
	assert!(pair.decrypt(&share).is_ok());
}

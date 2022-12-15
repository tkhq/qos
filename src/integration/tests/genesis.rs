use std::{fs, io::Read, path::Path, process::Command};

use borsh::de::BorshDeserialize;
use integration::LOCAL_HOST;
use qos_attest::nitro::unsafe_attestation_doc_from_der;
use qos_core::protocol::services::genesis::GenesisOutput;
use qos_crypto::{sha_256, shamir::shares_reconstruct};
use qos_p256::{P256Pair, P256Public};
use qos_test_primitives::{ChildWrapper, PathWrapper};
use rand::{seq::SliceRandom, thread_rng};
use sequoia_openpgp::{
	crypto::SessionKey,
	packet::{PKESK, SKESK},
	parse::{
		stream::{
			DecryptionHelper, DecryptorBuilder, MessageStructure,
			VerificationHelper,
		},
		Parse,
	},
	policy::{Policy, StandardPolicy},
	types::SymmetricAlgorithm,
	Cert, Fingerprint, KeyHandle,
};

const DR_KEY_PUBLIC_PATH: &str = "./mock/dr/dr_public.pgp";
const DR_KEY_PRIVATE_PATH: &str = "./mock/dr/dr_private.pgp";

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
		format!("{}/dr_wrapped_quorum_key.asc", &*genesis_dir);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", &*all_personal_dir, user);
	let get_key_paths =
		|user: &str| (format!("{}.secret", user), format!("{}.pub", user));

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
		fs::create_dir_all(&personal_dir(user)).unwrap();
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
			"--qos-build-fingerprints",
			"./mock/qos-build-fingerprints.txt",
			"--pcr3-preimage-path",
			"./mock/pcr3-preimage.txt",
			"--dr-key-cert-path",
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

			assert_eq!(sha_256(&plain_text_share), member.share_hash);

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
				"--qos-build-fingerprints",
				"./mock/qos-build-fingerprints.txt",
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
			Path::new(&personal_dir(user)).join(format!("{}.secret", user));
		let share_path =
			Path::new(&personal_dir(user)).join(format!("{}.share", user));
		let share_key_pair = P256Pair::from_hex_file(share_key_path).unwrap();

		// Check the share is encrypted to personal key
		let share =
			share_key_pair.decrypt(&fs::read(share_path).unwrap()).unwrap();
		// Cross check that the share belongs `decrypted_shares`, which we
		// created out of band in this test.
		assert!(decrypted_shares.contains(&share));
	}

	// Check the Encrypted DR Key
	let p = StandardPolicy::new();
	let dr_key_cert = Cert::from_file(DR_KEY_PRIVATE_PATH).unwrap();
	let helper = Helper { secret: &dr_key_cert, policy: &p };
	let mut decryptor = DecryptorBuilder::from_file(dr_wrapped_quorum_key_path)
		.unwrap()
		.with_policy(&p, None, helper)
		.unwrap();

	let mut quorum_master_seed_buf = Vec::new();
	decryptor.read_to_end(&mut quorum_master_seed_buf).unwrap();
	let quorum_master_seed: [u8; 32] =
		quorum_master_seed_buf.try_into().unwrap();
	let pair = P256Pair::from_master_seed(&quorum_master_seed).unwrap();
	assert!(pair == reconstructed);
}

// Below Helper impl taken from https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/openpgp/examples/generate-encrypt-decrypt.rs
struct Helper<'a> {
	secret: &'a Cert,
	policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
	fn get_certs(
		&mut self,
		_ids: &[KeyHandle],
	) -> sequoia_openpgp::Result<Vec<Cert>> {
		// Return public keys for signature verification here.
		Ok(Vec::new())
	}

	fn check(
		&mut self,
		_structure: MessageStructure,
	) -> sequoia_openpgp::Result<()> {
		// Implement your signature verification policy here.
		Ok(())
	}
}

impl<'a> DecryptionHelper for Helper<'a> {
	fn decrypt<D>(
		&mut self,
		pkesks: &[PKESK],
		_skesks: &[SKESK],
		sym_algo: Option<SymmetricAlgorithm>,
		mut decrypt: D,
	) -> sequoia_openpgp::Result<Option<Fingerprint>>
	where
		D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
	{
		let key = self
			.secret
			.keys()
			.unencrypted_secret()
			.with_policy(self.policy, None)
			.for_storage_encryption()
			.next()
			.unwrap()
			.key()
			.clone();

		// The secret key is not encrypted.
		let mut pair = key.into_keypair().unwrap();

		pkesks[0]
			.decrypt(&mut pair, sym_algo)
			.map(|(algo, session_key)| decrypt(algo, &session_key));

		// XXX: In production code, return the Fingerprint of the
		// recipient's Cert here
		Ok(None)
	}
}

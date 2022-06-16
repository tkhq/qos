use std::{path::Path, process::Command};

use borsh::de::BorshDeserialize;
use qos_client::attest;
use qos_core::protocol::services::genesis::GenesisOutput;
use qos_crypto::{shamir::shares_reconstruct, RsaPair, RsaPub};
use rand::{seq::SliceRandom, thread_rng};

#[tokio::test]
async fn genesis_e2e() {
	let usock = "genesis_e2e.sock";
	let host_port = "3008";
	let host_ip = "127.0.0.1";
	let secret_path = "./genesis_e2e.secret";
	let pivot_path = "./genesis_e2e.pivot";

	let key_dir = "./genesis-setup-tmp";
	let namespace = "vapers-only";
	let genesis_output_dir = "./genesis-out-tmp";
	let attestation_doc_path =
		format!("{}/attestation_doc.genesis", genesis_output_dir);
	let genesis_output_path = format!("{}/output.genesis", genesis_output_dir);

	let get_key_paths = |user: String| {
		(
			format!("{}/{}.{}.setup.key", key_dir, user, namespace),
			format!("{}/{}.{}.setup.pub", key_dir, user, namespace),
		)
	};

	let threshold = 2;
	let user1 = "user1";
	let (user1_private_setup, user1_public_setup) =
		get_key_paths(user1.to_string());

	let user2 = "user2";
	let (user2_private_setup, user2_public_setup) =
		get_key_paths(user2.to_string());

	let user3 = "user3";
	let (user3_private_setup, user3_public_setup) =
		get_key_paths(user3.to_string());

	// -- CLIENT Create 3 setup keys
	// Make sure the directory keys are getting written to already exist.
	let _ = std::fs::create_dir(key_dir);
	for (u, private, public) in [
		(user1, user1_private_setup, user1_public_setup),
		(user2, user2_private_setup, user2_public_setup),
		(user3, user3_private_setup, user3_public_setup),
	] {
		assert!(Command::new("../target/debug/client_cli")
			.args([
				"generate-setup-key",
				"--key-dir",
				key_dir,
				"--namespace",
				namespace,
				"--alias",
				u,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
		assert!(Path::new(&public).is_file());
		assert!(Path::new(&private).is_file());
	}

	// -- ENCLAVE Start enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--secret-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--mock",
			"true",
		])
		.spawn()
		.unwrap();

	// -- HOST start host
	let mut host_child_process = Command::new("../target/debug/host_cli")
		.args([
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
			"--usock",
			usock,
		])
		.spawn()
		.unwrap();

	// -- Make sure the enclave and host have time to boot
	std::thread::sleep(std::time::Duration::from_secs(1));

	// -- CLIENT Read in files with keys, create genesis input, send genesis
	// input, and write genesis output to file
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"boot-genesis",
			"--threshold",
			"2", // threshold
			"--key-dir",
			key_dir,
			"--out-dir",
			genesis_output_dir,
			"--host-ip",
			host_ip,
			"--host-port",
			host_port
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- Read in files generated from the genesis boot
	// Decode the attestation doc to make sure it passes basic checks
	let _attestation_doc = attest::nitro::attestation_doc_from_der(
		&std::fs::read(attestation_doc_path).unwrap(),
		&attest::nitro::cert_from_pem(attest::nitro::AWS_ROOT_CERT_PEM)
			.expect("AWS ROOT CERT is not valid PEM"),
		attest::nitro::MOCK_SECONDS_SINCE_EPOCH,
	);
	let genesis_output = GenesisOutput::try_from_slice(
		&std::fs::read(genesis_output_path).unwrap(),
	)
	.unwrap();

	// -- Recreate the quorum key from the encrypted shares.
	let mut decrypted_shares: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.map(|member| {
			let (private_setup, _) =
				get_key_paths(member.setup_member.alias.clone());
			let setup_pair = RsaPair::from_pem_file(private_setup).unwrap();

			// Decrypt the personal key with the setup key
			let personal_key = RsaPair::from_der(
				&setup_pair
					.envelope_decrypt(&member.encrypted_personal_key)
					.unwrap(),
			)
			.unwrap();

			// Decrypt the share with the personal key
			personal_key
				.envelope_decrypt(&member.encrypted_quorum_key_share)
				.unwrap()
		})
		.collect();

	decrypted_shares.shuffle(&mut thread_rng());
	let reconstructed =
		RsaPair::from_der(&shares_reconstruct(&decrypted_shares[0..threshold]))
			.unwrap();
	assert_eq!(
		*reconstructed.public_key(),
		RsaPub::from_der(&genesis_output.quorum_key).unwrap()
	);

	// -- Clean up
	for file in
		[secret_path.to_string(), pivot_path.to_string(), usock.to_string()]
	{
		let _ = std::fs::remove_file(file);
	}
	let _ = std::fs::remove_dir_all(key_dir);
	let _ = std::fs::remove_dir_all(genesis_output_dir);
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
}

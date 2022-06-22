use std::{fs, path::Path, process::Command};

use borsh::de::BorshDeserialize;
use qos_client::attest;
use qos_core::{
	hex,
	protocol::{
		services::{
			boot::{
				Approval, Manifest, Namespace, NitroConfig, PivotConfig,
				QuorumMember, QuorumSet, RestartPolicy,
			},
			genesis::GenesisOutput,
		},
		QosHash,
	},
};
use qos_crypto::{sha_256, shamir::shares_reconstruct, RsaPair, RsaPub};
use qos_test::PIVOT_OK_PATH;
use rand::{seq::SliceRandom, thread_rng};

#[tokio::test]
async fn boot_e2e() {
	let usock = "boot_e2e.sock";
	let host_port = "3009";
	let host_ip = "127.0.0.1";
	let secret_path = "./boot_e2e.secret";
	let pivot_path = "./boot_e2e.pivot";

	let manifest_dir = "./boot-e2e-manifest-tmp";
	let key_dir = "./boot-e2e-genesis-setup-tmp";
	let namespace = "quit-coding-to-vape";
	let genesis_output_dir = "./boot-e2e-genesis-out-tmp";
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
	let _ = fs::create_dir(key_dir);
	for (u, private, public) in [
		(&user1, &user1_private_setup, &user1_public_setup),
		(&user2, &user2_private_setup, &user2_public_setup),
		(&user3, &user3_private_setup, &user3_public_setup),
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

	// -- ENCLAVE start enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--secret-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--mock",
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

	// Kill the enclave and host - we will restart them later for standard boot
	assert!(host_child_process.kill().is_ok());
	assert!(enclave_child_process.kill().is_ok());

	// -- Read in files generated from the genesis boot
	// Decode the attestation doc to make sure it passes basic checks
	let _attestation_doc = attest::nitro::attestation_doc_from_der(
		&fs::read(attestation_doc_path).unwrap(),
		&attest::nitro::cert_from_pem(attest::nitro::AWS_ROOT_CERT_PEM)
			.expect("AWS ROOT CERT is not valid PEM"),
		attest::nitro::MOCK_SECONDS_SINCE_EPOCH,
	);
	let genesis_output =
		GenesisOutput::try_from_slice(&fs::read(&genesis_output_path).unwrap())
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

	// -- CLIENT make sure each user can run `after-genesis` against their
	// member output and setup key
	let get_after_paths = |user: String| {
		(
			format!(
				"{}/{}.{}.personal.pub",
				genesis_output_dir, user, namespace
			),
			format!(
				"{}/{}.{}.personal.key",
				genesis_output_dir, user, namespace
			),
			format!("{}/{}.{}.share", genesis_output_dir, user, namespace),
		)
	};
	let mock_pcr = vec![0u8; 48];
	let mock_pcr_hex = &qos_core::hex::encode(&mock_pcr);
	for (u, setup_key_path) in [
		(user1, &user1_private_setup),
		(user2, &user2_private_setup),
		(user3, &user3_private_setup),
	] {
		assert!(Command::new("../target/debug/client_cli")
			.args([
				"after-genesis",
				"--setup-key-path",
				setup_key_path,
				"--genesis-dir",
				genesis_output_dir,
				"--pcr0",
				mock_pcr_hex,
				"--pcr1",
				mock_pcr_hex,
				"--pcr2",
				mock_pcr_hex
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
		let (personal_pub, personal_priv, share_path) =
			get_after_paths(u.to_string());

		// Read in the personal public and private key
		let public = RsaPub::from_pem_file(personal_pub).unwrap();
		let private = RsaPair::from_pem_file(personal_priv).unwrap();
		assert_eq!(
			private.public_key_to_der().unwrap(),
			public.public_key_to_der().unwrap()
		);
		// Check the share is encrypted to personal key
		let share =
			private.envelope_decrypt(&fs::read(share_path).unwrap()).unwrap();
		// Cross check that the share belongs `decrypted_shares`, which we
		// created out of band in this test.
		assert!(decrypted_shares.contains(&share));
	}

	// -- CLIENT create manifest.
	// Make sure the dir we are writing the manifest too exists
	let _ = fs::create_dir(manifest_dir);
	let pivot = fs::read(PIVOT_OK_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let mock_pivot_hash_hex = hex::encode(&mock_pivot_hash);
	// Put the root cert in the key dir just to make after test clean up easier
	let root_cert_path = format!("{}/root-cert.pem", manifest_dir);
	fs::write(&root_cert_path, attest::nitro::AWS_ROOT_CERT_PEM).unwrap();

	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-manifest",
			"--genesis-out-path",
			genesis_output_path.as_str(),
			"--nonce",
			"2",
			"--namespace",
			namespace,
			"--pivot-hash",
			&mock_pivot_hash_hex,
			"--restart-policy",
			"always",
			"--pcr0",
			mock_pcr_hex,
			"--pcr1",
			mock_pcr_hex,
			"--pcr2",
			mock_pcr_hex,
			"--root-cert-path",
			&root_cert_path,
			"--out-dir",
			manifest_dir,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check the manifest written to file
	let manifest_path = format!("{}/{}.2.manifest", manifest_dir, namespace);
	let manifest = {
		let buf = fs::read(&manifest_path).unwrap();
		Manifest::try_from_slice(&buf).unwrap()
	};
	let quorum_set_members: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.map(|m| QuorumMember {
			alias: m.setup_member.alias.clone(),
			pub_key: m.public_personal_key.clone(),
		})
		.collect();
	assert_eq!(
		manifest,
		Manifest {
			namespace: Namespace { name: namespace.to_string(), nonce: 2 },
			pivot: PivotConfig {
				hash: mock_pivot_hash.try_into().unwrap(),
				restart: RestartPolicy::Always
			},
			quorum_key: genesis_output.quorum_key.clone(),
			quorum_set: QuorumSet {
				threshold: genesis_output.threshold,
				members: quorum_set_members
			},
			enclave: NitroConfig {
				pcr0: mock_pcr.clone(),
				pcr1: mock_pcr.clone(),
				pcr2: mock_pcr,
				aws_root_certificate: attest::nitro::cert_from_pem(
					attest::nitro::AWS_ROOT_CERT_PEM
				)
				.unwrap()
			},
		}
	);

	// -- CLIENT make sure each user can run `sign-manifest`
	for alias in [user1, user2, user3] {
		let (_, personal_path, _) = get_after_paths(alias.to_string());
		let approval_path = format!(
			"{}/{}.{}.{}.approval",
			manifest_dir, alias, namespace, manifest.namespace.nonce,
		);
		assert!(!Path::new(&approval_path).exists());

		assert!(Command::new("../target/debug/client_cli")
			.args([
				"sign-manifest",
				"--manifest-hash",
				hex::encode(&manifest.qos_hash()).as_str(),
				"--personal-key-path",
				&personal_path,
				"--manifest-path",
				&manifest_path,
				"--out-dir",
				manifest_dir,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		// Read in the generated approval to check it was created correctly
		let approval =
			Approval::try_from_slice(&fs::read(approval_path).unwrap())
				.unwrap();
		let personal_pair = RsaPair::from_pem_file(personal_path).unwrap();

		let signature =
			personal_pair.sign_sha256(&manifest.qos_hash()).unwrap();
		assert_eq!(approval.signature, signature);

		assert_eq!(approval.member.alias, alias);
		assert_eq!(
			approval.member.pub_key,
			personal_pair.public_key_to_der().unwrap(),
		);
	}

	// -- ENCLAVE start enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--secret-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--mock",
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

	// -- CLIENT broadcast boot standard instruction
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"boot-standard",
			"--boot-dir",
			manifest_dir,
			"--pivot-path",
			PIVOT_OK_PATH,
			"--host-port",
			host_port,
			"--host-ip",
			host_ip,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- Clean up
	for file in
		[secret_path.to_string(), pivot_path.to_string(), usock.to_string()]
	{
		let _ = fs::remove_file(file);
	}
	let _ = fs::remove_dir_all(key_dir);
	let _ = fs::remove_dir_all(genesis_output_dir);
	let _ = fs::remove_dir_all(manifest_dir);
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
}

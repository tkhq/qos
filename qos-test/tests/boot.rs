use std::{fs, process::Command};

use borsh::de::BorshDeserialize;
use qos_client::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
	MOCK_SECONDS_SINCE_EPOCH,
};
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
use qos_crypto::{sha_256, RsaPair};
use qos_test::PIVOT_OK2_PATH;



//   "Measurements": {                                                                                                   │69 |     BadEphemeralKeyPath
//     "HashAlgorithm": "Sha384 { ... }",                                                                                │   |     ^^^^^^^^^^^^^^^^^^^
//     "PCR0": "8cceb679ae5c334c88b21a40478593f2ae8fbf2c63f0705cc503aa129ef9341e6f55f2d4b0e0c99e7ef30d6b13ead8af",       │
//     "PCR1": "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",       │   Compiling qos-host v0.1.0 (/home/tk/src/qos/qos-host)
//     "PCR2": "99e38c61adeda7c1686416518f9e9f5516e5c6b3d4046de6da99702febf39efa5162d9ce74320e3f05defef3b694c296"        │warning: `qos-core` (lib) generated 2 warnings
//   }   

const EPH_PATH: &str = "../qos-core/src/protocol/attestor/static/boot_e2e_mock_eph.secret";
const PCR0: &str = "8cceb679ae5c334c88b21a40478593f2ae8fbf2c63f0705cc503aa129ef9341e6f55f2d4b0e0c99e7ef30d6b13ead8af";
const PCR1: &str = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";
const PCR2: &str = "99e38c61adeda7c1686416518f9e9f5516e5c6b3d4046de6da99702febf39efa5162d9ce74320e3f05defef3b694c296";


#[tokio::test]
async fn boot_e2e() {
	let manifest_hash = "ef3decf6a20cee82b0891383a59940960435349a334792866d0ae570fc8eef2c";
	let eph_path = EPH_PATH;

	let usock = "boot_e2e.sock";
	let host_port = "3009";
	let host_ip = "127.0.0.1";
	let tmp = "./tmp";
	fs::create_dir_all(tmp).unwrap();
	let secret_path = "./tmp/boot_e2e.secret";
	let pivot_path = "./tmp/boot_e2e.pivot";

	let boot_dir = "./boot-e2e-boot-dir-tmp";
	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";
	let genesis_dir = "./mock/boot-e2e/genesis-dir";
	let root_cert_path = "./mock/boot-e2e/root-cert.pem";

	let namespace = "quit-coding-to-vape";

	let attestation_doc_path = format!("{}/attestation_doc.boot", boot_dir);
	let genesis_output_path = format!("{}/output.genesis", genesis_dir);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", all_personal_dir, user);

	let user1 = "user1";
	let user2 = "user2";
	let user3 = "user3";

	// // -- CLIENT create manifest.
	let pivot = fs::read(PIVOT_OK2_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let mock_pivot_hash_hex = hex::encode(&mock_pivot_hash);

	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-manifest",
			"--genesis-dir",
			genesis_dir,
			"--nonce",
			"2",
			"--namespace",
			namespace,
			"--pivot-hash",
			&mock_pivot_hash_hex,
			"--restart-policy",
			"always",
			"--pcr0",
			PCR0,
			"--pcr1",
			PCR1,
			"--pcr2",
			PCR2,
			"--root-cert-path",
			root_cert_path,
			"--boot-dir",
			boot_dir,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check the manifest written to file
	let manifest_path = format!("{}/{}.2.manifest", boot_dir, namespace);
	let manifest =
		Manifest::try_from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

	let genesis_output =
		GenesisOutput::try_from_slice(&fs::read(&genesis_output_path).unwrap())
			.unwrap();

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
				hash: mock_pivot_hash,
				restart: RestartPolicy::Always
			},
			quorum_key: genesis_output.quorum_key.clone(),
			quorum_set: QuorumSet {
				threshold: genesis_output.threshold,
				members: quorum_set_members
			},
			enclave: NitroConfig {
				pcr0: hex::decode(PCR0).unwrap(),
				pcr1: hex::decode(PCR1).unwrap(),
				pcr2: hex::decode(PCR2).unwrap(),
				aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap()
			},
		}
	);

	// -- CLIENT make sure each user can run `sign-manifest`
	for alias in [user1, user2, user3] {
		let approval_path = format!(
			"{}/{}.{}.{}.approval",
			boot_dir, alias, namespace, manifest.namespace.nonce,
		);

		println!("{}", hex::encode(&manifest.qos_hash()));

		assert!(Command::new("../target/debug/client_cli")
			.args([
				"sign-manifest",
				"--manifest-hash",
				hex::encode(&manifest.qos_hash()).as_str(),
				"--personal-dir",
				&personal_dir(alias),
				"--boot-dir",
				boot_dir,
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
		let personal_pair = RsaPair::from_pem_file(&format!(
			"{}/{}.{}.personal.key",
			personal_dir(alias),
			alias,
			namespace
		))
		.unwrap();

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
			"--ephemeral-file",
			eph_path,
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
			boot_dir,
			"--pivot-path",
			PIVOT_OK2_PATH,
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
	// Check that the attestation doc was written
	drop(attestation_doc_from_der(
		&fs::read(attestation_doc_path).unwrap(),
		&cert_from_pem(AWS_ROOT_CERT_PEM)
			.expect("AWS ROOT CERT is not valid PEM"),
		MOCK_SECONDS_SINCE_EPOCH,
	));

	// TODO: need to have an attestation doc with an ephemeral key we know
	// For each user, post a share
	for user in [&user1, &user2] {
		assert!(Command::new("../target/debug/client_cli")
		.args([
			"post-share",
			"--boot-dir",
			boot_dir,
			"--personal-dir",
			&personal_dir(&user1),
			"--manifest-hash",
			hex::encode(&manifest.qos_hash()).as_str(),
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
	}

	for f in [&secret_path, &pivot_path, &usock, &eph_path] {
		drop(fs::remove_file(f));
	}
	drop(fs::remove_dir_all(boot_dir));
	drop(fs::remove_dir_all(tmp));
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
}

use std::{fs, path::Path, process::Command};

use borsh::de::BorshDeserialize;
use qos_client::attest::{
	self,
	nitro::{
		attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
		MOCK_SECONDS_SINCE_EPOCH,
	},
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

	let boot_dir = "./boot-e2e-boot-dir-tmp";
	let all_personal_dir = "./mock/boot-e2e/personal-dir";
	let genesis_dir = "./mock/boot-e2e/boot-e2e-genesis-tmp";
	let namespace = "quit-coding-to-vape";

	let attestation_doc_path =
		format!("{}/attestation_doc.genesis", genesis_dir);
	let genesis_output_path = format!("{}/output.genesis", genesis_dir);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", all_personal_dir, user);


	let threshold = 2;
	let user1 = "user1";
	let user2 = "user2";
	let user3 = "user3";

	// -- CLIENT Create 3 setup keys
	// Make sure the directory keys are getting written to already exist.

	// // -- CLIENT create manifest.
	// // Make sure the dir we are writing the manifest too exists
	// let _ = fs::create_dir(manifest_dir);
	// let pivot = fs::read(PIVOT_OK_PATH).unwrap();
	// let mock_pivot_hash = sha_256(&pivot);
	// let mock_pivot_hash_hex = hex::encode(&mock_pivot_hash);
	// // Put the root cert in the key dir just to make after test clean up
	// easier let root_cert_path = format!("{}/root-cert.pem", manifest_dir);
	// fs::write(&root_cert_path, attest::nitro::AWS_ROOT_CERT_PEM).unwrap();

	// assert!(Command::new("../target/debug/client_cli")
	// 	.args([
	// 		"generate-manifest",
	// 		"--genesis-out-path",
	// 		genesis_output_path.as_str(),
	// 		"--nonce",
	// 		"2",
	// 		"--namespace",
	// 		namespace,
	// 		"--pivot-hash",
	// 		&mock_pivot_hash_hex,
	// 		"--restart-policy",
	// 		"always",
	// 		"--pcr0",
	// 		mock_pcr_hex,
	// 		"--pcr1",
	// 		mock_pcr_hex,
	// 		"--pcr2",
	// 		mock_pcr_hex,
	// 		"--root-cert-path",
	// 		&root_cert_path,
	// 		"--out-dir",
	// 		manifest_dir,
	// 	])
	// 	.spawn()
	// 	.unwrap()
	// 	.wait()
	// 	.unwrap()
	// 	.success());

	// // Check the manifest written to file
	// let manifest_path = format!("{}/{}.2.manifest", manifest_dir, namespace);
	// let manifest = {
	// 	let buf = fs::read(&manifest_path).unwrap();
	// 	Manifest::try_from_slice(&buf).unwrap()
	// };
	// let quorum_set_members: Vec<_> = genesis_output
	// 	.member_outputs
	// 	.iter()
	// 	.map(|m| QuorumMember {
	// 		alias: m.setup_member.alias.clone(),
	// 		pub_key: m.public_personal_key.clone(),
	// 	})
	// 	.collect();
	// assert_eq!(
	// 	manifest,
	// 	Manifest {
	// 		namespace: Namespace { name: namespace.to_string(), nonce: 2 },
	// 		pivot: PivotConfig {
	// 			hash: mock_pivot_hash,
	// 			restart: RestartPolicy::Always
	// 		},
	// 		quorum_key: genesis_output.quorum_key.clone(),
	// 		quorum_set: QuorumSet {
	// 			threshold: genesis_output.threshold,
	// 			members: quorum_set_members
	// 		},
	// 		enclave: NitroConfig {
	// 			pcr0: mock_pcr.clone(),
	// 			pcr1: mock_pcr.clone(),
	// 			pcr2: mock_pcr,
	// 			aws_root_certificate: attest::nitro::cert_from_pem(
	// 				attest::nitro::AWS_ROOT_CERT_PEM
	// 			)
	// 			.unwrap()
	// 		},
	// 	}
	// );

	// // -- CLIENT make sure each user can run `sign-manifest`
	// for alias in [user1, user2, user3] {
	// 	let (_, personal_path, _) = get_after_paths(alias.to_string());
	// 	let approval_path = format!(
	// 		"{}/{}.{}.{}.approval",
	// 		manifest_dir, alias, namespace, manifest.namespace.nonce,
	// 	);
	// 	assert!(!Path::new(&approval_path).exists());

	// 	assert!(Command::new("../target/debug/client_cli")
	// 		.args([
	// 			"sign-manifest",
	// 			"--manifest-hash",
	// 			hex::encode(&manifest.qos_hash()).as_str(),
	// 			"--personal-key-path",
	// 			&personal_path,
	// 			"--manifest-path",
	// 			&manifest_path,
	// 			"--out-dir",
	// 			manifest_dir,
	// 		])
	// 		.spawn()
	// 		.unwrap()
	// 		.wait()
	// 		.unwrap()
	// 		.success());

	// 	// Read in the generated approval to check it was created correctly
	// 	let approval =
	// 		Approval::try_from_slice(&fs::read(approval_path).unwrap())
	// 			.unwrap();
	// 	let personal_pair = RsaPair::from_pem_file(personal_path).unwrap();

	// 	let signature =
	// 		personal_pair.sign_sha256(&manifest.qos_hash()).unwrap();
	// 	assert_eq!(approval.signature, signature);

	// 	assert_eq!(approval.member.alias, alias);
	// 	assert_eq!(
	// 		approval.member.pub_key,
	// 		personal_pair.public_key_to_der().unwrap(),
	// 	);
	// }

	// // -- ENCLAVE start enclave
	// let mut enclave_child_process = Command::new("../target/debug/core_cli")
	// 	.args([
	// 		"--usock",
	// 		usock,
	// 		"--secret-file",
	// 		secret_path,
	// 		"--pivot-file",
	// 		pivot_path,
	// 		"--mock",
	// 	])
	// 	.spawn()
	// 	.unwrap();

	// // -- HOST start host
	// let mut host_child_process = Command::new("../target/debug/host_cli")
	// 	.args([
	// 		"--host-port",
	// 		host_port,
	// 		"--host-ip",
	// 		host_ip,
	// 		"--usock",
	// 		usock,
	// 	])
	// 	.spawn()
	// 	.unwrap();

	// // -- Make sure the enclave and host have time to boot
	// std::thread::sleep(std::time::Duration::from_secs(1));

	// // -- CLIENT broadcast boot standard instruction
	// assert!(Command::new("../target/debug/client_cli")
	// 	.args([
	// 		"boot-standard",
	// 		"--boot-dir",
	// 		manifest_dir,
	// 		"--pivot-path",
	// 		PIVOT_OK_PATH,
	// 		"--host-port",
	// 		host_port,
	// 		"--host-ip",
	// 		host_ip,
	// 	])
	// 	.spawn()
	// 	.unwrap()
	// 	.wait()
	// 	.unwrap()
	//

	// for path in [secret_path.to_string(), pivot_path.to_string(), usock.to_string()]
	// {
	// 	drop(fs::remove_file(path));
	// }
	// drop(fs::remove_dir_all(genesis_dir));
	// drop(fs::remove_dir_all(all_personal_dir));
	// enclave_child_process.kill().unwrap();
	// host_child_process.kill().unwrap();
}

use std::{
	fs,
	io::Write,
	path::Path,
	process::{Command, Stdio},
};

use borsh::de::BorshDeserialize;
use integration::{LOCAL_HOST, PCR3, PIVOT_OK2_PATH, PIVOT_OK2_SUCCESS_FILE};
use qos_attest::nitro::{cert_from_pem, AWS_ROOT_CERT_PEM};
use qos_core::protocol::{
	attestor::mock::{
		MOCK_NSM_ATTESTATION_DOCUMENT, MOCK_PCR0, MOCK_PCR1, MOCK_PCR2,
	},
	services::{
		boot::{
			Approval, Manifest, ManifestSet, Namespace, NitroConfig,
			PivotConfig, RestartPolicy, ShareSet,
		},
		genesis::{GenesisMemberOutput, GenesisOutput},
	},
	QosHash,
};
use qos_crypto::{sha_256, RsaPair};
use qos_test_primitives::{ChildWrapper, PathWrapper};

const PIVOT_BUILD_FINGERPRINTS_PATH: &str =
	"./mock/pivot-build-fingerprints.txt";

#[tokio::test]
async fn boot_e2e() {
	let host_port = qos_test_primitives::find_free_port().unwrap();
	let tmp: PathWrapper = "/tmp/boot-e2e".into();
	fs::create_dir_all(&*tmp).unwrap();

	let usock: PathWrapper = "/tmp/boot-e2e/boot_e2e.sock".into();
	let secret_path: PathWrapper = "/tmp/boot-e2e/boot_e2e.secret".into();
	let pivot_path: PathWrapper = "/tmp/boot-e2e/boot_e2e.pivot".into();
	let manifest_path: PathWrapper = "/tmp/boot-e2e/boot_e2e.manifest".into();
	let eph_path: PathWrapper = "/tmp/boot-e2e/ephemeral_key.secret".into();

	let boot_dir: PathWrapper = "/tmp/boot-e2e/boot-dir".into();
	fs::create_dir_all(&*boot_dir).unwrap();
	let attestation_dir: PathWrapper = "/tmp/boot-e2e/attestation-dir".into();
	fs::create_dir_all(&*attestation_dir).unwrap();

	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";

	let namespace = "quit-coding-to-vape";

	let attestation_doc_path = format!("{}/boot_attestation_doc", &*boot_dir);

	let personal_dir =
		|user: &str| format!("{}/{}-dir", all_personal_dir, user);

	let user1 = "user1";
	let user2 = "user2";
	let user3 = "user3";

	// -- Create pivot-build-fingerprints.txt
	let pivot = fs::read(PIVOT_OK2_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let build_fingerprints = {
		let mut build_fingerprints =
			qos_hex::encode(&mock_pivot_hash).as_bytes().to_vec();
		build_fingerprints.extend_from_slice(b"\n");
		build_fingerprints.extend_from_slice(b"mock-pivot-commit");
		build_fingerprints
	};
	std::fs::write(PIVOT_BUILD_FINGERPRINTS_PATH, build_fingerprints).unwrap();

	// -- CLIENT create manifest.
	let msg = "testing420";
	let pivot_args = format!("[--msg,{}]", msg);

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-manifest",
			"--nonce",
			"2",
			"--namespace",
			namespace,
			"--restart-policy",
			"never",
			"--pivot-build-fingerprints",
			"./mock/pivot-build-fingerprints.txt",
			"--qos-build-fingerprints",
			"./mock/qos-build-fingerprints.txt",
			"--pcr3-preimage-path",
			"./mock/namespaces/pcr3-preimage.txt",
			"--boot-dir",
			&*boot_dir,
			"--pivot-args",
			&pivot_args,
			"--manifest-set-dir",
			"./mock/keys/manifest-set",
			"--share-set-dir",
			"./mock/keys/share-set",
			"--namespace-dir",
			"./mock/namespaces/quit-coding-to-vape"
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check the manifest written to file
	let cli_manifest_path = format!("{}/{}.2.manifest", &*boot_dir, namespace);
	let manifest =
		Manifest::try_from_slice(&fs::read(&cli_manifest_path).unwrap())
			.unwrap();

	let genesis_output = {
		let contents =
			fs::read("./mock/boot-e2e/genesis-dir/genesis_output").unwrap();
		GenesisOutput::try_from_slice(&contents).unwrap()
	};
	// For simplicity sake, we use the same keys for the share set and manifest
	// set.
	let mut members: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.cloned()
		.map(|GenesisMemberOutput { share_set_member, .. }| share_set_member)
		.collect();
	members.sort();

	let namespace_field = Namespace {
		name: namespace.to_string(),
		nonce: 2,
		quorum_key: genesis_output.quorum_key,
	};
	assert_eq!(manifest.namespace, namespace_field);
	let pivot = PivotConfig {
		commit: "mock-pivot-commit".to_string(),
		hash: mock_pivot_hash,
		restart: RestartPolicy::Never,
		args: vec!["--msg".to_string(), msg.to_string()],
	};
	assert_eq!(manifest.pivot, pivot);
	let manifest_set = ManifestSet { threshold: 2, members: members.clone() };
	assert_eq!(manifest.manifest_set, manifest_set);
	let share_set = ShareSet { threshold: 2, members };
	assert_eq!(manifest.share_set, share_set);
	let enclave = NitroConfig {
		pcr0: qos_hex::decode(MOCK_PCR0).unwrap(),
		pcr1: qos_hex::decode(MOCK_PCR1).unwrap(),
		pcr2: qos_hex::decode(MOCK_PCR2).unwrap(),
		pcr3: qos_hex::decode(PCR3).unwrap(),
		aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
		qos_commit: "mock-qos-commit".to_string(),
	};
	assert_eq!(manifest.enclave, enclave);

	assert_eq!(
		manifest,
		Manifest {
			namespace: namespace_field,
			pivot,
			manifest_set,
			share_set,
			enclave,
		}
	);

	// -- CLIENT make sure each user can run `approve-manifest`
	for alias in [user1, user2, user3] {
		let approval_path = format!(
			"{}/{}.{}.{}.approval",
			&*boot_dir, alias, namespace, manifest.namespace.nonce,
		);

		let mut child = Command::new("../target/debug/qos_client")
			.args([
				"approve-manifest",
				"--personal-dir",
				&personal_dir(alias),
				"--manifest-dir",
				&*boot_dir,
				"--pcr3-preimage-path",
				"./mock/namespaces/pcr3-preimage.txt",
				"--pivot-build-fingerprints",
				"./mock/pivot-build-fingerprints.txt",
				"--qos-build-fingerprints",
				"./mock/qos-build-fingerprints.txt",
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--share-set-dir",
				"./mock/keys/share-set",
				"--namespace-dir",
				"./mock/namespaces/quit-coding-to-vape",
				"--alias",
				alias,
			])
			.stdin(Stdio::piped())
			// .stdout(Stdio::piped())
			.spawn()
			.unwrap();

		// For each of the 4 user prompts, write "yes"+enter to confirm we
		// agree.
		let mut stdin = child.stdin.take().expect("Failed to open stdin");
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");
		stdin.write_all("yes\n".as_bytes()).expect("Failed to write to stdin");

		// Wait for the command to write the approval and exit
		assert!(child.wait().unwrap().success());

		// Read in the generated approval to check it was created correctly
		let approval =
			Approval::try_from_slice(&fs::read(approval_path).unwrap())
				.unwrap();
		let personal_pair = RsaPair::from_pem_file(&format!(
			"{}/{}.{}.share_key.secret",
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
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				&*usock,
				"--quorum-file",
				&*secret_path,
				"--pivot-file",
				&*pivot_path,
				"--ephemeral-file",
				&*eph_path,
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
				&host_port.to_string(),
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

	// -- CLIENT broadcast boot standard instruction
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-standard",
			"--boot-dir",
			&*boot_dir,
			"--pivot-path",
			PIVOT_OK2_PATH,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--pcr3-preimage-path",
			"./mock/pcr3-preimage.txt",
			"--unsafe-skip-attestation",
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let att_doc = fs::read(&attestation_doc_path).unwrap();
	assert_eq!(att_doc, MOCK_NSM_ATTESTATION_DOCUMENT);

	// For each user, post a share,
	// and sanity check the pivot has not yet executed.
	assert!(!Path::new(PIVOT_OK2_SUCCESS_FILE).exists());
	for user in [&user1, &user2] {
		// Get attestation doc and manifest
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"get-attestation-doc",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--attestation-dir",
				&*attestation_dir
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		// Encrypt share to ephemeral key
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"proxy-re-encrypt-share",
				"--attestation-dir",
				&*attestation_dir,
				"--manifest-hash",
				qos_hex::encode(&manifest.qos_hash()).as_str(),
				"--personal-dir",
				&personal_dir(user),
				"--pcr3-preimage-path",
				"./mock/pcr3-preimage.txt",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				&*eph_path,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		// Post the encrypted share
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"post-share",
				"--host-port",
				&host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--attestation-dir",
				&*attestation_dir
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
	}

	// Give the enclave time to start the pivot
	std::thread::sleep(std::time::Duration::from_secs(2));

	// Check that the pivot executed
	let contents = std::fs::read(PIVOT_OK2_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);
	fs::remove_file(PIVOT_OK2_SUCCESS_FILE).unwrap();
}

use std::{fs, process::Command};

use integration::{LOCAL_HOST, MOCK_QOS_RELEASE_DIR, PIVOT_LOOP_PATH};
use qos_crypto::sha_256;
use qos_p256::{P256Pair, P256Public};
use qos_test_primitives::{ChildWrapper, PathWrapper};

const NAMESPACE: &str = "a-namespace";
const CLI_MANIFEST_PATH: &str = "/tmp/key-fwd-e2e/boot-dir/manifest";
const MANIFEST_ENVELOPE_PATH: &str =
	"/tmp/key-fwd-e2e/boot-dir/manifest_envelope";
const ALL_PERSONAL_DIR: &str = "./mock/boot-e2e/all-personal-dir";
const BOOT_DIR: &str = "/tmp/key-fwd-e2e/boot-dir";
const TMP_DIR: &str = "/tmp/key-fwd-e2e";
const ATTESTATION_DOC_PATH: &str = "/tmp/key-fwd-e2e/attestation_doc";
const PIVOT_BUILD_FINGERPRINTS_PATH: &str =
	"/tmp/key-fwd-e2e/pivot-build-fingerprints.txt";
const USERS: &[&str] = &["user1", "user2", "user3"];
const TEST_MSG: &str = "test-msg";
const NEW_ATTESTATION_DOC_PATH: &str = "/tmp/key-fwd-e2e/new_attestation_doc";
const ENCRYPTED_QUORUM_KEY_PATH: &str = "/tmp/key-fwd-e2e/encrypted_quorum_key";
const SHARED_EPH_PATH: &str = "/tmp/key-fwd-e2e/shared_eph.secret";
const QUORUM_KEY_PUB_PATH: &str = "./mock/namespaces/quit-coding-to-vape/quorum_key.pub";

#[tokio::test]
async fn key_fwd_e2e() {
	// Make sure everything in the temp dir gets dropped
	let _: PathWrapper = TMP_DIR.into();
	fs::create_dir_all(BOOT_DIR).unwrap();
	let old_host_port = qos_test_primitives::find_free_port().unwrap();
	let new_host_port = qos_test_primitives::find_free_port().unwrap();

	build_pivot_fingerprints();
	generate_manifest_envelope();
	let (_enclave_child_wrapper, _host_child_wrapper) =
		boot_old_enclave(old_host_port);

	// start up new enclave
	let new_secret_path = "/tmp/key-fwd-e2e/new_secret.secret";
	let new_pivot_path = "/tmp/key-fwd-e2e/new_pivot.pivot";
	let new_manifest_path = "/tmp/key-fwd-e2e/new_manifest.manifest";
	let new_usock = "/tmp/key-fwd-e2e/new_usock.sock";

	// -- ENCLAVE start new enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				new_usock,
				"--quorum-file",
				new_secret_path,
				"--pivot-file",
				new_pivot_path,
				"--ephemeral-file",
				SHARED_EPH_PATH, /* this is shared so the old enclave can
				                  * encrypt to this key. See `extract_key` logic */
				"--mock",
				"--manifest-file",
				new_manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// -- HOST start new host
	let mut _host_child_process: ChildWrapper =
		Command::new("../target/debug/qos_host")
			.args([
				"--host-port",
				&new_host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				new_usock,
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the new enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(new_host_port);

	// -- CLIENT broadcast boot key fwd instruction
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-key-fwd",
			"--manifest-envelope-path",
			MANIFEST_ENVELOPE_PATH,
			"--pivot-path",
			PIVOT_LOOP_PATH,
			"--attestation-doc-path",
			NEW_ATTESTATION_DOC_PATH,
			"--host-port",
			&new_host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT broadcast key request to the old enclave
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"export-key",
			"--manifest-envelope-path",
			MANIFEST_ENVELOPE_PATH,
			"--attestation-doc-path",
			NEW_ATTESTATION_DOC_PATH,
			"--encrypted-quorum-key-path",
			ENCRYPTED_QUORUM_KEY_PATH,
			"--host-port",
			&old_host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT broadcast encrypted quorum to the new enclave
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"inject-key",
			"--encrypted-quorum-key-path",
			ENCRYPTED_QUORUM_KEY_PATH,
			"--host-port",
			&new_host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// Check that the quorum key got written
	let quorum_pair = P256Pair::from_hex_file(new_secret_path).unwrap();
	let quorum_pub = P256Public::from_hex_file(
		QUORUM_KEY_PUB_PATH,
	)
	.unwrap();
	assert!(quorum_pair.public_key() == quorum_pub);
}

fn generate_manifest_envelope() {
	let pivot_args = format!("[--msg,{TEST_MSG}]");
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-manifest",
			"--nonce",
			"2",
			"--namespace",
			NAMESPACE,
			"--restart-policy",
			"always",
			"--pcr3-preimage-path",
			"./mock/namespaces/pcr3-preimage.txt",
			"--pivot-build-fingerprints",
			PIVOT_BUILD_FINGERPRINTS_PATH,
			"--qos-release-dir",
			MOCK_QOS_RELEASE_DIR,
			"--manifest-path",
			CLI_MANIFEST_PATH,
			"--pivot-args",
			&pivot_args,
			"--manifest-set-dir",
			"./mock/keys/manifest-set",
			"--share-set-dir",
			"./mock/keys/share-set",
			"--quorum-key-path",
			QUORUM_KEY_PUB_PATH
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT make sure each user can run `approve-manifest`
	for alias in USERS {
		let secret_path = format!("{}/{}.secret", &personal_dir(alias), alias);

		assert!(Command::new("../target/debug/qos_client")
			.args([
				"approve-manifest",
				"--secret-path",
				&*secret_path,
				"--manifest-path",
				CLI_MANIFEST_PATH,
				"--manifest-approvals-dir",
				BOOT_DIR,
				"--pcr3-preimage-path",
				"./mock/namespaces/pcr3-preimage.txt",
				"--pivot-build-fingerprints",
				PIVOT_BUILD_FINGERPRINTS_PATH,
				"--qos-release-dir",
				MOCK_QOS_RELEASE_DIR,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--share-set-dir",
				"./mock/keys/share-set",
				"--quorum-key-path",
				QUORUM_KEY_PUB_PATH,
				"--alias",
				alias,
				"--unsafe-auto-confirm",
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
	}
}

fn boot_old_enclave(old_host_port: u16) -> (ChildWrapper, ChildWrapper) {
	let old_secret_path = "/tmp/key-fwd-e2e/old_secret.secret";
	let old_pivot_path = "/tmp/key-fwd-e2e/old_pivot.pivot";
	let old_manifest_path = "/tmp/key-fwd-e2e/old_manifest.manifest";
	let old_usock = "/tmp/key-fwd-e2e/old_usock.sock";

	// -- ENCLAVE start old enclave
	let enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				old_usock,
				"--quorum-file",
				old_secret_path,
				"--pivot-file",
				old_pivot_path,
				"--ephemeral-file",
				SHARED_EPH_PATH,
				"--mock",
				"--manifest-file",
				old_manifest_path,
			])
			.spawn()
			.unwrap()
			.into();

	// -- HOST start old host
	let host_child_process: ChildWrapper =
		Command::new("../target/debug/qos_host")
			.args([
				"--host-port",
				&old_host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--usock",
				old_usock,
			])
			.spawn()
			.unwrap()
			.into();

	// -- Make sure the old enclave and host have time to boot
	qos_test_primitives::wait_until_port_is_bound(old_host_port);

	// -- CLIENT generate the manifest envelope
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-manifest-envelope",
			"--manifest-approvals-dir",
			BOOT_DIR,
			"--manifest-path",
			CLI_MANIFEST_PATH,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT broadcast boot standard instruction
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-standard",
			"--manifest-envelope-path",
			MANIFEST_ENVELOPE_PATH,
			"--pivot-path",
			PIVOT_LOOP_PATH,
			"--host-port",
			&old_host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--pcr3-preimage-path",
			"./mock/namespaces/pcr3-preimage.txt",
			"--unsafe-skip-attestation",
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"get-attestation-doc",
			"--host-port",
			&old_host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
			"--attestation-doc-path",
			ATTESTATION_DOC_PATH
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	for user in USERS[0..2].iter() {
		let share_path = format!("{}/{}.share", &personal_dir(user), user);
		let secret_path = format!("{}/{}.secret", &personal_dir(user), user);
		let eph_wrapped_share_path: PathWrapper =
			format!("{}/{}.eph_wrapped.share", TMP_DIR, user).into();
		let approval_path: PathWrapper =
			format!("{}/{}.attestation.approval", TMP_DIR, user).into();
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"proxy-re-encrypt-share",
				"--share-path",
				&share_path,
				"--secret-path",
				&secret_path,
				"--attestation-doc-path",
				ATTESTATION_DOC_PATH,
				"--eph-wrapped-share-path",
				&eph_wrapped_share_path,
				"--approval-path",
				&approval_path,
				"--manifest-envelope-path",
				MANIFEST_ENVELOPE_PATH,
				"--pcr3-preimage-path",
				"./mock/namespaces/pcr3-preimage.txt",
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				SHARED_EPH_PATH,
				"--unsafe-auto-confirm",
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		assert!(Command::new("../target/debug/qos_client")
			.args([
				"post-share",
				"--host-port",
				&old_host_port.to_string(),
				"--host-ip",
				LOCAL_HOST,
				"--eph-wrapped-share-path",
				&eph_wrapped_share_path,
				"--approval-path",
				&approval_path,
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());
	}

	// Check that the enclave wrote its quorum key
	let quorum_pair = P256Pair::from_hex_file(old_secret_path).unwrap();
	let quorum_pub = P256Public::from_hex_file(QUORUM_KEY_PUB_PATH)
	.unwrap();
	assert!(quorum_pair.public_key() == quorum_pub);

	(enclave_child_process, host_child_process)
}

fn personal_dir(user: &str) -> String {
	format!("{ALL_PERSONAL_DIR}/{user}-dir")
}

fn build_pivot_fingerprints() {
	let pivot = fs::read(PIVOT_LOOP_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let build_fingerprints = {
		let mut build_fingerprints =
			qos_hex::encode(&mock_pivot_hash).as_bytes().to_vec();
		build_fingerprints.extend_from_slice(b"\n");
		build_fingerprints.extend_from_slice(b"mock-pivot-commit");
		build_fingerprints
	};
	std::fs::write(PIVOT_BUILD_FINGERPRINTS_PATH, build_fingerprints).unwrap();
}

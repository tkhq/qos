use std::{fs, process::Command};

use integration::{
	LOCAL_HOST, PCR3_PRE_IMAGE_PATH, PIVOT_LOOP_PATH, QOS_DIST_DIR,
};
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
const PIVOT_HASH_PATH: &str = "/tmp/key-fwd-e2e/pivot-hash-path.txt";
const USERS: &[&str] = &["user1", "user2", "user3"];
const TEST_MSG: &str = "test-msg";
const NEW_ATTESTATION_DOC_PATH: &str = "/tmp/key-fwd-e2e/new_attestation_doc";
const ENCRYPTED_QUORUM_KEY_PATH: &str = "/tmp/key-fwd-e2e/encrypted_quorum_key";
const SHARED_EPH_PATH: &str = "/tmp/key-fwd-e2e/shared_eph.secret";
const QUORUM_KEY_PUB_PATH: &str =
	"./mock/namespaces/quit-coding-to-vape/quorum_key.pub";

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

	// We manually remove the ephemeral key file because if we didn't, we'd get a failure from the
	// NEW enclave: as it comes up it'd try to write its ephemeral key at `SHARED_EPH_PATH` and fail
	// to write because the file already exists.
	// Why does the file already exist? Because the OLD enclave already persisted its ephemeral key
	// there (and why is this a problem you ask? Well, that's just the semantics of `write_as_read_only`
	// -- for security reasons, we want to avoid silently/accidentally overriding key material)
	//
	// Another question you might ask is: why do we need to share this ephemeral key path at all?
	// Can't we just give OLD and NEW enclaves their own ephemeral path and be done?
	// That's a nice thought, but unfortunately we can't quite do that. To perform a key-forward boot,
	// in normal conditions, the OLD enclave encrypts its quorum key to the NEW enclave's ephemeral
	// public key. The "transport" mechanism for this public key is the AWS attestation (`public_key` field).
	// Which means we'd need to produce AWS attestations dynamically. And unfortunately, that's just a pain
	// in the rear to mock/produce in testing. So here we are.
	//
	// The solution we've found is to share the ephemeral key between OLD and NEW enclave AND have
	// a special case: when `qos_core` is compiled with the `mock` feature, the OLD enclave encrypts its
	// quorum key to its _own_ ephemeral public key (rather than the AWS attestation `public_key` field.)
	// See `export_key_internal` for details.
	//
	// Because the OLD and NEW enclave share the ephemeral key path, the NEW enclave can trivially decrypt
	// the encrypted quorum key that is injected, and the integration test works.
	//
	// This is obviously a test-only quirk: in a real situation enclaves have their own filesystems..!
	fs::remove_file(SHARED_EPH_PATH).unwrap();

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
				                  * encrypt to this key. See `extract_key`
				                  * logic */
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
	let quorum_pub = P256Public::from_hex_file(QUORUM_KEY_PUB_PATH).unwrap();
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
			PCR3_PRE_IMAGE_PATH,
			"--pivot-hash-path",
			PIVOT_HASH_PATH,
			"--qos-release-dir",
			QOS_DIST_DIR,
			"--manifest-path",
			CLI_MANIFEST_PATH,
			"--pivot-args",
			&pivot_args,
			"--manifest-set-dir",
			"./mock/keys/manifest-set",
			"--share-set-dir",
			"./mock/keys/share-set",
			"--patch-set-dir",
			"./mock/keys/manifest-set",
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
				PCR3_PRE_IMAGE_PATH,
				"--pivot-hash-path",
				PIVOT_HASH_PATH,
				"--qos-release-dir",
				QOS_DIST_DIR,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--share-set-dir",
				"./mock/keys/share-set",
				"--patch-set-dir",
				"./mock/keys/manifest-set",
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
			PCR3_PRE_IMAGE_PATH,
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
			ATTESTATION_DOC_PATH,
			"--manifest-envelope-path",
			"/tmp/dont_care"
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
			format!("{TMP_DIR}/{user}.eph_wrapped.share").into();
		let approval_path: PathWrapper =
			format!("{TMP_DIR}/{user}.attestation.approval").into();
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
				PCR3_PRE_IMAGE_PATH,
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
	let quorum_pub = P256Public::from_hex_file(QUORUM_KEY_PUB_PATH).unwrap();
	assert!(quorum_pair.public_key() == quorum_pub);

	(enclave_child_process, host_child_process)
}

fn personal_dir(user: &str) -> String {
	format!("{ALL_PERSONAL_DIR}/{user}-dir")
}

fn build_pivot_fingerprints() {
	let pivot = fs::read(PIVOT_LOOP_PATH).unwrap();
	let mock_pivot_hash = sha_256(&pivot);
	let mock_pivot_hash_hex = qos_hex::encode(&mock_pivot_hash);
	std::fs::write(PIVOT_HASH_PATH, mock_pivot_hash_hex).unwrap();
}

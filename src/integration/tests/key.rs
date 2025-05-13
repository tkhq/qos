use std::time::{Duration, SystemTime};
use std::{fs, process::Command};
use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::{header_map::HeaderMap, CoseSign1};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde_bytes::ByteBuf;
use integration::{
	LOCAL_HOST, PCR3_PRE_IMAGE_PATH, PIVOT_LOOP_PATH, QOS_DIST_DIR,
};

use der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use std::str::FromStr;
use qos_crypto::sha_256;
use qos_nsm::nitro::unsafe_attestation_doc_from_der;
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
const NEW_ATTESTATION_DOC_PATH_FIXED: &str = "/tmp/key-fwd-e2e/new_attestation_doc_fixed";
const ENCRYPTED_QUORUM_KEY_PATH: &str = "/tmp/key-fwd-e2e/encrypted_quorum_key";
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

	// start up new enclave
	let new_quorum_path = "/tmp/key-fwd-e2e/new_quorum.secret";
	let new_ephemeral_path = "/tmp/key-fwd-e2e/new_ephemeral.secret";
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
				new_quorum_path,
				"--pivot-file",
				new_pivot_path,
				"--ephemeral-file",
				new_ephemeral_path,
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

	let mut attestation_doc = unsafe_attestation_doc_from_der(&fs::read(NEW_ATTESTATION_DOC_PATH).unwrap()).unwrap();
	let new_ephemeral_key_pair = P256Pair::from_hex_file(new_ephemeral_path).unwrap();
	let new_ephemeral_key_pair_public_bytes = new_ephemeral_key_pair.public_key().to_bytes();
	println!("new_ephemeral_key_pair_public_bytes: {:?} (hex: {})", new_ephemeral_key_pair_public_bytes, qos_hex::encode(&new_ephemeral_key_pair_public_bytes));
	attestation_doc.public_key = Some(ByteBuf::from(new_ephemeral_key_pair_public_bytes));

	// See https://github.com/awslabs/aws-nitro-enclaves-cose/blob/6064f826d551a9db0bd42e9cf928feaf272e8d17/src/crypto/openssl_pkey.rs#L24C9-L24C23
	// P-384 is the recommended curve to work with SHA-384, which aws nitros use.
	let nid = Nid::SECP384R1;
	let group = EcGroup::from_curve_name(nid).unwrap();
	let ec_key = EcKey::generate(&group).unwrap();
	let signing_key_public_der = ec_key.public_key_to_der().unwrap();
	let signing_key = PKey::from_ec_key(ec_key).unwrap();

	// Create the certificate (needs to be inserted in the attestation)
	let serial_number = SerialNumber::from(42u32);
	let validity = Validity::from_now(Duration::new(60, 0)).unwrap();
	let profile = Profile::Root;
	let subject = Name::from_str("CN=Turnkey World Domination,O=World domination Inc,C=US").unwrap();
	let pub_key = SubjectPublicKeyInfoOwned::try_from(signing_key_public_der.into()).expect("get rsa pub key");

	//let mut signer = Rsa::generate(2048).unwrap();
	let signer_key = qos_hex::decode("83e41c719b3616993060d35cc054c8c1cd232d166f0ef13392fa7c3614b62060").unwrap();
	let signer_secret_key = p256::SecretKey::from_slice(&signer_key).unwrap();

	let mut builder = CertificateBuilder::new(
		profile,
		serial_number,
		validity,
		subject,
		pub_key,
		&signer_secret_key,
	).unwrap();
	attestation_doc.certificate = builder.build().unwrap();

	let fixed_attestation_doc = CoseSign1::new::<Openssl>(&attestation_doc.to_binary(), &HeaderMap::new(), &signing_key).unwrap();
	fs::write(NEW_ATTESTATION_DOC_PATH_FIXED, fixed_attestation_doc.as_bytes(false).unwrap()).unwrap();

	// -- CLIENT broadcast key request to the old enclave
	assert!(Command::new("../target/debug/qos_client")
		.args([
			"export-key",
			"--manifest-envelope-path",
			MANIFEST_ENVELOPE_PATH,
			"--attestation-doc-path",
			NEW_ATTESTATION_DOC_PATH_FIXED,
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
	let quorum_pair = P256Pair::from_hex_file(new_quorum_path).unwrap();
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
	let old_ephemeral_path = "/tmp/key-fwd-e2e/old_ephemeral.secret";
	let old_quorum_path = "/tmp/key-fwd-e2e/old_quorum.secret";
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
				old_quorum_path,
				"--pivot-file",
				old_pivot_path,
				"--ephemeral-file",
				old_ephemeral_path,
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
				PCR3_PRE_IMAGE_PATH,
				"--manifest-set-dir",
				"./mock/keys/manifest-set",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				&old_ephemeral_path,
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
	let quorum_pair = P256Pair::from_hex_file(old_quorum_path).unwrap();
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

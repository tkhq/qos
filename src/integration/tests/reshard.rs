use std::{fs, process::Command};

use integration::{LOCAL_HOST, QOS_DIST_DIR};
use qos_test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test]
async fn reshard_e2e() {
	let tmp: PathWrapper = "/tmp/reshard_e2e".into();
	drop(fs::create_dir_all(&*tmp));
	let eph_path: PathWrapper = "/tmp/reshard_e2e/eph.secret".into();
	let usock: PathWrapper = "/tmp/reshard_e2e/usock.sock".into();
	let secret_path: PathWrapper = "/tmp/reshard_e2e/quorum.secret".into();
	let attestation_doc_path: PathWrapper = "/tmp/reshard_e2e/att_doc".into();
	// TODO: we will have to do this on a per member basis
	let reshard_input_path: PathWrapper =
		"/tmp/reshard_e2e/reshard_input.json".into();

	let eph_path: PathWrapper = "/tmp/reshard_e2e/ephemeral_key.secret".into();

	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";
	let personal_dir = |user: &str| format!("{all_personal_dir}/{user}-dir");
	let user1 = "user1";
	let user2 = "user2";
	let user3 = "user3";

	let host_port = qos_test_primitives::find_free_port().unwrap();

	// Start Enclave
	let mut _enclave_child_process: ChildWrapper =
		Command::new("../target/debug/qos_core")
			.args([
				"--usock",
				&*usock,
				"--quorum-file",
				&*secret_path,
				"--pivot-file",
				"/tmp/reshard_e2e/never_write_pivot_file",
				"--ephemeral-file",
				&*eph_path,
				"--mock",
				"--manifest-file",
				"/tmp/reshard_e2e/never_write_manifest",
			])
			.spawn()
			.unwrap()
			.into();

	// Start Host
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

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"generate-reshard-input",
			"--qos-release-dir",
			QOS_DIST_DIR,
			"--pcr3-preimage-path",
			"./mock/namespaces/pcr3-preimage.txt",
			"--quorum-key-path",
			"./mock/namespaces/quit-coding-to-vape/quorum_key.pub",
			"--old-share-set-dir",
			"./mock/keys/share-set",
			"--new-share-set-dir",
			"./mock/keys/new-share-set",
			"--reshard-input-path",
			&*reshard_input_path,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
	// TODO: assert contents of reshard_input?

	qos_test_primitives::wait_until_port_is_bound(host_port);

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"boot-reshard",
			"--reshard-input-path",
			&*reshard_input_path,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	assert!(Command::new("../target/debug/qos_client")
		.args([
			"get-reshard-attestation-doc",
			"--attestation-doc-path",
			&*attestation_doc_path,
			"--host-port",
			&host_port.to_string(),
			"--host-ip",
			LOCAL_HOST,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	for user in [&user1, &user2] {
		// TODO(zeke): dry this logic up with boot standard
		let share_path = format!("{}/{}.share", &personal_dir(user), user);
		let secret_path = format!("{}/{}.secret", &personal_dir(user), user);
		let eph_wrapped_share_path: PathWrapper =
			format!("{}/{}.eph_wrapped.share", &*tmp, user).into();
		let approval_path: PathWrapper =
			format!("{}/{}.attestation.approval", &*tmp, user).into();

		assert!(Command::new("../target/debug/qos_client")
			.args([
				"reshard-re-encrypt-share",
				"--secret-path",
				&secret_path,
				"--share-path",
				&share_path,
				"--attestation-doc-path",
				&*attestation_doc_path,
				"--approval-path",
				&*approval_path,
				"--eph-wrapped-share-path",
				&eph_wrapped_share_path,
				"--reshard-input-path",
				&*reshard_input_path,
				"--qos-release-dir",
				QOS_DIST_DIR,
				"--quorum-key-path",
				// TODO: make const
				"./mock/namespaces/quit-coding-to-vape/quorum_key.pub",
				"--pcr3-preimage-path",
				"./mock/namespaces/pcr3-preimage.txt", // TODO: make const
				"--new-share-set-dir",
				"./mock/keys/new-share-set",
				"--old-share-set-dir",
				"./mock/keys/share-set",
				"--alias",
				user,
				"--unsafe-skip-attestation",
				"--unsafe-eph-path-override",
				&*eph_path,
				// TODO: skip this if it doesn't work
				"--unsafe-auto-confirm",
			])
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success());

		// Post the encrypted share
		assert!(Command::new("../target/debug/qos_client")
			.args([
				"reshard-post-share",
				"--host-port",
				&host_port.to_string(),
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
}

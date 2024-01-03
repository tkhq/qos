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


	assert!(Command::new("../target/debug/qos_client")
		.args([
			"reshard-re-encrypt-share",
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


}

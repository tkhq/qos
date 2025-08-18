use std::{
	collections::HashMap,
	fs,
	io::{BufRead, BufReader, Write},
	path::Path,
	process::{Command, Stdio},
};

use integration::{LOCAL_HOST, PCR3_PRE_IMAGE_PATH, QOS_DIST_DIR};
use qos_crypto::n_choose_k;
use qos_p256::P256Pair;
use qos_test_primitives::{ChildWrapper, PathWrapper};

#[tokio::test]
async fn reshard_e2e() {
	let tmp: PathWrapper = "/tmp/reshard_e2e".into();
	drop(fs::create_dir_all(&*tmp));
	let _eph_path: PathWrapper = "/tmp/reshard_e2e/eph.secret".into();
	let usock: PathWrapper = "/tmp/reshard_e2e/usock.sock".into();
	let secret_path: PathWrapper = "/tmp/reshard_e2e/quorum.secret".into();
	let attestation_doc_path: PathWrapper = "/tmp/reshard_e2e/att_doc".into();
	let reshard_input_path: PathWrapper =
		"/tmp/reshard_e2e/reshard_input.json".into();
	let reshard_output_path: PathWrapper =
		"/tmp/reshard_e2e/reshard_output.json".into();
	let eph_path: PathWrapper = "/tmp/reshard_e2e/ephemeral_key.secret".into();

	let all_personal_dir = "./mock/boot-e2e/all-personal-dir";
	let personal_dir = |user: &str| format!("{all_personal_dir}/{user}-dir");
	let user1 = "user1";
	let user2 = "user2";

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

	qos_test_primitives::wait_until_port_is_bound(host_port);
}

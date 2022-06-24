// TODO: [now] Make an ok pivot3

#[tokio::test]
async fn dev_boot_e2e() {
	let tmp = "./dev-boot-e2e-tmp/";
	let usock = "./dev-boot-e2e-tmp/sock.sock";
	let secret_path = "./dev-boot-e2e-tmp/quorum.secret";
	let pivot_path = "./dev-boot-e2e-tmp/pivot.pivot";
	let eph_path = "./dev-boot-e2e-tmp/eph.secret";

	let host_port = "3010";
	let host_ip = "127.0.0.1";

	// Start Enclave
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

	// Start Host
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

	// Run `dangerous-dev-boot`
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"dangerous-dev-boot",
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

	// Make sure pivot ran
	assert!(Path::new(PIVOT_OK3_SUCCESS_FILE).exists());
	fs::remove_file(PIVOT_OK3_SUCCESS_FILE).unwrap();

	// Clean up
	drop(fs::remove_dir_all(tmp));
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
}

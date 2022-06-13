use std::process::Command;

use borsh::de::BorshDeserialize;
use qos_client::request;
use qos_core::protocol::{BootInstruction, GenesisSet, ProtocolMsg};

#[tokio::test]
async fn genesis_e2e() {
	let usock = "genesis_e2e.sock";
	let host_port = "3008";
	let host_ip = "127.0.0.1";
	let message_url = format!("http://{}:{}/message", host_ip, host_port);
	let secret_path = "./genesis_e2e.secret";
	let pivot_path = "./genesis_e2e.pivot";

	let key_directory = "./genesis-test-temp";
	let namespace = "vapers-only";
	// The directory the setup keys will be written to/ read from
	let _ = std::fs::create_dir(key_directory);

	let get_key_paths = |user| {
		(
			format!("{}/{}.{}.setup.key", key_directory, user, namespace),
			format!("{}/{}.{}.setup.pub", key_directory, user, namespace),
		)
	};
	let user1 = "baker-1";
	let (user1_private_setup, user1_public_setup) = get_key_paths(user1);

	let user2 = "baker-2";
	let (user2_private_setup, user2_public_setup) = get_key_paths(user2);

	let user3 = "baker-3";
	let (user3_private_setup, user3_public_setup) = get_key_paths(user3);

	// -- CLIENT Create 3 setup keys
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			namespace,
			"--alias",
			user1,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			namespace,
			"--alias",
			user2,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			namespace,
			"--alias",
			user3,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// -- CLIENT Read in files with keys to create genesis input and write to
	// file
	assert!(Command::new("../target/debug/client_cli")
		.args([
			"generate-genesis-configuration",
			"--threshold",
			"2",
			"--key-directory",
			key_directory,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let genesis_config = "./genesis.configuration";

	// -- ENCLAVE Start enclave
	let mut enclave_child_process = Command::new("../target/debug/core_cli")
		.args([
			"--usock",
			usock,
			"--secret-file",
			secret_path,
			"--pivot-file",
			pivot_path,
			"--mock",
			"true",
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

	// -- CLIENT send genesis input
	let genesis_boot_msg = {
		let genesis_config = std::fs::read(genesis_config).unwrap();
		let genesis_config =
			GenesisSet::try_from_slice(&genesis_config).unwrap();
		ProtocolMsg::BootRequest(BootInstruction::Genesis {
			set: genesis_config,
		})
	};
	let response = request::post(&message_url, genesis_boot_msg).unwrap();

	// -- CLIENT verify genesis output
	matches!(response, ProtocolMsg::BootGenesisResponse { .. });
	// 	- recreate quorum key

	// -- Clean up
	for file in [
		user1_private_setup,
		user1_public_setup,
		user2_private_setup,
		user2_public_setup,
		user3_private_setup,
		user3_public_setup,
		genesis_config.to_string(),
		secret_path.to_string(),
		pivot_path.to_string(),
	] {
		let _ = std::fs::remove_file(file);
	}
	let _ = std::fs::remove_dir_all(key_directory);
	enclave_child_process.kill().unwrap();
	host_child_process.kill().unwrap();
}

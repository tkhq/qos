use std::process::Command;

#[tokio::test]
async fn genesis_e2e() {
	let key_directory = "./genesis-test-temp";
	let _ = std::fs::create_dir(key_directory);

	let get_key_paths = |user| {
		(
			format!("{}/{}.vapers-only.setup.key", key_directory, user),
			format!("{}/{}.vapers-only.setup.pub", key_directory, user),
		)
	};
	let user1 = "baker-1";
	let (user1_private_setup, user1_public_setup) = get_key_paths(user1);

	let user2 = "baker-2";
	let (user2_private_setup, user2_public_setup) = get_key_paths(user2);

	let user3 = "baker-3";
	let (user3_private_setup, user3_public_setup) = get_key_paths(user3);

	// -- CLIENT Create 3 setup keys
	Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			"vapers-only",
			"--alias",
			user1,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			"vapers-only",
			"--alias",
			user2,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	Command::new("../target/debug/client_cli")
		.args([
			"generate-setup-key",
			"--key-directory",
			key_directory,
			"--namespace",
			"vapers-only",
			"--alias",
			user3,
		])
		.spawn()
		.unwrap()
		.wait()
		.unwrap();

	// -- CLIENT Read in files with keys to create genesis input and write to
	// file
	Command::new("../target/debug/client_cli")
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
		.unwrap();

	// -- ENCLAVE Start enclave

	// -- HOST start host

	// -- CLIENT send genesis input

	// -- CLIENT verify genesis output
	// 	- recreate quorum key

	for file in [
		user1_private_setup,
		user1_public_setup,
		user2_private_setup,
		user2_public_setup,
		user3_private_setup,
		user3_public_setup,
	] {
		let _ = std::fs::remove_file(file);
	}

	let _ = std::fs::remove_dir_all(key_directory);
}

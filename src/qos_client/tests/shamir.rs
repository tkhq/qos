use std::process::Command;

use qos_test_primitives::PathWrapper;

const SECRET: &[u8] = b"our little secret :)";

#[test]
fn shamir_commands_work() {
	let _tmp: PathWrapper = "/tmp/shamir_commands_works".into();
	let secret_path: &str = "/tmp/shamir_commands_works/secret";
	let shares_dir: &str = "/tmp/shamir_commands_works/shares";
	let reconstructed_secret_path: &str =
		"/tmp/shamir_commands_works/reconstructed_secret";

	std::fs::create_dir_all(&shares_dir).unwrap();
	std::fs::write(secret_path, SECRET).unwrap();

	assert!(Command::new("../target/debug/qos_client")
		.arg("shamir-split")
		.arg("--secret-path")
		.arg(secret_path)
		.arg("--total-shares")
		.arg("4")
		.arg("--threshold")
		.arg("3")
		.arg("--output-dir")
		.arg(shares_dir)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	// The expected shares
	let share1 = "/tmp/shamir_commands_works/shares/1.share";
	let share2 = "/tmp/shamir_commands_works/shares/2.share";
	let share3 = "/tmp/shamir_commands_works/shares/3.share";
	let share4 = "/tmp/shamir_commands_works/shares/4.share";

	assert!(!std::fs::read(share1).unwrap().is_empty());
	assert!(!std::fs::read(share2).unwrap().is_empty());
	assert!(!std::fs::read(share3).unwrap().is_empty());
	assert!(!std::fs::read(share4).unwrap().is_empty());

	assert!(Command::new("../target/debug/qos_client")
		.arg("shamir-reconstruct")
		.arg("--share")
		.arg(share1)
		.arg("--share")
		.arg(share3)
		.arg("--share")
		.arg(share4)
		.arg("--output-path")
		.arg(reconstructed_secret_path)
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.success());

	let reconstructed = std::fs::read(reconstructed_secret_path).unwrap();
	assert_eq!(reconstructed, SECRET);
}

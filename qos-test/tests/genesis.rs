use std::process::Command;

#[tokio::test]
async fn genesis_e2e() {
	// -- CLIENT Create 3 setup keys
	Command::new("../target/debug/core_cli")
		.args([
			"generate-setup-key",
			"--path",
			"./",
			"--namespace",
			"vapers-only",
			"--alias",
			"baker-1",
		])
		.spawn()
		.unwrap();

	// Command::new("../target/debug/core_cli")
	// 	.args([
	// 		"generate-setup-key",
	// 		"--path",
	// 		"./",
	// 		"--namespace",
	// 		"vapers-only",
	// 		"--alias",
	// 		"baker-2",
	// 	])
	// 	.spawn()
	// 	.unwrap();

	// Command::new("../target/debug/core_cli")
	// 	.args([
	// 		"generate-setup-key",
	// 		"--path",
	// 		"./",
	// 		"--namespace",
	// 		"vapers-only",
	// 		"--alias",
	// 		"baker-3",
	// 	])
	// 	.spawn()
	// .unwrap();

	// -- CLIENT Read in files with keys to create genesis input and write to
	// file

	// -- ENCLAVE Start enclave

	// -- HOST start host

	// -- CLIENT send genesis input

	// -- CLIENT verify genesis output
	// 	- recreate quorum key
}

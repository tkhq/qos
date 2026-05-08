use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::{env, fs};

use integration::{PivotWasmExecuteRequest, PivotWasmMsg};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
};

fn main() {
	let args: Vec<String> = env::args().collect();
	match args.get(1).map(String::as_str) {
		Some("setup-pivot-wasm") => setup_pivot_wasm(),
		Some("test-pivot-wasm") => {
			let rt = tokio::runtime::Runtime::new().unwrap();
			rt.block_on(test_pivot_wasm());
		}
		_ => {
			eprintln!("Usage: cargo xtask <setup-pivot-wasm|test-pivot-wasm>");
			std::process::exit(1);
		}
	}
}

fn setup_pivot_wasm() {
	let out_dir = PathBuf::from("target/pivot-wasm");
	fs::create_dir_all(&out_dir).expect("failed to create output dir");

	// 1. Generate owner keypair
	let owner = qos_p256::P256Pair::generate().expect("keygen failed");

	let secret_path = out_dir.join("owner.secret.keep");
	fs::write(&secret_path, owner.to_master_seed_hex())
		.expect("failed to write owner secret");

	let pub_path = out_dir.join("owner.pub");
	owner
		.public_key()
		.to_hex_file(&pub_path)
		.expect("failed to write owner pub");

	let pub_hex =
		String::from_utf8(owner.public_key().to_hex_bytes()).unwrap();

	// 2. Build WASM modules
	let wasm_targets = [
		("wasm_policy", "integration/wasm_policy"),
		("wasm_program", "integration/wasm_program"),
	];

	for (name, path) in &wasm_targets {
		eprintln!("Building {name}...");
		let status = Command::new("cargo")
			.args([
				"build",
				"--manifest-path",
				&format!("{path}/Cargo.toml"),
				"--target",
				"wasm32-unknown-unknown",
				"--release",
				"--target-dir",
				"target",
			])
			.status()
			.expect("failed to run cargo build");

		assert!(status.success(), "failed to build {name}");
	}

	let policy_wasm_path = PathBuf::from(
		"target/wasm32-unknown-unknown/release/wasm_policy.wasm",
	);

	// 3. Sign the example policy
	let policy_wasm =
		fs::read(&policy_wasm_path).expect("failed to read policy wasm");
	let policy_hash = qos_crypto::sha_256(&policy_wasm);
	let signature = owner.sign(&policy_hash).expect("signing failed");

	let sig_path = out_dir.join("policy.sig");
	fs::write(&sig_path, &signature).expect("failed to write signature");

	let sig_hex = qos_hex::encode(&signature);

	// 4. Print summary
	println!();
	println!("=== pivot-wasm setup complete ===");
	println!();
	println!("Owner secret:  {}", secret_path.display());
	println!("Owner pub:     {}", pub_path.display());
	println!("Policy sig:    {}", sig_path.display());
	println!("Policy WASM:   {}", policy_wasm_path.display());
	println!(
		"Program WASM:  target/wasm32-unknown-unknown/release/wasm_program.wasm"
	);
	println!();
	println!("Owner public key hex:");
	println!("  {pub_hex}");
	println!();
	println!("Policy signature hex:");
	println!("  {sig_hex}");
	println!();
	println!("Pivot args for dangerous-dev-boot:");
	println!(
		"  --pivot-args '[/tmp/pivot_wasm.sock,{pub_hex},./local-enclave/qos.ephemeral.key]'"
	);
}

async fn test_pivot_wasm() {
	let socket_path = "/tmp/pivot_wasm.sock";
	let out_dir = PathBuf::from("target/pivot-wasm");

	// Load artifacts from setup
	let policy_wasm =
		fs::read("target/wasm32-unknown-unknown/release/wasm_policy.wasm")
			.expect("policy wasm not found — run `cargo xtask setup-pivot-wasm` first");
	let program_wasm =
		fs::read("target/wasm32-unknown-unknown/release/wasm_program.wasm")
			.expect("program wasm not found");
	let policy_signature =
		fs::read(out_dir.join("policy.sig"))
			.expect("policy.sig not found — run `cargo xtask setup-pivot-wasm` first");

	let input = b"hello world";

	// Build request
	let request = PivotWasmMsg::ExecuteRequest(PivotWasmExecuteRequest {
		policy_wasm,
		policy_signature,
		program_wasm,
		input: input.to_vec(),
	});

	let request_bytes =
		borsh::to_vec(&request).expect("failed to serialize request");

	// Connect and send
	let pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("failed to create stream pool")
		.shared();
	let client = SocketClient::new(pool, Duration::from_secs(30));

	println!("Sending request to {socket_path}...");
	let response_bytes = client
		.call(&request_bytes)
		.await
		.expect("request failed");

	// Decode response
	let response: PivotWasmMsg =
		borsh::from_slice(&response_bytes).expect("failed to deserialize response");

	match response {
		PivotWasmMsg::ExecuteResponse(resp) => {
			let output = String::from_utf8_lossy(&resp.output);
			println!("Success!");
			println!("  Input:  {}", String::from_utf8_lossy(input));
			println!("  Output: {output}");
			println!("  Policy hash:  {}", qos_hex::encode(&resp.attestation.policy_hash));
			println!("  Program hash: {}", qos_hex::encode(&resp.attestation.program_hash));
			println!("  Attestation signature present: {}", !resp.attestation.signature.is_empty());
		}
		PivotWasmMsg::PolicyDenied => {
			println!("Policy denied the request");
		}
		PivotWasmMsg::InvalidSignature => {
			println!("Invalid policy signature");
		}
		PivotWasmMsg::RuntimeError { message } => {
			println!("Runtime error: {message}");
		}
		_ => {
			println!("Unexpected response: {response:?}");
		}
	}
}

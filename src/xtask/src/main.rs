use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::{env, fs};

use borsh::BorshDeserialize;
use integration::{
	PivotWasmArtifact, PivotWasmArtifactEnvelope, PivotWasmArtifactKind,
	PivotWasmExecuteRequest, PivotWasmGovernance, PivotWasmMsg,
	PivotWasmRegisterArtifactRequest,
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::{Approval, ManifestSet, QuorumMember},
};
use qos_p256::P256Pair;

const OUT_DIR: &str = "target/meta-pivot";
const GOVERNANCE_DIR: &str = "target/meta-pivot/governance";
const ARTIFACTS_DIR: &str = "target/meta-pivot/artifacts";
const ENVELOPES_DIR: &str = "target/meta-pivot/envelopes";
const ATTESTATIONS_DIR: &str = "target/meta-pivot/attestations";
const SOCKET_PATH: &str = "/tmp/pivot_wasm.sock";

#[derive(Clone)]
struct ArtifactSpec {
	name: &'static str,
	crate_name: &'static str,
	manifest_path: &'static str,
	kind: PivotWasmArtifactKind,
}

fn main() {
	let args: Vec<String> = env::args().collect();
	match args.get(1).map(String::as_str) {
		Some("meta-pivot") => match args.get(2).map(String::as_str) {
			Some("setup") => setup_meta_pivot(),
			Some("build-artifacts") => build_artifacts(),
			Some("approve-artifacts") => approve_artifacts(),
			Some("register") => {
				let rt = tokio::runtime::Runtime::new().unwrap();
				rt.block_on(register_artifacts());
			}
			Some("invoke") => {
				let rt = tokio::runtime::Runtime::new().unwrap();
				rt.block_on(invoke(&args[3..]));
			}
			Some("e2e") => {
				let rt = tokio::runtime::Runtime::new().unwrap();
				rt.block_on(meta_pivot_e2e());
			}
			_ => usage(),
		},
		Some("setup-pivot-wasm") => {
			setup_meta_pivot();
			build_artifacts();
			approve_artifacts();
		}
		Some("test-pivot-wasm") => {
			let rt = tokio::runtime::Runtime::new().unwrap();
			rt.block_on(meta_pivot_e2e());
		}
		_ => usage(),
	}
}

fn usage() -> ! {
	eprintln!(
		"Usage: cargo xtask meta-pivot <setup|build-artifacts|approve-artifacts|register|invoke|e2e>"
	);
	std::process::exit(1);
}

fn artifact_specs() -> Vec<ArtifactSpec> {
	vec![
		ArtifactSpec {
			name: "reverse",
			crate_name: "reverse_function",
			manifest_path:
				"integration/wasm_examples/functions/reverse/Cargo.toml",
			kind: PivotWasmArtifactKind::Function,
		},
		ArtifactSpec {
			name: "sha256",
			crate_name: "sha256_function",
			manifest_path:
				"integration/wasm_examples/functions/sha256/Cargo.toml",
			kind: PivotWasmArtifactKind::Function,
		},
		ArtifactSpec {
			name: "allow-hashlist",
			crate_name: "allow_hashlist_policy",
			manifest_path:
				"integration/wasm_examples/policies/allow_hashlist/Cargo.toml",
			kind: PivotWasmArtifactKind::Policy,
		},
		ArtifactSpec {
			name: "max-input-len",
			crate_name: "max_input_len_policy",
			manifest_path:
				"integration/wasm_examples/policies/max_input_len/Cargo.toml",
			kind: PivotWasmArtifactKind::Policy,
		},
	]
}

fn setup_meta_pivot() {
	create_dirs();

	let aliases = ["user1", "user2", "user3"];
	let mut members = Vec::new();
	for alias in aliases {
		let pair = P256Pair::generate().expect("keygen failed");
		let secret_path = governance_dir().join(format!("{alias}.secret.keep"));
		let pub_path = governance_dir().join(format!("{alias}.pub"));
		pair.to_hex_file(&secret_path)
			.expect("failed to write artifact approval secret");
		pair.public_key()
			.to_hex_file(&pub_path)
			.expect("failed to write artifact approval public key");
		members.push(QuorumMember {
			alias: alias.into(),
			pub_key: pair.public_key().to_bytes(),
		});
	}

	let governance = PivotWasmGovernance {
		artifact_set: ManifestSet { threshold: 2, members },
	};
	write_borsh(governance_path(), &governance, "WASM governance");

	let local_ephemeral =
		P256Pair::generate().expect("local ephemeral keygen failed");
	local_ephemeral
		.to_hex_file(local_ephemeral_path())
		.expect("failed to write local ephemeral key");

	println!("=== meta-pivot setup complete ===");
	println!("Governance: {}", governance_path().display());
	println!("Artifacts:  {}", artifacts_dir().display());
	println!("Envelopes:  {}", envelopes_dir().display());
	println!("Local eph:  {}", local_ephemeral_path().display());
	println!();
	println!("Pivot args for dangerous-dev-boot:");
	println!(
		"  --pivot-args '[{SOCKET_PATH},{},./local-enclave/qos.ephemeral.key]'",
		governance_path().display()
	);
	println!();
	println!("Direct local pivot command:");
	println!(
		"  cargo run --bin pivot_wasm -- {SOCKET_PATH} {} {}",
		governance_path().display(),
		local_ephemeral_path().display()
	);
}

fn build_artifacts() {
	create_dirs();
	for spec in artifact_specs() {
		eprintln!("Building {}...", spec.name);
		let status = Command::new("cargo")
			.args([
				"build",
				"--manifest-path",
				spec.manifest_path,
				"--target",
				"wasm32-unknown-unknown",
				"--release",
				"--target-dir",
				"target",
			])
			.status()
			.expect("failed to run cargo build");
		assert!(status.success(), "failed to build {}", spec.name);

		let source = wasm_output_path(&spec);
		let dest = artifact_path(spec.name);
		fs::copy(&source, &dest).unwrap_or_else(|e| {
			panic!(
				"failed to copy {} to {}: {e}",
				source.display(),
				dest.display()
			)
		});
		println!("{} -> {}", spec.name, dest.display());
	}
}

fn approve_artifacts() {
	create_dirs();
	if !governance_path().exists() {
		setup_meta_pivot();
	}

	for spec in artifact_specs() {
		let wasm = fs::read(artifact_path(spec.name)).unwrap_or_else(|e| {
			panic!(
				"missing artifact for {} at {}: {e}; run `cargo xtask meta-pivot build-artifacts`",
				spec.name,
				artifact_path(spec.name).display()
			)
		});
		let metadata = format!(
			"name={};crate={};kind={:?};version=0.1.0",
			spec.name, spec.crate_name, spec.kind
		);
		let artifact = PivotWasmArtifact::new(
			spec.kind.clone(),
			spec.name,
			"0.1.0",
			&wasm,
			metadata.as_bytes(),
		);
		let envelope = PivotWasmArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				sign_artifact_approval("user1", &artifact),
				sign_artifact_approval("user2", &artifact),
			],
		};

		write_borsh(envelope_path(spec.name), &envelope, "artifact envelope");
		println!(
			"approved {} {}",
			spec.name,
			qos_hex::encode(&artifact.wasm_hash)
		);
	}
}

async fn register_artifacts() {
	for spec in artifact_specs() {
		let envelope = read_envelope(spec.name);
		let wasm = fs::read(artifact_path(spec.name)).unwrap_or_else(|e| {
			panic!("failed to read artifact {}: {e}", spec.name)
		});
		let response = call_pivot(PivotWasmMsg::RegisterArtifactRequest(
			PivotWasmRegisterArtifactRequest { envelope, wasm },
		))
		.await;
		match response {
			PivotWasmMsg::RegisterArtifactResponse(resp) => {
				println!(
					"registered {} {}",
					resp.artifact.name,
					qos_hex::encode(&resp.artifact.wasm_hash)
				);
			}
			PivotWasmMsg::InvalidApproval { message }
			| PivotWasmMsg::RuntimeError { message } => {
				panic!("failed to register {}: {message}", spec.name);
			}
			other => panic!("unexpected register response: {other:?}"),
		}
	}
}

async fn invoke(args: &[String]) {
	let options = InvokeOptions::parse(args);
	let policy = read_envelope(options.policy);
	let function = read_envelope(options.function);
	let response =
		call_pivot(PivotWasmMsg::ExecuteRequest(PivotWasmExecuteRequest {
			policy_hash: policy.artifact.wasm_hash,
			function_hash: function.artifact.wasm_hash,
			input: options.input.as_bytes().to_vec(),
		}))
		.await;

	match response {
		PivotWasmMsg::ExecuteResponse(resp) => {
			println!("Success");
			println!("  Function: {}", options.function);
			println!("  Policy:   {}", options.policy);
			println!("  Input:    {}", options.input);
			println!("  Output:   {}", display_bytes(&resp.output));
			println!(
				"  Function hash: {}",
				qos_hex::encode(&resp.attestation.payload.function_hash)
			);
			println!(
				"  Policy hash:   {}",
				qos_hex::encode(&resp.attestation.payload.policy_hash)
			);
			println!(
				"  Signature:     {}",
				qos_hex::encode(&resp.attestation.signature)
			);
			write_borsh(
				attestations_dir().join("last-execution.borsh"),
				&resp.attestation,
				"execution attestation",
			);
		}
		PivotWasmMsg::PolicyDenied { reason } => {
			println!("Policy denied: {reason}");
		}
		PivotWasmMsg::RuntimeError { message }
		| PivotWasmMsg::InvalidApproval { message } => {
			panic!("invoke failed: {message}");
		}
		other => panic!("unexpected execute response: {other:?}"),
	}
}

async fn meta_pivot_e2e() {
	register_artifacts().await;
	invoke(&[]).await;
}

async fn call_pivot(message: PivotWasmMsg) -> PivotWasmMsg {
	let pool = StreamPool::new(SocketAddress::new_unix(SOCKET_PATH), 1)
		.expect("failed to create stream pool")
		.shared();
	let client = SocketClient::new(pool, Duration::from_secs(30));
	let request = borsh::to_vec(&message).expect("failed to serialize request");
	let response = client.call(&request).await.expect("request failed");
	PivotWasmMsg::try_from_slice(&response)
		.expect("failed to deserialize response")
}

fn sign_artifact_approval(
	alias: &str,
	artifact: &PivotWasmArtifact,
) -> Approval {
	let pair = P256Pair::from_hex_file(
		governance_dir().join(format!("{alias}.secret.keep")),
	)
	.expect("failed to read artifact approval secret");
	Approval {
		signature: pair
			.sign(&artifact.approval_payload_hash())
			.expect("failed to sign artifact"),
		member: QuorumMember {
			alias: alias.into(),
			pub_key: pair.public_key().to_bytes(),
		},
	}
}

fn read_envelope(name: &str) -> PivotWasmArtifactEnvelope {
	let path = envelope_path(name);
	let bytes = fs::read(&path).unwrap_or_else(|e| {
		panic!("failed to read envelope {}: {e}", path.display())
	});
	PivotWasmArtifactEnvelope::try_from_slice(&bytes).unwrap_or_else(|e| {
		panic!("failed to decode envelope {}: {e}", path.display())
	})
}

fn write_borsh<P, T>(path: P, value: &T, label: &str)
where
	P: AsRef<Path>,
	T: borsh::BorshSerialize,
{
	let bytes = borsh::to_vec(value).expect("failed to serialize value");
	fs::write(path.as_ref(), bytes).unwrap_or_else(|e| {
		panic!("failed to write {label} to {}: {e}", path.as_ref().display())
	});
}

fn create_dirs() {
	for path in [
		out_dir(),
		governance_dir(),
		artifacts_dir(),
		envelopes_dir(),
		attestations_dir(),
	] {
		fs::create_dir_all(path).expect("failed to create meta-pivot dir");
	}
}

fn out_dir() -> PathBuf {
	PathBuf::from(OUT_DIR)
}

fn governance_dir() -> PathBuf {
	PathBuf::from(GOVERNANCE_DIR)
}

fn artifacts_dir() -> PathBuf {
	PathBuf::from(ARTIFACTS_DIR)
}

fn envelopes_dir() -> PathBuf {
	PathBuf::from(ENVELOPES_DIR)
}

fn attestations_dir() -> PathBuf {
	PathBuf::from(ATTESTATIONS_DIR)
}

fn governance_path() -> PathBuf {
	governance_dir().join("artifact_set.borsh")
}

fn local_ephemeral_path() -> PathBuf {
	governance_dir().join("local-ephemeral.secret.keep")
}

fn artifact_path(name: &str) -> PathBuf {
	artifacts_dir().join(format!("{name}.wasm"))
}

fn envelope_path(name: &str) -> PathBuf {
	envelopes_dir().join(format!("{name}.envelope.borsh"))
}

fn wasm_output_path(spec: &ArtifactSpec) -> PathBuf {
	PathBuf::from(format!(
		"target/wasm32-unknown-unknown/release/{}.wasm",
		spec.crate_name
	))
}

fn display_bytes(bytes: &[u8]) -> String {
	String::from_utf8(bytes.to_vec())
		.unwrap_or_else(|_| format!("0x{}", qos_hex::encode(bytes)))
}

struct InvokeOptions<'a> {
	function: &'a str,
	policy: &'a str,
	input: String,
}

impl<'a> InvokeOptions<'a> {
	fn parse(args: &'a [String]) -> Self {
		let mut function = "reverse";
		let mut policy = "max-input-len";
		let mut input = "hello world".to_string();
		let mut i = 0;
		while i < args.len() {
			match args[i].as_str() {
				"--policy" => {
					i += 1;
					policy = args
						.get(i)
						.map(String::as_str)
						.unwrap_or_else(|| panic!("--policy requires a value"));
				}
				"--input" => {
					i += 1;
					input = args
						.get(i)
						.unwrap_or_else(|| panic!("--input requires a value"))
						.clone();
				}
				value => {
					function = value;
				}
			}
			i += 1;
		}

		Self { function, policy, input }
	}
}

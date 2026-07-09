//! Demo driver for `pivot_vfaas`. Run via `cargo xtask <subcommand>`.
//!
//! Subcommands:
//! - `bootstrap`: generate the owner key and build the example WASM blobs.
//! - `build-wasm <name>`: build a single example to wasm32-unknown-unknown.
//! - `register-program --wasm <path>`: sign + send `RegisterProgramRequest`.
//! - `register-policy --wasm <path>`: sign + send `RegisterPolicyRequest`.
//! - `execute --program <hash> --policy <hash> --input <bytes>`:
//!   send `ExecuteRequest` and verify the returned attestation.
//! - `ls`: list registered program and policy hashes.

use std::{
	path::{Path, PathBuf},
	process::Command,
	time::Duration,
};

use borsh::BorshDeserialize;
use clap::{Parser, Subcommand};
use integration::{
	Decision, VfaasMsg,
	vfaas::{
		build_register_policy, build_register_program, owner_keygen,
		verify_execution_attestation,
	},
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
};
use qos_p256::P256Pair;

const DEFAULT_SOCKET: &str = "/tmp/pivot_vfaas.sock";
const DEFAULT_WORKDIR: &str = "./local-vfaas";
const EXAMPLES: &[(&str, &str)] = &[
	("reverse", "vfaas_reverse"),
	("allow-small-input", "vfaas_allow_small_input"),
];

#[derive(Parser)]
#[command(name = "xtask", about = "vfaas demo driver")]
struct Cli {
	#[command(subcommand)]
	command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
	/// Generate the owner key and build all example WASM blobs.
	Bootstrap {
		#[arg(long, default_value = DEFAULT_WORKDIR)]
		workdir: PathBuf,
	},
	/// Build a single example crate to wasm32-unknown-unknown.
	BuildWasm {
		/// Example name (directory under src/vfaas/examples/).
		name: String,
		#[arg(long, default_value = DEFAULT_WORKDIR)]
		workdir: PathBuf,
	},
	/// Register a program WASM blob with the running pivot.
	RegisterProgram {
		#[arg(long)]
		wasm: PathBuf,
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
		#[arg(long, default_value = DEFAULT_WORKDIR)]
		workdir: PathBuf,
	},
	/// Register a policy WASM blob with the running pivot.
	RegisterPolicy {
		#[arg(long)]
		wasm: PathBuf,
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
		#[arg(long, default_value = DEFAULT_WORKDIR)]
		workdir: PathBuf,
	},
	/// Send an execute request and verify the returned attestation.
	Execute {
		#[arg(long)]
		program: String,
		#[arg(long)]
		policy: String,
		#[arg(long)]
		input: String,
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
	/// List registered program and policy hashes.
	Ls {
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let result = match cli.command {
		Cmd::Bootstrap { workdir } => bootstrap(&workdir).await,
		Cmd::BuildWasm { name, workdir } => {
			build_wasm(&name, &workdir).map(|_| ())
		}
		Cmd::RegisterProgram {
			wasm,
			socket,
			workdir,
		} => register(&wasm, &socket, &workdir, RegisterKind::Program).await,
		Cmd::RegisterPolicy {
			wasm,
			socket,
			workdir,
		} => register(&wasm, &socket, &workdir, RegisterKind::Policy).await,
		Cmd::Execute {
			program,
			policy,
			input,
			socket,
		} => execute(&program, &policy, &input, &socket).await,
		Cmd::Ls { socket } => ls(&socket).await,
	};
	if let Err(e) = result {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

enum RegisterKind {
	Program,
	Policy,
}

async fn bootstrap(workdir: &Path) -> Result<(), String> {
	std::fs::create_dir_all(workdir.join("wasm"))
		.map_err(|e| format!("create_dir_all: {e}"))?;

	let secret_path = workdir.join("owner.secret");
	if secret_path.exists() {
		println!(
			"owner key already exists at {} (skipping keygen)",
			secret_path.display()
		);
	} else {
		let owner = owner_keygen().map_err(|e| format!("keygen: {e:?}"))?;
		owner
			.to_hex_file(&secret_path)
			.map_err(|e| format!("write owner.secret: {e:?}"))?;
		owner
			.public_key()
			.to_hex_file(workdir.join("owner.pub"))
			.map_err(|e| format!("write owner.pub: {e:?}"))?;
		println!("generated owner key at {}", secret_path.display());
	}

	for (dir, crate_name) in EXAMPLES {
		println!("building example: {dir}");
		let wasm = build_wasm(dir, workdir)?;
		println!("  -> {} ({} bytes)", wasm.display(), std::fs::metadata(&wasm).map(|m| m.len()).unwrap_or(0));
		let _ = crate_name; // tracked for clarity; actually used inside build_wasm
	}
	Ok(())
}

fn build_wasm(name: &str, workdir: &Path) -> Result<PathBuf, String> {
	let crate_name = EXAMPLES
		.iter()
		.find(|(d, _)| *d == name)
		.map(|(_, c)| *c)
		.ok_or_else(|| {
			format!(
				"unknown example {name:?}; known: {:?}",
				EXAMPLES.iter().map(|(d, _)| *d).collect::<Vec<_>>()
			)
		})?;

	let manifest = PathBuf::from("src/vfaas/examples")
		.join(name)
		.join("Cargo.toml");
	let status = Command::new("cargo")
		.args([
			"build",
			"--release",
			"--target",
			"wasm32-unknown-unknown",
			"--manifest-path",
		])
		.arg(&manifest)
		.status()
		.map_err(|e| format!("spawn cargo build: {e}"))?;
	if !status.success() {
		return Err(format!("cargo build failed for {name}"));
	}

	let built = PathBuf::from("src/vfaas/examples")
		.join(name)
		.join("target/wasm32-unknown-unknown/release")
		.join(format!("{crate_name}.wasm"));
	if !built.exists() {
		return Err(format!(
			"expected wasm output at {} but file is missing",
			built.display()
		));
	}

	let dest = workdir.join("wasm").join(format!("{name}.wasm"));
	std::fs::create_dir_all(workdir.join("wasm"))
		.map_err(|e| format!("create wasm dir: {e}"))?;
	std::fs::copy(&built, &dest).map_err(|e| {
		format!("copy {} -> {}: {e}", built.display(), dest.display())
	})?;
	Ok(dest)
}

async fn register(
	wasm_path: &Path,
	socket: &Path,
	workdir: &Path,
	kind: RegisterKind,
) -> Result<(), String> {
	let owner = load_owner(workdir)?;
	let wasm = std::fs::read(wasm_path)
		.map_err(|e| format!("read {}: {e}", wasm_path.display()))?;

	let msg = match kind {
		RegisterKind::Program => build_register_program(&owner, wasm),
		RegisterKind::Policy => build_register_policy(&owner, wasm),
	}
	.map_err(|e| format!("build register request: {e:?}"))?;

	let resp = call(socket, &msg).await?;
	match (kind, &resp) {
		(
			RegisterKind::Program,
			VfaasMsg::RegisterProgramResponse { hash },
		)
		| (
			RegisterKind::Policy,
			VfaasMsg::RegisterPolicyResponse { hash },
		) => {
			println!("registered: {}", qos_hex::encode(hash));
			Ok(())
		}
		(_, VfaasMsg::Error(e)) => Err(format!("pivot error: {e}")),
		(_, other) => Err(format!("unexpected response: {other:?}")),
	}
}

async fn execute(
	program_hex: &str,
	policy_hex: &str,
	input: &str,
	socket: &Path,
) -> Result<(), String> {
	let program_hash = parse_hash(program_hex, "program")?;
	let policy_hash = parse_hash(policy_hex, "policy")?;
	let input_bytes = input.as_bytes().to_vec();

	let msg = VfaasMsg::ExecuteRequest {
		program_hash,
		policy_hash,
		input: input_bytes,
	};

	let resp = call(socket, &msg).await?;
	let VfaasMsg::ExecuteResponse {
		decision,
		output,
		attestation,
	} = resp
	else {
		if let VfaasMsg::Error(e) = resp {
			return Err(format!("pivot error: {e}"));
		}
		return Err(format!("unexpected response: {resp:?}"));
	};

	verify_execution_attestation(&attestation)
		.map_err(|e| format!("attestation verification failed: {e:?}"))?;
	println!("attestation verified (signed by enclave ephemeral key).");
	println!("request_id: {}", attestation.attestation.request_id);
	println!("decision:   {:?}", decision);
	match (&decision, output) {
		(Decision::Allow, Some(bytes)) => {
			println!("output ({} bytes):", bytes.len());
			match std::str::from_utf8(&bytes) {
				Ok(s) => println!("  utf8: {s:?}"),
				Err(_) => println!("  hex:  {}", qos_hex::encode(&bytes)),
			}
		}
		(Decision::Allow, None) => {
			println!("(no output bytes returned)");
		}
		(Decision::Deny(reason), _) => {
			println!("denied: {reason}");
		}
	}
	Ok(())
}

async fn ls(socket: &Path) -> Result<(), String> {
	let programs = call(socket, &VfaasMsg::ListProgramsRequest).await?;
	let policies = call(socket, &VfaasMsg::ListPoliciesRequest).await?;
	match programs {
		VfaasMsg::ListProgramsResponse { hashes } => {
			println!("programs ({}):", hashes.len());
			for h in hashes {
				println!("  {}", qos_hex::encode(&h));
			}
		}
		VfaasMsg::Error(e) => return Err(format!("programs: {e}")),
		other => return Err(format!("unexpected: {other:?}")),
	}
	match policies {
		VfaasMsg::ListPoliciesResponse { hashes } => {
			println!("policies ({}):", hashes.len());
			for h in hashes {
				println!("  {}", qos_hex::encode(&h));
			}
		}
		VfaasMsg::Error(e) => return Err(format!("policies: {e}")),
		other => return Err(format!("unexpected: {other:?}")),
	}
	Ok(())
}

fn load_owner(workdir: &Path) -> Result<P256Pair, String> {
	let path = workdir.join("owner.secret");
	P256Pair::from_hex_file(&path)
		.map_err(|e| format!("load owner key from {}: {e:?}", path.display()))
}

fn parse_hash(hex: &str, label: &str) -> Result<[u8; 32], String> {
	let bytes = qos_hex::decode(hex.trim())
		.map_err(|e| format!("{label} hash hex: {e:?}"))?;
	bytes
		.try_into()
		.map_err(|v: Vec<u8>| {
			format!("{label} hash must be 32 bytes, got {}", v.len())
		})
}

async fn call(socket: &Path, msg: &VfaasMsg) -> Result<VfaasMsg, String> {
	let addr = SocketAddress::new_unix(socket);
	let pool = StreamPool::new(addr, 1)
		.map_err(|e| format!("stream pool: {e:?}"))?
		.shared();
	let client = SocketClient::new(pool, Duration::from_secs(30));
	let payload =
		borsh::to_vec(msg).map_err(|e| format!("serialize request: {e}"))?;
	let bytes = client
		.call(&payload)
		.await
		.map_err(|e| format!("pivot call: {e:?}"))?;
	VfaasMsg::try_from_slice(&bytes)
		.map_err(|e| format!("deserialize response: {e}"))
}

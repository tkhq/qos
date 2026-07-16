//! Demo driver for `pivot_vfaas`. Run via `cargo xtask <subcommand>`.
//!
//! Subcommands:
//! - `bootstrap`: generate the 2-of-3 artifact quorum and the local
//!   ephemeral key, and write the Borsh `ManifestSet` governance file.
//! - `build [name]`: build example crates to `wasm32-unknown-unknown`.
//! - `approve [name] [--policy <policy>]`: build artifact descriptors and
//!   collect 2-of-3 quorum signatures into envelope files. For functions
//!   this also signs the program→policy ruleset binding — a program cannot
//!   be registered without one.
//! - `register [name]`: register approved artifacts (and, for functions,
//!   their rulesets) with the running pivot.
//! - `invoke <function> ...`: execute under the function's quorum-bound
//!   policy and verify the returned attestation.
//! - `ls`: list registered artifacts and their policy bindings.
//! - `demo`: the whole three-act pitch script against a freshly spawned
//!   pivot.
//!
//! Artifacts are addressed by name everywhere; hashes live in envelope
//! files under `target/vfaas/` and are never copy-pasted by hand.

use std::{
	path::{Path, PathBuf},
	process::{Child, Command},
	time::Duration,
};

use borsh::BorshDeserialize;
use clap::{Parser, Subcommand, ValueEnum};
use integration::{
	vfaas::{
		AttestationVerifyError, RegisteredArtifact, VfaasMsg,
		governance::{
			Artifact, ArtifactEnvelope, ArtifactKind, Ruleset,
			RulesetEnvelope, approve_artifact, approve_ruleset,
		},
		verify_execution_attestation,
	},
	wait_for_usock,
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::{ManifestSet, QuorumMember},
};
use qos_crypto::sha_256;
use qos_p256::P256Pair;
use vfaas_abi::{ExecutionAttestation, ExecutionOutcome, PolicyHash, ProgramHash};
use vfaas_fee_calculator::{FeeQuote, FeeRequest, Tier};

/// Repo root, resolved at compile time so xtask works from any cwd.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const DEFAULT_SOCKET: &str = "/tmp/pivot_vfaas.sock";
const QUORUM_ALIASES: [&str; 3] = ["user1", "user2", "user3"];
const QUORUM_THRESHOLD: u32 = 2;
const APPROVERS: [&str; 2] = ["user1", "user2"];

struct ExampleSpec {
	/// Artifact + directory name under `src/vfaas/examples/`.
	name: &'static str,
	/// Crate name, i.e. the wasm file stem cargo produces.
	crate_name: &'static str,
	kind: ArtifactKind,
	/// Per-artifact fuel budget; part of the signed descriptor.
	fuel_budget: Option<u64>,
	/// For functions: the default policy the quorum binds the program to.
	/// Overridable per approval with `--policy`; a program cannot register
	/// without a binding.
	bound_policy: Option<&'static str>,
}

const EXAMPLES: &[ExampleSpec] = &[
	ExampleSpec {
		name: "reverse",
		crate_name: "vfaas_reverse",
		kind: ArtifactKind::Function,
		fuel_budget: None,
		bound_policy: Some("allow-small-input"),
	},
	ExampleSpec {
		name: "fee-calculator",
		crate_name: "vfaas_fee_calculator",
		kind: ArtifactKind::Function,
		// Deliberately non-default to show budgets are approved per
		// artifact as part of the signed descriptor.
		fuel_budget: Some(2_000_000),
		bound_policy: Some("allow-small-input"),
	},
	ExampleSpec {
		name: "allow-small-input",
		crate_name: "vfaas_allow_small_input",
		kind: ArtifactKind::Policy,
		fuel_budget: None,
		bound_policy: None,
	},
	ExampleSpec {
		name: "allow-hashlist",
		crate_name: "vfaas_allow_hashlist",
		kind: ArtifactKind::Policy,
		fuel_budget: None,
		bound_policy: None,
	},
];

#[derive(Parser)]
#[command(name = "xtask", about = "vfaas demo driver")]
struct Cli {
	#[command(subcommand)]
	command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
	/// Generate the artifact quorum, governance file, and ephemeral key.
	Bootstrap,
	/// Build example crates to wasm32-unknown-unknown.
	Build {
		/// Example name; omit to build all.
		name: Option<String>,
	},
	/// Sign artifact descriptors into 2-of-3 approved envelopes; for
	/// functions, also sign the program→policy ruleset binding.
	Approve {
		/// Example name; omit to approve all.
		name: Option<String>,
		/// Policy to bind (functions only); defaults to the example's
		/// declared policy. Requires a single example name.
		#[arg(long)]
		policy: Option<String>,
	},
	/// Register approved artifacts with the running pivot.
	Register {
		/// Example name; omit to register all.
		name: Option<String>,
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
	/// Execute a function under its quorum-bound policy and verify the
	/// attestation.
	Invoke {
		/// Function artifact name.
		function: String,
		/// Raw string input, Borsh-encoded as bytes (for `reverse`).
		#[arg(long, conflicts_with_all = ["amount", "tier"])]
		input: Option<String>,
		/// Transaction amount in cents (for `fee-calculator`).
		#[arg(long, requires = "tier")]
		amount: Option<u64>,
		/// Pricing tier (for `fee-calculator`).
		#[arg(long, requires = "amount")]
		tier: Option<TierArg>,
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
	/// List registered artifacts.
	Ls {
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
	/// Run the full three-act demo against a freshly spawned pivot.
	Demo {
		#[arg(long, default_value = DEFAULT_SOCKET)]
		socket: PathBuf,
	},
}

#[derive(Clone, Copy, ValueEnum)]
enum TierArg {
	Basic,
	Pro,
	Enterprise,
}

impl From<TierArg> for Tier {
	fn from(tier: TierArg) -> Self {
		match tier {
			TierArg::Basic => Tier::Basic,
			TierArg::Pro => Tier::Pro,
			TierArg::Enterprise => Tier::Enterprise,
		}
	}
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let result = match cli.command {
		Cmd::Bootstrap => bootstrap(),
		Cmd::Build { name } => for_each_spec(name.as_deref(), build_wasm),
		Cmd::Approve { name, policy } => {
			approve_cmd(name.as_deref(), policy.as_deref())
		}
		Cmd::Register { name, socket } => {
			register(name.as_deref(), &socket).await
		}
		Cmd::Invoke { function, input, amount, tier, socket } => {
			invoke(&function, input, amount, tier, &socket).await.map(|_| ())
		}
		Cmd::Ls { socket } => ls(&socket).await,
		Cmd::Demo { socket } => demo(&socket).await,
	};
	if let Err(e) = result {
		eprintln!("error: {e}");
		std::process::exit(1);
	}
}

// --- paths ---------------------------------------------------------------

fn repo_root() -> PathBuf {
	PathBuf::from(REPO_ROOT)
}

fn vfaas_dir() -> PathBuf {
	repo_root().join("target/vfaas")
}

fn governance_dir() -> PathBuf {
	vfaas_dir().join("governance")
}

fn artifacts_dir() -> PathBuf {
	vfaas_dir().join("artifacts")
}

fn envelopes_dir() -> PathBuf {
	vfaas_dir().join("envelopes")
}

fn manifest_set_path() -> PathBuf {
	governance_dir().join("manifest_set.borsh")
}

fn ephemeral_key_path() -> PathBuf {
	governance_dir().join("local-ephemeral.secret.keep")
}

fn member_secret_path(alias: &str) -> PathBuf {
	governance_dir().join(format!("{alias}.secret.keep"))
}

fn artifact_path(name: &str) -> PathBuf {
	artifacts_dir().join(format!("{name}.wasm"))
}

fn envelope_path(name: &str) -> PathBuf {
	envelopes_dir().join(format!("{name}.envelope.borsh"))
}

fn ruleset_path(name: &str) -> PathBuf {
	envelopes_dir().join(format!("{name}.ruleset.borsh"))
}

fn spec(name: &str) -> Result<&'static ExampleSpec, String> {
	EXAMPLES.iter().find(|s| s.name == name).ok_or_else(|| {
		format!(
			"unknown example {name:?}; known: {:?}",
			EXAMPLES.iter().map(|s| s.name).collect::<Vec<_>>()
		)
	})
}

fn for_each_spec(
	name: Option<&str>,
	f: impl Fn(&ExampleSpec) -> Result<(), String>,
) -> Result<(), String> {
	match name {
		Some(name) => f(spec(name)?),
		None => {
			for spec in EXAMPLES {
				f(spec)?;
			}
			Ok(())
		}
	}
}

// --- bootstrap -----------------------------------------------------------

fn bootstrap() -> Result<(), String> {
	std::fs::create_dir_all(governance_dir())
		.map_err(|e| format!("create governance dir: {e}"))?;

	if manifest_set_path().exists() {
		println!(
			"governance already bootstrapped at {} (delete target/vfaas to reset)",
			manifest_set_path().display()
		);
		return Ok(());
	}

	let mut members = Vec::new();
	for alias in QUORUM_ALIASES {
		let pair =
			P256Pair::generate().map_err(|e| format!("keygen: {e:?}"))?;
		pair.to_hex_file(member_secret_path(alias))
			.map_err(|e| format!("write {alias} secret: {e:?}"))?;
		members.push(QuorumMember {
			alias: alias.into(),
			pub_key: pair.public_key().to_bytes(),
		});
		println!("generated quorum member key: {alias}");
	}

	let manifest_set =
		ManifestSet { threshold: QUORUM_THRESHOLD, members };
	write_borsh(&manifest_set_path(), &manifest_set, "manifest set")?;
	println!(
		"wrote {QUORUM_THRESHOLD}-of-{} governance file: {}",
		QUORUM_ALIASES.len(),
		manifest_set_path().display()
	);

	let ephemeral =
		P256Pair::generate().map_err(|e| format!("ephemeral keygen: {e:?}"))?;
	ephemeral
		.to_hex_file(ephemeral_key_path())
		.map_err(|e| format!("write ephemeral key: {e:?}"))?;
	println!("wrote local ephemeral key: {}", ephemeral_key_path().display());

	println!();
	println!("run the pivot with:");
	println!(
		"  cargo run --bin pivot_vfaas -- {DEFAULT_SOCKET} {} {}",
		manifest_set_path().display(),
		ephemeral_key_path().display()
	);
	Ok(())
}

// --- build ---------------------------------------------------------------

fn build_wasm(spec: &ExampleSpec) -> Result<(), String> {
	println!("building {} to wasm32-unknown-unknown...", spec.name);
	let manifest = repo_root()
		.join("src/vfaas/examples")
		.join(spec.name)
		.join("Cargo.toml");
	let status = Command::new("cargo")
		.args(["build", "--release", "--target", "wasm32-unknown-unknown"])
		.arg("--manifest-path")
		.arg(&manifest)
		.arg("--target-dir")
		.arg(repo_root().join("target"))
		.status()
		.map_err(|e| format!("spawn cargo build: {e}"))?;
	if !status.success() {
		return Err(format!("cargo build failed for {}", spec.name));
	}

	let built = repo_root()
		.join("target/wasm32-unknown-unknown/release")
		.join(format!("{}.wasm", spec.crate_name));
	std::fs::create_dir_all(artifacts_dir())
		.map_err(|e| format!("create artifacts dir: {e}"))?;
	let dest = artifact_path(spec.name);
	std::fs::copy(&built, &dest).map_err(|e| {
		format!("copy {} -> {}: {e}", built.display(), dest.display())
	})?;
	let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
	println!("  -> {} ({size} bytes)", dest.display());
	Ok(())
}

// --- approve -------------------------------------------------------------

fn approve_cmd(
	name: Option<&str>,
	policy_override: Option<&str>,
) -> Result<(), String> {
	if policy_override.is_some() && name.is_none() {
		return Err(
			"--policy requires a single example name to bind it to".into()
		);
	}
	for_each_spec(name, |spec| approve(spec, policy_override))
}

fn approve(
	spec: &ExampleSpec,
	policy_override: Option<&str>,
) -> Result<(), String> {
	let wasm = std::fs::read(artifact_path(spec.name)).map_err(|e| {
		format!(
			"missing artifact {}: {e}; run `cargo xtask build` first",
			artifact_path(spec.name).display()
		)
	})?;
	let metadata = format!(
		"name={};crate={};kind={:?};version=0.1.0",
		spec.name, spec.crate_name, spec.kind
	);
	let artifact = Artifact::new(
		spec.kind,
		spec.name,
		"0.1.0",
		&wasm,
		metadata.as_bytes(),
		spec.fuel_budget,
	);

	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: load_approvers()?
			.into_iter()
			.map(|(pair, member)| approve_artifact(&artifact, &pair, member))
			.collect(),
	};
	std::fs::create_dir_all(envelopes_dir())
		.map_err(|e| format!("create envelopes dir: {e}"))?;
	write_borsh(&envelope_path(spec.name), &envelope, "artifact envelope")?;
	let budget = artifact
		.fuel_budget
		.map_or_else(|| "default".to_string(), |b| b.to_string());
	println!(
		"approved {} ({:?}, fuel budget: {budget}) by {APPROVERS:?}: {}",
		spec.name,
		spec.kind,
		qos_hex::encode(&artifact.wasm_hash)
	);

	// The same quorum signs the program→policy binding: a function may not
	// register without one, and rebinding takes a fresh 2-of-3 approval.
	match spec.kind {
		ArtifactKind::Function => {
			let policy_name = policy_override
				.or(spec.bound_policy)
				.ok_or_else(|| {
					format!(
						"function {} declares no policy; pass --policy",
						spec.name
					)
				})?;
			let policy_spec = self::spec(policy_name)?;
			if policy_spec.kind != ArtifactKind::Policy {
				return Err(format!(
					"{policy_name} is a {:?}, not a policy",
					policy_spec.kind
				));
			}
			let policy_wasm = std::fs::read(artifact_path(policy_name))
				.map_err(|e| {
					format!(
						"missing policy artifact {}: {e}; run `cargo xtask \
						 build` first",
						artifact_path(policy_name).display()
					)
				})?;
			let ruleset = Ruleset {
				program: ProgramHash::new(artifact.wasm_hash),
				policy: PolicyHash::new(sha_256(&policy_wasm)),
			};
			let ruleset_envelope = RulesetEnvelope {
				ruleset,
				approvals: load_approvers()?
					.into_iter()
					.map(|(pair, member)| {
						approve_ruleset(&ruleset, &pair, member)
					})
					.collect(),
			};
			write_borsh(
				&ruleset_path(spec.name),
				&ruleset_envelope,
				"ruleset envelope",
			)?;
			println!(
				"  bound {} -> policy {policy_name} ({}) by {APPROVERS:?}",
				spec.name, ruleset.policy
			);
		}
		ArtifactKind::Policy => {
			if let Some(policy) = policy_override {
				return Err(format!(
					"{} is a policy; --policy {policy} only applies to \
					 functions",
					spec.name
				));
			}
		}
	}
	Ok(())
}

/// Load the demo's approving quorum members and their signing keys.
fn load_approvers() -> Result<Vec<(P256Pair, QuorumMember)>, String> {
	APPROVERS
		.iter()
		.map(|alias| {
			let pair = P256Pair::from_hex_file(member_secret_path(alias))
				.map_err(|e| {
					format!(
						"load {alias} key: {e:?}; run `cargo xtask bootstrap` \
						 first"
					)
				})?;
			let member = QuorumMember {
				alias: (*alias).into(),
				pub_key: pair.public_key().to_bytes(),
			};
			Ok((pair, member))
		})
		.collect()
}

// --- register / ls -------------------------------------------------------

async fn register(name: Option<&str>, socket: &Path) -> Result<(), String> {
	let mut specs: Vec<&ExampleSpec> = match name {
		Some(name) => vec![spec(name)?],
		None => EXAMPLES.iter().collect(),
	};
	// The pivot refuses a program whose bound policy is not yet registered,
	// so policies go first.
	specs.sort_by_key(|spec| match spec.kind {
		ArtifactKind::Policy => 0,
		ArtifactKind::Function => 1,
	});
	for spec in specs {
		let envelope = read_envelope(spec.name)?;
		let wasm = std::fs::read(artifact_path(spec.name))
			.map_err(|e| format!("read artifact {}: {e}", spec.name))?;
		let ruleset = match spec.kind {
			ArtifactKind::Function => Some(read_ruleset(spec.name)?),
			ArtifactKind::Policy => None,
		};
		let bound = ruleset
			.as_ref()
			.map(|rs| format!(" under policy {}", rs.ruleset.policy))
			.unwrap_or_default();
		let response = call(
			socket,
			&VfaasMsg::RegisterArtifactRequest { envelope, wasm, ruleset },
		)
		.await?;
		match response {
			VfaasMsg::RegisterArtifactResponse { artifact } => {
				println!(
					"registered {} {}{bound}",
					artifact.name,
					qos_hex::encode(&artifact.wasm_hash)
				);
			}
			VfaasMsg::Error(e) => {
				return Err(format!("register {}: {e}", spec.name));
			}
			other => {
				return Err(format!("unexpected response: {other:?}"));
			}
		}
	}
	Ok(())
}

async fn ls(socket: &Path) -> Result<(), String> {
	let response = call(socket, &VfaasMsg::ListArtifactsRequest).await?;
	let VfaasMsg::ListArtifactsResponse { artifacts } = response else {
		return Err(format!("unexpected response: {response:?}"));
	};
	// Resolve each function's bound policy hash to a name when the policy
	// is registered on the same pivot.
	let names_by_hash: std::collections::HashMap<[u8; 32], String> = artifacts
		.iter()
		.map(|ra| (ra.artifact.wasm_hash, ra.artifact.name.clone()))
		.collect();
	println!("registered artifacts ({}):", artifacts.len());
	for RegisteredArtifact { artifact, approval_count, bound_policy } in
		artifacts
	{
		let budget = artifact
			.fuel_budget
			.map_or_else(|| "default".to_string(), |b| b.to_string());
		let policy = bound_policy.map_or_else(
			|| "-".to_string(),
			|hash| {
				names_by_hash
					.get(hash.as_bytes())
					.cloned()
					.unwrap_or_else(|| hash.to_string())
			},
		);
		println!(
			"  {:<20} {:?}v{} approvals={approval_count} fuel={budget} \
			 policy={policy} {}",
			artifact.name,
			artifact.kind,
			artifact.version,
			qos_hex::encode(&artifact.wasm_hash),
		);
	}
	Ok(())
}

// --- invoke --------------------------------------------------------------

async fn invoke(
	function: &str,
	input: Option<String>,
	amount: Option<u64>,
	tier: Option<TierArg>,
	socket: &Path,
) -> Result<ExecutionAttestation, String> {
	let function_envelope = read_envelope(function)?;

	// The caller names only the program. The gating policy was fixed by the
	// quorum-approved ruleset at registration and cannot be chosen here.
	let input_bytes = encode_input(input, amount, tier)?;
	let msg = VfaasMsg::ExecuteRequest {
		program: ProgramHash::new(function_envelope.artifact.wasm_hash),
		input: input_bytes,
	};

	let response = call(socket, &msg).await?;
	let VfaasMsg::ExecuteResponse { output, attestation } = response else {
		if let VfaasMsg::Error(e) = response {
			return Err(format!("pivot error: {e}"));
		}
		return Err(format!("unexpected response: {response:?}"));
	};

	verify_execution_attestation(&attestation)
		.map_err(|e: AttestationVerifyError| {
			format!("attestation verification FAILED: {e:?}")
		})?;

	println!("attestation: VERIFIED (signed by enclave ephemeral key)");
	println!("  engine:     {}", qos_hex::encode(&attestation.payload.engine_id));
	println!("  request_id: {}", attestation.payload.request_id);
	match &attestation.payload.outcome {
		ExecutionOutcome::Allowed { output_hash } => {
			println!("  outcome:    ALLOWED");
			println!("  output_hash: {}", qos_hex::encode(output_hash));
			match output {
				Some(bytes) => print_output(function, &bytes),
				None => println!("  (no output bytes returned)"),
			}
		}
		ExecutionOutcome::Denied { reason } => {
			println!("  outcome:    DENIED — {reason}");
		}
		ExecutionOutcome::Failed { stage, reason } => {
			println!("  outcome:    FAILED at {stage:?} — {reason}");
		}
	}
	Ok(attestation)
}

fn encode_input(
	input: Option<String>,
	amount: Option<u64>,
	tier: Option<TierArg>,
) -> Result<Vec<u8>, String> {
	if let (Some(amount), Some(tier)) = (amount, tier) {
		let request = FeeRequest { amount_cents: amount, tier: tier.into() };
		return borsh::to_vec(&request)
			.map_err(|e| format!("encode FeeRequest: {e}"));
	}
	let text = input.unwrap_or_else(|| "hello world".to_string());
	borsh::to_vec(&text.into_bytes())
		.map_err(|e| format!("encode input bytes: {e}"))
}

fn print_output(function: &str, bytes: &[u8]) {
	if function == "fee-calculator"
		&& let Ok(quote) = FeeQuote::try_from_slice(bytes)
	{
		println!(
			"  output:     fee = {} cents (applied rate: {} bps)",
			quote.fee_cents, quote.applied_bps
		);
		return;
	}
	// Programs like `reverse` emit Borsh Vec<u8>.
	if let Ok(raw) = Vec::<u8>::try_from_slice(bytes) {
		match std::str::from_utf8(&raw) {
			Ok(s) => println!("  output:     {s:?}"),
			Err(_) => println!("  output:     0x{}", qos_hex::encode(&raw)),
		}
		return;
	}
	println!("  output:     0x{}", qos_hex::encode(bytes));
}

// --- demo ----------------------------------------------------------------

/// Kills the spawned pivot when the demo exits, success or failure.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

async fn demo(socket: &Path) -> Result<(), String> {
	banner("ACT 1 — the function author experience");
	println!(
		"The whole authoring surface is one typed Rust function; see\n  \
		 src/vfaas/examples/fee-calculator/src/lib.rs\n\
		 No unsafe, no FFI, no enclave knowledge. Its tests run with no wasm\n\
		 toolchain at all:"
	);
	run_cargo_test("fee-calculator")?;

	banner("ACT 2 — governance: 2-of-3 quorum approval, no reboot");
	bootstrap()?;
	for_each_spec(None, build_wasm)?;
	// Approving a function also signs its program→policy binding: the
	// quorum decides which policy gates which program, not the caller.
	for_each_spec(None, |spec| approve(spec, None))?;

	println!("\nbuilding + starting the pivot (one long-lived deployment)...");
	let status = Command::new("cargo")
		.args(["build", "-p", "integration", "--bin", "pivot_vfaas"])
		.current_dir(repo_root())
		.status()
		.map_err(|e| format!("spawn cargo build: {e}"))?;
	if !status.success() {
		return Err("cargo build --bin pivot_vfaas failed".to_string());
	}
	let pivot = Command::new(repo_root().join("target/debug/pivot_vfaas"))
		.arg(socket)
		.arg(manifest_set_path())
		.arg(ephemeral_key_path())
		.spawn()
		.map_err(|e| format!("spawn pivot: {e}"))?;
	let _pivot_guard = KillOnDrop(pivot);
	wait_for_usock(socket).await;

	println!(
		"\nregistering quorum-approved artifacts with the RUNNING pivot —\n\
		 no new manifest, no re-provisioning, no reboot:"
	);
	register(None, socket).await?;
	ls(socket).await?;

	banner("ACT 3 — verifiability: every outcome is enclave-signed");
	println!("[1/4] typed business logic: quote fees on $10,000.00 (Pro tier)");
	let a = invoke(
		"fee-calculator",
		None,
		Some(1_000_000),
		Some(TierArg::Pro),
		socket,
	)
	.await?;
	expect_outcome(&a, "ALLOWED", matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }))?;

	println!("\n[2/4] smoke test: reverse \"hello world\"");
	let a =
		invoke("reverse", Some("hello world".to_string()), None, None, socket)
			.await?;
	expect_outcome(&a, "ALLOWED", matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }))?;

	println!("\n[3/4] policy denial — 2 KiB input against the 1 KiB policy limit");
	let a = invoke("reverse", Some("x".repeat(2048)), None, None, socket)
		.await?;
	expect_outcome(&a, "DENIED", matches!(a.payload.outcome, ExecutionOutcome::Denied { .. }))?;
	println!("  ^ the denial itself is enclave-signed and just verified");

	println!(
		"\n[4/4] policy rotation — the quorum rebinds reverse to the hash \
		 allowlist"
	);
	println!(
		"  (a fresh 2-of-3 ruleset approval + re-register; still no reboot,\n\
		   and the caller never chooses the policy)"
	);
	approve(spec("reverse")?, Some("allow-hashlist"))?;
	register(Some("reverse"), socket).await?;
	let a =
		invoke("reverse", Some("hello world".to_string()), None, None, socket)
			.await?;
	expect_outcome(&a, "DENIED", matches!(a.payload.outcome, ExecutionOutcome::Denied { .. }))?;
	println!("  ^ the allowlist pins a placeholder hash, so reverse is refused");

	banner("demo complete");
	println!(
		"Same deployment: two functions and two policies hot-registered under\n\
		 2-of-3 quorum approval, each program bound to its policy by a signed\n\
		 ruleset, one live policy rotation — and every outcome verified\n\
		 against the enclave's ephemeral key."
	);
	Ok(())
}

fn expect_outcome(
	attestation: &ExecutionAttestation,
	expected: &str,
	matched: bool,
) -> Result<(), String> {
	if matched {
		Ok(())
	} else {
		Err(format!(
			"demo expected {expected}, got {:?}",
			attestation.payload.outcome
		))
	}
}

fn run_cargo_test(example: &str) -> Result<(), String> {
	let manifest = repo_root()
		.join("src/vfaas/examples")
		.join(example)
		.join("Cargo.toml");
	let status = Command::new("cargo")
		.args(["test", "-q", "--manifest-path"])
		.arg(&manifest)
		.arg("--target-dir")
		.arg(repo_root().join("target/vfaas/host-tests"))
		.status()
		.map_err(|e| format!("spawn cargo test: {e}"))?;
	if status.success() {
		Ok(())
	} else {
		Err(format!("cargo test failed for {example}"))
	}
}

fn banner(title: &str) {
	println!("\n=== {title} ===\n");
}

// --- plumbing ------------------------------------------------------------

fn read_envelope(name: &str) -> Result<ArtifactEnvelope, String> {
	// Names are validated against the spec table so typos fail with the
	// list of known artifacts rather than a missing-file error.
	let spec = spec(name)?;
	let path = envelope_path(spec.name);
	let bytes = std::fs::read(&path).map_err(|e| {
		format!(
			"read envelope {}: {e}; run `cargo xtask approve` first",
			path.display()
		)
	})?;
	ArtifactEnvelope::try_from_slice(&bytes)
		.map_err(|e| format!("decode envelope {}: {e}", path.display()))
}

fn read_ruleset(name: &str) -> Result<RulesetEnvelope, String> {
	let path = ruleset_path(spec(name)?.name);
	let bytes = std::fs::read(&path).map_err(|e| {
		format!(
			"read ruleset {}: {e}; run `cargo xtask approve` first",
			path.display()
		)
	})?;
	RulesetEnvelope::try_from_slice(&bytes)
		.map_err(|e| format!("decode ruleset {}: {e}", path.display()))
}

fn write_borsh<T: borsh::BorshSerialize>(
	path: &Path,
	value: &T,
	label: &str,
) -> Result<(), String> {
	let bytes =
		borsh::to_vec(value).map_err(|e| format!("serialize {label}: {e}"))?;
	std::fs::write(path, bytes)
		.map_err(|e| format!("write {label} to {}: {e}", path.display()))
}

async fn call(socket: &Path, msg: &VfaasMsg) -> Result<VfaasMsg, String> {
	let pool = StreamPool::new(SocketAddress::new_unix(socket), 1)
		.map_err(|e| format!("stream pool: {e:?}"))?
		.shared();
	let client = SocketClient::new(pool, Duration::from_secs(30));
	let payload =
		borsh::to_vec(msg).map_err(|e| format!("serialize request: {e}"))?;
	let bytes = client
		.call(&payload)
		.await
		.map_err(|e| format!("pivot call failed: {e:?} (is the pivot running?)"))?;
	VfaasMsg::try_from_slice(&bytes)
		.map_err(|e| format!("deserialize response: {e}"))
}

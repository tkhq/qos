//! Demo driver for `pivot_vfaas`. Run via `cargo xtask <subcommand>`.
//!
//! Every networked subcommand talks to a pivot over one of two endpoints:
//! `--socket` (the Borsh protocol on a local unix socket) or `--url` (the
//! JSON/HTTP front, e.g. a TVC-deployed enclave). Artifacts are addressed
//! by name everywhere; hashes live in envelope files under `target/vfaas/`
//! and are never copy-pasted by hand.
//!
//! Subcommands: `bootstrap`, `pubkeys`, `build`, `approve`, `register`,
//! `invoke`, `ls`, `demo` — each carries its own `--help` text, which the
//! talk's demo site renders verbatim.

use std::{
	collections::{HashMap, HashSet},
	path::{Path, PathBuf},
	process::{Child, Command},
	time::Duration,
};

use borsh::BorshDeserialize;
use clap::{Args, Parser, Subcommand, ValueEnum};
use integration::{
	vfaas::{
		AttestationVerifyError, VfaasMsg,
		governance::{
			Artifact, ArtifactEnvelope, ArtifactKind, Ruleset, RulesetEnvelope,
			approve_artifact, approve_ruleset,
		},
		http, verify_execution_attestation,
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
use vfaas_abi::{
	ExecutionAttestation, ExecutionAttestationPayload, ExecutionOutcome,
	PolicyHash, ProgramHash,
};
use vfaas_fee_calculator::{FeeQuote, FeeRequest, Tier};
use vfaas_sanctions_screening::{Screen, Status, Verdict};

/// Repo root, resolved at compile time so xtask works from any cwd.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const DEFAULT_SOCKET: &str = "/tmp/pivot_vfaas.sock";
const QUORUM_ALIASES: [&str; 3] = ["user1", "user2", "user3"];
const QUORUM_THRESHOLD: u32 = 2;
const APPROVERS: [&str; 2] = ["user1", "user2"];

struct ExampleSpec {
	/// Spec name: how the artifact is addressed on this CLI, and the file
	/// stem under `target/vfaas/{artifacts,envelopes}`.
	name: &'static str,
	/// Directory under `src/vfaas/examples/`. Differs from `name` for
	/// feature variants of the same crate.
	dir: &'static str,
	/// Crate name, i.e. the wasm file stem cargo produces.
	crate_name: &'static str,
	/// Name in the signed artifact descriptor. Versions of the same
	/// artifact share it.
	artifact_name: &'static str,
	/// Version in the signed artifact descriptor.
	version: &'static str,
	/// Cargo features the wasm is built with.
	features: &'static [&'static str],
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
		dir: "reverse",
		crate_name: "vfaas_reverse",
		artifact_name: "reverse",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Function,
		fuel_budget: None,
		bound_policy: Some("allow-small-input"),
	},
	ExampleSpec {
		name: "fee-calculator",
		dir: "fee-calculator",
		crate_name: "vfaas_fee_calculator",
		artifact_name: "fee-calculator",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Function,
		// Deliberately non-default to show budgets are approved per
		// artifact as part of the signed descriptor.
		fuel_budget: Some(2_000_000),
		bound_policy: Some("allow-small-input"),
	},
	ExampleSpec {
		name: "sanctions-screening",
		dir: "sanctions-screening",
		crate_name: "vfaas_sanctions_screening",
		artifact_name: "sanctions-screening",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Function,
		fuel_budget: None,
		bound_policy: Some("screening-rules"),
	},
	// The upgrade-demo variant: same crate, `list-v2` feature, new wasm
	// hash — a new content address registered against the running pivot.
	ExampleSpec {
		name: "sanctions-screening-v2",
		dir: "sanctions-screening",
		crate_name: "vfaas_sanctions_screening",
		artifact_name: "sanctions-screening",
		version: "0.2.0",
		features: &["list-v2"],
		kind: ArtifactKind::Function,
		fuel_budget: None,
		bound_policy: Some("screening-rules"),
	},
	ExampleSpec {
		name: "allow-small-input",
		dir: "allow-small-input",
		crate_name: "vfaas_allow_small_input",
		artifact_name: "allow-small-input",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Policy,
		fuel_budget: None,
		bound_policy: None,
	},
	ExampleSpec {
		name: "allow-hashlist",
		dir: "allow-hashlist",
		crate_name: "vfaas_allow_hashlist",
		artifact_name: "allow-hashlist",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Policy,
		fuel_budget: None,
		bound_policy: None,
	},
	ExampleSpec {
		name: "screening-rules",
		dir: "screening-rules",
		crate_name: "vfaas_screening_rules",
		artifact_name: "screening-rules",
		version: "0.1.0",
		features: &[],
		kind: ArtifactKind::Policy,
		fuel_budget: None,
		bound_policy: None,
	},
];

#[derive(Parser)]
#[command(
	name = "xtask",
	about = "vfaas demo driver: build, approve, register, and invoke \
	         quorum-approved WASM artifacts on a running pivot"
)]
struct Cli {
	#[command(subcommand)]
	command: Cmd,
}

/// Where a networked subcommand sends its requests.
#[derive(Args)]
struct EndpointArgs {
	/// Unix socket of a locally running pivot (Borsh protocol).
	#[arg(long, default_value = DEFAULT_SOCKET, conflicts_with = "url")]
	socket: PathBuf,
	/// Base URL of a pivot's HTTP front, e.g. a TVC app URL. Registration
	/// repeats until every replica behind the URL has acknowledged.
	#[arg(long)]
	url: Option<String>,
}

impl From<EndpointArgs> for Endpoint {
	fn from(args: EndpointArgs) -> Self {
		match args.url {
			Some(url) => Self::Http(url.trim_end_matches('/').to_string()),
			None => Self::Usock(args.socket),
		}
	}
}

#[derive(Subcommand)]
enum Cmd {
	/// Generate the demo's 2-of-3 artifact quorum and local ephemeral key.
	///
	/// Writes three quorum member signing keys (user1/user2/user3), a
	/// Borsh ManifestSet governance file with threshold 2, and a local
	/// ephemeral key, all under target/vfaas/governance/. These are the
	/// same primitives QOS uses for manifest approval: the manifest set is
	/// the artifact-approval quorum. Idempotent — delete target/vfaas to
	/// reset.
	Bootstrap,
	/// Print the quorum members' composite public keys as JSON.
	///
	/// Output is a newOperators array ready to paste into a TVC app
	/// config, so the enclave's manifest set is built from exactly the
	/// keys that sign artifact approvals here. Requires bootstrap.
	Pubkeys,
	/// Build example crates to wasm32-unknown-unknown.
	///
	/// Builds each example with its declared cargo features and copies the
	/// wasm to target/vfaas/artifacts/<name>.wasm. The wasm hash is the
	/// artifact's content address: sanctions-screening and
	/// sanctions-screening-v2 build the same crate with different features
	/// and therefore different addresses.
	Build {
		/// Example name; omit to build all.
		name: Option<String>,
	},
	/// Sign artifact descriptors into 2-of-3 approved envelopes.
	///
	/// Members sign the whole descriptor — name, version, kind, wasm hash,
	/// ABI version, fuel budget — not just the blob. For functions this
	/// also signs the program→policy ruleset binding: which policy gates
	/// which program is a quorum decision, never a caller choice, and a
	/// program cannot register without one.
	Approve {
		/// Example name; omit to approve all.
		name: Option<String>,
		/// Policy to bind (functions only); defaults to the example's
		/// declared policy. Requires a single example name.
		#[arg(long)]
		policy: Option<String>,
		/// Signing key file of a quorum member; repeat for each approver.
		/// The member alias is the file name up to the first dot (e.g.
		/// user1.secret.keep → user1). Defaults to the bootstrap-generated
		/// user1 and user2 keys.
		#[arg(long = "member-secret")]
		member_secrets: Vec<PathBuf>,
	},
	/// Register approved artifacts with the running pivot.
	///
	/// Sends the exact signed envelope bytes plus the wasm blob; the pivot
	/// re-verifies the 2-of-3 approvals against its manifest set before
	/// accepting. Policies register before functions (a program's bound
	/// policy must already be registered). Over --url, registration
	/// repeats until every replica has acknowledged — each replica reports
	/// a fingerprint of its ephemeral key.
	Register {
		/// Example name; omit to register all.
		name: Option<String>,
		#[command(flatten)]
		endpoint: EndpointArgs,
	},
	/// Execute a function and verify the returned attestation.
	///
	/// The caller names only the program — the pivot resolves the
	/// quorum-bound policy, runs it first, and runs the program only on
	/// Allow. Over --url the request goes to the content-addressed path
	/// POST /f/<wasm-hash>: the URL says exactly which code runs. The
	/// enclave-signed attestation (allowed, denied, or failed) is verified
	/// client-side before anything is trusted.
	Invoke {
		/// Function artifact name.
		function: String,
		/// Raw string input, Borsh-encoded as bytes (for `reverse`).
		#[arg(long, conflicts_with_all = ["amount", "tier", "address"])]
		input: Option<String>,
		/// Transaction amount in cents (for `fee-calculator`).
		#[arg(long, requires = "tier", conflicts_with = "address")]
		amount: Option<u64>,
		/// Pricing tier (for `fee-calculator`).
		#[arg(long, requires = "amount")]
		tier: Option<TierArg>,
		/// Address to screen (for `sanctions-screening`).
		#[arg(long)]
		address: Option<String>,
		#[command(flatten)]
		endpoint: EndpointArgs,
	},
	/// List registered artifacts and their policy bindings.
	Ls {
		#[command(flatten)]
		endpoint: EndpointArgs,
	},
	/// Run the full demo script against a freshly spawned local pivot.
	///
	/// Authoring, 2-of-3 approval, hot registration, typed invocation,
	/// an attested denial, a live policy rotation, and a sanctions-list
	/// upgrade registered against the running pivot — every outcome
	/// verified against the enclave ephemeral key.
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

/// A function's typed input, parsed from the CLI flags.
enum ProgramInput {
	/// Borsh `Vec<u8>` of a string (reverse-style programs).
	Text(String),
	/// A fee-calculator request.
	Fee { amount_cents: u64, tier: Tier },
	/// A sanctions-screening request.
	Address(String),
}

impl ProgramInput {
	fn from_flags(
		input: Option<String>,
		amount: Option<u64>,
		tier: Option<TierArg>,
		address: Option<String>,
	) -> Self {
		if let Some(address) = address {
			return Self::Address(address);
		}

		if let (Some(amount_cents), Some(tier)) = (amount, tier) {
			return Self::Fee { amount_cents, tier: tier.into() };
		}

		Self::Text(input.unwrap_or_else(|| "hello world".to_string()))
	}

	fn encode(&self) -> Result<Vec<u8>, String> {
		match self {
			Self::Text(text) => borsh::to_vec(&text.clone().into_bytes())
				.map_err(|e| format!("encode input bytes: {e}")),
			Self::Fee { amount_cents, tier } => {
				let request =
					FeeRequest { amount_cents: *amount_cents, tier: *tier };
				borsh::to_vec(&request)
					.map_err(|e| format!("encode FeeRequest: {e}"))
			}
			Self::Address(address) => {
				let request = Screen { address: address.clone() };
				borsh::to_vec(&request)
					.map_err(|e| format!("encode Screen: {e}"))
			}
		}
	}
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let result = match cli.command {
		Cmd::Bootstrap => bootstrap(),
		Cmd::Pubkeys => pubkeys(),
		Cmd::Build { name } => for_each_spec(name.as_deref(), build_wasm),
		Cmd::Approve { name, policy, member_secrets } => {
			approve_cmd(name.as_deref(), policy.as_deref(), &member_secrets)
		}
		Cmd::Register { name, endpoint } => {
			register(name.as_deref(), &endpoint.into()).await
		}
		Cmd::Invoke { function, input, amount, tier, address, endpoint } => {
			let program_input =
				ProgramInput::from_flags(input, amount, tier, address);
			invoke(&function, &program_input, &endpoint.into())
				.await
				.map(|_| ())
		}
		Cmd::Ls { endpoint } => ls(&endpoint.into()).await,
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

// --- bootstrap / pubkeys ---------------------------------------------------

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

	let manifest_set = ManifestSet { threshold: QUORUM_THRESHOLD, members };
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
	println!("  cargo run --bin pivot_vfaas -- --usock {DEFAULT_SOCKET} \\");
	println!(
		"    --manifest-set {} --ephemeral-key {}",
		manifest_set_path().display(),
		ephemeral_key_path().display()
	);
	Ok(())
}

fn pubkeys() -> Result<(), String> {
	let operators = QUORUM_ALIASES
		.iter()
		.map(|alias| {
			let pair = P256Pair::from_hex_file(member_secret_path(alias))
				.map_err(|e| {
					format!(
						"load {alias} key: {e:?}; run `cargo xtask bootstrap` \
						 first"
					)
				})?;
			Ok(serde_json::json!({
				"name": alias,
				"publicKey": qos_hex::encode(&pair.public_key().to_bytes()),
			}))
		})
		.collect::<Result<Vec<_>, String>>()?;

	let json = serde_json::to_string_pretty(&operators)
		.map_err(|e| format!("serialize operators: {e}"))?;
	println!("{json}");
	Ok(())
}

// --- build ---------------------------------------------------------------

fn build_wasm(spec: &ExampleSpec) -> Result<(), String> {
	println!("building {} to wasm32-unknown-unknown...", spec.name);
	let manifest = repo_root()
		.join("src/vfaas/examples")
		.join(spec.dir)
		.join("Cargo.toml");
	let mut cargo = Command::new("cargo");
	cargo
		.args(["build", "--release", "--target", "wasm32-unknown-unknown"])
		.arg("--manifest-path")
		.arg(&manifest)
		.arg("--target-dir")
		.arg(repo_root().join("target"));

	if !spec.features.is_empty() {
		cargo.arg("--features").arg(spec.features.join(","));
	}

	let status =
		cargo.status().map_err(|e| format!("spawn cargo build: {e}"))?;

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
	member_secrets: &[PathBuf],
) -> Result<(), String> {
	if policy_override.is_some() && name.is_none() {
		return Err(
			"--policy requires a single example name to bind it to".into()
		);
	}

	let approvers = load_approvers(member_secrets)?;
	for_each_spec(name, |spec| approve(spec, policy_override, &approvers))
}

fn approve(
	spec: &ExampleSpec,
	policy_override: Option<&str>,
	approvers: &[(P256Pair, QuorumMember)],
) -> Result<(), String> {
	let approver_aliases: Vec<&str> =
		approvers.iter().map(|(_, member)| member.alias.as_str()).collect();
	let wasm = std::fs::read(artifact_path(spec.name)).map_err(|e| {
		format!(
			"missing artifact {}: {e}; run `cargo xtask build` first",
			artifact_path(spec.name).display()
		)
	})?;
	let metadata = format!(
		"name={};crate={};kind={:?};version={}",
		spec.artifact_name, spec.crate_name, spec.kind, spec.version
	);
	let artifact = Artifact::new(
		spec.kind,
		spec.artifact_name,
		spec.version,
		&wasm,
		metadata.as_bytes(),
		spec.fuel_budget,
	);

	let envelope = ArtifactEnvelope {
		artifact: artifact.clone(),
		approvals: approvers
			.iter()
			.map(|(pair, member)| {
				approve_artifact(&artifact, pair, member.clone())
			})
			.collect(),
	};
	std::fs::create_dir_all(envelopes_dir())
		.map_err(|e| format!("create envelopes dir: {e}"))?;
	write_borsh(&envelope_path(spec.name), &envelope, "artifact envelope")?;
	let budget = artifact
		.fuel_budget
		.map_or_else(|| "default".to_string(), |b| b.to_string());
	println!(
		"approved {} v{} ({:?}, fuel budget: {budget}) by \
		 {approver_aliases:?}: {}",
		spec.name,
		spec.version,
		spec.kind,
		qos_hex::encode(&artifact.wasm_hash)
	);

	// The same quorum signs the program→policy binding: a function may not
	// register without one, and rebinding takes a fresh 2-of-3 approval.
	match spec.kind {
		ArtifactKind::Function => {
			let policy_name =
				policy_override.or(spec.bound_policy).ok_or_else(|| {
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
				approvals: approvers
					.iter()
					.map(|(pair, member)| {
						approve_ruleset(&ruleset, pair, member.clone())
					})
					.collect(),
			};
			write_borsh(
				&ruleset_path(spec.name),
				&ruleset_envelope,
				"ruleset envelope",
			)?;
			println!(
				"  bound {} -> policy {policy_name} ({}) by \
				 {approver_aliases:?}",
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

/// Load the approving quorum members and their signing keys: the given
/// key files (alias = file name up to the first dot), or the demo's
/// bootstrap-generated approvers when none are given.
fn load_approvers(
	member_secrets: &[PathBuf],
) -> Result<Vec<(P256Pair, QuorumMember)>, String> {
	if member_secrets.is_empty() {
		return APPROVERS
			.iter()
			.map(|alias| {
				load_member((*alias).to_string(), &member_secret_path(alias))
			})
			.collect();
	}

	member_secrets
		.iter()
		.map(|path| {
			let alias = path
				.file_name()
				.and_then(|name| name.to_str())
				.and_then(|name| name.split('.').next())
				.filter(|stem| !stem.is_empty())
				.ok_or_else(|| {
					format!(
						"cannot derive a member alias from {}",
						path.display()
					)
				})?;
			load_member(alias.to_string(), path)
		})
		.collect()
}

fn load_member(
	alias: String,
	path: &Path,
) -> Result<(P256Pair, QuorumMember), String> {
	let pair = P256Pair::from_hex_file(path).map_err(|e| {
		format!(
			"load {alias} key from {}: {e:?}; run `cargo xtask bootstrap` \
			 first",
			path.display()
		)
	})?;
	let member = QuorumMember { alias, pub_key: pair.public_key().to_bytes() };
	Ok((pair, member))
}

// --- endpoint ---------------------------------------------------------------

/// A pivot to talk to: a local unix socket speaking Borsh `VfaasMsg`, or
/// an HTTP front (possibly load-balanced across enclave replicas).
enum Endpoint {
	Usock(PathBuf),
	Http(String),
}

/// Why an execute call failed at the request level (nothing was attested).
enum CallError {
	/// The program's content address is not registered on the replica that
	/// answered — over a load balancer, retrying may land elsewhere.
	NotFound(String),
	Other(String),
}

impl std::fmt::Display for CallError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NotFound(e) | Self::Other(e) => write!(f, "{e}"),
		}
	}
}

impl Endpoint {
	/// Register one artifact. Over HTTP the registration repeats until no
	/// new replica fingerprint has acknowledged for several consecutive
	/// attempts, so every replica behind a load balancer holds the
	/// artifact; each ack is printed as it lands.
	async fn register_artifact(
		&self,
		name: &str,
		envelope: ArtifactEnvelope,
		wasm: Vec<u8>,
		ruleset: Option<RulesetEnvelope>,
	) -> Result<(), String> {
		let bound = ruleset
			.as_ref()
			.map(|rs| format!(" under policy {}", rs.ruleset.policy))
			.unwrap_or_default();

		match self {
			Self::Usock(socket) => {
				let msg = VfaasMsg::RegisterArtifactRequest {
					envelope,
					wasm,
					ruleset,
				};
				match usock_call(socket, &msg).await? {
					VfaasMsg::RegisterArtifactResponse { artifact } => {
						println!(
							"registered {} {}{bound}",
							artifact.name,
							qos_hex::encode(&artifact.wasm_hash)
						);
						Ok(())
					}
					VfaasMsg::Error(e) => Err(format!("register {name}: {e}")),
					other => Err(format!("unexpected response: {other:?}")),
				}
			}
			Self::Http(base) => {
				let envelope_borsh = borsh::to_vec(&envelope)
					.map_err(|e| format!("serialize envelope: {e}"))?;
				let ruleset_borsh = ruleset
					.as_ref()
					.map(borsh::to_vec)
					.transpose()
					.map_err(|e| format!("serialize ruleset: {e}"))?;
				let request = http::RegisterRequest {
					envelope: qos_hex::encode(&envelope_borsh),
					wasm: qos_hex::encode(&wasm),
					ruleset: ruleset_borsh.map(|bytes| qos_hex::encode(&bytes)),
				};

				// Saturate the replica set: stop once several consecutive
				// acks bring no new fingerprint (a single-replica endpoint
				// converges just as well as a 3-replica one).
				let mut replicas: HashSet<String> = HashSet::new();
				let mut acks_without_new = 0;

				for attempt in 1..=20 {
					let ack: http::Registered =
						post_json(&format!("{base}/artifacts"), &request)
							.map_err(|e| format!("register {name}: {e}"))?;
					let fingerprint =
						ack.replica.unwrap_or_else(|| "unknown".to_string());

					if replicas.insert(fingerprint.clone()) {
						acks_without_new = 0;
						println!(
							"registered {} {} on replica {fingerprint} \
							 ({} distinct){bound}",
							ack.name,
							ack.wasm_hash,
							replicas.len()
						);
					} else {
						acks_without_new += 1;
					}

					if acks_without_new >= 4 {
						break;
					}

					if attempt < 20 {
						tokio::time::sleep(Duration::from_millis(500)).await;
					}
				}

				println!("  {name}: live on {} replica(s)", replicas.len());
				Ok(())
			}
		}
	}

	/// List registered artifacts, normalized to the JSON summary shape.
	async fn list(&self) -> Result<http::Artifacts, String> {
		match self {
			Self::Usock(socket) => {
				let response =
					usock_call(socket, &VfaasMsg::ListArtifactsRequest).await?;
				let VfaasMsg::ListArtifactsResponse { artifacts } = response
				else {
					return Err(format!("unexpected response: {response:?}"));
				};
				Ok(http::Artifacts {
					replica: None,
					artifacts: artifacts
						.iter()
						.map(http::ArtifactSummary::from)
						.collect(),
				})
			}
			Self::Http(base) => get_json(&format!("{base}/artifacts")),
		}
	}

	/// Execute a program by content address and return the raw output plus
	/// the enclave-signed attestation (not yet verified).
	async fn execute(
		&self,
		program: ProgramHash,
		input: Vec<u8>,
	) -> Result<(Option<Vec<u8>>, ExecutionAttestation), CallError> {
		match self {
			Self::Usock(socket) => {
				let msg = VfaasMsg::ExecuteRequest { program, input };
				let response =
					usock_call(socket, &msg).await.map_err(CallError::Other)?;
				match response {
					VfaasMsg::ExecuteResponse { output, attestation } => {
						Ok((output, attestation))
					}
					VfaasMsg::Error(e)
						if e.starts_with("artifact not registered") =>
					{
						Err(CallError::NotFound(format!("pivot error: {e}")))
					}
					VfaasMsg::Error(e) => {
						Err(CallError::Other(format!("pivot error: {e}")))
					}
					other => Err(CallError::Other(format!(
						"unexpected response: {other:?}"
					))),
				}
			}
			Self::Http(base) => {
				let url = format!("{base}/f/{program}");
				println!("POST {url}");
				let request =
					http::ExecuteRequest { input: qos_hex::encode(&input) };
				let execution: http::Execution = post_json(&url, &request)?;

				let output = execution
					.output
					.as_deref()
					.map(|hex| {
						qos_hex::decode(hex).map_err(|e| {
							CallError::Other(format!(
								"response output is not hex: {e:?}"
							))
						})
					})
					.transpose()?;
				// Reconstruct the attestation from the exact signed bytes;
				// the decoded JSON payload is for humans, the Borsh is for
				// the verifier.
				let attestation = decode_attestation(&execution.attestation)
					.map_err(CallError::Other)?;
				Ok((output, attestation))
			}
		}
	}
}

/// Rebuild an [`ExecutionAttestation`] from its JSON rendering, decoding
/// the payload from `payload_borsh` — the byte string the signature
/// actually covers.
fn decode_attestation(
	attestation: &http::Attestation,
) -> Result<ExecutionAttestation, String> {
	let payload_borsh = qos_hex::decode(&attestation.payload_borsh)
		.map_err(|e| format!("payloadBorsh is not hex: {e:?}"))?;
	let payload =
		ExecutionAttestationPayload::try_from_slice(&payload_borsh)
			.map_err(|e| format!("payloadBorsh is not a Borsh payload: {e}"))?;
	let signature = qos_hex::decode(&attestation.signature)
		.map_err(|e| format!("signature is not hex: {e:?}"))?;
	let ephemeral_public_key =
		qos_hex::decode(&attestation.ephemeral_public_key)
			.map_err(|e| format!("ephemeralPublicKey is not hex: {e:?}"))?;
	Ok(ExecutionAttestation { payload, signature, ephemeral_public_key })
}

fn http_agent() -> ureq::Agent {
	ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build()
}

fn post_json<T: serde::de::DeserializeOwned>(
	url: &str,
	body: &impl serde::Serialize,
) -> Result<T, CallError> {
	let response = http_agent()
		.post(url)
		.send_json(body)
		.map_err(|e| http_error(url, e))?;
	response.into_json().map_err(|e| {
		CallError::Other(format!("decode response from {url}: {e}"))
	})
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
	let response = http_agent()
		.get(url)
		.call()
		.map_err(|e| http_error(url, e).to_string())?;
	response.into_json().map_err(|e| format!("decode response from {url}: {e}"))
}

fn http_error(url: &str, error: ureq::Error) -> CallError {
	match error {
		ureq::Error::Status(code, response) => {
			let detail = response
				.into_json::<http::Error>()
				.map_or_else(|e| format!("undecodable body: {e}"), |b| b.error);
			let message = format!("{url} returned {code}: {detail}");

			if code == 404 {
				CallError::NotFound(message)
			} else {
				CallError::Other(message)
			}
		}
		ureq::Error::Transport(t) => CallError::Other(format!(
			"{url} transport error: {t} (is the pivot reachable?)"
		)),
	}
}

// --- register / ls -------------------------------------------------------

async fn register(
	name: Option<&str>,
	endpoint: &Endpoint,
) -> Result<(), String> {
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
		endpoint.register_artifact(spec.name, envelope, wasm, ruleset).await?;
	}
	Ok(())
}

async fn ls(endpoint: &Endpoint) -> Result<(), String> {
	let listing = endpoint.list().await?;
	// Resolve each function's bound policy hash to a name when the policy
	// is registered on the same pivot.
	let names_by_hash: HashMap<&str, &str> = listing
		.artifacts
		.iter()
		.map(|a| (a.wasm_hash.as_str(), a.name.as_str()))
		.collect();

	if let Some(replica) = &listing.replica {
		println!("answered by replica {replica}");
	}

	println!("registered artifacts ({}):", listing.artifacts.len());
	for artifact in &listing.artifacts {
		let budget = artifact
			.fuel_budget
			.map_or_else(|| "default".to_string(), |b| b.to_string());
		let policy = artifact.bound_policy.as_deref().map_or_else(
			|| "-".to_string(),
			|hash| {
				names_by_hash
					.get(hash)
					.map_or_else(|| hash.to_string(), ToString::to_string)
			},
		);
		println!(
			"  {:<20} {}v{} approvals={} fuel={budget} policy={policy} {}",
			artifact.name,
			artifact.kind,
			artifact.version,
			artifact.approval_count,
			artifact.wasm_hash,
		);
	}
	Ok(())
}

// --- invoke --------------------------------------------------------------

async fn invoke(
	function: &str,
	input: &ProgramInput,
	endpoint: &Endpoint,
) -> Result<(ExecutionAttestation, Option<Vec<u8>>), String> {
	let function_envelope = read_envelope(function)?;

	// The caller names only the program. The gating policy was fixed by the
	// quorum-approved ruleset at registration and cannot be chosen here.
	let program = ProgramHash::new(function_envelope.artifact.wasm_hash);
	let input_bytes = input.encode()?;

	// Behind a load balancer a replica that missed registration may answer;
	// retrying lands on another replica.
	let mut attempt = 1;
	let (output, attestation) = loop {
		match endpoint.execute(program, input_bytes.clone()).await {
			Ok(result) => break result,
			Err(CallError::NotFound(e)) if attempt < 5 => {
				println!("  replica miss ({e}), retry {attempt}/5");
				attempt += 1;
				tokio::time::sleep(Duration::from_millis(500)).await;
			}
			Err(e) => return Err(e.to_string()),
		}
	};

	verify_execution_attestation(&attestation).map_err(
		|e: AttestationVerifyError| {
			format!("attestation verification FAILED: {e:?}")
		},
	)?;

	println!("attestation: VERIFIED (signed by enclave ephemeral key)");
	println!(
		"  engine:     {}",
		qos_hex::encode(&attestation.payload.engine_id)
	);
	println!("  request_id: {}", attestation.payload.request_id);
	match &attestation.payload.outcome {
		ExecutionOutcome::Allowed { output_hash } => {
			println!("  outcome:    ALLOWED");
			println!("  output_hash: {}", qos_hex::encode(output_hash));
			match &output {
				Some(bytes) => print_output(function, bytes),
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
	Ok((attestation, output))
}

fn print_output(function: &str, bytes: &[u8]) {
	if function.starts_with("sanctions-screening")
		&& let Ok(verdict) = Verdict::try_from_slice(bytes)
	{
		let status = match verdict.status {
			Status::Clear => "CLEAR",
			Status::Flagged => "FLAGGED",
		};
		println!(
			"  output:     {status} (screened against list v{})",
			verdict.list_version
		);
		return;
	}

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
	let endpoint = Endpoint::Usock(socket.to_path_buf());

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
	let approvers = load_approvers(&[])?;
	for_each_spec(None, |spec| approve(spec, None, &approvers))?;

	println!("\nbuilding + starting the pivot (one long-lived deployment)...");
	let status = Command::new("cargo")
		.args(["build", "-p", "integration", "--bin", "pivot_vfaas"])
		.current_dir(repo_root())
		.status()
		.map_err(|e| format!("spawn cargo build: {e}"))?;

	if !status.success() {
		return Err("cargo build --bin pivot_vfaas failed".to_string());
	}

	// A dead pivot leaves its socket file behind; wait_for_usock would see
	// it and let registration race the fresh pivot's boot.
	let _ = std::fs::remove_file(socket);
	let pivot = Command::new(repo_root().join("target/debug/pivot_vfaas"))
		.arg("--usock")
		.arg(socket)
		.arg("--manifest-set")
		.arg(manifest_set_path())
		.arg("--ephemeral-key")
		.arg(ephemeral_key_path())
		.args(["--port", "0"])
		.spawn()
		.map_err(|e| format!("spawn pivot: {e}"))?;
	let _pivot_guard = KillOnDrop(pivot);
	wait_for_usock(socket).await;

	println!(
		"\nregistering quorum-approved artifacts with the RUNNING pivot —\n\
		 no new manifest, no re-provisioning, no reboot:"
	);
	// Everything except the v2 screening list — registering that live IS
	// the upgrade act below.
	for name in [
		"allow-small-input",
		"allow-hashlist",
		"screening-rules",
		"reverse",
		"fee-calculator",
		"sanctions-screening",
	] {
		register(Some(name), &endpoint).await?;
	}
	ls(&endpoint).await?;

	banner("ACT 3 — verifiability: every outcome is enclave-signed");
	println!("[1/7] typed business logic: quote fees on $10,000.00 (Pro tier)");
	let fee_input =
		ProgramInput::Fee { amount_cents: 1_000_000, tier: Tier::Pro };
	let (a, _) = invoke("fee-calculator", &fee_input, &endpoint).await?;
	expect_outcome(
		&a,
		"ALLOWED",
		matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }),
	)?;

	println!("\n[2/7] smoke test: reverse \"hello world\"");
	let hello = ProgramInput::Text("hello world".to_string());
	let (a, _) = invoke("reverse", &hello, &endpoint).await?;
	expect_outcome(
		&a,
		"ALLOWED",
		matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }),
	)?;

	println!(
		"\n[3/7] policy denial — 2 KiB input against the 1 KiB policy limit"
	);
	let oversized = ProgramInput::Text("x".repeat(2048));
	let (a, _) = invoke("reverse", &oversized, &endpoint).await?;
	expect_outcome(
		&a,
		"DENIED",
		matches!(a.payload.outcome, ExecutionOutcome::Denied { .. }),
	)?;
	println!("  ^ the denial itself is enclave-signed and just verified");

	println!(
		"\n[4/7] policy rotation — the quorum rebinds reverse to the hash \
		 allowlist"
	);
	println!(
		"  (a fresh 2-of-3 ruleset approval + re-register; still no reboot,\n\
		   and the caller never chooses the policy)"
	);
	approve(spec("reverse")?, Some("allow-hashlist"), &approvers)?;
	register(Some("reverse"), &endpoint).await?;
	let (a, _) = invoke("reverse", &hello, &endpoint).await?;
	expect_outcome(
		&a,
		"DENIED",
		matches!(a.payload.outcome, ExecutionOutcome::Denied { .. }),
	)?;
	println!(
		"  ^ the allowlist pins a placeholder hash, so reverse is refused"
	);

	println!(
		"\n[5/7] screening policy — a malformed address never reaches the \
		 program"
	);
	let malformed = ProgramInput::Address("0xnope".to_string());
	let (a, _) = invoke("sanctions-screening", &malformed, &endpoint).await?;
	expect_outcome(
		&a,
		"DENIED",
		matches!(a.payload.outcome, ExecutionOutcome::Denied { .. }),
	)?;

	let watched = ProgramInput::Address(
		"0x3333333333333333333333333333333333333333".to_string(),
	);
	println!("\n[6/7] sanctions screening under list v1: screen 0x3333…");
	let (a, output) =
		invoke("sanctions-screening", &watched, &endpoint).await?;
	expect_outcome(
		&a,
		"ALLOWED",
		matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }),
	)?;
	expect_verdict(output.as_deref(), 1, Status::Clear)?;

	println!(
		"\n[7/7] the upgrade — list v2 registered against the RUNNING pivot"
	);
	println!(
		"  (new wasm hash = new content address; fresh 2-of-3 approval;\n\
		   list v1 stays registered and auditable under its own hash)"
	);
	register(Some("sanctions-screening-v2"), &endpoint).await?;
	let (a, output) =
		invoke("sanctions-screening-v2", &watched, &endpoint).await?;
	expect_outcome(
		&a,
		"ALLOWED",
		matches!(a.payload.outcome, ExecutionOutcome::Allowed { .. }),
	)?;
	expect_verdict(output.as_deref(), 2, Status::Flagged)?;
	ls(&endpoint).await?;

	banner("demo complete");
	println!(
		"Same deployment: three functions and three policies hot-registered\n\
		 under 2-of-3 quorum approval, each program bound to its policy by a\n\
		 signed ruleset, one live policy rotation, one live sanctions-list\n\
		 upgrade — and every outcome verified against the enclave's\n\
		 ephemeral key."
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

fn expect_verdict(
	output: Option<&[u8]>,
	list_version: u32,
	status: Status,
) -> Result<(), String> {
	let bytes = output.ok_or("demo expected screening output bytes")?;
	let verdict = Verdict::try_from_slice(bytes)
		.map_err(|e| format!("screening output is not a Verdict: {e}"))?;

	if verdict == (Verdict { list_version, status }) {
		Ok(())
	} else {
		Err(format!(
			"demo expected list v{list_version} {status:?}, got {verdict:?}"
		))
	}
}

fn run_cargo_test(example: &str) -> Result<(), String> {
	let manifest =
		repo_root().join("src/vfaas/examples").join(example).join("Cargo.toml");
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

async fn usock_call(socket: &Path, msg: &VfaasMsg) -> Result<VfaasMsg, String> {
	let pool = StreamPool::new(SocketAddress::new_unix(socket), 1)
		.map_err(|e| format!("stream pool: {e:?}"))?
		.shared();
	let client = SocketClient::new(pool, Duration::from_secs(30));
	let payload =
		borsh::to_vec(msg).map_err(|e| format!("serialize request: {e}"))?;
	let bytes = client.call(&payload).await.map_err(|e| {
		format!("pivot call failed: {e:?} (is the pivot running?)")
	})?;
	VfaasMsg::try_from_slice(&bytes)
		.map_err(|e| format!("deserialize response: {e}"))
}

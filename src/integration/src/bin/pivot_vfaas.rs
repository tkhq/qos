//! Verifiable Functions as a Service pivot.
//!
//! Holds an in-memory registry of quorum-approved WASM artifacts (programs
//! and policies). Registration requires an `ArtifactEnvelope` whose
//! approvals verify against the `ManifestSet` this pivot was launched with
//! — the same K-of-N quorum machinery QOS uses for manifests. A program is
//! additionally registered with a quorum-approved `RulesetEnvelope` binding
//! it to an already-registered policy: which policy gates which program is
//! a quorum decision, never a caller choice. The WASM module is compiled at
//! registration time (a garbage blob fails to register, not to execute)
//! and the compiled module is cached; per-call cost is a fresh `Store` +
//! instantiation.
//!
//! Execute names a registered program; the pivot resolves its bound policy,
//! evaluates the policy first, and runs the program only on
//! `Decision::Allow`. Every attempt — allowed, denied, or failed — produces
//! an `ExecutionAttestationPayload` signed by the enclave ephemeral key, so
//! denials and crashes are as auditable as successes.
//!
//! The primary surface is HTTP/1 on `--host`/`--port` (TVC's ingress bridge
//! connects to it inside the enclave): `GET /health`, `GET /artifacts`,
//! `POST /artifacts`, and the content-addressed `POST /f/{wasmHash}` — the
//! path names the exact program you are invoking. `--usock` additionally
//! serves the Borsh `VfaasMsg` protocol for local tooling and tests.
//!
//! The artifact-approval quorum comes from `--manifest-envelope` (the
//! enclave's own `/qos.manifest`, the TVC default: the quorum that approved
//! the enclave approves its functions) or `--manifest-set` (a bare Borsh
//! `ManifestSet` for local development).

use std::{
	collections::HashMap,
	net::SocketAddr,
	sync::{
		Arc,
		atomic::{AtomicU64, Ordering},
	},
};

use axum::{
	Json, Router,
	extract::{DefaultBodyLimit, Path, State},
	http::StatusCode,
	response::{IntoResponse, Response},
	routing::{get, post},
};
use borsh::BorshDeserialize;
use integration::vfaas::{
	DEFAULT_FUEL_PER_CALL, RegisteredArtifact, VfaasMsg, engine_id,
	governance::{
		Artifact, ArtifactEnvelope, ArtifactKind, RulesetEnvelope,
		verify_artifact_envelope, verify_ruleset_envelope,
	},
	http,
};
use qos_core::{
	EPHEMERAL_KEY_FILE, MANIFEST_FILE,
	handles::EphemeralKeyHandle,
	io::{SocketAddress, StreamPool},
	protocol::services::boot::{ManifestSet, VersionedManifestEnvelope},
	server::{RequestProcessor, SocketServer},
};
use qos_crypto::sha_256;
use tokio::sync::RwLock;
use vfaas_abi::{
	Decision, ExecutionAttestation, ExecutionAttestationPayload,
	ExecutionOutcome, PolicyHash, PolicyRequest, ProgramHash, Stage,
	VFAAS_ABI_VERSION,
};
use wasmtime::{Config, Engine, Linker, Memory, Module, Store, TypedFunc};

/// How many concurrent connections the socket server accepts.
const SERVER_CONCURRENCY: usize = 16;

/// A registered artifact: the approved envelope, the raw blob (policies
/// receive the program bytes), the module compiled at registration, and —
/// for programs — the quorum-approved binding to the policy gating it.
#[derive(Clone)]
struct StoredArtifact {
	envelope: ArtifactEnvelope,
	wasm: Arc<Vec<u8>>,
	module: Module,
	/// `Some` iff the artifact is a `Function`; enforced at registration.
	ruleset: Option<RulesetEnvelope>,
}

impl StoredArtifact {
	fn artifact(&self) -> &Artifact {
		&self.envelope.artifact
	}
}

#[derive(Clone)]
struct Processor {
	artifact_set: Arc<ManifestSet>,
	ephemeral_key_handle: EphemeralKeyHandle<String>,
	artifacts: Arc<RwLock<HashMap<[u8; 32], StoredArtifact>>>,
	request_id: Arc<AtomicU64>,
	engine: Engine,
	engine_id: [u8; 32],
}

impl Processor {
	/// Infallible: the wasmtime `Engine` and the parsed `ManifestSet` are
	/// built by the caller; `new` only assembles finished values.
	fn new(
		engine: Engine,
		artifact_set: ManifestSet,
		ephemeral_key_handle: EphemeralKeyHandle<String>,
	) -> Self {
		Self {
			artifact_set: Arc::new(artifact_set),
			ephemeral_key_handle,
			artifacts: Arc::new(RwLock::new(HashMap::new())),
			request_id: Arc::new(AtomicU64::new(0)),
			engine,
			engine_id: engine_id(),
		}
	}

	async fn handle(&self, msg: VfaasMsg) -> VfaasMsg {
		match msg {
			VfaasMsg::RegisterArtifactRequest { envelope, wasm, ruleset } => {
				self.register(envelope, wasm, ruleset).await
			}
			VfaasMsg::ListArtifactsRequest => self.list().await,
			VfaasMsg::ExecuteRequest { program, input } => {
				self.execute(program, input).await
			}
			VfaasMsg::RegisterArtifactResponse { .. }
			| VfaasMsg::ListArtifactsResponse { .. }
			| VfaasMsg::ExecuteResponse { .. }
			| VfaasMsg::Error(_) => VfaasMsg::Error(
				"unexpected message: response sent as request".to_string(),
			),
		}
	}

	async fn register(
		&self,
		envelope: ArtifactEnvelope,
		wasm: Vec<u8>,
		ruleset: Option<RulesetEnvelope>,
	) -> VfaasMsg {
		if sha_256(&wasm) != envelope.artifact.wasm_hash {
			return VfaasMsg::Error(format!(
				"artifact hash mismatch for {}",
				envelope.artifact.name
			));
		}
		if envelope.artifact.abi_version != VFAAS_ABI_VERSION {
			return VfaasMsg::Error(format!(
				"artifact {} targets ABI v{}, engine speaks v{VFAAS_ABI_VERSION}",
				envelope.artifact.name, envelope.artifact.abi_version
			));
		}
		if let Err(e) = verify_artifact_envelope(&envelope, &self.artifact_set)
		{
			return VfaasMsg::Error(format!(
				"approval verification failed: {e}"
			));
		}

		// A program registers with — and only ever runs under — a
		// quorum-approved policy binding.
		match (envelope.artifact.kind, &ruleset) {
			(ArtifactKind::Function, None) => {
				return VfaasMsg::Error(format!(
					"program {} cannot be registered without a \
					 quorum-approved policy ruleset",
					envelope.artifact.name
				));
			}
			(ArtifactKind::Policy, Some(_)) => {
				return VfaasMsg::Error(format!(
					"policy {} cannot carry a ruleset; rulesets bind programs",
					envelope.artifact.name
				));
			}
			(ArtifactKind::Function, Some(rs)) => {
				if rs.ruleset.program
					!= ProgramHash::new(envelope.artifact.wasm_hash)
				{
					return VfaasMsg::Error(format!(
						"ruleset binds program {}, not {} ({})",
						rs.ruleset.program,
						envelope.artifact.name,
						qos_hex::encode(&envelope.artifact.wasm_hash),
					));
				}
				if let Err(e) = verify_ruleset_envelope(rs, &self.artifact_set)
				{
					return VfaasMsg::Error(format!(
						"ruleset approval verification failed: {e}"
					));
				}
				if let Err(e) = self
					.lookup(*rs.ruleset.policy.as_bytes(), ArtifactKind::Policy)
					.await
				{
					return VfaasMsg::Error(format!(
						"ruleset for {} names an unusable policy: {e}",
						envelope.artifact.name
					));
				}
			}
			(ArtifactKind::Policy, None) => {}
		}

		// Compile at registration: an invalid blob is rejected here, with
		// the registrant, instead of surfacing at execution time.
		let engine = self.engine.clone();
		let blob = wasm.clone();
		let compiled =
			tokio::task::spawn_blocking(move || Module::new(&engine, &blob))
				.await;
		let module = match compiled {
			Ok(Ok(module)) => module,
			Ok(Err(e)) => {
				return VfaasMsg::Error(format!(
					"artifact {} is not valid wasm: {e}",
					envelope.artifact.name
				));
			}
			Err(join_err) => {
				return VfaasMsg::Error(format!(
					"module compilation task panicked: {join_err}"
				));
			}
		};

		let artifact = envelope.artifact.clone();
		self.artifacts.write().await.insert(
			artifact.wasm_hash,
			StoredArtifact { envelope, wasm: Arc::new(wasm), module, ruleset },
		);
		VfaasMsg::RegisterArtifactResponse { artifact }
	}

	async fn list(&self) -> VfaasMsg {
		let mut artifacts: Vec<_> = self
			.artifacts
			.read()
			.await
			.values()
			.map(|stored| RegisteredArtifact {
				artifact: stored.artifact().clone(),
				approval_count: u32::try_from(stored.envelope.approvals.len())
					.unwrap_or(u32::MAX),
				bound_policy: stored
					.ruleset
					.as_ref()
					.map(|rs| rs.ruleset.policy),
			})
			.collect();
		artifacts.sort_by(|a, b| {
			a.artifact
				.name
				.cmp(&b.artifact.name)
				.then(a.artifact.version.cmp(&b.artifact.version))
		});
		VfaasMsg::ListArtifactsResponse { artifacts }
	}

	async fn lookup(
		&self,
		hash: [u8; 32],
		kind: ArtifactKind,
	) -> Result<StoredArtifact, String> {
		let stored = self
			.artifacts
			.read()
			.await
			.get(&hash)
			.cloned()
			.ok_or_else(|| {
				format!("artifact not registered: {}", qos_hex::encode(&hash))
			})?;
		if stored.artifact().kind != kind {
			return Err(format!(
				"artifact {} is a {:?}, expected a {kind:?}",
				stored.artifact().name,
				stored.artifact().kind
			));
		}
		Ok(stored)
	}

	async fn execute(&self, program: ProgramHash, input: Vec<u8>) -> VfaasMsg {
		let program_artifact = match self
			.lookup(*program.as_bytes(), ArtifactKind::Function)
			.await
		{
			Ok(stored) => stored,
			Err(e) => return VfaasMsg::Error(e),
		};
		// The gating policy comes from the registered ruleset, never the
		// request. Registration guarantees a function carries a binding, so
		// a miss here is a pivot bug.
		let Some(policy) =
			program_artifact.ruleset.as_ref().map(|rs| rs.ruleset.policy)
		else {
			return VfaasMsg::Error(format!(
				"program {} has no bound policy",
				program_artifact.artifact().name
			));
		};
		let policy_artifact =
			match self.lookup(*policy.as_bytes(), ArtifactKind::Policy).await {
				Ok(stored) => stored,
				Err(e) => return VfaasMsg::Error(e),
			};

		let input_hash = sha_256(&input);
		let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
		let attest = |outcome: ExecutionOutcome, output: Option<Vec<u8>>| {
			self.attest(
				program, policy, input_hash, outcome, request_id, output,
			)
		};

		// Policy first. It sees the program hash and bytes plus the input.
		let policy_request = PolicyRequest {
			program_hash: program,
			input_hash,
			input: input.clone(),
			program: Some((*program_artifact.wasm).clone()),
		};
		let policy_input = match borsh::to_vec(&policy_request) {
			Ok(bytes) => bytes,
			Err(e) => {
				return VfaasMsg::Error(format!(
					"serialize policy request: {e}"
				));
			}
		};

		let decision_bytes = match self
			.run_artifact(&policy_artifact, "__vfaas_evaluate", policy_input)
			.await
		{
			Ok(bytes) => bytes,
			Err(RunError::Task(e)) => return VfaasMsg::Error(e),
			Err(RunError::Wasm(reason)) => {
				return attest(
					ExecutionOutcome::Failed { stage: Stage::Policy, reason },
					None,
				);
			}
		};
		let decision = match Decision::try_from_slice(&decision_bytes) {
			Ok(decision) => decision,
			Err(e) => {
				return attest(
					ExecutionOutcome::Failed {
						stage: Stage::Policy,
						reason: format!(
							"policy returned non-Decision bytes: {e}"
						),
					},
					None,
				);
			}
		};

		if let Decision::Deny(reason) = decision {
			return attest(ExecutionOutcome::Denied { reason }, None);
		}

		// Allow → run the program on the raw input bytes.
		let output = match self
			.run_artifact(&program_artifact, "__vfaas_execute", input)
			.await
		{
			Ok(bytes) => bytes,
			Err(RunError::Task(e)) => return VfaasMsg::Error(e),
			Err(RunError::Wasm(reason)) => {
				return attest(
					ExecutionOutcome::Failed { stage: Stage::Program, reason },
					None,
				);
			}
		};

		attest(
			ExecutionOutcome::Allowed { output_hash: sha_256(&output) },
			Some(output),
		)
	}

	/// Run a cached module's entrypoint on a blocking thread with the
	/// artifact's approved fuel budget.
	async fn run_artifact(
		&self,
		stored: &StoredArtifact,
		entrypoint: &'static str,
		input: Vec<u8>,
	) -> Result<Vec<u8>, RunError> {
		let engine = self.engine.clone();
		let module = stored.module.clone();
		let fuel =
			stored.artifact().fuel_budget.unwrap_or(DEFAULT_FUEL_PER_CALL);
		tokio::task::spawn_blocking(move || {
			run_wasm(&engine, &module, entrypoint, &input, fuel)
		})
		.await
		.map_err(|join_err| {
			RunError::Task(format!("{entrypoint} task panicked: {join_err}"))
		})?
		.map_err(RunError::Wasm)
	}

	fn attest(
		&self,
		program_hash: ProgramHash,
		policy_hash: PolicyHash,
		input_hash: [u8; 32],
		outcome: ExecutionOutcome,
		request_id: u64,
		output: Option<Vec<u8>>,
	) -> VfaasMsg {
		let payload = ExecutionAttestationPayload {
			engine_id: self.engine_id,
			abi_version: VFAAS_ABI_VERSION,
			program_hash,
			policy_hash,
			input_hash,
			outcome,
			request_id,
		};
		match self.sign(payload) {
			Ok(attestation) => {
				VfaasMsg::ExecuteResponse { output, attestation }
			}
			Err(reason) => VfaasMsg::Error(reason),
		}
	}

	/// This replica's identity: the first 8 hex chars of the ephemeral
	/// public key, unique per enclave. Clients registering an artifact on
	/// every replica count distinct values of this.
	fn replica(&self) -> Option<String> {
		let key = self.ephemeral_key_handle.get_ephemeral_key().ok()?;
		let mut fingerprint = qos_hex::encode(&key.public_key().to_bytes());
		fingerprint.truncate(8);
		Some(fingerprint)
	}

	fn sign(
		&self,
		payload: ExecutionAttestationPayload,
	) -> Result<ExecutionAttestation, String> {
		let ephemeral = self
			.ephemeral_key_handle
			.get_ephemeral_key()
			.map_err(|e| format!("ephemeral key unavailable: {e:?}"))?;
		let bytes = borsh::to_vec(&payload)
			.map_err(|e| format!("attestation serialization failed: {e}"))?;
		let signature = ephemeral
			.sign(&bytes)
			.map_err(|e| format!("ephemeral signing failed: {e:?}"))?;
		Ok(ExecutionAttestation {
			payload,
			signature,
			ephemeral_public_key: ephemeral.public_key().to_bytes(),
		})
	}
}

/// How a WASM run failed.
enum RunError {
	/// The blocking task itself died; a host-side error, not attestable as
	/// an execution outcome.
	Task(String),
	/// The guest trapped, ran out of fuel, or violated the ABI.
	Wasm(String),
}

/// Instantiate a fresh `Store` for the given precompiled module, write
/// `input` into linear memory via the exported `alloc`, call `entrypoint`,
/// and return the bytes it packed into its `u64` return value.
fn run_wasm(
	engine: &Engine,
	module: &Module,
	entrypoint: &str,
	input: &[u8],
	fuel: u64,
) -> Result<Vec<u8>, String> {
	let mut store: Store<()> = Store::new(engine, ());
	store.set_fuel(fuel).map_err(|e| format!("set_fuel: {e:#}"))?;
	let linker: Linker<()> = Linker::new(engine);
	let instance = linker
		.instantiate(&mut store, module)
		.map_err(|e| format!("wasmtime instantiate: {e:#}"))?;

	let memory: Memory = instance
		.get_memory(&mut store, "memory")
		.ok_or_else(|| "wasm module does not export `memory`".to_string())?;
	let alloc_fn: TypedFunc<u32, u32> = instance
		.get_typed_func(&mut store, "alloc")
		.map_err(|e| format!("wasm module missing `alloc`: {e}"))?;
	let entry: TypedFunc<(u32, u32), u64> = instance
		.get_typed_func(&mut store, entrypoint)
		.map_err(|e| format!("wasm module missing `{entrypoint}`: {e}"))?;

	let in_len = u32::try_from(input.len())
		.map_err(|_| "input larger than u32::MAX".to_string())?;
	let in_ptr = alloc_fn
		.call(&mut store, in_len)
		.map_err(|e| format!("alloc trap: {e:#}"))?;
	memory
		.write(&mut store, in_ptr as usize, input)
		.map_err(|e| format!("memory write: {e}"))?;

	// `{e:#}` prints the whole cause chain — a fuel-exhaustion trap's
	// "all fuel consumed" cause would otherwise be lost.
	let packed = entry
		.call(&mut store, (in_ptr, in_len))
		.map_err(|e| format!("{entrypoint} trap: {e:#}"))?;
	#[allow(clippy::cast_possible_truncation)]
	let out_ptr = (packed >> 32) as u32;
	#[allow(clippy::cast_possible_truncation)]
	let out_len = (packed & 0xFFFF_FFFF) as u32;

	let mut out = vec![0u8; out_len as usize];
	memory
		.read(&store, out_ptr as usize, &mut out)
		.map_err(|e| format!("memory read: {e}"))?;
	Ok(out)
}

impl RequestProcessor for Processor {
	async fn process(&self, request: &[u8]) -> Vec<u8> {
		let response = match VfaasMsg::try_from_slice(request) {
			Ok(msg) => self.handle(msg).await,
			Err(e) => VfaasMsg::Error(format!("malformed VfaasMsg: {e}")),
		};
		borsh::to_vec(&response).unwrap_or_else(|e| {
			let fallback =
				VfaasMsg::Error(format!("response serialization failed: {e}"));
			borsh::to_vec(&fallback).expect("Error variant must serialize")
		})
	}
}

/// Where the artifact-approval quorum comes from.
enum QuorumSource {
	/// The enclave's own signed manifest (`/qos.manifest`, the TVC layout):
	/// the manifest set that approved this enclave approves its artifacts.
	ManifestEnvelope(String),
	/// A bare Borsh `ManifestSet` file, for local development and tests.
	ManifestSet(String),
}

struct Cli {
	host: String,
	port: u16,
	quorum: QuorumSource,
	ephemeral_key_path: String,
	usock: Option<String>,
}

impl Default for Cli {
	fn default() -> Self {
		Self {
			host: "127.0.0.1".to_string(),
			port: 3000,
			quorum: QuorumSource::ManifestEnvelope(MANIFEST_FILE.to_string()),
			ephemeral_key_path: EPHEMERAL_KEY_FILE.to_string(),
			usock: None,
		}
	}
}

impl Cli {
	fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
		let mut cli = Self::default();
		let mut args = args.into_iter();
		let mut quorum = None;

		while let Some(arg) = args.next() {
			match arg.as_str() {
				"--host" => cli.host = next_value(&mut args, "--host")?,
				"--port" => {
					cli.port = next_value(&mut args, "--port")?
						.parse()
						.map_err(|e| format!("invalid --port value: {e}"))?;
				}
				"--manifest-envelope" => set_quorum(
					&mut quorum,
					QuorumSource::ManifestEnvelope(next_value(
						&mut args,
						"--manifest-envelope",
					)?),
				)?,
				"--manifest-set" => set_quorum(
					&mut quorum,
					QuorumSource::ManifestSet(next_value(
						&mut args,
						"--manifest-set",
					)?),
				)?,
				"--ephemeral-key" => {
					cli.ephemeral_key_path =
						next_value(&mut args, "--ephemeral-key")?;
				}
				"--usock" => {
					cli.usock = Some(next_value(&mut args, "--usock")?);
				}
				_ => return Err(format!("unknown argument: {arg}")),
			}
		}

		if let Some(quorum) = quorum {
			cli.quorum = quorum;
		}

		Ok(cli)
	}
}

fn next_value(
	args: &mut impl Iterator<Item = String>,
	name: &str,
) -> Result<String, String> {
	args.next().ok_or_else(|| format!("missing value for {name}"))
}

fn set_quorum(
	slot: &mut Option<QuorumSource>,
	source: QuorumSource,
) -> Result<(), String> {
	if slot.replace(source).is_some() {
		return Err("pass exactly one of --manifest-envelope / --manifest-set"
			.to_string());
	}

	Ok(())
}

async fn health(State(processor): State<Processor>) -> Json<http::Health> {
	Json(http::Health {
		status: "healthy".to_string(),
		replica: processor.replica(),
	})
}

async fn list_artifacts(State(processor): State<Processor>) -> Response {
	match processor.handle(VfaasMsg::ListArtifactsRequest).await {
		VfaasMsg::ListArtifactsResponse { artifacts } => {
			Json(http::Artifacts {
				replica: processor.replica(),
				artifacts: artifacts
					.iter()
					.map(http::ArtifactSummary::from)
					.collect(),
			})
			.into_response()
		}
		other => error_response(&other),
	}
}

async fn register_artifact(
	State(processor): State<Processor>,
	Json(request): Json<http::RegisterRequest>,
) -> Response {
	let msg = match request.into_msg() {
		Ok(msg) => msg,
		Err(error) => {
			return (StatusCode::BAD_REQUEST, Json(http::Error { error }))
				.into_response();
		}
	};

	match processor.handle(msg).await {
		VfaasMsg::RegisterArtifactResponse { artifact } => {
			Json(http::Registered {
				replica: processor.replica(),
				name: artifact.name,
				version: artifact.version,
				wasm_hash: qos_hex::encode(&artifact.wasm_hash),
			})
			.into_response()
		}
		other => error_response(&other),
	}
}

async fn execute_program(
	State(processor): State<Processor>,
	Path(program): Path<String>,
	Json(request): Json<http::ExecuteRequest>,
) -> Response {
	let parsed = qos_hex::decode(&program)
		.map_err(|e| format!("program address is not hex: {e:?}"))
		.and_then(|bytes| {
			<[u8; 32]>::try_from(bytes).map_err(|bytes| {
				format!("program address must be 32 bytes, got {}", bytes.len())
			})
		});
	let program = match parsed {
		Ok(hash) => ProgramHash::new(hash),
		Err(error) => {
			return (StatusCode::BAD_REQUEST, Json(http::Error { error }))
				.into_response();
		}
	};
	let input = match qos_hex::decode(&request.input) {
		Ok(input) => input,
		Err(e) => {
			return (
				StatusCode::BAD_REQUEST,
				Json(http::Error { error: format!("input is not hex: {e:?}") }),
			)
				.into_response();
		}
	};

	match processor.handle(VfaasMsg::ExecuteRequest { program, input }).await {
		VfaasMsg::ExecuteResponse { output, attestation } => {
			Json(http::Execution {
				output: output.map(|bytes| qos_hex::encode(&bytes)),
				attestation: http::Attestation::from(&attestation),
			})
			.into_response()
		}
		other => error_response(&other),
	}
}

/// Map a pivot rejection to an HTTP status. Attested denials and failures
/// never reach here — they are 200s carrying an attestation; this is only
/// for request-level errors where nothing was attested.
fn error_response(msg: &VfaasMsg) -> Response {
	let (status, error) = match msg {
		VfaasMsg::Error(e) => {
			// `lookup` misses are the only not-found shape the processor
			// produces; everything else it rejects is a bad request.
			let status = if e.starts_with("artifact not registered") {
				StatusCode::NOT_FOUND
			} else {
				StatusCode::BAD_REQUEST
			};
			(status, e.clone())
		}
		other => (
			StatusCode::INTERNAL_SERVER_ERROR,
			format!("unexpected pivot response: {other:?}"),
		),
	};
	(status, Json(http::Error { error })).into_response()
}

#[tokio::main]
async fn main() {
	let cli =
		Cli::parse(std::env::args().skip(1)).unwrap_or_else(|e| panic!("{e}"));

	let artifact_set = match &cli.quorum {
		QuorumSource::ManifestEnvelope(path) => {
			let bytes = std::fs::read(path)
				.expect("unable to read manifest envelope file");
			VersionedManifestEnvelope::try_from_slice_compat(&bytes)
				.expect("file is not a manifest envelope")
				.manifest_set()
				.clone()
		}
		QuorumSource::ManifestSet(path) => {
			let bytes =
				std::fs::read(path).expect("unable to read manifest set file");
			ManifestSet::try_from_slice(&bytes)
				.expect("manifest set file is not a Borsh ManifestSet")
		}
	};

	let mut config = Config::new();
	config.consume_fuel(true);
	let engine =
		Engine::new(&config).expect("unable to construct wasmtime engine");

	let processor = Processor::new(
		engine,
		artifact_set,
		EphemeralKeyHandle::new(cli.ephemeral_key_path.clone()),
	);

	let _usock_server = cli.usock.as_ref().map(|path| {
		let pool = StreamPool::new(SocketAddress::new_unix(path), 1)
			.expect("unable to create vfaas pivot pool");
		SocketServer::listen_all(pool, processor.clone(), SERVER_CONCURRENCY)
			.expect("unable to start vfaas usock server")
	});

	let addr: SocketAddr = format!("{}:{}", cli.host, cli.port)
		.parse()
		.expect("invalid --host/--port combination");
	let router = Router::new()
		.route("/health", get(health))
		.route("/artifacts", get(list_artifacts).post(register_artifact))
		.route("/f/:program", post(execute_program))
		.layer(DefaultBodyLimit::max(16 * 1024 * 1024))
		.with_state(processor);

	axum::Server::bind(&addr)
		.serve(router.into_make_service())
		.await
		.expect("http server failed");
}

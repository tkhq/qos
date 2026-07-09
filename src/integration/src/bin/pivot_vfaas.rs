//! Verifiable Functions as a Service pivot.
//!
//! Holds in-memory registries of owner-signed WASM blobs (programs and
//! policies). Clients register a blob by sending the bytes plus an owner
//! signature over `DOMAIN || sha256(wasm)`; the pivot verifies against the
//! single owner public key it was launched with.
//!
//! Execute selects a registered (program, policy) pair, runs the policy
//! first; if the policy returns `Allow`, runs the program; signs an
//! [`integration::ExecutionAttestation`] with the ephemeral key and returns
//! it to the client.
//!
//! Args: `<usock_path> <owner_pubkey_hex> <ephemeral_key_path>`.

use std::{
	collections::HashMap,
	sync::{
		Arc,
		atomic::{AtomicU64, Ordering},
	},
};

use borsh::BorshDeserialize;
use integration::{
	Decision, ExecutionAttestation, SignedExecutionAttestation,
	VFAAS_POLICY_DOMAIN, VFAAS_PROGRAM_DOMAIN, VfaasMsg, VfaasPolicyRequest,
};
use qos_core::{
	handles::EphemeralKeyHandle,
	io::{SocketAddress, StreamPool},
	server::{RequestProcessor, SocketServer},
};
use qos_crypto::sha_256;
use qos_p256::P256Public;
use tokio::sync::RwLock;
use wasmtime::{Config, Engine, Linker, Memory, Module, Store, TypedFunc};

/// Fuel budget per WASM execution. Fresh budget per call.
const FUEL_PER_CALL: u64 = 1_000_000;

type Registry = Arc<RwLock<HashMap<[u8; 32], Arc<Vec<u8>>>>>;

#[derive(Clone)]
struct Processor {
	owner_pubkey: Arc<P256Public>,
	ephemeral_key_handle: EphemeralKeyHandle<String>,
	programs: Registry,
	policies: Registry,
	request_id: Arc<AtomicU64>,
	engine: Engine,
}

impl Processor {
	fn new(
		owner_pubkey: P256Public,
		ephemeral_key_handle: EphemeralKeyHandle<String>,
	) -> Result<Self, String> {
		let mut config = Config::new();
		config.consume_fuel(true);
		// Deterministic: no SIMD, no threads (default in 30 anyway).
		let engine = Engine::new(&config)
			.map_err(|e| format!("wasmtime engine: {e}"))?;
		Ok(Self {
			owner_pubkey: Arc::new(owner_pubkey),
			ephemeral_key_handle,
			programs: Arc::new(RwLock::new(HashMap::new())),
			policies: Arc::new(RwLock::new(HashMap::new())),
			request_id: Arc::new(AtomicU64::new(0)),
			engine,
		})
	}

	async fn handle(&self, msg: VfaasMsg) -> VfaasMsg {
		match msg {
			VfaasMsg::RegisterProgramRequest { wasm, signature } => {
				match self.register(&wasm, &signature, VFAAS_PROGRAM_DOMAIN) {
					Ok(hash) => {
						self.programs
							.write()
							.await
							.insert(hash, Arc::new(wasm));
						VfaasMsg::RegisterProgramResponse { hash }
					}
					Err(reason) => VfaasMsg::Error(reason),
				}
			}
			VfaasMsg::RegisterPolicyRequest { wasm, signature } => {
				match self.register(&wasm, &signature, VFAAS_POLICY_DOMAIN) {
					Ok(hash) => {
						self.policies
							.write()
							.await
							.insert(hash, Arc::new(wasm));
						VfaasMsg::RegisterPolicyResponse { hash }
					}
					Err(reason) => VfaasMsg::Error(reason),
				}
			}
			VfaasMsg::ListProgramsRequest => VfaasMsg::ListProgramsResponse {
				hashes: self.programs.read().await.keys().copied().collect(),
			},
			VfaasMsg::ListPoliciesRequest => VfaasMsg::ListPoliciesResponse {
				hashes: self.policies.read().await.keys().copied().collect(),
			},
			VfaasMsg::ExecuteRequest {
				program_hash,
				policy_hash,
				input,
			} => self.execute(program_hash, policy_hash, input).await,
			VfaasMsg::RegisterProgramResponse { .. }
			| VfaasMsg::RegisterPolicyResponse { .. }
			| VfaasMsg::ListProgramsResponse { .. }
			| VfaasMsg::ListPoliciesResponse { .. }
			| VfaasMsg::ExecuteResponse { .. }
			| VfaasMsg::Error(_) => {
				VfaasMsg::Error("unexpected message: response sent as request"
					.to_string())
			}
		}
	}

	fn register(
		&self,
		wasm: &[u8],
		signature: &[u8],
		domain: &[u8],
	) -> Result<[u8; 32], String> {
		let hash = sha_256(wasm);
		let mut signed_message =
			Vec::with_capacity(domain.len() + hash.len());
		signed_message.extend_from_slice(domain);
		signed_message.extend_from_slice(&hash);
		self.owner_pubkey
			.verify(&signed_message, signature)
			.map_err(|e| format!("invalid owner signature: {e:?}"))?;
		Ok(hash)
	}

	async fn execute(
		&self,
		program_hash: [u8; 32],
		policy_hash: [u8; 32],
		input: Vec<u8>,
	) -> VfaasMsg {
		let program = self.programs.read().await.get(&program_hash).cloned();
		let policy = self.policies.read().await.get(&policy_hash).cloned();
		let (Some(program), Some(policy)) = (program, policy) else {
			return VfaasMsg::Error(format!(
				"unknown program ({}) or policy ({}) hash",
				qos_hex::encode(&program_hash),
				qos_hex::encode(&policy_hash),
			));
		};

		let input_hash = sha_256(&input);
		let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);

		// Run policy first.
		let policy_request = VfaasPolicyRequest {
			program: (*program).clone(),
			input: input.clone(),
		};
		let policy_input = match borsh::to_vec(&policy_request) {
			Ok(b) => b,
			Err(e) => {
				return VfaasMsg::Error(format!(
					"serialize policy request: {e}"
				));
			}
		};

		let engine = self.engine.clone();
		let policy_bytes = policy.clone();
		let policy_result = tokio::task::spawn_blocking(move || {
			run_wasm(&engine, &policy_bytes, "__vfaas_evaluate", &policy_input)
		})
		.await;
		let policy_output = match policy_result {
			Ok(Ok(bytes)) => bytes,
			Ok(Err(e)) => {
				return self.signed_error_response(
					program_hash,
					policy_hash,
					input_hash,
					request_id,
					format!("policy execution failed: {e}"),
				);
			}
			Err(join_err) => {
				return VfaasMsg::Error(format!(
					"policy task panicked: {join_err}"
				));
			}
		};
		let decision: Decision =
			match BorshDeserialize::try_from_slice(&policy_output) {
				Ok(d) => d,
				Err(e) => {
					return self.signed_error_response(
						program_hash,
						policy_hash,
						input_hash,
						request_id,
						format!("policy returned non-Decision bytes: {e}"),
					);
				}
			};

		if let Decision::Deny(_) = &decision {
			return self.build_response(
				program_hash,
				policy_hash,
				input_hash,
				None,
				decision,
				request_id,
				None,
			);
		}

		// Allow → run program.
		let engine = self.engine.clone();
		let program_bytes = program.clone();
		let program_input = match borsh::to_vec(&input) {
			Ok(b) => b,
			Err(e) => {
				return VfaasMsg::Error(format!(
					"serialize program input: {e}"
				));
			}
		};
		let program_result = tokio::task::spawn_blocking(move || {
			run_wasm(
				&engine,
				&program_bytes,
				"__vfaas_execute",
				&program_input,
			)
		})
		.await;
		let program_output = match program_result {
			Ok(Ok(bytes)) => bytes,
			Ok(Err(e)) => {
				return self.signed_error_response(
					program_hash,
					policy_hash,
					input_hash,
					request_id,
					format!("program execution failed: {e}"),
				);
			}
			Err(join_err) => {
				return VfaasMsg::Error(format!(
					"program task panicked: {join_err}"
				));
			}
		};

		// Program emits Borsh-serialized Vec<u8>; decode to the raw bytes.
		let output: Vec<u8> =
			match BorshDeserialize::try_from_slice(&program_output) {
				Ok(v) => v,
				Err(e) => {
					return self.signed_error_response(
						program_hash,
						policy_hash,
						input_hash,
						request_id,
						format!("program returned non-Vec<u8> bytes: {e}"),
					);
				}
			};
		let output_hash = sha_256(&output);

		self.build_response(
			program_hash,
			policy_hash,
			input_hash,
			Some(output_hash),
			decision,
			request_id,
			Some(output),
		)
	}

	#[allow(clippy::too_many_arguments)]
	fn build_response(
		&self,
		program_hash: [u8; 32],
		policy_hash: [u8; 32],
		input_hash: [u8; 32],
		output_hash: Option<[u8; 32]>,
		decision: Decision,
		request_id: u64,
		output: Option<Vec<u8>>,
	) -> VfaasMsg {
		let attestation = ExecutionAttestation {
			program_hash,
			policy_hash,
			input_hash,
			output_hash,
			decision: decision.clone(),
			request_id,
		};
		match self.sign_attestation(attestation) {
			Ok(signed) => VfaasMsg::ExecuteResponse {
				decision,
				output,
				attestation: signed,
			},
			Err(reason) => VfaasMsg::Error(reason),
		}
	}

	fn signed_error_response(
		&self,
		program_hash: [u8; 32],
		policy_hash: [u8; 32],
		input_hash: [u8; 32],
		request_id: u64,
		reason: String,
	) -> VfaasMsg {
		self.build_response(
			program_hash,
			policy_hash,
			input_hash,
			None,
			Decision::Deny(reason),
			request_id,
			None,
		)
	}

	fn sign_attestation(
		&self,
		attestation: ExecutionAttestation,
	) -> Result<SignedExecutionAttestation, String> {
		let ephemeral = self
			.ephemeral_key_handle
			.get_ephemeral_key()
			.map_err(|e| format!("ephemeral key unavailable: {e:?}"))?;
		let payload = borsh::to_vec(&attestation)
			.map_err(|e| format!("attestation serialization failed: {e}"))?;
		let signature = ephemeral
			.sign(&payload)
			.map_err(|e| format!("ephemeral signing failed: {e:?}"))?;
		let ephemeral_public_key = ephemeral.public_key().to_bytes();
		Ok(SignedExecutionAttestation {
			attestation,
			signature,
			ephemeral_public_key,
		})
	}
}

/// Instantiate a fresh `Store` + `Instance`, write `input` into linear memory
/// via the exported `alloc`, call `entrypoint`, and return the output bytes
/// the entrypoint packed into its `u64` return.
fn run_wasm(
	engine: &Engine,
	wasm: &[u8],
	entrypoint: &str,
	input: &[u8],
) -> Result<Vec<u8>, String> {
	let module = Module::new(engine, wasm)
		.map_err(|e| format!("wasmtime compile module: {e}"))?;
	let mut store: Store<()> = Store::new(engine, ());
	store
		.set_fuel(FUEL_PER_CALL)
		.map_err(|e| format!("set_fuel: {e}"))?;
	let linker: Linker<()> = Linker::new(engine);
	let instance = linker
		.instantiate(&mut store, &module)
		.map_err(|e| format!("wasmtime instantiate: {e}"))?;

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
		.map_err(|e| format!("alloc trap: {e}"))?;
	memory
		.write(&mut store, in_ptr as usize, input)
		.map_err(|e| format!("memory write: {e}"))?;

	let packed = entry
		.call(&mut store, (in_ptr, in_len))
		.map_err(|e| format!("{entrypoint} trap: {e}"))?;
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

#[tokio::main]
async fn main() {
	let mut args = std::env::args().skip(1);
	let socket_path = args.next().expect("missing arg 1: <usock_path>");
	let owner_pubkey_hex =
		args.next().expect("missing arg 2: <owner_pubkey_hex>");
	let ephemeral_key_path =
		args.next().expect("missing arg 3: <ephemeral_key_path>");

	let owner_pubkey_bytes = qos_hex::decode(&owner_pubkey_hex)
		.expect("owner public key is not valid hex");
	let owner_pubkey = P256Public::from_bytes(&owner_pubkey_bytes)
		.expect("owner public key bytes are not a valid P256Public");

	let pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("unable to create vfaas pivot pool");

	let processor = Processor::new(
		owner_pubkey,
		EphemeralKeyHandle::new(ephemeral_key_path),
	)
	.expect("unable to construct vfaas processor");

	let _server = SocketServer::listen_all(pool, processor, 16)
		.expect("unable to start vfaas pivot server");

	tokio::signal::ctrl_c().await.expect("failed to wait for ctrl_c");
}

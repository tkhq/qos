use std::sync::{Arc, RwLock as StdRwLock};

use borsh::BorshDeserialize;
use integration::pivot_wasm::{
	attestation::sign_execution_attestation,
	engine::WasmEngine,
	errors::PivotWasmError,
	protocol::{
		PivotWasmExecuteRequest, PivotWasmExecuteResponse, PivotWasmGovernance,
		PivotWasmMsg,
	},
	registry::WasmRegistry,
};
use qos_core::{
	handles::EphemeralKeyHandle,
	io::{SocketAddress, StreamPool},
	server::{RequestProcessor, SocketServer},
};
use qos_crypto::sha_256;
use qos_wasm_sdk::Decision;
use tokio::sync::RwLock;

struct WasmProcessor {
	engine: WasmEngine,
	engine_id: [u8; 32],
	registry: StdRwLock<WasmRegistry>,
	ephemeral_key_handle: EphemeralKeyHandle,
}

impl WasmProcessor {
	fn new(
		governance: PivotWasmGovernance,
		ephemeral_key_handle: EphemeralKeyHandle,
	) -> Result<Arc<RwLock<Self>>, PivotWasmError> {
		Ok(Arc::new(RwLock::new(Self {
			engine: WasmEngine::new()?,
			engine_id: sha_256(b"qos-pivot-wasm-engine-v1"),
			registry: StdRwLock::new(WasmRegistry::new(governance)),
			ephemeral_key_handle,
		})))
	}

	fn handle_execute_request(
		&self,
		request: PivotWasmExecuteRequest,
	) -> Result<PivotWasmExecuteResponse, PivotWasmError> {
		let (policy_wasm, function_wasm) = {
			let registry = self.registry.read().map_err(|_| {
				PivotWasmError::runtime("registry lock poisoned")
			})?;
			let (_, policy_wasm) =
				registry.policy_bytes(&request.policy_hash)?;
			let (_, function_wasm) =
				registry.function_bytes(&request.function_hash)?;
			(policy_wasm, function_wasm)
		};

		let decision = self.engine.execute_policy(
			&policy_wasm,
			request.function_hash,
			&function_wasm,
			&request.input,
		)?;
		match decision {
			Decision::Allow => {}
			Decision::Deny { reason } => {
				return Err(PivotWasmError::PolicyDenied(reason));
			}
		}

		let output =
			self.engine.execute_function(&function_wasm, &request.input)?;
		let attestation = sign_execution_attestation(
			self.engine_id,
			request.policy_hash,
			request.function_hash,
			&request.input,
			&output,
			&self.ephemeral_key_handle,
		)?;

		Ok(PivotWasmExecuteResponse { output, attestation })
	}
}

impl RequestProcessor for WasmProcessor {
	async fn process(&self, request: &[u8]) -> Vec<u8> {
		let msg = match PivotWasmMsg::try_from_slice(request) {
			Ok(m) => m,
			Err(_) => {
				return borsh::to_vec(&PivotWasmMsg::RuntimeError {
					message: "invalid request".into(),
				})
				.expect("borsh serialization cannot fail")
			}
		};

		let response = match msg {
			PivotWasmMsg::RegisterArtifactRequest(request) => {
				let result = self
					.registry
					.write()
					.map_err(|_| {
						PivotWasmError::runtime("registry lock poisoned")
					})
					.and_then(|mut registry| registry.register(request));
				result
					.map(PivotWasmMsg::RegisterArtifactResponse)
					.unwrap_or_else(PivotWasmMsg::from)
			}
			PivotWasmMsg::ListArtifactsRequest => match self.registry.read() {
				Ok(registry) => PivotWasmMsg::ListArtifactsResponse {
					artifacts: registry.list(),
				},
				Err(_) => PivotWasmMsg::RuntimeError {
					message: "registry lock poisoned".into(),
				},
			},
			PivotWasmMsg::ExecuteRequest(request) => self
				.handle_execute_request(request)
				.map(PivotWasmMsg::ExecuteResponse)
				.unwrap_or_else(PivotWasmMsg::from),
			_ => PivotWasmMsg::RuntimeError {
				message: "unexpected message variant".into(),
			},
		};

		borsh::to_vec(&response).expect("borsh serialization cannot fail")
	}
}

fn read_governance(path: &str) -> PivotWasmGovernance {
	let bytes = std::fs::read(path).unwrap_or_else(|e| {
		panic!("failed to read WASM governance file {path}: {e}")
	});
	PivotWasmGovernance::try_from_slice(&bytes).unwrap_or_else(|e| {
		panic!("failed to decode WASM governance file {path}: {e}")
	})
}

#[tokio::main]
async fn main() {
	let args: Vec<String> = std::env::args().collect();
	if args.len() != 4 {
		eprintln!(
			"Usage: pivot_wasm <socket-path> <governance-path> <ephemeral-key-path>"
		);
		std::process::exit(2);
	}

	let socket_path = &args[1];
	let governance_path = &args[2];
	let eph_key_path = &args[3];

	let governance = read_governance(governance_path);
	let ephemeral_key_handle = EphemeralKeyHandle::new(eph_key_path.clone());
	let processor = WasmProcessor::new(governance, ephemeral_key_handle)
		.expect("failed to initialize WASM processor");

	let app_pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("unable to create app pool");

	let _server = SocketServer::listen_all(app_pool, &processor, 1).unwrap();

	tokio::signal::ctrl_c().await.unwrap();
}

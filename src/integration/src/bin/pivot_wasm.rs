use std::sync::Arc;

use borsh::BorshDeserialize;
use integration::{
	PivotWasmExecuteRequest, PivotWasmExecuteResponse,
	PivotWasmExecutionAttestation, PivotWasmMsg,
};
use qos_core::{
	handles::EphemeralKeyHandle,
	io::{SocketAddress, StreamPool},
	server::{RequestProcessor, SocketServer},
};
use qos_crypto::sha_256;
use qos_p256::P256Public;
use tokio::sync::RwLock;
use wasmtime::{Config, Engine, Linker, Module, Store};

const FUEL_LIMIT: u64 = 1_000_000;

struct WasmProcessor {
	engine: Engine,
	owner_public_key: P256Public,
	ephemeral_key_handle: EphemeralKeyHandle,
}

impl WasmProcessor {
	fn new(
		owner_public_key: P256Public,
		ephemeral_key_handle: EphemeralKeyHandle,
	) -> Arc<RwLock<Self>> {
		let mut config = Config::new();
		config.consume_fuel(true);
		let engine =
			Engine::new(&config).expect("failed to create wasmtime engine");
		Arc::new(RwLock::new(Self {
			engine,
			owner_public_key,
			ephemeral_key_handle,
		}))
	}

	fn execute_module(
		&self,
		wasm_bytes: &[u8],
		input: &[u8],
	) -> Result<Vec<u8>, String> {
		let module = Module::new(&self.engine, wasm_bytes)
			.map_err(|e| format!("module compilation: {e}"))?;

		let linker = Linker::<()>::new(&self.engine);
		let mut store = Store::new(&self.engine, ());
		store.set_fuel(FUEL_LIMIT).map_err(|e| format!("set fuel: {e}"))?;

		let instance = linker
			.instantiate(&mut store, &module)
			.map_err(|e| format!("instantiation: {e}"))?;

		let alloc = instance
			.get_typed_func::<i32, i32>(&mut store, "alloc")
			.map_err(|e| format!("missing alloc export: {e}"))?;
		let ptr = alloc
			.call(&mut store, input.len() as i32)
			.map_err(|e| format!("alloc failed: {e}"))?;

		let memory = instance
			.get_memory(&mut store, "memory")
			.ok_or("missing memory export")?;
		memory
			.write(&mut store, ptr as usize, input)
			.map_err(|e| format!("memory write: {e}"))?;

		let execute = instance
			.get_typed_func::<(i32, i32), i64>(&mut store, "execute")
			.map_err(|e| format!("missing execute export: {e}"))?;
		let result_packed = execute
			.call(&mut store, (ptr, input.len() as i32))
			.map_err(|e| format!("execute failed: {e}"))?;

		let result_ptr = (result_packed >> 32) as usize;
		let result_len = (result_packed & 0xFFFF_FFFF) as usize;

		let data = memory.data(&store);
		if result_ptr + result_len > data.len() {
			return Err("result out of bounds".into());
		}
		Ok(data[result_ptr..result_ptr + result_len].to_vec())
	}

	fn handle_execute_request(
		&self,
		PivotWasmExecuteRequest {
			policy_wasm,
			policy_signature,
			program_wasm,
			input,
		}: PivotWasmExecuteRequest,
	) -> Result<PivotWasmExecuteResponse, String> {
		// 1. Verify policy signature
		let policy_hash = sha_256(&policy_wasm);
		if self
			.owner_public_key
			.verify(&policy_hash, &policy_signature)
			.is_err()
		{
			return Err("invalid signature".into());
		}

		// 2. Build policy input: program_wasm_len (u32 LE) || program_wasm || user_input
		let program_len_bytes = (program_wasm.len() as u32).to_le_bytes();
		let mut policy_input =
			Vec::with_capacity(4 + program_wasm.len() + input.len());
		policy_input.extend_from_slice(&program_len_bytes);
		policy_input.extend_from_slice(&program_wasm);
		policy_input.extend_from_slice(&input);

		// 3. Run policy
		let policy_result =
			match self.execute_module(&policy_wasm, &policy_input) {
				Ok(r) => r,
				Err(e) => return Err(format!("policy execution: {e}")),
			};

		if policy_result.first() != Some(&1) {
			return Err("policy denied".into());
		}

		// 4. Run program
		let output = match self.execute_module(&program_wasm, &input) {
			Ok(o) => o,
			Err(e) => {
				return Err(format!("program execution: {e}"));
			}
		};

		// 5. Build and sign execution attestation
		let program_hash = sha_256(&program_wasm);
		let input_hash = sha_256(&input);
		let output_hash = sha_256(&output);

		let attestation_payload = borsh::to_vec(&(
			policy_hash,
			program_hash,
			input_hash,
			output_hash,
		))
		.expect("borsh serialization cannot fail");

		let ephemeral_key = match self.ephemeral_key_handle.get_ephemeral_key()
		{
			Ok(k) => k,
			Err(e) => {
				return Err(format!("ephemeral key: {e:?}"));
			}
		};

		let signature = match ephemeral_key.sign(&attestation_payload) {
			Ok(s) => s,
			Err(e) => {
				return Err(format!("signing: {e:?}"));
			}
		};

		let public_key = ephemeral_key.public_key().to_bytes();

		Ok(PivotWasmExecuteResponse {
			output,
			attestation: PivotWasmExecutionAttestation {
				policy_hash,
				program_hash,
				input_hash,
				output_hash,
				signature,
				public_key,
			},
		})
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

		match msg {
			PivotWasmMsg::ExecuteRequest(request) => {
				let result = self
					.handle_execute_request(request)
					.map(PivotWasmMsg::ExecuteResponse)
					.unwrap_or_else(PivotWasmMsg::from);

				borsh::to_vec(&result).expect("borsh serialization cannot fail")
			}
			_ => borsh::to_vec(&PivotWasmMsg::RuntimeError {
				message: "unexpected message variant".into(),
			})
			.expect("borsh serialization cannot fail"),
		}
	}
}

#[tokio::main]
async fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path = &args[1];
	let owner_pub_hex = &args[2];
	let eph_key_path = &args[3];

	let pub_bytes =
		qos_hex::decode(owner_pub_hex).expect("invalid owner public key hex");
	let owner_public_key =
		P256Public::from_bytes(&pub_bytes).expect("invalid owner public key");

	let ephemeral_key_handle = EphemeralKeyHandle::new(eph_key_path.clone());

	let app_pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("unable to create app pool");

	let _server = SocketServer::listen_all(
		app_pool,
		&WasmProcessor::new(owner_public_key, ephemeral_key_handle),
		1,
	)
	.unwrap();

	tokio::signal::ctrl_c().await.unwrap();
}

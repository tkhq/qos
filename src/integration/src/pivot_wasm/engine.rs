//! Wasmtime execution wrapper for registered WASM artifacts.

use borsh::BorshDeserialize;
use qos_crypto::sha_256;
use qos_wasm_sdk::{Decision, PolicyContext};
use wasmtime::{Config, Engine, Linker, Module, Store};

use super::errors::PivotWasmError;

const FUEL_LIMIT: u64 = 1_000_000;

pub struct WasmEngine {
	engine: Engine,
}

impl WasmEngine {
	pub fn new() -> Result<Self, PivotWasmError> {
		let mut config = Config::new();
		config.consume_fuel(true);
		let engine = Engine::new(&config)
			.map_err(|e| PivotWasmError::runtime(format!("engine: {e}")))?;
		Ok(Self { engine })
	}

	pub fn execute_function(
		&self,
		wasm_bytes: &[u8],
		input: &[u8],
	) -> Result<Vec<u8>, PivotWasmError> {
		self.execute_module(wasm_bytes, input)
	}

	pub fn execute_policy(
		&self,
		policy_wasm: &[u8],
		function_hash: [u8; 32],
		function_wasm: &[u8],
		input: &[u8],
	) -> Result<Decision, PivotWasmError> {
		let context = PolicyContext {
			function_hash,
			function_wasm: function_wasm.to_vec(),
			input_hash: sha_256(input),
			input: input.to_vec(),
		};
		let context_bytes = borsh::to_vec(&context).map_err(|e| {
			PivotWasmError::runtime(format!("policy context encode: {e}"))
		})?;
		let decision_bytes =
			self.execute_module(policy_wasm, &context_bytes)?;
		Decision::try_from_slice(&decision_bytes).map_err(|e| {
			PivotWasmError::runtime(format!("policy decision decode: {e}"))
		})
	}

	fn execute_module(
		&self,
		wasm_bytes: &[u8],
		input: &[u8],
	) -> Result<Vec<u8>, PivotWasmError> {
		let input_len: i32 = input
			.len()
			.try_into()
			.map_err(|_| PivotWasmError::runtime("input too large"))?;
		let module = Module::new(&self.engine, wasm_bytes).map_err(|e| {
			PivotWasmError::runtime(format!("module compilation: {e}"))
		})?;

		let linker = Linker::<()>::new(&self.engine);
		let mut store = Store::new(&self.engine, ());
		store
			.set_fuel(FUEL_LIMIT)
			.map_err(|e| PivotWasmError::runtime(format!("set fuel: {e}")))?;

		let instance =
			linker.instantiate(&mut store, &module).map_err(|e| {
				PivotWasmError::runtime(format!("instantiation: {e}"))
			})?;

		let alloc = instance
			.get_typed_func::<i32, i32>(&mut store, "alloc")
			.map_err(|e| {
				PivotWasmError::runtime(format!("missing alloc export: {e}"))
			})?;
		let ptr = alloc.call(&mut store, input_len).map_err(|e| {
			PivotWasmError::runtime(format!("alloc failed: {e}"))
		})?;
		if ptr < 0 {
			return Err(PivotWasmError::runtime(
				"alloc returned negative pointer",
			));
		}

		let memory = instance
			.get_memory(&mut store, "memory")
			.ok_or_else(|| PivotWasmError::runtime("missing memory export"))?;
		memory.write(&mut store, ptr as usize, input).map_err(|e| {
			PivotWasmError::runtime(format!("memory write: {e}"))
		})?;

		let execute = instance
			.get_typed_func::<(i32, i32), i64>(&mut store, "execute")
			.map_err(|e| {
				PivotWasmError::runtime(format!("missing execute export: {e}"))
			})?;
		let result_packed =
			execute.call(&mut store, (ptr, input_len)).map_err(|e| {
				PivotWasmError::runtime(format!("execute failed: {e}"))
			})?;

		let result_ptr = ((result_packed >> 32) as u32) as usize;
		let result_len = (result_packed as u32) as usize;
		let result_end =
			result_ptr.checked_add(result_len).ok_or_else(|| {
				PivotWasmError::runtime("result pointer overflow")
			})?;

		let data = memory.data(&store);
		if result_end > data.len() {
			return Err(PivotWasmError::runtime("result out of bounds"));
		}

		Ok(data[result_ptr..result_end].to_vec())
	}
}

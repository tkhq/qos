//! Integration tests.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};
use std::time::Duration;
use tokio::net::TcpStream;

/// Path to the file `pivot_ok` writes on success for tests.
pub const PIVOT_OK_SUCCESS_FILE: &str = "./pivot_ok_works";
/// Path to the file `pivot_ok2` writes on success for tests.
pub const PIVOT_OK2_SUCCESS_FILE: &str = "./pivot_ok2_works";
/// Path to the file `pivot_ok3` writes on success for tests.
pub const PIVOT_OK3_SUCCESS_FILE: &str = "./pivot_ok3_works";
/// Path to the file `pivot_pool_size` writes on success for tests.
pub const PIVOT_POOL_SIZE_SUCCESS_FILE: &str = "./pivot_pool_size_works";
/// Path to the file `pivot_tcp` writes on success for tests.
pub const PIVOT_TCP_SUCCESS_FILE: &str = "./pivot_tcp_works";
/// Path to `pivot_ok` bin for tests.
pub const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
/// Path to `pivot_ok2` bin for tests.
pub const PIVOT_OK2_PATH: &str = "../target/debug/pivot_ok2";
/// Path to `pivot_ok3` bin for tests.
pub const PIVOT_OK3_PATH: &str = "../target/debug/pivot_ok3";
/// Path to `pivot_tcp` bin for tests.
pub const PIVOT_TCP_PATH: &str = "../target/debug/pivot_tcp";
/// Path to pivot loop bin for tests.
pub const PIVOT_LOOP_PATH: &str = "../target/debug/pivot_loop";
/// Path to `pivot_abort` bin for tests.
pub const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";
/// Path to an enclave app that has routes to test remote connection features.
pub const PIVOT_REMOTE_TLS_PATH: &str = "../target/debug/pivot_remote_tls";
/// Path to an enclave app that has routes to test remote connection features.
pub const QOS_NET_PATH: &str = "../target/debug/qos_net";
/// Path to an enclave app that has routes to stress our socket.
pub const PIVOT_SOCKET_STRESS_PATH: &str =
	"../target/debug/pivot_socket_stress";
/// Path to an enclave app that has routes to fetch app proofs.
pub const PIVOT_PROOF_PATH: &str = "../target/debug/pivot_proof";
/// Path to the WASM pivot app.
pub const PIVOT_WASM_PATH: &str = "../target/debug/pivot_wasm";
/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";
/// PCR3 image associated with the preimage in `./mock/pcr3-preimage.txt`.
pub const PCR3: &str = "78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6";
/// QOS dist directory.
pub const QOS_DIST_DIR: &str = "./mock/dist";
/// Mock pcr3 pre-image.
pub const PCR3_PRE_IMAGE_PATH: &str = "./mock/namespaces/pcr3-preimage.txt";

const MSG: &str = "msg";
const POOL_SIZE: &str = "pool-size";

/// Request/Response messages for "socket stress" pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotSocketStressMsg {
	/// Request a [`Self::OkResponse`] with a specific identifier.
	OkRequest(u64),
	/// A successful response to [`Self::OkRequest`].
	OkResponse(u64),
	/// Request the app to panic. Does not have a response.
	PanicRequest,
	/// Request a response that will be slower than the provided `u64` value in milliseconds
	SlowRequest(u64), // milliseconds
	/// Response to [`Self::SlowRequest`].
	SlowResponse(u64),
}

/// Request/Response messages for the "remote TLS" pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotRemoteTlsMsg {
	/// Request a remote host / port to be fetched over the socket.
	/// We assume the port to be 443, and we use Google's servers to perform
	/// DNS resolution (8.8.8.8)
	RemoteTlsRequest {
		/// Hostname (e.g. "api.turnkey.com")
		host: String,
		/// Path to fetch (e.g. "/health")
		path: String,
	},
	/// A successful response to [`Self::RemoteTlsRequest`] with the contents
	/// of the response.
	RemoteTlsResponse(String),
}

/// Request/Response messages for the "proof" pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotProofMsg {
	/// Simple request for an addition
	AdditionRequest {
		/// First input
		a: usize,
		/// Second input to add
		b: usize,
	},
	/// A successful response to [`Self::AdditionRequest`]
	AdditionResponse {
		/// The addition result
		result: usize,
		/// The addition proof, proving the result
		proof: AdditionProof,
	},
}

/// An addition proof: which contains a signature, a public key, and a payload
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub struct AdditionProof {
	/// Signature of the ephemeral key over the proof message
	pub signature: Vec<u8>,
	/// Ephemeral public key
	pub public_key: Vec<u8>,
	/// Proof payload, over which we sign
	pub payload: AdditionProofPayload,
}

/// Payload of an addition proof, with the two input integers (a, b) and the result (result)
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub struct AdditionProofPayload {
	/// First integer in the addition
	pub a: usize,
	/// Second integer in the addition
	pub b: usize,
	/// Result of the addition
	pub result: usize,
}

/// Request/Response messages for the WASM pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotWasmMsg {
	/// Request execution of a policy-gated WASM program.
	ExecuteRequest(PivotWasmExecuteRequest),
	/// Successful execution response with attestation.
	ExecuteResponse(PivotWasmExecuteResponse),
	/// The policy WASM denied execution.
	PolicyDenied,
	/// The policy signature failed verification.
	InvalidSignature,
	/// A runtime error occurred.
	RuntimeError {
		/// Error message.
		message: String,
	},
}

impl From<String> for PivotWasmMsg {
	fn from(message: String) -> Self {
		match message.as_str() {
			"policy denied" => PivotWasmMsg::PolicyDenied,
			"invalid signature" => PivotWasmMsg::InvalidSignature,
			_ => PivotWasmMsg::RuntimeError { message },
		}
	}
}

/// Request wasm execution details
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub struct PivotWasmExecuteRequest {
	/// The WASM policy module binary (signed by owner).
	pub policy_wasm: Vec<u8>,
	/// Signature of `sha256(policy_wasm)` by the owner key.
	pub policy_signature: Vec<u8>,
	/// The WASM program module binary (unsigned).
	pub program_wasm: Vec<u8>,
	/// Arbitrary input data.
	pub input: Vec<u8>,
}

/// Execution output and attestation.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub struct PivotWasmExecuteResponse {
	/// Output bytes from the program.
	pub output: Vec<u8>,
	/// Attestation binding the output to the computation.
	pub attestation: PivotWasmExecutionAttestation,
}

/// Attestation that binds an output to the specific policy, program, and input
/// that produced it, signed by the enclave's ephemeral key.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub struct PivotWasmExecutionAttestation {
	/// SHA-256 of the policy WASM binary.
	pub policy_hash: [u8; 32],
	/// SHA-256 of the program WASM binary.
	pub program_hash: [u8; 32],
	/// SHA-256 of the input data.
	pub input_hash: [u8; 32],
	/// SHA-256 of the output data.
	pub output_hash: [u8; 32],
	/// Ephemeral key signature over the borsh-serialized attestation fields above.
	pub signature: Vec<u8>,
	/// Ephemeral public key bytes.
	pub public_key: Vec<u8>,
}

/// Wait for a given usock file to exist and be connectible with a timeout of 5s.
///
/// # Panics
/// Panics if `fs::exists` errors.
pub async fn wait_for_usock(path: &str) {
	let addr = SocketAddress::new_unix(path);
	let pool = StreamPool::single(addr).unwrap().shared();
	let client = SocketClient::new(pool, Duration::from_millis(50));

	for _ in 0..50 {
		if std::fs::exists(path).unwrap() && client.try_connect().await.is_ok()
		{
			break;
		}

		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

pub async fn wait_for_tcp_sock(host_addr: &str) {
	// attempt to connect, this can fail a few times due to timing, max 1s timeout
	let mut attempts = 0;
	loop {
		if let Ok(_stream) = TcpStream::connect(&host_addr).await {
			return;
		}
		assert!((attempts <= 9), "unable to connect to {host_addr}");
		attempts += 1;
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

struct PivotParser;
impl GetParserForOptions for PivotParser {
	fn parser() -> Parser {
		Parser::new()
			.token(
				Token::new(MSG, "A msg to write")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(POOL_SIZE, "App pool size")
					.takes_value(true)
					.required(false),
			)
	}
}

/// Simple pivot CLI.
pub struct Cli;
impl Cli {
	/// Execute the CLI.
	pub fn execute(path: &str) {
		for i in 0..3 {
			std::thread::sleep(std::time::Duration::from_millis(i));
		}

		let mut args: Vec<String> = std::env::args().collect();
		let opts = OptionsParser::<PivotParser>::parse(&mut args)
			.expect("Entered invalid CLI args");

		let msg = opts.single(MSG).expect("required argument.");

		std::fs::write(path, msg).expect("Failed to write to pivot success");
	}
}

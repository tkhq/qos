//! Integration tests.

pub mod vfaas;

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};
use std::{path::Path, time::Duration};
use tokio::net::{TcpStream, ToSocketAddrs};

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
pub const PIVOT_OK_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_ok");
/// Path to `pivot_ok2` bin for tests.
pub const PIVOT_OK2_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_ok2");
/// Path to `pivot_ok3` bin for tests.
pub const PIVOT_OK3_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_ok3");
/// Path to `pivot_tcp` bin for tests.
pub const PIVOT_TCP_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_tcp");
/// Path to pivot loop bin for tests.
pub const PIVOT_LOOP_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_loop");
/// Path to `pivot_abort` bin for tests.
pub const PIVOT_ABORT_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_abort");
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_panic");
/// Path to an enclave app that has routes to test remote connection features.
pub const PIVOT_REMOTE_TLS_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_remote_tls");
/// Path to an enclave app that has routes to test remote connection features.
pub const QOS_NET_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_net");
/// Path to an enclave app that has routes to stress our socket.
pub const PIVOT_SOCKET_STRESS_PATH: &str = concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../../target/debug/pivot_socket_stress"
);
/// Path to an enclave app that has routes to fetch app proofs.
pub const PIVOT_PROOF_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/pivot_proof");
/// Path to `qos_bridge` bin for tests.
pub const QOS_BRIDGE_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_bridge");
/// Path to `qos_client` bin for tests.
pub const QOS_CLIENT_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_client");
/// Path to `qos_core` bin for tests.
pub const QOS_CORE_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_core");
/// Path to `qos_host` bin for tests.
pub const QOS_HOST_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_host");
/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";
/// PCR3 image associated with the preimage in `./mock/pcr3-preimage.txt`.
pub const PCR3: &str = "78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6";
/// QOS dist directory.
pub const QOS_DIST_DIR: &str = "./mock/dist";
/// Mock pcr3 pre-image.
pub const PCR3_PRE_IMAGE_PATH: &str = "./mock/namespaces/pcr3-preimage.txt";

const MSG: &str = "msg";
const ENV_KEY: &str = "env-key";
const MISSING_ENV_KEY: &str = "missing-env-key";
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

/// Domain separator prepended to program WASM hashes before owner signing.
/// Prevents reusing a program signature as a policy signature.
pub const VFAAS_PROGRAM_DOMAIN: &[u8] = b"vfaas-program-v1";
/// Domain separator prepended to policy WASM hashes before owner signing.
pub const VFAAS_POLICY_DOMAIN: &[u8] = b"vfaas-policy-v1";

/// Host-side mirror of `vfaas_sdk::PolicyRequest`. The host serializes this
/// with Borsh and passes the bytes as the single argument to the policy
/// `__vfaas_evaluate` export. Structural compatibility with the SDK type
/// is enforced by sharing the field order and Borsh layout.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub struct VfaasPolicyRequest {
	/// The full bytes of the program WASM module about to run.
	pub program: Vec<u8>,
	/// The input bytes the program will receive.
	pub input: Vec<u8>,
}

/// Request/Response messages for the `pivot_vfaas` app.
///
/// The pivot maintains in-memory registries of owner-signed program and policy
/// WASM blobs. Clients register a blob with a signature over
/// `DOMAIN || sha256(wasm)`; the pivot verifies against the owner public key
/// it was launched with. Execute selects a registered program + policy pair,
/// runs the policy first (which can inspect the program bytes + input), and
/// runs the program iff the policy returns `Allow`. The pivot signs the
/// resulting `ExecutionAttestation` with its ephemeral key.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum VfaasMsg {
	/// Register a program WASM blob with an owner signature.
	RegisterProgramRequest {
		/// The WASM module bytes.
		wasm: Vec<u8>,
		/// Owner signature over `VFAAS_PROGRAM_DOMAIN || sha256(wasm)`.
		signature: Vec<u8>,
	},
	/// Register a policy WASM blob with an owner signature.
	RegisterPolicyRequest {
		/// The WASM module bytes.
		wasm: Vec<u8>,
		/// Owner signature over `VFAAS_POLICY_DOMAIN || sha256(wasm)`.
		signature: Vec<u8>,
	},
	/// List the hashes of registered programs.
	ListProgramsRequest,
	/// List the hashes of registered policies.
	ListPoliciesRequest,
	/// Execute a registered program gated by a registered policy.
	ExecuteRequest {
		/// SHA-256 of the program WASM bytes.
		program_hash: [u8; 32],
		/// SHA-256 of the policy WASM bytes.
		policy_hash: [u8; 32],
		/// Untyped input bytes; the program decodes them.
		input: Vec<u8>,
	},
	/// Response to [`Self::RegisterProgramRequest`].
	RegisterProgramResponse {
		/// SHA-256 of the registered program WASM.
		hash: [u8; 32],
	},
	/// Response to [`Self::RegisterPolicyRequest`].
	RegisterPolicyResponse {
		/// SHA-256 of the registered policy WASM.
		hash: [u8; 32],
	},
	/// Response to [`Self::ListProgramsRequest`].
	ListProgramsResponse {
		/// Hashes of all currently registered programs.
		hashes: Vec<[u8; 32]>,
	},
	/// Response to [`Self::ListPoliciesRequest`].
	ListPoliciesResponse {
		/// Hashes of all currently registered policies.
		hashes: Vec<[u8; 32]>,
	},
	/// Response to [`Self::ExecuteRequest`].
	ExecuteResponse {
		/// Policy decision.
		decision: Decision,
		/// Program output bytes when `decision = Allow`; `None` otherwise.
		output: Option<Vec<u8>>,
		/// Enclave-signed attestation binding hashes to the decision.
		attestation: SignedExecutionAttestation,
	},
	/// Error response. Carries a human-readable reason.
	Error(String),
}

/// Outcome of a policy evaluation.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub enum Decision {
	/// Program execution is permitted.
	Allow,
	/// Program execution is denied with a human-readable reason.
	Deny(String),
}

/// Unsigned record of an execution attempt.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub struct ExecutionAttestation {
	/// SHA-256 of the program WASM.
	pub program_hash: [u8; 32],
	/// SHA-256 of the policy WASM.
	pub policy_hash: [u8; 32],
	/// SHA-256 of the input bytes.
	pub input_hash: [u8; 32],
	/// SHA-256 of the output bytes; `None` when no output was produced.
	pub output_hash: Option<[u8; 32]>,
	/// Policy decision.
	pub decision: Decision,
	/// Monotonic per-pivot request counter; orders executions.
	pub request_id: u64,
}

/// [`ExecutionAttestation`] signed by the enclave ephemeral key.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub struct SignedExecutionAttestation {
	/// The attestation payload (Borsh-serialized when signing).
	pub attestation: ExecutionAttestation,
	/// Signature of the ephemeral key over `borsh::to_vec(&attestation)`.
	pub signature: Vec<u8>,
	/// Ephemeral public key bytes (SEC1 encrypt_public || sign_public).
	pub ephemeral_public_key: Vec<u8>,
}

/// Wait for a given usock file to exist and be connectible with a timeout of 5s.
///
/// # Panics
/// Panics if `fs::exists` errors.
pub async fn wait_for_usock<P: AsRef<Path>>(path: P) {
	let path = path.as_ref();
	let addr = SocketAddress::new_unix(path);
	let pool = StreamPool::single(addr).unwrap().shared();
	let client = SocketClient::new(pool, Duration::from_millis(50));

	for _ in 0..50 {
		if std::fs::exists(path).unwrap() && client.try_connect().await.is_ok()
		{
			return;
		}

		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	panic!("unable to connect to usock at path: {}", path.display())
}

pub async fn wait_for_tcp_sock<Addr>(host_addr: &Addr)
where
	Addr: ToSocketAddrs + std::fmt::Debug,
{
	// Some integration flows start the listener only after a few control-loop
	// iterations, so give the socket enough time to appear before failing.
	let mut attempts = 0;
	loop {
		if let Ok(_stream) = TcpStream::connect(host_addr).await {
			return;
		}

		assert!((attempts <= 99), "unable to connect to {host_addr:?}");
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
				Token::new(ENV_KEY, "Env var name to append")
					.takes_value(true)
					.required(false),
			)
			.token(
				Token::new(
					MISSING_ENV_KEY,
					"Env var name expected to be missing",
				)
				.takes_value(true)
				.required(false),
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

		let mut msg = opts.single(MSG).expect("required argument.").to_string();

		// Env tests set one variable in the parent process and a different
		// variable in the manifest, then pass both names to this pivot. This
		// code fails if the parent-only name is visible here, appends the
		// manifest variable's value to `msg`, and writes that combined string
		// to `path`. The test reads `path` and expects `msg + env_value`.
		if let Some(key) = opts.single(MISSING_ENV_KEY) {
			assert!(
				std::env::var(key).is_err(),
				"unexpected env var leaked into pivot process: {key}"
			);
		}

		if let Some(key) = opts.single(ENV_KEY) {
			let value = std::env::var(key).expect("expected pivot env var");
			msg.push_str(&value);
		}

		std::fs::write(path, msg).expect("Failed to write to pivot success");
	}
}

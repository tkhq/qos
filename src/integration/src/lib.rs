//! Integration tests.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::parser::{GetParserForOptions, OptionsParser, Parser, Token};

/// Path to the file `pivot_ok` writes on success for tests.
pub const PIVOT_OK_SUCCESS_FILE: &str = "./pivot_ok_works";
/// Path to the file `pivot_ok2` writes on success for tests.
pub const PIVOT_OK2_SUCCESS_FILE: &str = "./pivot_ok2_works";
/// Path to the file `pivot_ok3` writes on success for tests.
pub const PIVOT_OK3_SUCCESS_FILE: &str = "./pivot_ok3_works";
/// Path to the file `pivot_ok4` writes on success for tests.
pub const PIVOT_OK4_SUCCESS_FILE: &str = "./pivot_ok4_works";
/// Path to the file `pivot_ok5` writes on success for tests.
pub const PIVOT_OK5_SUCCESS_FILE: &str = "./pivot_ok5_works";
/// Path to pivot_ok bin for tests.
pub const PIVOT_OK_PATH: &str = "../target/debug/pivot_ok";
/// Path to pivot_ok2 bin for tests.
pub const PIVOT_OK2_PATH: &str = "../target/debug/pivot_ok2";
/// Path to pivot_ok3 bin for tests.
pub const PIVOT_OK3_PATH: &str = "../target/debug/pivot_ok3";
/// Path to pivot_ok4 bin for tests.
pub const PIVOT_OK4_PATH: &str = "../target/debug/pivot_ok4";
/// Path to pivot_ok5 bin for tests.
pub const PIVOT_OK5_PATH: &str = "../target/debug/pivot_ok5";
/// Path to pivot loop bin for tests.
pub const PIVOT_LOOP_PATH: &str = "../target/debug/pivot_loop";
/// Path to pivot_abort bin for tests.
pub const PIVOT_ABORT_PATH: &str = "../target/debug/pivot_abort";
/// Path to pivot panic for tests.
pub const PIVOT_PANIC_PATH: &str = "../target/debug/pivot_panic";
/// Path to an enclave app that has routes to test remote connection features.
pub const PIVOT_REMOTE_TLS_PATH: &str = "../target/debug/pivot_remote_tls";
/// Path to an enclave app that has routes to test remote connection features.
pub const PIVOT_ASYNC_REMOTE_TLS_PATH: &str =
	"../target/debug/pivot_async_remote_tls";
/// Path to an enclave app that has routes to test remote connection features.
pub const QOS_NET_PATH: &str = "../target/debug/qos_net";
/// Path to an enclave app that has routes to test async remote connection features.
pub const ASYNC_QOS_NET_PATH: &str = "../target/debug/async_qos_net";
/// Path to an enclave app that has routes to stress our socket.
pub const PIVOT_SOCKET_STRESS_PATH: &str =
	"../target/debug/pivot_socket_stress";
/// Path to an enclave app that has routes to fetch app proofs.
pub const PIVOT_PROOF_PATH: &str = "../target/debug/pivot_proof";
/// Local host IP address.
pub const LOCAL_HOST: &str = "127.0.0.1";
/// PCR3 image associated with the preimage in `./mock/pcr3-preimage.txt`.
pub const PCR3: &str = "78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6";
/// QOS dist directory.
pub const QOS_DIST_DIR: &str = "./mock/dist";
/// Mock pcr3 pre-image.
pub const PCR3_PRE_IMAGE_PATH: &str = "./mock/namespaces/pcr3-preimage.txt";

const MSG: &str = "msg";

/// Request/Response messages for "socket stress" pivot app.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq)]
pub enum PivotSocketStressMsg {
	/// Request a [`Self::OkResponse`].
	OkRequest,
	/// A successful response to [`Self::OkRequest`].
	OkResponse,
	/// Request the app to panic. Does not have a response.
	PanicRequest,
	/// Request a response that will be slower then
	/// `ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS`.
	SlowRequest,
	/// Response to [`Self::SlowRequest`].
	SlowResponse,
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

struct PivotParser;
impl GetParserForOptions for PivotParser {
	fn parser() -> Parser {
		Parser::new().token(
			Token::new(MSG, "A msg to write").takes_value(true).required(true),
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

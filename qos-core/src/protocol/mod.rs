//! Quorum protocol state machine.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_crypto::sha_256;

use crate::server;

pub mod attestor;
pub mod msg;
pub mod services;

use attestor::NsmProvider;
use msg::ProtocolMsg;
use services::boot;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

/// 256bit hash
pub type Hash256 = [u8; 32];

/// Canonical hash of `QuorumOS` types.
pub trait QosHash: BorshSerialize {
	/// Get the canonical hash.
	fn qos_hash(&self) -> Hash256 {
		sha_256(&self.try_to_vec().expect("Implements borsh serialize"))
	}
}

// Blanket implement QosHash for any type that implements BorshSerialize.
impl<T: BorshSerialize> QosHash for T {}

/// A error from protocol execution.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolError {
	/// TODO
	InvalidShare,
	/// Failed to reconstruct the quorum key while provisioning.
	ReconstructionError,
	/// Filesystem error
	IOError,
	/// Cryptography error
	CryptoError,
	/// Approval was not valid for a manifest.
	InvalidManifestApproval(boot::Approval),
	/// [`ManifestEnvelope`] did not have approvals
	NotEnoughApprovals,
	/// Protocol Message could not be matched against an available route.
	/// Ensure the executor is in the correct phase.
	NoMatchingRoute(ProtocolPhase),
	/// Hash of the Pivot binary does not match the pivot configuration in the
	/// manifest.
	InvalidPivotHash,
	/// The message is too large.
	OversizeMsg,
	/// Message could not be deserialized
	InvalidMsg,
	/// An error occurred with the enclave client.
	EnclaveClient,
	/// Failed attempting to decrypt something.
	DecryptionFailed,
	/// Could not create a private key.
	InvalidPrivateKey,
	/// Failed to parse from string.
	FailedToParseFromString,
	BadEphemeralKeyPath
}

impl From<qos_crypto::CryptoError> for ProtocolError {
	fn from(_: qos_crypto::CryptoError) -> Self {
		Self::CryptoError
	}
}

impl From<openssl::error::ErrorStack> for ProtocolError {
	fn from(_err: openssl::error::ErrorStack) -> Self {
		Self::CryptoError
	}
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

/// Protocol executor state.
#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum ProtocolPhase {
	/// The state machine cannot recover. The enclave must be rebooted.
	UnrecoverableError,
	/// Waiting to receive a boot instruction.
	WaitingForBootInstruction,
	/// Waiting to receive K quorum shards
	WaitingForQuorumShards,
	/// The enclave has successfully provisioned its quorum key.
	QuorumKeyProvisioned,
}

/// Enclave executor state
// TODO only include mutables in here, all else should be written to file as
// read only
pub struct ProtocolState {
	provisioner: services::provision::SecretBuilder,
	attestor: Box<dyn NsmProvider>,
	pivot_file: String,
	ephemeral_key_file: String,
	secret_file: String,
	phase: ProtocolPhase,
	manifest: Option<boot::ManifestEnvelope>,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
		ephemeral_key_file: String,
	) -> Self {
		let provisioner = services::provision::SecretBuilder::new();
		Self {
			attestor,
			provisioner,
			pivot_file,
			ephemeral_key_file,
			secret_file,
			phase: ProtocolPhase::WaitingForBootInstruction,
			manifest: None,
		}
	}
}

/// Maybe rename state machine?
/// Enclave state machine that executes when given a `ProtocolMsg`.
pub struct Executor {
	state: ProtocolState,
}

impl Executor {
	/// Create a new `Self`.
	#[must_use]
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
		ephemeral_key_file: String,
	) -> Self {
		Self {
			state: ProtocolState::new(
				attestor,
				secret_file,
				pivot_file,
				ephemeral_key_file,
			),
		}
	}

	fn routes(&self) -> Vec<Box<ProtocolHandler>> {
		match self.state.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![Box::new(handlers::status)]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				Box::new(handlers::status),
				Box::new(handlers::boot_genesis),
				Box::new(handlers::boot_standard),
				// Below are here just for development convenience
				Box::new(handlers::nsm_request),
			],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![Box::new(handlers::status), Box::new(handlers::provision)]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![Box::new(handlers::status), Box::new(handlers::proxy)]
			}
		}
	}
}

impl server::Routable for Executor {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		let err_resp = || {
			ProtocolMsg::ErrorResponse
				.try_to_vec()
				.expect("ProtocolMsg can always be serialized. qed.")
		};

		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return err_resp();
		}

		let msg_req = match ProtocolMsg::try_from_slice(&req_bytes) {
			Ok(req) => req,
			Err(_) => return err_resp(),
		};

		for handler in &self.routes() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => {
					return msg_resp
						.try_to_vec()
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.state.phase.clone());
		ProtocolMsg::ProtocolErrorResponse(err)
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized. qed.")
	}
}

mod handlers {
	use crate::protocol::{
		msg::ProtocolMsg,
		services::{boot, genesis, provision},
		ProtocolPhase, ProtocolState,
	};

	// TODO: Add tests for this in the middle of some integration tests
	/// Status of the enclave.
	pub(super) fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::StatusRequest = req {
			Some(ProtocolMsg::StatusResponse(state.phase.clone()))
		} else {
			None
		}
	}

	pub(super) fn proxy(
		_req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		// TODO
		None
	}

	pub(super) fn nsm_request(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest { nsm_request } = req {
			let nsm_response = {
				let fd = state.attestor.nsm_init();
				state.attestor.nsm_process_request(fd, nsm_request.clone())
			};

			Some(ProtocolMsg::NsmResponse { nsm_response })
		} else {
			None
		}
	}

	pub(super) fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProvisionRequest { share } = req {
			match provision::provision(share, state) {
				Ok(reconstructed) => {
					Some(ProtocolMsg::ProvisionResponse { reconstructed })
				}
				Err(e) => {
					state.phase = ProtocolPhase::UnrecoverableError;
					Some(ProtocolMsg::ProtocolErrorResponse(e))
				}
			}
		} else {
			None
		}
	}

	/// Handle `ProtocolMsg::BootStandardRequest`.
	pub(super) fn boot_standard(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::BootStandardRequest { manifest_envelope, pivot } =
			req
		{
			match boot::boot_standard(state, manifest_envelope, pivot) {
				Ok(nsm_response) => {
					Some(ProtocolMsg::BootStandardResponse { nsm_response })
				}
				Err(e) => {
					state.phase = ProtocolPhase::UnrecoverableError;
					Some(ProtocolMsg::ProtocolErrorResponse(e))
				}
			}
		} else {
			None
		}
	}

	pub(super) fn boot_genesis(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::BootGenesisRequest { set } = req {
			match genesis::boot_genesis(state, set) {
				Ok((genesis_output, nsm_response)) => {
					Some(ProtocolMsg::BootGenesisResponse {
						nsm_response,
						genesis_output,
					})
				}
				Err(e) => {
					state.phase = ProtocolPhase::UnrecoverableError;
					Some(ProtocolMsg::ProtocolErrorResponse(e))
				}
			}
		} else {
			None
		}
	}
}

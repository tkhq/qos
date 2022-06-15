//! Quorum protocol state machine.

use borsh::{BorshDeserialize, BorshSerialize};

mod attestor;
mod boot;
mod genesis;
mod msg;
mod provisioner;

pub use attestor::{
	types::{NsmDigest, NsmRequest, NsmResponse},
	MockNsm, Nsm, NsmProvider, MOCK_NSM_ATTESTATION_DOCUMENT,
};
pub use boot::{Approval, ManifestEnvelope};
pub use genesis::{
	GenesisMemberOutput, GenesisOutput, GenesisSet, SetupMember,
};
pub use msg::*;
use provisioner::SecretProvisioner;

use crate::server;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

/// 256bit hash
pub type Hash256 = [u8; 32];

/// A error from protocol execution.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolError {
	/// TODO
	InvalidShare,
	/// TODO
	ReconstructionError,
	/// Filesystem error
	IOError,
	/// Cryptography error
	CryptoError,
	/// Approval was not valid for a manifest.
	InvalidManifestApproval(Approval),
	/// [`ManifestEnvelope`] did not have approvals
	NotEnoughApprovals,
	/// Protocol Message could not be matched against an available route.
	/// Ensure the executor is in the correct phase.
	NoMatchingRoute(ProtocolPhase),
	/// Hash of the Pivot binary does not match the pivot configuration in the
	/// manifest.
	InvalidPivotHash,
	/// The [`Msg`] is too large.
	OversizeMsg,
	/// Message could not be deserialized
	InvalidMsg,
	/// An error occurred with the enclave client.
	EnclaveClient,
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
}

/// Enclave executor state
// TODO only include mutables in here, all else should be written to file as
// read only
pub struct ProtocolState {
	provisioner: SecretProvisioner,
	attestor: Box<dyn NsmProvider>,
	pivot_file: String,
	ephemeral_key_file: String,
	phase: ProtocolPhase,
	manifest: Option<ManifestEnvelope>,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
		ephemeral_key_file: String,
	) -> Self {
		let provisioner = SecretProvisioner::new(secret_file);
		Self {
			attestor,
			provisioner,
			pivot_file,
			ephemeral_key_file,
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
			ProtocolPhase::WaitingForQuorumShards => vec![
				Box::new(handlers::status),
				// TODO: reconstruct when the K'th key is received
				Box::new(handlers::provision),
			],
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
	use super::{
		boot, genesis, ProtocolError, ProtocolMsg, ProtocolPhase, ProtocolState,
	};

	/// Unwrap an ok or return early with a generic error.
	/// TODO: this try and pass through the returned error
	macro_rules! ok {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return Some(ProtocolMsg::ErrorResponse),
			}
		};
	}

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
		if let ProtocolMsg::ProvisionRequest { share: pr } = req {
			// TODO: share should be encrypted to ephemeral key
			// TODO: ensure state is waiting for provision
			match state.provisioner.add_share(pr.share.clone()) {
				Ok(_) => {
					// TODO: change phase to attempting to constructing quorum
					// key

					if state.provisioner.count()
						>= state
							.manifest
							.as_ref()
							.unwrap()
							.manifest
							.quorum_set
							.threshold as usize
					{
						let private_key_der =
							ok!(state.provisioner.reconstruct());
						let public_key_der = ok!(ok!(
							qos_crypto::RsaPair::from_der(&private_key_der)
						)
						.public_key_to_der());
						// Verify we constructed the correct key
						if public_key_der
							!= state
								.manifest
								.as_ref()
								.unwrap()
								.manifest
								.quorum_key
						{
							state.phase = ProtocolPhase::UnrecoverableError;
							return Some(ProtocolMsg::ProtocolErrorResponse(
								ProtocolError::ReconstructionError,
							));
						}
						// Write the secrete to file
						ok!(std::fs::write(
							state.provisioner.secret_file(),
							private_key_der
						));
						// Let the caller know we reconstructed the secrete
						// TODO: set phase to ProvisionFinished
						Some(ProtocolMsg::ProvisionResponse {
							reconstructed: true,
						})
					} else {
						Some(ProtocolMsg::ProvisionResponse {
							reconstructed: false,
						})
					}
				}
				Err(_) => Some(ProtocolMsg::ErrorResponse),
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
			let nsm_response =
				match boot::boot_standard(state, manifest_envelope, pivot) {
					Ok(r) => r,
					Err(e) => {
						state.phase = ProtocolPhase::UnrecoverableError;
						return Some(ProtocolMsg::ProtocolErrorResponse(e));
					}
				};

			Some(ProtocolMsg::BootStandardResponse { nsm_response })
		} else {
			None
		}
	}

	pub(super) fn boot_genesis(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::BootGenesisRequest { set } = req {
			let (genesis_output, nsm_response) =
				match genesis::boot_genesis(state, set) {
					Ok(r) => r,
					Err(e) => {
						state.phase = ProtocolPhase::UnrecoverableError;
						return Some(ProtocolMsg::ProtocolErrorResponse(e));
					}
				};

			Some(ProtocolMsg::BootGenesisResponse {
				nsm_response,
				genesis_output,
			})
		} else {
			None
		}
	}
}

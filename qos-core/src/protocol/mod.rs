//! Quorum protocol.

use std::{
	fs::{set_permissions, Permissions},
	os::unix::fs::PermissionsExt,
};

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
use provisioner::*;

use crate::server;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

pub type Hash256 = [u8; 32];

#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolError {
	InvalidShare,
	ReconstructionError,
	IOError,
	CryptoError,
	InvalidManifestApproval(Approval),
	NotEnoughApprovals,
	NoMatchingRoute(ProtocolPhase),
	InvalidPivotHash,
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

#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum ProtocolPhase {
	UnrecoverableError,
	WaitingForBootInstruction,
	WaitingForQuorumShards,
}

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

pub struct Executor {
	state: ProtocolState,
}

impl Executor {
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
				// TODO: should only be `boot_instruction` & status, but don't
				// want to break tests
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm_attestation),
				Box::new(handlers::load),
				Box::new(handlers::status),
				Box::new(handlers::boot_instruction),
			],
			ProtocolPhase::WaitingForQuorumShards => vec![
				Box::new(handlers::provision),
				// Drop this .. Just wait for K'th key to reconstruct
				Box::new(handlers::reconstruct),
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
			return err_resp()
		}

		let msg_req = match ProtocolMsg::try_from_slice(&req_bytes) {
			Ok(req) => req,
			Err(_) => return err_resp(),
		};

		for handler in self.routes().iter() {
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
	use qos_crypto::RsaPair;

	use super::*;

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
	pub fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::StatusRequest = req {
			Some(ProtocolMsg::StatusResponse(state.phase.clone()))
		} else {
			None
		}
	}

	pub fn empty(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EmptyRequest = req {
			Some(ProtocolMsg::EmptyResponse)
		} else {
			None
		}
	}

	pub fn echo(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EchoRequest(e) = req {
			Some(ProtocolMsg::EchoResponse(e.clone()))
		} else {
			None
		}
	}

	pub fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProvisionRequest(pr) = req {
			match state.provisioner.add_share(pr.share.clone()) {
				Ok(_) => Some(ProtocolMsg::SuccessResponse),
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn reconstruct(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ReconstructRequest = req {
			match state.provisioner.reconstruct() {
				Ok(secret) => {
					state.provisioner.secret = Some(secret);
					Some(ProtocolMsg::SuccessResponse)
				}
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn nsm_attestation(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest(NsmRequest::Attestation { .. }) = req {
			let request = NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(
					RsaPair::generate().unwrap().public_key_to_pem().unwrap(),
				),
			};
			let fd = state.attestor.nsm_init();
			let response = state.attestor.nsm_process_request(fd, request);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}

	pub fn load(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::LoadRequest(Load { executable, signatures: _ }) =
			req
		{
			// TODO: this should be fixed when we have the executable load logic
			// figured out
			// for SignatureWithPubKey { signature, path } in signatures {
			// 	let pub_key = match RsaPub::from_pem_file(path) {
			// 		Ok(p) => p,
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	};
			// 	match pub_key.verify_sha256(&signature[..], &data[..]) {
			// 		Ok(_) => {}
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	}
			// }

			ok!(std::fs::write(&state.pivot_file, executable));
			ok!(set_permissions(
				&state.pivot_file,
				Permissions::from_mode(0o111)
			));

			Some(ProtocolMsg::SuccessResponse)
		} else {
			None
		}
	}

	pub fn boot_instruction(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		macro_rules! ok_or_err {
			( $e:expr ) => {
				match $e {
					Ok(r) => r,
					Err(e) => {
						state.phase = ProtocolPhase::UnrecoverableError;
						return Some(ProtocolMsg::ProtocolErrorResponse(e))
					}
				}
			};
		}

		// TODO: look into breaking this up into separate handler since there
		// services are totally different.
		match req {
			ProtocolMsg::BootRequest(BootInstruction::Standard {
				manifest_envelope,
				pivot,
			}) => {
				let nsm_response = ok_or_err!(boot::boot_standard(
					state,
					*manifest_envelope.clone(),
					pivot
				));
				Some(ProtocolMsg::BootStandardResponse(nsm_response))
			}
			ProtocolMsg::BootRequest(BootInstruction::Genesis { set }) => {
				let (genesis_output, nsm_response) =
					ok_or_err!(genesis::boot_genesis(state, set));

				Some(ProtocolMsg::BootGenesisResponse {
					nsm_response,
					genesis_output,
				})
			}
			_ => None,
		}
	}
}

//! Quorum protocol.

use std::{
	fs::{set_permissions, Permissions},
	os::unix::fs::PermissionsExt,
};

mod attestor;
mod boot;
mod genesis;
mod msg;
mod provisioner;

pub use attestor::{MockNsm, Nsm, NsmProvider, MOCK_NSM_ATTESTATION_DOCUMENT};
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

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProtocolError {
	InvalidShare,
	ReconstructionError,
	IOError,
	CryptoError,
	InvalidManifestApproval(Approval),
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

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
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
	fn process(&mut self, mut req_bytes: Vec<u8>) -> Vec<u8> {
		let err_resp = || {
			serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
				.expect("ProtocolMsg can always be serialized. qed.")
		};

		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return err_resp()
		}

		let msg_req = match serde_cbor::from_slice(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => return err_resp(),
		};

		for handler in self.routes().iter() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => {
					return serde_cbor::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.state.phase.clone());
		serde_cbor::to_vec(&ProtocolMsg::ProtocolErrorResponse(err))
			.expect("ProtocolMsg can always be serialized. qed.")
	}
}

mod handlers {
	use qos_crypto::{sha_256, RsaPair};
	use serde_bytes::ByteBuf;

	use super::*;

	macro_rules! ok {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return Some(ProtocolMsg::ErrorResponse),
			}
		};
	}

	macro_rules! ok_unrecoverable {
		( $e:expr, $state:ident ) => {
			match $e {
				Ok(x) => x,
				Err(_) => {
					$state.phase = ProtocolPhase::UnrecoverableError;
					return Some(ProtocolMsg::ErrorResponse)
				}
			}
		};
	}

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
				public_key: Some(ByteBuf::from(
					RsaPair::generate().unwrap().public_key_to_pem().unwrap(),
				)),
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
		macro_rules! ok {
			( $e:expr ) => {
				ok_unrecoverable!($e, state)
			};
		}

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

		match req {
			ProtocolMsg::BootRequest(BootInstruction::Standard {
				manifest_envelope,
				pivot,
			}) => {
				ok_or_err!(manifest_envelope.check_approvals());

				let ephemeral_key = ok!(RsaPair::generate());

				// Write the ephemeral key to the filesystem
				ok!(std::fs::write(
					state.ephemeral_key_file.clone(),
					ok!(ephemeral_key.private_key_to_der()),
				));

				// TODO: should we encode the pivot before hashing it?
				if sha_256(pivot) != manifest_envelope.manifest.pivot.hash {
					return Some(ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::InvalidPivotHash,
					))
				};
				ok!(std::fs::write(&state.pivot_file, pivot));
				ok!(std::fs::set_permissions(
					&state.pivot_file,
					Permissions::from_mode(0o111)
				));
				// Pivot config is implicitly saved to state when we add the
				// manifest

				state.manifest = Some(*manifest_envelope.clone());

				// Get the attestation document from the NSM
				let nsm_response = {
					let request = NsmRequest::Attestation {
						user_data: Some(ByteBuf::from(
							manifest_envelope.manifest.hash(),
						)),
						nonce: None,
						public_key: Some(ByteBuf::from(
							ephemeral_key.public_key_to_pem().unwrap(),
						)),
					};
					let fd = state.attestor.nsm_init();

					state.attestor.nsm_process_request(fd, request)
				};

				// TODO: Should we check PCRs to reduce chance of user error?

				state.phase = ProtocolPhase::WaitingForQuorumShards;
				Some(ProtocolMsg::BootStandardResponse(nsm_response))
			}
			ProtocolMsg::BootRequest(BootInstruction::Genesis { set }) => {
				// Output of a genesis ceremony is:
				//  - Quorum Key has been created
				//  - Quorum Set has been created
				//  - Quorum Key has been sharded to that specific Quorum Set
				//  - NOT: A manifest file
				// Immediately after a genesis ceremony:
				//  - Members of the Quorum Set sign the Quorum Configuration
				//  - This serves as the initial proof-of-access for that Quorum
				//    Set
				// Then, a manifest file is constructed using that Quorum
				// Set
				//  - Threshold members sign this manifest file
				// Later, on some cadence, Quorum Members sign a separate
				// proof-of-access
				//  - This second proof-of-access necessitates using a something
				//    "recent" like a hash of a recent ETH block

				// TODO: Entropy!
				let quorum_pair = ok!(RsaPair::generate());

				let genesis_output =
					ok_or_err!(GenesisOutput::try_from(&quorum_pair, set));

				// Get the attestation document from the NSM
				let nsm_response = {
					let request = NsmRequest::Attestation {
						user_data: Some(ByteBuf::from(genesis_output.hash())),
						nonce: None,
						public_key: None,
					};
					let fd = state.attestor.nsm_init();

					state.attestor.nsm_process_request(fd, request)
				};

				Some(ProtocolMsg::BootGenesisResponse {
					attestation_doc: nsm_response,
					genesis_output,
				})
			}
			_ => None,
		}
	}
}

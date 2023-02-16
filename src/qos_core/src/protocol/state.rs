//! Quorum protocol state machine
use super::{
	error::ProtocolError, msg::ProtocolMsg, services::provision::SecretBuilder,
};
use crate::{client::Client, handles::Handles, io::SocketAddress};
use borsh::BorshSerialize;
use qos_nsm::NsmProvider;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

/// Enclave phase
#[derive(
	Debug, PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
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
	/// Waiting for a forwarded key to be injected
	WaitingForForwardedKey,
}

/// Enclave state
pub(crate) struct ProtocolState {
	pub provisioner: SecretBuilder,
	pub attestor: Box<dyn NsmProvider>,
	pub phase: ProtocolPhase,
	pub app_client: Client,
	pub handles: Handles,
}

impl ProtocolState {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		app_addr: SocketAddress,
	) -> Self {
		let provisioner = SecretBuilder::new();
		Self {
			attestor,
			provisioner,
			phase: ProtocolPhase::WaitingForBootInstruction,
			handles,
			app_client: Client::new(app_addr),
		}
	}

	pub fn handle_msg(&mut self, msg_req: &ProtocolMsg) -> Vec<u8> {
		for handler in &self.routes() {
			match handler(msg_req, self) {
				Some(msg_resp) => {
					return msg_resp
						.try_to_vec()
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.phase.clone());
		ProtocolMsg::ProtocolErrorResponse(err)
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized. qed.")
	}

	fn routes(&self) -> Vec<Box<ProtocolHandler>> {
		match self.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![Box::new(handlers::status)]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				// baseline routes
				Box::new(handlers::status),
				Box::new(handlers::nsm_request),
				// phase specific routes
				Box::new(handlers::boot_genesis),
				Box::new(handlers::boot_standard),
				Box::new(handlers::boot_key_forward),
			],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					// baseline routes
					Box::new(handlers::status),
					Box::new(handlers::nsm_request),
					Box::new(handlers::live_attestation_doc),
					// phase specific routes
					Box::new(handlers::provision),
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![
					// baseline routes
					Box::new(handlers::status),
					Box::new(handlers::nsm_request),
					Box::new(handlers::live_attestation_doc),
					// phase specific routes
					Box::new(handlers::proxy),
					Box::new(handlers::export_key),
				]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					// baseline routes
					Box::new(handlers::status),
					Box::new(handlers::nsm_request),
					Box::new(handlers::live_attestation_doc),
					// phase specific routes
					Box::new(handlers::inject_key),
				]
			}
		}
	}
}

mod handlers {
	use crate::protocol::{
		msg::ProtocolMsg,
		services::{
			attestation, boot, genesis, key, key::EncryptedQuorumKey, provision,
		},
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
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProxyRequest { data: req_data } = req {
			let resp_data = match state.app_client.send(req_data) {
				Ok(resp_data) => resp_data,
				Err(e) => {
					return Some(ProtocolMsg::ProtocolErrorResponse(e.into()))
				}
			};

			Some(ProtocolMsg::ProxyResponse { data: resp_data })
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
		if let ProtocolMsg::ProvisionRequest { share, approval } = req {
			match provision::provision(share, approval.clone(), state) {
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
		if let ProtocolMsg::BootGenesisRequest { set, dr_key } = req {
			match genesis::boot_genesis(state, set, dr_key.clone()) {
				Ok((genesis_output, nsm_response)) => {
					Some(ProtocolMsg::BootGenesisResponse {
						nsm_response,
						genesis_output: Box::new(genesis_output),
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

	pub(super) fn live_attestation_doc(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::LiveAttestationDocRequest = req {
			match attestation::live_attestation_doc(state) {
				Ok(nsm_response) => {
					Some(ProtocolMsg::LiveAttestationDocResponse {
						nsm_response,
						manifest_envelope: state
							.handles
							.get_manifest_envelope()
							.ok()
							.map(Box::new),
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

	pub(super) fn boot_key_forward(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::BootKeyForwardRequest { manifest_envelope, pivot } =
			req
		{
			match key::boot_key_forward(state, manifest_envelope, pivot) {
				Ok(nsm_response) => {
					Some(ProtocolMsg::BootKeyForwardResponse { nsm_response })
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

	pub(super) fn export_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ExportKeyRequest {
			manifest_envelope,
			cose_sign1_attestation_doc,
		} = req
		{
			match key::export_key(
				state,
				manifest_envelope,
				cose_sign1_attestation_doc,
			) {
				Ok(EncryptedQuorumKey { encrypted_quorum_key, signature }) => {
					Some(ProtocolMsg::ExportKeyResponse {
						encrypted_quorum_key,
						signature,
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

	pub(super) fn inject_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::InjectKeyRequest {
			encrypted_quorum_key,
			signature,
		} = req
		{
			match key::inject_key(
				state,
				EncryptedQuorumKey {
					encrypted_quorum_key: encrypted_quorum_key.clone(),
					signature: signature.clone(),
				},
			) {
				Ok(()) => Some(ProtocolMsg::InjectKeyResponse),
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

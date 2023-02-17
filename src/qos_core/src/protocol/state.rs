//! Quorum protocol state machine
use super::{
	error::ProtocolError, msg::ProtocolMsg, services::provision::SecretBuilder,
};
use crate::{client::Client, handles::Handles, io::SocketAddress};
use borsh::BorshSerialize;
use qos_nsm::NsmProvider;

/// Enclave phase
#[derive(
	Debug,
	Copy,
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
)]
pub enum ProtocolPhase {
	/// The state machine cannot recover. The enclave must be rebooted.
	UnrecoverableError,
	/// Waiting to receive a boot instruction.
	WaitingForBootInstruction,
	/// Genesis service has been booted. No further actions.
	GenesisBooted,
	/// Waiting to receive K quorum shards
	WaitingForQuorumShards,
	/// The enclave has successfully provisioned its quorum key.
	QuorumKeyProvisioned,
	/// Waiting for a forwarded key to be injected
	WaitingForForwardedKey,
}

/// Enclave routes
type ProtocolRouteResponse = Option<Result<ProtocolMsg, ProtocolMsg>>;
type ProtocolRouteHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> ProtocolRouteResponse;

struct ProtocolRoute {
	handler: Box<ProtocolRouteHandler>,
	ok_phase: ProtocolPhase,
	err_phase: ProtocolPhase,
}

impl ProtocolRoute {
	pub fn new(
		handler: Box<ProtocolRouteHandler>,
		ok_phase: ProtocolPhase,
		err_phase: ProtocolPhase,
	) -> Self {
		ProtocolRoute { handler, ok_phase, err_phase }
	}

	pub fn try_msg(
		&self,
		msg: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		let resp = (self.handler)(msg, state);

		// ignore transitions in special cases
		if let Some(ref msg_resp) = resp {
			if let Ok(ProtocolMsg::ProvisionResponse { reconstructed }) =
				msg_resp
			{
				if !reconstructed {
					return resp;
				}
			}
		}

		// handle state transitions
		let transition = match resp {
			None => None,
			Some(ref result) => match result {
				Ok(_) => Some(self.ok_phase),
				Err(_) => Some(self.err_phase),
			},
		};

		if let Some(phase) = transition {
			if let Err(e) = state.transition(phase) {
				return Some(Err(ProtocolMsg::ProtocolErrorResponse(e)));
			}
		};

		resp
	}
}

/// Enclave state
pub(crate) struct ProtocolState {
	pub provisioner: SecretBuilder,
	pub attestor: Box<dyn NsmProvider>,
	pub app_client: Client,
	pub handles: Handles,
	phase: ProtocolPhase,
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

	pub fn get_phase(&self) -> ProtocolPhase {
		self.phase
	}

	pub fn handle_msg(&mut self, msg_req: &ProtocolMsg) -> Vec<u8> {
		for route in &self.routes() {
			match route.try_msg(msg_req, self) {
				None => continue,
				Some(result) => match result {
					Ok(msg_resp) => {
						return msg_resp.try_to_vec().expect(
							"ProtocolMsg can always be serialized. qed.",
						)
					}
					Err(msg_resp) => {
						return msg_resp.try_to_vec().expect(
							"ProtocolMsg can always be serialized. qed.",
						)
					}
				},
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.phase);
		ProtocolMsg::ProtocolErrorResponse(err)
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized. qed.")
	}

	#[allow(clippy::too_many_lines)]
	fn routes(&self) -> Vec<ProtocolRoute> {
		// TODO(tim): dry up these routes
		#[allow(clippy::match_same_arms)]
		match self.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![ProtocolRoute::new(
					Box::new(handlers::status),
					self.phase,
					self.phase,
				)]
			}
			ProtocolPhase::GenesisBooted => {
				vec![ProtocolRoute::new(
					Box::new(handlers::status),
					self.phase,
					self.phase,
				)]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				// baseline routes
				ProtocolRoute::new(
					Box::new(handlers::status),
					self.phase,
					self.phase,
				),
				ProtocolRoute::new(
					Box::new(handlers::nsm_request),
					self.phase,
					self.phase,
				),
				// phase specific routes
				ProtocolRoute::new(
					Box::new(handlers::boot_genesis),
					ProtocolPhase::GenesisBooted,
					ProtocolPhase::UnrecoverableError,
				),
				ProtocolRoute::new(
					Box::new(handlers::boot_standard),
					ProtocolPhase::WaitingForQuorumShards,
					ProtocolPhase::UnrecoverableError,
				),
				ProtocolRoute::new(
					Box::new(handlers::boot_key_forward),
					ProtocolPhase::WaitingForForwardedKey,
					ProtocolPhase::UnrecoverableError,
				),
			],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					// baseline routes
					ProtocolRoute::new(
						Box::new(handlers::status),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::nsm_request),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::live_attestation_doc),
						self.phase,
						ProtocolPhase::UnrecoverableError,
					),
					// phase specific routes
					ProtocolRoute::new(
						Box::new(handlers::provision),
						ProtocolPhase::QuorumKeyProvisioned,
						ProtocolPhase::UnrecoverableError,
					),
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![
					// baseline routes
					ProtocolRoute::new(
						Box::new(handlers::status),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::nsm_request),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::live_attestation_doc),
						self.phase,
						ProtocolPhase::UnrecoverableError,
					),
					// phase specific routes
					ProtocolRoute::new(
						Box::new(handlers::proxy),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::export_key),
						self.phase,
						ProtocolPhase::UnrecoverableError,
					),
				]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					// baseline routes
					ProtocolRoute::new(
						Box::new(handlers::status),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::nsm_request),
						self.phase,
						self.phase,
					),
					ProtocolRoute::new(
						Box::new(handlers::live_attestation_doc),
						self.phase,
						ProtocolPhase::UnrecoverableError,
					),
					// phase specific routes
					ProtocolRoute::new(
						Box::new(handlers::inject_key),
						ProtocolPhase::QuorumKeyProvisioned,
						ProtocolPhase::UnrecoverableError,
					),
				]
			}
		}
	}

	pub fn transition(
		&mut self,
		next: ProtocolPhase,
	) -> Result<(), ProtocolError> {
		if self.phase == next {
			return Ok(());
		}

		#[allow(clippy::match_same_arms)]
		let transitions = match self.phase {
			ProtocolPhase::UnrecoverableError => vec![],
			ProtocolPhase::WaitingForBootInstruction => vec![
				ProtocolPhase::GenesisBooted,
				ProtocolPhase::WaitingForQuorumShards,
				ProtocolPhase::WaitingForForwardedKey,
			],
			ProtocolPhase::GenesisBooted => vec![],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![ProtocolPhase::QuorumKeyProvisioned]
			}
			ProtocolPhase::QuorumKeyProvisioned => vec![],
			ProtocolPhase::WaitingForForwardedKey => {
				vec![ProtocolPhase::QuorumKeyProvisioned]
			}
		};

		if !transitions.contains(&next) {
			let prev = self.phase;
			self.phase = ProtocolPhase::UnrecoverableError;
			return Err(ProtocolError::InvalidStateTransition(prev, next));
		}

		self.phase = next;
		Ok(())
	}
}

mod handlers {
	use super::ProtocolRouteResponse;
	use crate::protocol::{
		msg::ProtocolMsg,
		services::{
			attestation, boot, genesis, key, key::EncryptedQuorumKey, provision,
		},
		ProtocolState,
	};

	// TODO: Add tests for this in the middle of some integration tests
	/// Status of the enclave.
	pub(super) fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::StatusRequest = req {
			Some(Ok(ProtocolMsg::StatusResponse(state.get_phase())))
		} else {
			None
		}
	}

	pub(super) fn proxy(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ProxyRequest { data: req_data } = req {
			let result = state
				.app_client
				.send(req_data)
				.map(|data| ProtocolMsg::ProxyResponse { data })
				.map_err(|e| ProtocolMsg::ProtocolErrorResponse(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn nsm_request(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::NsmRequest { nsm_request } = req {
			let nsm_response = {
				let fd = state.attestor.nsm_init();
				state.attestor.nsm_process_request(fd, nsm_request.clone())
			};
			let result = Ok(ProtocolMsg::NsmResponse { nsm_response });
			Some(result)
		} else {
			None
		}
	}

	pub(super) fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ProvisionRequest { share, approval } = req {
			let result = provision::provision(share, approval.clone(), state)
				.map(|reconstructed| ProtocolMsg::ProvisionResponse {
					reconstructed,
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	/// Handle `ProtocolMsg::BootStandardRequest`.
	pub(super) fn boot_standard(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::BootStandardRequest { manifest_envelope, pivot } =
			req
		{
			let result = boot::boot_standard(state, manifest_envelope, pivot)
				.map(|nsm_response| ProtocolMsg::BootStandardResponse {
					nsm_response,
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn boot_genesis(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::BootGenesisRequest { set, dr_key } = req {
			let result = genesis::boot_genesis(state, set, dr_key.clone())
				.map(|(genesis_output, nsm_response)| {
					ProtocolMsg::BootGenesisResponse {
						nsm_response,
						genesis_output: Box::new(genesis_output),
					}
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn live_attestation_doc(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::LiveAttestationDocRequest = req {
			let result = attestation::live_attestation_doc(state)
				.map(|nsm_response| ProtocolMsg::LiveAttestationDocResponse {
					nsm_response,
					manifest_envelope: state
						.handles
						.get_manifest_envelope()
						.ok()
						.map(Box::new),
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn boot_key_forward(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::BootKeyForwardRequest { manifest_envelope, pivot } =
			req
		{
			let result = key::boot_key_forward(state, manifest_envelope, pivot)
				.map(|nsm_response| ProtocolMsg::BootKeyForwardResponse {
					nsm_response,
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn export_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ExportKeyRequest {
			manifest_envelope,
			cose_sign1_attestation_doc,
		} = req
		{
			let result = key::export_key(
				state,
				manifest_envelope,
				cose_sign1_attestation_doc,
			)
			.map(|key| {
				let EncryptedQuorumKey { encrypted_quorum_key, signature } =
					key;
				ProtocolMsg::ExportKeyResponse {
					encrypted_quorum_key,
					signature,
				}
			})
			.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn inject_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::InjectKeyRequest {
			encrypted_quorum_key,
			signature,
		} = req
		{
			let result = key::inject_key(
				state,
				EncryptedQuorumKey {
					encrypted_quorum_key: encrypted_quorum_key.clone(),
					signature: signature.clone(),
				},
			)
			.map(|_| ProtocolMsg::InjectKeyResponse)
			.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}
}

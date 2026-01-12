//! Quorum protocol state machine
use prost::Message;
use qos_nsm::NsmProvider;

use super::{
	error::ProtocolError,
	msg::{protocol_msg, ProtocolMsg, ProtocolMsgExt},
	services::provision::SecretBuilder,
};
use crate::handles::Handles;

/// Enclave phase
#[derive(Debug, Copy, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
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
	ok_phase: ProtocolPhase, // the next phase if handler() == Ok
	err_phase: ProtocolPhase, // the next phase if handler() == Err
}

impl ProtocolRoute {
	pub fn try_msg(
		&self,
		msg: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		let resp = (self.handler)(msg, state);

		// ignore transitions in special cases
		if let Some(Ok(ref msg_resp)) = resp {
			if let Some(protocol_msg::Msg::ProvisionResponse(ref prov)) =
				msg_resp.msg
			{
				if !prov.reconstructed {
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
				return Some(Err(ProtocolMsg::error_response(e.into())));
			}
		};

		resp
	}

	pub fn status(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::status),
			current_phase,
			current_phase,
		)
	}

	pub fn manifest_envelope(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::manifest_envelope),
			current_phase,
			current_phase,
		)
	}

	pub fn live_attestation_doc(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::live_attestation_doc),
			current_phase,
			current_phase,
		)
	}

	pub fn boot_genesis(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_genesis),
			ProtocolPhase::GenesisBooted,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn boot_standard(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_standard),
			ProtocolPhase::WaitingForQuorumShards,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn boot_key_forward(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_key_forward),
			ProtocolPhase::WaitingForForwardedKey,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn provision(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::provision),
			ProtocolPhase::QuorumKeyProvisioned,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn export_key(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::export_key),
			current_phase,
			current_phase,
		)
	}

	pub fn inject_key(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::inject_key),
			ProtocolPhase::QuorumKeyProvisioned,
			ProtocolPhase::UnrecoverableError,
		)
	}

	fn new(
		handler: Box<ProtocolRouteHandler>,
		ok_phase: ProtocolPhase,
		err_phase: ProtocolPhase,
	) -> Self {
		ProtocolRoute { handler, ok_phase, err_phase }
	}
}

/// Enclave state
pub(crate) struct ProtocolState {
	pub provisioner: SecretBuilder,
	pub attestor: Box<dyn NsmProvider>,
	pub handles: Handles,
	phase: ProtocolPhase,
}

impl ProtocolState {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		#[allow(unused)] test_only_init_phase_override: Option<ProtocolPhase>,
	) -> Self {
		let provisioner = SecretBuilder::new();

		#[cfg(any(feature = "mock", test))]
		let init_phase = if let Some(phase) = test_only_init_phase_override {
			phase
		} else {
			ProtocolPhase::WaitingForBootInstruction
		};
		#[cfg(not(any(feature = "mock", test)))]
		let init_phase = ProtocolPhase::WaitingForBootInstruction;

		Self { attestor, provisioner, phase: init_phase, handles }
	}

	pub fn get_phase(&self) -> ProtocolPhase {
		self.phase
	}

	pub fn handle_msg(&mut self, msg_req: &ProtocolMsg) -> Vec<u8> {
		for route in &self.routes() {
			match route.try_msg(msg_req, self) {
				None => continue,
				Some(result) => match result {
					Ok(msg_resp) | Err(msg_resp) => {
						return msg_resp.encode_to_vec();
					}
				},
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.phase);
		ProtocolMsg::error_response(err.into()).encode_to_vec()
	}

	#[allow(clippy::too_many_lines)]
	fn routes(&self) -> Vec<ProtocolRoute> {
		#[allow(clippy::match_same_arms)]
		match self.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![
					ProtocolRoute::status(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
				]
			}
			ProtocolPhase::GenesisBooted => {
				vec![ProtocolRoute::status(self.phase)]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				// baseline routes
				ProtocolRoute::status(self.phase),
				ProtocolRoute::manifest_envelope(self.phase),
				// phase specific routes
				ProtocolRoute::boot_genesis(self.phase),
				ProtocolRoute::boot_standard(self.phase),
				ProtocolRoute::boot_key_forward(self.phase),
			],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::provision(self.phase),
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::export_key(self.phase),
				]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::inject_key(self.phase),
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
				ProtocolPhase::UnrecoverableError,
				ProtocolPhase::GenesisBooted,
				ProtocolPhase::WaitingForQuorumShards,
				ProtocolPhase::WaitingForForwardedKey,
			],
			ProtocolPhase::GenesisBooted => {
				vec![ProtocolPhase::UnrecoverableError]
			}
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					ProtocolPhase::UnrecoverableError,
					ProtocolPhase::QuorumKeyProvisioned,
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![ProtocolPhase::UnrecoverableError]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					ProtocolPhase::UnrecoverableError,
					ProtocolPhase::QuorumKeyProvisioned,
				]
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
		msg::{protocol_msg, ProtocolMsg, ProtocolMsgExt},
		services::{
			attestation, boot, boot::nsm_response_to_proto, genesis, key,
			key::EncryptedQuorumKey, provision,
		},
		ProtocolState,
	};

	/// Status of the enclave.
	pub(super) fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::StatusRequest(_)) = &req.msg {
			Some(Ok(ProtocolMsg::status_response(
				qos_proto::ProtocolPhase::from(state.get_phase()),
			)))
		} else {
			None
		}
	}

	pub(super) fn manifest_envelope(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::ManifestEnvelopeRequest(_)) = &req.msg {
			Some(Ok(ProtocolMsg::manifest_envelope_response(
				state.handles.get_manifest_envelope().ok(),
			)))
		} else {
			None
		}
	}

	pub(super) fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::ProvisionRequest(prov_req)) = &req.msg {
			let approval = match &prov_req.approval {
				Some(a) => a.clone(),
				None => {
					return Some(Err(ProtocolMsg::error_response(
						crate::protocol::ProtocolError::MissingApprovalMember.into(),
					)))
				}
			};
			let result = provision::provision(&prov_req.share, approval, state)
				.map(ProtocolMsg::provision_response)
				.map_err(|e| ProtocolMsg::error_response(e.into()));

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
		if let Some(protocol_msg::Msg::BootStandardRequest(boot_req)) = &req.msg {
			let envelope = match &boot_req.manifest_envelope {
				Some(e) => e,
				None => {
					return Some(Err(ProtocolMsg::error_response(
						crate::protocol::ProtocolError::MissingManifest.into(),
					)))
				}
			};
			let result = boot::boot_standard(state, envelope, &boot_req.pivot)
				.map(|nsm_response| {
					ProtocolMsg::boot_standard_response(
						nsm_response_to_proto(nsm_response),
					)
				})
				.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn boot_genesis(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::BootGenesisRequest(genesis_req)) = &req.msg
		{
			let set = match &genesis_req.set {
				Some(s) => s,
				None => {
					return Some(Err(ProtocolMsg::error_response(
						crate::protocol::ProtocolError::MissingShareSet.into(),
					)))
				}
			};
			let result =
				genesis::boot_genesis(state, set, genesis_req.dr_key.clone())
					.map(|(genesis_output, nsm_response)| {
						ProtocolMsg::boot_genesis_response(
							nsm_response_to_proto(nsm_response),
							genesis_output,
						)
					})
					.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn live_attestation_doc(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::LiveAttestationDocRequest(_)) = &req.msg {
			let result = attestation::live_attestation_doc(state)
				.map(|nsm_response| {
					ProtocolMsg::live_attestation_doc_response(
						nsm_response_to_proto(nsm_response),
						state.handles.get_manifest_envelope().ok(),
					)
				})
				.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn boot_key_forward(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::BootKeyForwardRequest(boot_req)) = &req.msg
		{
			let envelope = match &boot_req.manifest_envelope {
				Some(e) => e,
				None => {
					return Some(Err(ProtocolMsg::error_response(
						crate::protocol::ProtocolError::MissingManifest.into(),
					)))
				}
			};
			let result = key::boot_key_forward(state, envelope, &boot_req.pivot)
				.map(|nsm_response| {
					ProtocolMsg::boot_key_forward_response(
						nsm_response_to_proto(nsm_response),
					)
				})
				.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn export_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::ExportKeyRequest(export_req)) = &req.msg {
			let envelope = match &export_req.manifest_envelope {
				Some(e) => e,
				None => {
					return Some(Err(ProtocolMsg::error_response(
						crate::protocol::ProtocolError::MissingManifest.into(),
					)))
				}
			};
			let result = key::export_key(
				state,
				envelope,
				&export_req.cose_sign1_attestation_doc,
			)
			.map(|key| {
				let EncryptedQuorumKey { encrypted_quorum_key, signature } = key;
				ProtocolMsg::export_key_response(encrypted_quorum_key, signature)
			})
			.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn inject_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let Some(protocol_msg::Msg::InjectKeyRequest(inject_req)) = &req.msg {
			let result = key::inject_key(
				state,
				EncryptedQuorumKey {
					encrypted_quorum_key: inject_req.encrypted_quorum_key.clone(),
					signature: inject_req.signature.clone(),
				},
			)
			.map(|()| ProtocolMsg::inject_key_response())
			.map_err(|e| ProtocolMsg::error_response(e.into()));

			Some(result)
		} else {
			None
		}
	}
}

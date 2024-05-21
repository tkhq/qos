//! Quorum protocol state machine
use nix::sys::time::{TimeVal, TimeValLike};
use qos_nsm::NsmProvider;

#[cfg(feature = "remote_connection")]
use super::services::remote_connection::RemoteConnection;
use super::{
	error::ProtocolError, msg::ProtocolMsg, services::provision::SecretBuilder,
};
use crate::{client::Client, handles::Handles, io::SocketAddress};

/// The timeout for the qos core when making requests to an enclave app.
pub const ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS: i64 = 5;

/// Enclave phase
#[derive(
	Debug,
	Copy,
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
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
		if let Some(Ok(ProtocolMsg::ProvisionResponse { reconstructed })) = resp
		{
			if !reconstructed {
				return resp;
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

	pub fn proxy(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::proxy),
			current_phase,
			current_phase,
		)
	}

	#[cfg(feature = "remote_connection")]
	pub fn remote_open(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::remote_open),
			current_phase,
			current_phase,
		)
	}

	#[cfg(feature = "remote_connection")]
	pub fn remote_read(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::remote_read),
			current_phase,
			current_phase,
		)
	}

	#[cfg(feature = "remote_connection")]
	pub fn remote_write(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::remote_write),
			current_phase,
			current_phase,
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
	pub app_client: Client,
	pub handles: Handles,
	#[cfg(feature = "remote_connection")]
	pub remote_connections: Vec<RemoteConnection>,
	phase: ProtocolPhase,
}

impl ProtocolState {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		app_addr: SocketAddress,
		test_only_init_phase_override: Option<ProtocolPhase>,
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

		Self {
			attestor,
			provisioner,
			phase: init_phase,
			handles,
			app_client: Client::new(
				app_addr,
				TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
			),
			#[cfg(feature = "remote_connection")]
			remote_connections: vec![],
		}
	}

	pub fn get_phase(&self) -> ProtocolPhase {
		self.phase
	}

	#[cfg(feature = "remote_connection")]
	pub fn save_remote_connection(
		&mut self,
		connection: RemoteConnection,
	) -> Result<(), ProtocolError> {
		if self.remote_connections.iter().any(|c| c.id == connection.id) {
			Err(ProtocolError::DuplicateConnectionId(connection.id))
		} else {
			self.remote_connections.push(connection);
			Ok(())
		}
	}

	#[cfg(feature = "remote_connection")]
	pub fn get_remote_connection(
		&mut self,
		id: u32,
	) -> Option<&mut RemoteConnection> {
		self.remote_connections.iter_mut().find(|c| c.id == id)
	}

	pub fn handle_msg(&mut self, msg_req: &ProtocolMsg) -> Vec<u8> {
		for route in &self.routes() {
			match route.try_msg(msg_req, self) {
				None => continue,
				Some(result) => match result {
					Ok(msg_resp) | Err(msg_resp) => {
						return borsh::to_vec(&msg_resp).expect(
							"ProtocolMsg can always be serialized. qed.",
						)
					}
				},
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.phase);
		borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(err))
			.expect("ProtocolMsg can always be serialized. qed.")
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
					ProtocolRoute::proxy(self.phase),
					ProtocolRoute::export_key(self.phase),
					#[cfg(feature = "remote_connection")]
					ProtocolRoute::remote_open(self.phase),
					#[cfg(feature = "remote_connection")]
					ProtocolRoute::remote_read(self.phase),
					#[cfg(feature = "remote_connection")]
					ProtocolRoute::remote_write(self.phase),
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
	#[cfg(feature = "remote_connection")]
	use crate::protocol::services::remote_connection;
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

	pub(super) fn manifest_envelope(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ManifestEnvelopeRequest = req {
			Some(Ok(ProtocolMsg::ManifestEnvelopeResponse {
				manifest_envelope: Box::new(
					state.handles.get_manifest_envelope().ok(),
				),
			}))
		} else {
			None
		}
	}

	#[cfg(feature = "remote_connection")]
	pub(super) fn remote_open(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::RemoteOpenRequest {
			hostname,
			port,
			dns_resolvers,
			dns_port,
		} = req
		{
			match remote_connection::RemoteConnection::new(
				hostname.clone(),
				*port,
				dns_resolvers.clone(),
				*dns_port,
			) {
				Ok(remote_connection) => {
					let connection_id = remote_connection.id;
					match state.save_remote_connection(remote_connection) {
						Ok(()) => Some(Ok(ProtocolMsg::RemoteOpenResponse {
							connection_id,
						})),
						Err(e) => {
							Some(Err(ProtocolMsg::ProtocolErrorResponse(e)))
						}
					}
				}
				Err(e) => Some(Err(ProtocolMsg::ProtocolErrorResponse(e))),
			}
		} else {
			None
		}
	}

	#[cfg(feature = "remote_connection")]
	pub(super) fn remote_read(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		use std::io::Read;

		use crate::protocol::ProtocolError;

		if let ProtocolMsg::RemoteReadRequest { connection_id, size } = req {
			if let Some(connection) =
				state.get_remote_connection(*connection_id)
			{
				let mut buf: Vec<u8> = vec![0; *size];
				match connection.tcp_stream.read(&mut buf) {
					Ok(size) => {
						if size == 0 {
							Some(Err(ProtocolMsg::ProtocolErrorResponse(
								ProtocolError::RemoteConnectionClosed,
							)))
						} else {
							Some(Ok(ProtocolMsg::RemoteReadResponse {
								connection_id: *connection_id,
								data: buf,
							}))
						}
					}
					Err(e) => {
						Some(Err(ProtocolMsg::ProtocolErrorResponse(e.into())))
					}
				}
			} else {
				Some(Err(ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::RemoteConnectionIdNotFound(*connection_id),
				)))
			}
		} else {
			None
		}
	}

	#[cfg(feature = "remote_connection")]
	pub(super) fn remote_write(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		use std::io::Write;

		use crate::protocol::ProtocolError;

		if let ProtocolMsg::RemoteWriteRequest { connection_id, data } = req {
			if let Some(connection) =
				state.get_remote_connection(*connection_id)
			{
				match connection.tcp_stream.write(data) {
					Ok(size) => Some(Ok(ProtocolMsg::RemoteWriteResponse {
						connection_id: *connection_id,
						size,
					})),
					Err(e) => {
						Some(Err(ProtocolMsg::ProtocolErrorResponse(e.into())))
					}
				}
			} else {
				Some(Err(ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::RemoteConnectionIdNotFound(*connection_id),
				)))
			}
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
			.map(|()| ProtocolMsg::InjectKeyResponse)
			.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}
}

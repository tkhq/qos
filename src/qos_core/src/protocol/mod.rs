//! Quorum protocol state machine.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_crypto::sha_256;
use qos_nsm::NsmProvider;

use crate::{
	client::{self, Client},
	io::SocketAddress,
	server,
};

pub mod msg;
pub mod services;

use msg::ProtocolMsg;
use services::boot;

use crate::handles::Handles;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 128 * MEGABYTE;

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
#[derive(
	Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum ProtocolError {
	/// TODO
	InvalidShare,
	/// Failed to reconstruct the quorum key while provisioning.
	ReconstructionErrorEmptySecret,
	/// Reconstructed the incorrect key while provisioning.
	ReconstructionErrorIncorrectPubKey,
	/// Filesystem error
	IOError,
	/// Cryptography error
	/// Approval was not valid for a manifest.
	InvalidManifestApproval(boot::Approval),
	/// [`services::boot::ManifestEnvelope`] did not have approvals
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
	/// Got a path to a key that is used for testing. This error only occurs
	/// when the "mock" feature is disabled, which should always be the
	/// case in production.
	BadEphemeralKeyPath,
	/// Tried to modify state that must be static post pivoting.
	CannotModifyPostPivotStatic,
	/// For some reason the Ephemeral could not be read from the file
	/// system.
	FailedToGetEphemeralKey,
	/// Failed to write the Ephemeral key to the file system.
	FailedToPutEphemeralKey,
	/// For some reason the Quorum Key could not be read from the file
	/// system.
	FailedToGetQuorumKey,
	/// Failed to put the quorum key into the file system
	FailedToPutQuorumKey,
	/// For some reason the manifest envelope could not be read from the file
	/// system or decoded.
	FailedToGetManifestEnvelope,
	/// Failed to put the manifest envelope.
	FailedToPutManifestEnvelope,
	/// Failed to put the pivot executable.
	FailedToPutPivot,
	/// An error occurred with the app client.
	AppClientError,
	/// Payload is too big. See `MAX_ENCODED_MSG_LEN` for the upper bound on
	/// message size.
	OversizedPayload,
	/// A protocol message could not be deserialized.
	ProtocolMsgDeserialization,
	/// Share set approvals existed in the manifest envelope when they should
	/// not have.
	BadShareSetApprovals,
	/// Could not verify a message against an approval
	CouldNotVerifyApproval,
	/// Not a member of the [`ShareSet`].
	NotShareSetMember,
	/// Not a member of the [`ManifestSet`].
	NotManifestSetMember,
	/// `qos_p256` Error wrapper.
	P256Error(qos_p256::P256Error),
	/// Error with trying to read p256 DR public key.
	InvalidP256DRKey(qos_p256::P256Error),
	/// The provisioned secret is the incorrect length.
	IncorrectSecretLen,
	/// An error from the attest crate.
	QosAttestError(String),
	/// Quorum Key in the new manifest does not match the quorum key in the old
	/// manifest.
	DifferentQuorumKey,
	/// The manifest sets do not match.
	DifferentManifestSet,
	/// The manifests do not have the same namespace names.
	DifferentNamespaceName,
	/// The manifest has a lower nonce then the current manifest
	LowNonce,
	/// The manifests have different PCR0 values
	DifferentPcr0,
	/// The manifests have different PCR1 values
	DifferentPcr1,
	/// The manifests have different PCR2 values
	DifferentPcr2,
	/// The manifests have different PCR2 values
	DifferentPcr3,
	/// Attestation document is missing ephemeral key.
	MissingEphemeralKey,
	/// Ephemeral key cannot be decoded.
	InvalidEphemeralKey,
	/// Invalid signature over the encrypted quorum key.
	InvalidEncryptedQuorumKeySignature,
	/// Invalid length for encrypted quorum key secret.
	EncryptedQuorumKeyInvalidLen,
	/// The quorum secret was invalid.
	InvalidQuorumSecret,
	/// The injected quorum key was not the expected key.
	WrongQuorumKey,
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<client::ClientError> for ProtocolError {
	fn from(_: client::ClientError) -> Self {
		Self::AppClientError
	}
}

impl From<qos_p256::P256Error> for ProtocolError {
	fn from(err: qos_p256::P256Error) -> Self {
		Self::P256Error(err)
	}
}

impl From<qos_attest::AttestError> for ProtocolError {
	fn from(err: qos_attest::AttestError) -> Self {
		let msg = format!("{err:?}");
		Self::QosAttestError(msg)
	}
}

/// Protocol executor state.
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

/// Enclave executor state
// TODO only include mutables in here, all else should be written to file as
// read only
pub struct ProtocolState {
	provisioner: services::provision::SecretBuilder,
	attestor: Box<dyn NsmProvider>,
	phase: ProtocolPhase,
	handles: Handles,
	app_client: Client,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		app_addr: SocketAddress,
	) -> Self {
		let provisioner = services::provision::SecretBuilder::new();
		Self {
			attestor,
			provisioner,
			phase: ProtocolPhase::WaitingForBootInstruction,
			handles,
			app_client: Client::new(app_addr),
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
		handles: Handles,
		app_addr: SocketAddress,
	) -> Self {
		Self { state: ProtocolState::new(attestor, handles, app_addr) }
	}

	fn routes(&self) -> Vec<Box<ProtocolHandler>> {
		match self.state.phase {
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

impl server::RequestProcessor for Executor {
	fn process(&mut self, req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::OversizedPayload,
			)
			.try_to_vec()
			.expect("ProtocolMsg can always be serialized. qed.");
		}

		let msg_req = match ProtocolMsg::try_from_slice(&req_bytes) {
			Ok(req) => req,
			Err(_) => {
				return ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::ProtocolMsgDeserialization,
				)
				.try_to_vec()
				.expect("ProtocolMsg can always be serialized. qed.")
			}
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
	use super::services::{attestation, key::EncryptedQuorumKey};
	use crate::protocol::{
		msg::ProtocolMsg,
		services::{boot, genesis, key, provision},
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

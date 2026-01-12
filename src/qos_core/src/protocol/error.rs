//! Quorum protocol error
use qos_p256::P256Error;
use qos_proto::Approval;

use crate::{
	client::ClientError,
	io::IOError,
	protocol::ProtocolPhase,
};

/// An error from protocol execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
	/// A encrypted quorum key share sent to the enclave was invalid.
	InvalidShare,
	/// Failed to reconstruct the quorum key while provisioning.
	ReconstructionErrorEmptySecret,
	/// Reconstructed the incorrect key while provisioning.
	ReconstructionErrorIncorrectPubKey,
	/// Filesystem error
	IOError,
	/// Approval was not valid for a manifest.
	InvalidManifestApproval(Approval),
	/// Manifest envelope is missing the manifest field.
	MissingManifest,
	/// Manifest is missing the manifest_set field.
	MissingManifestSet,
	/// Manifest is missing the pivot field.
	MissingPivotConfig,
	/// Approval is missing the member field.
	MissingApprovalMember,
	/// Manifest is missing the namespace field.
	MissingNamespace,
	/// Manifest is missing the enclave field.
	MissingEnclaveConfig,
	/// Manifest is missing the share_set field.
	MissingShareSet,
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
	/// Got a path to a key that is used for testing. This error only occurs
	/// when the "mock" feature is disabled, which should always be the
	/// case in production.
	BadEphemeralKeyPath,
	/// Tried to modify state that must be static post pivoting.
	CannotModifyPostPivotStatic,
	/// For some reason the Ephemeral could not be read from the file
	/// system.
	FailedToGetEphemeralKey(P256Error),
	/// Failed to write the Ephemeral key to the file system.
	FailedToPutEphemeralKey,
	/// Failed to rotate the ephemeral key because the underlying file is missing.
	CannotRotateNonExistentEphemeralKey,
	/// Failed to delete the old ephemeral key (underlying failure in argument)
	CannotDeleteEphemeralKey(String),
	/// For some reason the Quorum Key could not be read from the file
	/// system.
	FailedToGetQuorumKey(P256Error),
	/// Failed to put the quorum key into the file system
	FailedToPutQuorumKey,
	/// For some reason the manifest envelope could not be read from the file
	/// system or decoded.
	FailedToGetManifestEnvelope,
	/// Failed to put the manifest envelope.
	FailedToPutManifestEnvelope,
	/// Failed to put the pivot executable.
	FailedToPutPivot,
	/// The socket client timed out while waiting to receive a response from
	/// the enclave app.
	AppClientRecvTimeout,
	/// The socket client was interrupted while trying to receive a response
	/// from the enclave app.
	AppClientRecvInterrupted,
	/// The socket client tried to call receive on a closed connection. Likely
	/// the enclave app panicked and closed the connection.
	AppClientRecvConnectionClosed,
	/// App client could not make a connection to a socket when trying to send.
	/// Likely the enclave app panic'ed and the apps server did not create the
	/// socket again.
	AppClientConnectError(String),
	/// App client encountered an error when calling the `send` system call.
	AppClientSendError(String),
	/// The socket client encountered an error when trying to execute a request
	/// to the enclave app.
	AppClientError(String),
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
	/// Not a member of the [`boot::ShareSet`].
	NotShareSetMember,
	/// Not a member of the [`boot::ManifestSet`].
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
	/// State machine transitioned unexpectedly
	InvalidStateTransition(ProtocolPhase, ProtocolPhase),
	/// The manifest envelope has duplicate approvals.
	DuplicateApproval,
	/// The new manifest was different from the old manifest when we expected
	/// them to be the same because they have the same nonce
	DifferentManifest,
	/// Error from the qos crypto library.
	QosCrypto(String),
	/// Error during expanding the `StreamPool`.
	PoolExpandError,
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<ClientError> for ProtocolError {
	fn from(err: ClientError) -> Self {
		match err {
			ClientError::IOError(IOError::RecvTimeout) => {
				ProtocolError::AppClientRecvTimeout
			}
			ClientError::IOError(IOError::RecvInterrupted) => {
				ProtocolError::AppClientRecvInterrupted
			}
			ClientError::IOError(IOError::RecvConnectionClosed) => {
				ProtocolError::AppClientRecvConnectionClosed
			}
			ClientError::IOError(IOError::ConnectNixError(e)) => {
				ProtocolError::AppClientConnectError(format!("{e:?}"))
			}
			ClientError::IOError(IOError::SendNixError(e)) => {
				ProtocolError::AppClientSendError(format!("{e:?}"))
			}
			e => ProtocolError::AppClientError(format!("{e:?}")),
		}
	}
}

impl From<qos_p256::P256Error> for ProtocolError {
	fn from(err: qos_p256::P256Error) -> Self {
		Self::P256Error(err)
	}
}

impl From<qos_nsm::nitro::AttestError> for ProtocolError {
	fn from(err: qos_nsm::nitro::AttestError) -> Self {
		let msg = format!("{err:?}");
		Self::QosAttestError(msg)
	}
}

impl From<ProtocolError> for qos_proto::ProtocolError {
	fn from(err: ProtocolError) -> Self {
		use qos_proto::ProtocolErrorCode;

		let (code, message, invalid_approval, p256_error, phase, expected_phase) =
			match err {
				ProtocolError::InvalidShare => {
					(ProtocolErrorCode::InvalidShare, None, None, None, None, None)
				}
				ProtocolError::ReconstructionErrorEmptySecret => (
					ProtocolErrorCode::ReconstructionErrorEmptySecret,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::ReconstructionErrorIncorrectPubKey => (
					ProtocolErrorCode::ReconstructionErrorIncorrectPubKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::IOError => {
					(ProtocolErrorCode::IoError, None, None, None, None, None)
				}
				ProtocolError::InvalidManifestApproval(approval) => (
					ProtocolErrorCode::InvalidManifestApproval,
					None,
					Some(approval),
					None,
					None,
					None,
				),
				ProtocolError::MissingManifest => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing manifest".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingManifestSet => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing manifest set".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingPivotConfig => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing pivot config".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingApprovalMember => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing approval member".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingNamespace => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing namespace".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingEnclaveConfig => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing enclave config".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingShareSet => (
					ProtocolErrorCode::InvalidMsg,
					Some("missing share set".to_string()),
					None,
					None,
					None,
					None,
				),
				ProtocolError::NotEnoughApprovals => (
					ProtocolErrorCode::NotEnoughApprovals,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::NoMatchingRoute(phase) => (
					ProtocolErrorCode::NoMatchingRoute,
					None,
					None,
					None,
					Some(ProtocolPhase::from(phase) as i32),
					None,
				),
				ProtocolError::InvalidPivotHash => (
					ProtocolErrorCode::InvalidPivotHash,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::OversizeMsg => {
					(ProtocolErrorCode::OversizeMsg, None, None, None, None, None)
				}
				ProtocolError::InvalidMsg => {
					(ProtocolErrorCode::InvalidMsg, None, None, None, None, None)
				}
				ProtocolError::EnclaveClient => (
					ProtocolErrorCode::EnclaveClient,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DecryptionFailed => (
					ProtocolErrorCode::DecryptionFailed,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::InvalidPrivateKey => (
					ProtocolErrorCode::InvalidPrivateKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToParseFromString => (
					ProtocolErrorCode::FailedToParseFromString,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::BadEphemeralKeyPath => (
					ProtocolErrorCode::BadEphemeralKeyPath,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::CannotModifyPostPivotStatic => (
					ProtocolErrorCode::CannotModifyPostPivotStatic,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToGetEphemeralKey(e) => (
					ProtocolErrorCode::FailedToGetEphemeralKey,
					None,
					None,
					Some(format!("{e:?}")),
					None,
					None,
				),
				ProtocolError::FailedToPutEphemeralKey => (
					ProtocolErrorCode::FailedToPutEphemeralKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::CannotRotateNonExistentEphemeralKey => (
					ProtocolErrorCode::CannotRotateNonExistentEphemeralKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::CannotDeleteEphemeralKey(msg) => (
					ProtocolErrorCode::CannotDeleteEphemeralKey,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToGetQuorumKey(e) => (
					ProtocolErrorCode::FailedToGetQuorumKey,
					None,
					None,
					Some(format!("{e:?}")),
					None,
					None,
				),
				ProtocolError::FailedToPutQuorumKey => (
					ProtocolErrorCode::FailedToPutQuorumKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToGetManifestEnvelope => (
					ProtocolErrorCode::FailedToGetManifestEnvelope,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToPutManifestEnvelope => (
					ProtocolErrorCode::FailedToPutManifestEnvelope,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::FailedToPutPivot => (
					ProtocolErrorCode::FailedToPutPivot,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientRecvTimeout => (
					ProtocolErrorCode::AppClientRecvTimeout,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientRecvInterrupted => (
					ProtocolErrorCode::AppClientRecvInterrupted,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientRecvConnectionClosed => (
					ProtocolErrorCode::AppClientRecvConnectionClosed,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientConnectError(msg) => (
					ProtocolErrorCode::AppClientConnectError,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientSendError(msg) => (
					ProtocolErrorCode::AppClientSendError,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::AppClientError(msg) => (
					ProtocolErrorCode::AppClientError,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::OversizedPayload => (
					ProtocolErrorCode::OversizedPayload,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::ProtocolMsgDeserialization => (
					ProtocolErrorCode::ProtocolMsgDeserialization,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::BadShareSetApprovals => (
					ProtocolErrorCode::BadShareSetApprovals,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::CouldNotVerifyApproval => (
					ProtocolErrorCode::CouldNotVerifyApproval,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::NotShareSetMember => (
					ProtocolErrorCode::NotShareSetMember,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::NotManifestSetMember => (
					ProtocolErrorCode::NotManifestSetMember,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::P256Error(e) => (
					ProtocolErrorCode::P256Error,
					None,
					None,
					Some(format!("{e:?}")),
					None,
					None,
				),
				ProtocolError::InvalidP256DRKey(e) => (
					ProtocolErrorCode::InvalidP256DrKey,
					None,
					None,
					Some(format!("{e:?}")),
					None,
					None,
				),
				ProtocolError::IncorrectSecretLen => (
					ProtocolErrorCode::IncorrectSecretLen,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::QosAttestError(msg) => (
					ProtocolErrorCode::QosAttestError,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentQuorumKey => (
					ProtocolErrorCode::DifferentQuorumKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentManifestSet => (
					ProtocolErrorCode::DifferentManifestSet,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentNamespaceName => (
					ProtocolErrorCode::DifferentNamespaceName,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::LowNonce => {
					(ProtocolErrorCode::LowNonce, None, None, None, None, None)
				}
				ProtocolError::DifferentPcr0 => (
					ProtocolErrorCode::DifferentPcr0,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentPcr1 => (
					ProtocolErrorCode::DifferentPcr1,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentPcr2 => (
					ProtocolErrorCode::DifferentPcr2,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentPcr3 => (
					ProtocolErrorCode::DifferentPcr3,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::MissingEphemeralKey => (
					ProtocolErrorCode::MissingEphemeralKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::InvalidEphemeralKey => (
					ProtocolErrorCode::InvalidEphemeralKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::InvalidEncryptedQuorumKeySignature => (
					ProtocolErrorCode::InvalidEncryptedQuorumKeySignature,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::EncryptedQuorumKeyInvalidLen => (
					ProtocolErrorCode::EncryptedQuorumKeyInvalidLen,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::InvalidQuorumSecret => (
					ProtocolErrorCode::InvalidQuorumSecret,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::WrongQuorumKey => (
					ProtocolErrorCode::WrongQuorumKey,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::InvalidStateTransition(from, to) => (
					ProtocolErrorCode::InvalidStateTransition,
					None,
					None,
					None,
					Some(ProtocolPhase::from(from) as i32),
					Some(ProtocolPhase::from(to) as i32),
				),
				ProtocolError::DuplicateApproval => (
					ProtocolErrorCode::DuplicateApproval,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::DifferentManifest => (
					ProtocolErrorCode::DifferentManifest,
					None,
					None,
					None,
					None,
					None,
				),
				ProtocolError::QosCrypto(msg) => (
					ProtocolErrorCode::QosCrypto,
					Some(msg),
					None,
					None,
					None,
					None,
				),
				ProtocolError::PoolExpandError => (
					ProtocolErrorCode::PoolExpandError,
					None,
					None,
					None,
					None,
					None,
				),
			};

		qos_proto::ProtocolError {
			code: code as i32,
			message,
			invalid_approval,
			p256_error,
			phase,
			expected_phase,
		}
	}
}

impl From<ProtocolPhase> for qos_proto::ProtocolPhase {
	fn from(phase: ProtocolPhase) -> Self {
		match phase {
			ProtocolPhase::UnrecoverableError => {
				qos_proto::ProtocolPhase::UnrecoverableError
			}
			ProtocolPhase::WaitingForBootInstruction => {
				qos_proto::ProtocolPhase::WaitingForBootInstruction
			}
			ProtocolPhase::GenesisBooted => qos_proto::ProtocolPhase::GenesisBooted,
			ProtocolPhase::WaitingForQuorumShards => {
				qos_proto::ProtocolPhase::WaitingForQuorumShards
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				qos_proto::ProtocolPhase::QuorumKeyProvisioned
			}
			ProtocolPhase::WaitingForForwardedKey => {
				qos_proto::ProtocolPhase::WaitingForForwardedKey
			}
		}
	}
}

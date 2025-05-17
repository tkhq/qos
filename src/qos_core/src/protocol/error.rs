//! Quorum protocol error
use borsh::{BorshDeserialize, BorshSerialize};
use qos_p256::P256Error;

use crate::{
	client::{self, ClientError},
	io::IOError,
	protocol::{services::boot, ProtocolPhase},
};

/// A error from protocol execution.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProtocolError {
	/// A encrypted quorum key share sent to the enclave was invalid.
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
	/// [`boot::ManifestEnvelope`] did not have approvals
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
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<client::ClientError> for ProtocolError {
	fn from(err: client::ClientError) -> Self {
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

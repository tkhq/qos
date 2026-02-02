//! Quorum protocol error
use borsh::{BorshDeserialize, BorshSerialize};
use qos_p256::P256Error;

use crate::{
	client::ClientError,
	io::IOError,
	protocol::{services::boot, ProtocolPhase},
};

/// A error from protocol execution.
#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	BorshSerialize,
	BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
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
	/// manifest. Contains (expected, actual) as hex strings.
	InvalidPivotHash { expected: String, actual: String },
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
	/// manifest. Contains (expected, actual) as hex strings.
	DifferentQuorumKey { expected: String, actual: String },
	/// The manifest sets do not match.
	/// Contains (expected_hash, actual_hash) as hex strings.
	DifferentManifestSet { expected: String, actual: String },
	/// The manifests do not have the same namespace names.
	/// Contains (expected, actual) namespace names.
	DifferentNamespaceName { expected: String, actual: String },
	/// The manifest has a lower nonce then the current manifest.
	/// Contains (expected_min, actual) nonce values.
	LowNonce { expected: u32, actual: u32 },
	/// The manifests have different PCR3 values.
	/// Contains (expected, actual) as hex strings.
	DifferentPcr3 { expected: String, actual: String },
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
	/// them to be the same because they have the same nonce.
	/// Contains (expected_hash, actual_hash) as hex strings.
	DifferentManifest { expected: String, actual: String },
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

impl std::fmt::Display for ProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidShare => write!(f, "invalid quorum key share"),
			Self::ReconstructionErrorEmptySecret => {
				write!(f, "failed to reconstruct quorum key: empty secret")
			}
			Self::ReconstructionErrorIncorrectPubKey => {
				write!(f, "reconstructed incorrect public key")
			}
			Self::IOError => write!(f, "filesystem error"),
			Self::InvalidManifestApproval(approval) => {
				write!(
					f,
					"invalid manifest approval from member '{}'",
					approval.member.alias
				)
			}
			Self::NotEnoughApprovals => write!(f, "not enough approvals"),
			Self::NoMatchingRoute(phase) => {
				write!(f, "no matching route for phase {phase:?}")
			}
			Self::InvalidPivotHash { expected, actual } => {
				write!(
					f,
					"invalid pivot hash: expected {expected}, got {actual}"
				)
			}
			Self::OversizeMsg => write!(f, "message too large"),
			Self::InvalidMsg => write!(f, "invalid message"),
			Self::EnclaveClient => write!(f, "enclave client error"),
			Self::DecryptionFailed => write!(f, "decryption failed"),
			Self::InvalidPrivateKey => write!(f, "invalid private key"),
			Self::FailedToParseFromString => {
				write!(f, "failed to parse from string")
			}
			Self::BadEphemeralKeyPath => write!(f, "bad ephemeral key path"),
			Self::CannotModifyPostPivotStatic => {
				write!(f, "cannot modify state after pivot")
			}
			Self::FailedToGetEphemeralKey(e) => {
				write!(f, "failed to get ephemeral key: {e:?}")
			}
			Self::FailedToPutEphemeralKey => {
				write!(f, "failed to put ephemeral key")
			}
			Self::CannotRotateNonExistentEphemeralKey => {
				write!(f, "cannot rotate non-existent ephemeral key")
			}
			Self::CannotDeleteEphemeralKey(e) => {
				write!(f, "cannot delete ephemeral key: {e}")
			}
			Self::FailedToGetQuorumKey(e) => {
				write!(f, "failed to get quorum key: {e:?}")
			}
			Self::FailedToPutQuorumKey => write!(f, "failed to put quorum key"),
			Self::FailedToGetManifestEnvelope => {
				write!(f, "failed to get manifest envelope")
			}
			Self::FailedToPutManifestEnvelope => {
				write!(f, "failed to put manifest envelope")
			}
			Self::FailedToPutPivot => write!(f, "failed to put pivot"),
			Self::AppClientRecvTimeout => {
				write!(f, "app client receive timeout")
			}
			Self::AppClientRecvInterrupted => {
				write!(f, "app client receive interrupted")
			}
			Self::AppClientRecvConnectionClosed => {
				write!(f, "app client connection closed")
			}
			Self::AppClientConnectError(e) => {
				write!(f, "app client connect error: {e}")
			}
			Self::AppClientSendError(e) => {
				write!(f, "app client send error: {e}")
			}
			Self::AppClientError(e) => write!(f, "app client error: {e}"),
			Self::OversizedPayload => write!(f, "oversized payload"),
			Self::ProtocolMsgDeserialization => {
				write!(f, "protocol message deserialization failed")
			}
			Self::BadShareSetApprovals => {
				write!(f, "unexpected share set approvals")
			}
			Self::CouldNotVerifyApproval => {
				write!(f, "could not verify approval")
			}
			Self::NotShareSetMember => write!(f, "not a share set member"),
			Self::NotManifestSetMember => {
				write!(f, "not a manifest set member")
			}
			Self::P256Error(e) => write!(f, "P256 error: {e:?}"),
			Self::InvalidP256DRKey(e) => {
				write!(f, "invalid P256 DR key: {e:?}")
			}
			Self::IncorrectSecretLen => write!(f, "incorrect secret length"),
			Self::QosAttestError(e) => write!(f, "attestation error: {e}"),
			Self::DifferentQuorumKey { expected, actual } => {
				write!(
					f,
					"different quorum key: expected {expected}, got {actual}"
				)
			}
			Self::DifferentManifestSet { expected, actual } => {
				write!(
					f,
					"different manifest set: expected {expected}, got {actual}"
				)
			}
			Self::DifferentNamespaceName { expected, actual } => {
				write!(
					f,
					"different namespace name: expected '{expected}', got '{actual}'"
				)
			}
			Self::LowNonce { expected, actual } => {
				write!(f, "manifest nonce too low: expected >= {expected}, got {actual}")
			}
			Self::DifferentPcr3 { expected, actual } => {
				write!(f, "different PCR3: expected {expected}, got {actual}")
			}
			Self::MissingEphemeralKey => write!(f, "missing ephemeral key"),
			Self::InvalidEphemeralKey => write!(f, "invalid ephemeral key"),
			Self::InvalidEncryptedQuorumKeySignature => {
				write!(f, "invalid encrypted quorum key signature")
			}
			Self::EncryptedQuorumKeyInvalidLen => {
				write!(f, "encrypted quorum key has invalid length")
			}
			Self::InvalidQuorumSecret => write!(f, "invalid quorum secret"),
			Self::WrongQuorumKey => write!(f, "wrong quorum key"),
			Self::InvalidStateTransition(from, to) => {
				write!(f, "invalid state transition from {from:?} to {to:?}")
			}
			Self::DuplicateApproval => write!(f, "duplicate approval"),
			Self::DifferentManifest { expected, actual } => {
				write!(
					f,
					"different manifest: expected {expected}, got {actual}"
				)
			}
			Self::QosCrypto(e) => write!(f, "crypto error: {e}"),
			Self::PoolExpandError => write!(f, "pool expand error"),
		}
	}
}

impl std::error::Error for ProtocolError {}

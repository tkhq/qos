//! Protobuf types for the protocol.
//!
//! This module re-exports types from `qos_proto` and provides conversions
//! between legacy borsh types and proto types.

pub use qos_proto::{
	// Manifest types
	Approval, Manifest, ManifestEnvelope, ManifestSet, MemberPubKey, Namespace,
	NitroConfig, PatchSet, PivotConfig, QuorumMember, RestartPolicy, ShareSet,
	// Genesis types
	GenesisMemberOutput, GenesisOutput, GenesisSet, MemberShard,
	RecoveredPermutation,
	// Protocol message types
	BootGenesisRequest, BootGenesisResponse, BootKeyForwardRequest,
	BootKeyForwardResponse, BootStandardRequest, BootStandardResponse,
	ExportKeyRequest, ExportKeyResponse, InjectKeyRequest, InjectKeyResponse,
	LiveAttestationDocRequest, LiveAttestationDocResponse,
	ManifestEnvelopeRequest, ManifestEnvelopeResponse, ProtocolError,
	ProtocolErrorCode, ProtocolMsg, ProtocolPhase, ProvisionRequest,
	ProvisionResponse, ProxyRequest, ProxyResponse, StatusRequest,
	StatusResponse,
	// NSM types
	AttestationRequest, AttestationResponse, DescribeNsmRequest,
	DescribeNsmResponse, DescribePcrRequest, DescribePcrResponse,
	ExtendPcrRequest, ExtendPcrResponse, GetRandomRequest, GetRandomResponse,
	LockPcrRequest, LockPcrResponse, LockPcrsRequest, LockPcrsResponse,
	NsmDigest, NsmErrorCode, NsmErrorResponse, NsmRequest, NsmResponse,
	// Hashing
	Hash256, ProtoHash,
};

use super::legacy;

// ============================================================================
// Conversions: Legacy -> Proto
// ============================================================================

impl From<&legacy::NitroConfig> for NitroConfig {
	fn from(v: &legacy::NitroConfig) -> Self {
		Self {
			pcr0: v.pcr0.clone(),
			pcr1: v.pcr1.clone(),
			pcr2: v.pcr2.clone(),
			pcr3: v.pcr3.clone(),
			aws_root_certificate: v.aws_root_certificate.clone(),
			qos_commit: v.qos_commit.clone(),
		}
	}
}

impl From<&legacy::RestartPolicy> for RestartPolicy {
	fn from(v: &legacy::RestartPolicy) -> Self {
		match v {
			legacy::RestartPolicy::Never => Self::Never,
			legacy::RestartPolicy::Always => Self::Always,
		}
	}
}

impl From<&legacy::PivotConfig> for PivotConfig {
	fn from(v: &legacy::PivotConfig) -> Self {
		Self {
			hash: v.hash.to_vec(),
			restart: RestartPolicy::from(&v.restart) as i32,
			args: v.args.clone(),
		}
	}
}

impl From<&legacy::QuorumMember> for QuorumMember {
	fn from(v: &legacy::QuorumMember) -> Self {
		Self { alias: v.alias.clone(), pub_key: v.pub_key.clone() }
	}
}

impl From<&legacy::MemberPubKey> for MemberPubKey {
	fn from(v: &legacy::MemberPubKey) -> Self {
		Self { pub_key: v.pub_key.clone() }
	}
}

impl From<&legacy::ManifestSet> for ManifestSet {
	fn from(v: &legacy::ManifestSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(QuorumMember::from).collect(),
		}
	}
}

impl From<&legacy::ShareSet> for ShareSet {
	fn from(v: &legacy::ShareSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(QuorumMember::from).collect(),
		}
	}
}

impl From<&legacy::PatchSet> for PatchSet {
	fn from(v: &legacy::PatchSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(MemberPubKey::from).collect(),
		}
	}
}

impl From<&legacy::Namespace> for Namespace {
	fn from(v: &legacy::Namespace) -> Self {
		Self {
			name: v.name.clone(),
			nonce: v.nonce,
			quorum_key: v.quorum_key.clone(),
		}
	}
}

impl From<&legacy::Manifest> for Manifest {
	fn from(v: &legacy::Manifest) -> Self {
		Self {
			namespace: Some(Namespace::from(&v.namespace)),
			pivot: Some(PivotConfig::from(&v.pivot)),
			manifest_set: Some(ManifestSet::from(&v.manifest_set)),
			share_set: Some(ShareSet::from(&v.share_set)),
			enclave: Some(NitroConfig::from(&v.enclave)),
			patch_set: Some(PatchSet::from(&v.patch_set)),
			client_timeout_ms: v.client_timeout_ms.map(|v| v as u32),
			pool_size: v.pool_size.map(|v| v as u32),
		}
	}
}

impl From<&legacy::Approval> for Approval {
	fn from(v: &legacy::Approval) -> Self {
		Self {
			signature: v.signature.clone(),
			member: Some(QuorumMember::from(&v.member)),
		}
	}
}

impl From<&legacy::ManifestEnvelope> for ManifestEnvelope {
	fn from(v: &legacy::ManifestEnvelope) -> Self {
		Self {
			manifest: Some(Manifest::from(&v.manifest)),
			manifest_set_approvals: v
				.manifest_set_approvals
				.iter()
				.map(Approval::from)
				.collect(),
			share_set_approvals: v
				.share_set_approvals
				.iter()
				.map(Approval::from)
				.collect(),
		}
	}
}

impl From<&legacy::GenesisSet> for GenesisSet {
	fn from(v: &legacy::GenesisSet) -> Self {
		Self {
			members: v.members.iter().map(QuorumMember::from).collect(),
			threshold: v.threshold,
		}
	}
}

impl From<&legacy::GenesisMemberOutput> for GenesisMemberOutput {
	fn from(v: &legacy::GenesisMemberOutput) -> Self {
		Self {
			share_set_member: Some(QuorumMember::from(&v.share_set_member)),
			encrypted_quorum_key_share: v.encrypted_quorum_key_share.clone(),
			share_hash: v.share_hash.to_vec(),
		}
	}
}

impl From<&legacy::GenesisOutput> for GenesisOutput {
	fn from(v: &legacy::GenesisOutput) -> Self {
		Self {
			quorum_key: v.quorum_key.clone(),
			member_outputs: v
				.member_outputs
				.iter()
				.map(GenesisMemberOutput::from)
				.collect(),
			recovery_permutations: v
				.recovery_permutations
				.iter()
				.map(RecoveredPermutation::from)
				.collect(),
			threshold: v.threshold,
			dr_key_wrapped_quorum_key: v.dr_key_wrapped_quorum_key.clone(),
			quorum_key_hash: v.quorum_key_hash.to_vec(),
			test_message_ciphertext: v.test_message_ciphertext.clone(),
			test_message_signature: v.test_message_signature.clone(),
			test_message: v.test_message.clone(),
		}
	}
}

impl From<&legacy::RecoveredPermutation> for RecoveredPermutation {
	fn from(_v: &legacy::RecoveredPermutation) -> Self {
		// RecoveredPermutation's inner field is pub(crate) so we can't access it
		// from here. For now return empty - this is only used for recovery
		// permutations which aren't currently populated.
		Self { shards: vec![] }
	}
}

// ============================================================================
// Conversions: Proto -> Legacy
// ============================================================================

impl From<&NitroConfig> for legacy::NitroConfig {
	fn from(v: &NitroConfig) -> Self {
		Self {
			pcr0: v.pcr0.clone(),
			pcr1: v.pcr1.clone(),
			pcr2: v.pcr2.clone(),
			pcr3: v.pcr3.clone(),
			aws_root_certificate: v.aws_root_certificate.clone(),
			qos_commit: v.qos_commit.clone(),
		}
	}
}

impl From<RestartPolicy> for legacy::RestartPolicy {
	fn from(v: RestartPolicy) -> Self {
		match v {
			RestartPolicy::Never => Self::Never,
			RestartPolicy::Always => Self::Always,
			RestartPolicy::Unspecified => Self::Never, // default
		}
	}
}

impl TryFrom<&PivotConfig> for legacy::PivotConfig {
	type Error = &'static str;

	fn try_from(v: &PivotConfig) -> Result<Self, Self::Error> {
		let hash: [u8; 32] =
			v.hash.clone().try_into().map_err(|_| "invalid hash length")?;
		Ok(Self {
			hash,
			restart: RestartPolicy::try_from(v.restart)
				.unwrap_or(RestartPolicy::Never)
				.into(),
			args: v.args.clone(),
		})
	}
}

impl From<&QuorumMember> for legacy::QuorumMember {
	fn from(v: &QuorumMember) -> Self {
		Self { alias: v.alias.clone(), pub_key: v.pub_key.clone() }
	}
}

impl From<&MemberPubKey> for legacy::MemberPubKey {
	fn from(v: &MemberPubKey) -> Self {
		Self { pub_key: v.pub_key.clone() }
	}
}

impl From<&ManifestSet> for legacy::ManifestSet {
	fn from(v: &ManifestSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(legacy::QuorumMember::from).collect(),
		}
	}
}

impl From<&ShareSet> for legacy::ShareSet {
	fn from(v: &ShareSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(legacy::QuorumMember::from).collect(),
		}
	}
}

impl From<&PatchSet> for legacy::PatchSet {
	fn from(v: &PatchSet) -> Self {
		Self {
			threshold: v.threshold,
			members: v.members.iter().map(legacy::MemberPubKey::from).collect(),
		}
	}
}

impl From<&Namespace> for legacy::Namespace {
	fn from(v: &Namespace) -> Self {
		Self {
			name: v.name.clone(),
			nonce: v.nonce,
			quorum_key: v.quorum_key.clone(),
		}
	}
}

impl TryFrom<&Manifest> for legacy::Manifest {
	type Error = &'static str;

	fn try_from(v: &Manifest) -> Result<Self, Self::Error> {
		Ok(Self {
			namespace: v
				.namespace
				.as_ref()
				.map(legacy::Namespace::from)
				.ok_or("missing namespace")?,
			pivot: v
				.pivot
				.as_ref()
				.map(legacy::PivotConfig::try_from)
				.transpose()?
				.ok_or("missing pivot")?,
			manifest_set: v
				.manifest_set
				.as_ref()
				.map(legacy::ManifestSet::from)
				.ok_or("missing manifest_set")?,
			share_set: v
				.share_set
				.as_ref()
				.map(legacy::ShareSet::from)
				.ok_or("missing share_set")?,
			enclave: v
				.enclave
				.as_ref()
				.map(legacy::NitroConfig::from)
				.ok_or("missing enclave")?,
			patch_set: v
				.patch_set
				.as_ref()
				.map(legacy::PatchSet::from)
				.ok_or("missing patch_set")?,
			client_timeout_ms: v.client_timeout_ms.map(|v| v as u16),
			pool_size: v.pool_size.map(|v| v as u8),
		})
	}
}

impl TryFrom<&Approval> for legacy::Approval {
	type Error = &'static str;

	fn try_from(v: &Approval) -> Result<Self, Self::Error> {
		Ok(Self {
			signature: v.signature.clone(),
			member: v
				.member
				.as_ref()
				.map(legacy::QuorumMember::from)
				.ok_or("missing member")?,
		})
	}
}

impl TryFrom<&ManifestEnvelope> for legacy::ManifestEnvelope {
	type Error = &'static str;

	fn try_from(v: &ManifestEnvelope) -> Result<Self, Self::Error> {
		Ok(Self {
			manifest: v
				.manifest
				.as_ref()
				.map(legacy::Manifest::try_from)
				.transpose()?
				.ok_or("missing manifest")?,
			manifest_set_approvals: v
				.manifest_set_approvals
				.iter()
				.map(legacy::Approval::try_from)
				.collect::<Result<Vec<_>, _>>()?,
			share_set_approvals: v
				.share_set_approvals
				.iter()
				.map(legacy::Approval::try_from)
				.collect::<Result<Vec<_>, _>>()?,
		})
	}
}

impl From<&GenesisSet> for legacy::GenesisSet {
	fn from(v: &GenesisSet) -> Self {
		Self {
			members: v.members.iter().map(legacy::QuorumMember::from).collect(),
			threshold: v.threshold,
		}
	}
}

impl TryFrom<&GenesisMemberOutput> for legacy::GenesisMemberOutput {
	type Error = &'static str;

	fn try_from(v: &GenesisMemberOutput) -> Result<Self, Self::Error> {
		let share_hash: [u8; 64] = v
			.share_hash
			.clone()
			.try_into()
			.map_err(|_| "invalid share_hash length")?;
		Ok(Self {
			share_set_member: v
				.share_set_member
				.as_ref()
				.map(legacy::QuorumMember::from)
				.ok_or("missing share_set_member")?,
			encrypted_quorum_key_share: v.encrypted_quorum_key_share.clone(),
			share_hash,
		})
	}
}

impl TryFrom<&GenesisOutput> for legacy::GenesisOutput {
	type Error = &'static str;

	fn try_from(v: &GenesisOutput) -> Result<Self, Self::Error> {
		let quorum_key_hash: [u8; 64] = v
			.quorum_key_hash
			.clone()
			.try_into()
			.map_err(|_| "invalid quorum_key_hash length")?;
		Ok(Self {
			quorum_key: v.quorum_key.clone(),
			member_outputs: v
				.member_outputs
				.iter()
				.map(legacy::GenesisMemberOutput::try_from)
				.collect::<Result<Vec<_>, _>>()?,
			recovery_permutations: vec![], // Can't convert back - internal field
			threshold: v.threshold,
			dr_key_wrapped_quorum_key: v.dr_key_wrapped_quorum_key.clone(),
			quorum_key_hash,
			test_message_ciphertext: v.test_message_ciphertext.clone(),
			test_message_signature: v.test_message_signature.clone(),
			test_message: v.test_message.clone(),
		})
	}
}

// ============================================================================
// Conversions: Protocol Error and Phase
// ============================================================================

impl From<&legacy::ProtocolError> for ProtocolErrorCode {
	fn from(v: &legacy::ProtocolError) -> Self {
		match v {
			legacy::ProtocolError::InvalidShare => Self::InvalidShare,
			legacy::ProtocolError::ReconstructionErrorEmptySecret => {
				Self::ReconstructionErrorEmptySecret
			}
			legacy::ProtocolError::ReconstructionErrorIncorrectPubKey => {
				Self::ReconstructionErrorIncorrectPubKey
			}
			legacy::ProtocolError::IOError => Self::IoError,
			legacy::ProtocolError::InvalidManifestApproval(_) => {
				Self::InvalidManifestApproval
			}
			legacy::ProtocolError::NotEnoughApprovals => Self::NotEnoughApprovals,
			legacy::ProtocolError::NoMatchingRoute(_) => Self::NoMatchingRoute,
			legacy::ProtocolError::InvalidPivotHash => Self::InvalidPivotHash,
			legacy::ProtocolError::OversizeMsg => Self::OversizeMsg,
			legacy::ProtocolError::InvalidMsg => Self::InvalidMsg,
			legacy::ProtocolError::EnclaveClient => Self::EnclaveClient,
			legacy::ProtocolError::DecryptionFailed => Self::DecryptionFailed,
			legacy::ProtocolError::InvalidPrivateKey => Self::InvalidPrivateKey,
			legacy::ProtocolError::FailedToParseFromString => {
				Self::FailedToParseFromString
			}
			legacy::ProtocolError::BadEphemeralKeyPath => Self::BadEphemeralKeyPath,
			legacy::ProtocolError::CannotModifyPostPivotStatic => {
				Self::CannotModifyPostPivotStatic
			}
			legacy::ProtocolError::FailedToGetEphemeralKey(_) => {
				Self::FailedToGetEphemeralKey
			}
			legacy::ProtocolError::FailedToPutEphemeralKey => {
				Self::FailedToPutEphemeralKey
			}
			legacy::ProtocolError::CannotRotateNonExistentEphemeralKey => {
				Self::CannotRotateNonExistentEphemeralKey
			}
			legacy::ProtocolError::CannotDeleteEphemeralKey(_) => {
				Self::CannotDeleteEphemeralKey
			}
			legacy::ProtocolError::FailedToGetQuorumKey(_) => {
				Self::FailedToGetQuorumKey
			}
			legacy::ProtocolError::FailedToPutQuorumKey => Self::FailedToPutQuorumKey,
			legacy::ProtocolError::FailedToGetManifestEnvelope => {
				Self::FailedToGetManifestEnvelope
			}
			legacy::ProtocolError::FailedToPutManifestEnvelope => {
				Self::FailedToPutManifestEnvelope
			}
			legacy::ProtocolError::FailedToPutPivot => Self::FailedToPutPivot,
			legacy::ProtocolError::AppClientRecvTimeout => Self::AppClientRecvTimeout,
			legacy::ProtocolError::AppClientRecvInterrupted => {
				Self::AppClientRecvInterrupted
			}
			legacy::ProtocolError::AppClientRecvConnectionClosed => {
				Self::AppClientRecvConnectionClosed
			}
			legacy::ProtocolError::AppClientConnectError(_) => {
				Self::AppClientConnectError
			}
			legacy::ProtocolError::AppClientSendError(_) => Self::AppClientSendError,
			legacy::ProtocolError::AppClientError(_) => Self::AppClientError,
			legacy::ProtocolError::OversizedPayload => Self::OversizedPayload,
			legacy::ProtocolError::ProtocolMsgDeserialization => {
				Self::ProtocolMsgDeserialization
			}
			legacy::ProtocolError::BadShareSetApprovals => Self::BadShareSetApprovals,
			legacy::ProtocolError::CouldNotVerifyApproval => {
				Self::CouldNotVerifyApproval
			}
			legacy::ProtocolError::NotShareSetMember => Self::NotShareSetMember,
			legacy::ProtocolError::NotManifestSetMember => Self::NotManifestSetMember,
			legacy::ProtocolError::P256Error(_) => Self::P256Error,
			legacy::ProtocolError::InvalidP256DRKey(_) => Self::InvalidP256DrKey,
			legacy::ProtocolError::IncorrectSecretLen => Self::IncorrectSecretLen,
			legacy::ProtocolError::QosAttestError(_) => Self::QosAttestError,
			legacy::ProtocolError::DifferentQuorumKey { .. } => Self::DifferentQuorumKey,
			legacy::ProtocolError::DifferentManifestSet { .. } => {
				Self::DifferentManifestSet
			}
			legacy::ProtocolError::DifferentNamespaceName { .. } => {
				Self::DifferentNamespaceName
			}
			legacy::ProtocolError::LowNonce { .. } => Self::LowNonce,
			legacy::ProtocolError::DifferentPcr3 { .. } => Self::DifferentPcr3,
			legacy::ProtocolError::MissingEphemeralKey => Self::MissingEphemeralKey,
			legacy::ProtocolError::InvalidEphemeralKey => Self::InvalidEphemeralKey,
			legacy::ProtocolError::InvalidEncryptedQuorumKeySignature => {
				Self::InvalidEncryptedQuorumKeySignature
			}
			legacy::ProtocolError::EncryptedQuorumKeyInvalidLen => {
				Self::EncryptedQuorumKeyInvalidLen
			}
			legacy::ProtocolError::InvalidQuorumSecret => Self::InvalidQuorumSecret,
			legacy::ProtocolError::WrongQuorumKey => Self::WrongQuorumKey,
			legacy::ProtocolError::InvalidStateTransition(_, _) => {
				Self::InvalidStateTransition
			}
			legacy::ProtocolError::DuplicateApproval => Self::DuplicateApproval,
			legacy::ProtocolError::DifferentManifest { .. } => Self::DifferentManifest,
			legacy::ProtocolError::QosCrypto(_) => Self::QosCrypto,
			legacy::ProtocolError::PoolExpandError => Self::PoolExpandError,
		}
	}
}

impl From<&legacy::ProtocolError> for ProtocolError {
	fn from(v: &legacy::ProtocolError) -> Self {
		Self {
			code: ProtocolErrorCode::from(v) as i32,
			message: Some(v.to_string()),
		}
	}
}

impl From<&crate::protocol::ProtocolPhase> for ProtocolPhase {
	fn from(v: &crate::protocol::ProtocolPhase) -> Self {
		match v {
			crate::protocol::ProtocolPhase::UnrecoverableError => {
				Self::UnrecoverableError
			}
			crate::protocol::ProtocolPhase::WaitingForBootInstruction => {
				Self::WaitingForBootInstruction
			}
			crate::protocol::ProtocolPhase::GenesisBooted => Self::GenesisBooted,
			crate::protocol::ProtocolPhase::WaitingForQuorumShards => {
				Self::WaitingForQuorumShards
			}
			crate::protocol::ProtocolPhase::QuorumKeyProvisioned => {
				Self::QuorumKeyProvisioned
			}
			crate::protocol::ProtocolPhase::WaitingForForwardedKey => {
				Self::WaitingForForwardedKey
			}
		}
	}
}

impl From<ProtocolPhase> for crate::protocol::ProtocolPhase {
	fn from(v: ProtocolPhase) -> Self {
		match v {
			ProtocolPhase::UnrecoverableError => Self::UnrecoverableError,
			ProtocolPhase::WaitingForBootInstruction => Self::WaitingForBootInstruction,
			ProtocolPhase::GenesisBooted => Self::GenesisBooted,
			ProtocolPhase::WaitingForQuorumShards => Self::WaitingForQuorumShards,
			ProtocolPhase::QuorumKeyProvisioned => Self::QuorumKeyProvisioned,
			ProtocolPhase::WaitingForForwardedKey => Self::WaitingForForwardedKey,
			ProtocolPhase::Unspecified => Self::WaitingForBootInstruction,
		}
	}
}

// ============================================================================
// Conversions: NSM Response (using functions to avoid orphan rule)
// ============================================================================

use qos_nsm::types::NsmResponse as LegacyNsmResponse;

fn nsm_response_to_proto(v: &LegacyNsmResponse) -> NsmResponse {
	use qos_proto::nsm_response::Response;
	let response = match v {
		LegacyNsmResponse::DescribePCR { lock, data } => {
			Response::DescribePcr(DescribePcrResponse {
				lock: *lock,
				data: data.clone(),
			})
		}
		LegacyNsmResponse::ExtendPCR { data } => {
			Response::ExtendPcr(ExtendPcrResponse { data: data.clone() })
		}
		LegacyNsmResponse::LockPCR => Response::LockPcr(LockPcrResponse {}),
		LegacyNsmResponse::LockPCRs => Response::LockPcrs(LockPcrsResponse {}),
		LegacyNsmResponse::DescribeNSM {
			version_major,
			version_minor,
			version_patch,
			module_id,
			max_pcrs,
			locked_pcrs,
			digest,
		} => Response::DescribeNsm(DescribeNsmResponse {
			version_major: *version_major as u32,
			version_minor: *version_minor as u32,
			version_patch: *version_patch as u32,
			module_id: module_id.clone(),
			max_pcrs: *max_pcrs as u32,
			locked_pcrs: locked_pcrs.iter().map(|x| *x as u32).collect(),
			digest: match digest {
				qos_nsm::types::NsmDigest::SHA256 => NsmDigest::Sha256 as i32,
				qos_nsm::types::NsmDigest::SHA384 => NsmDigest::Sha384 as i32,
				qos_nsm::types::NsmDigest::SHA512 => NsmDigest::Sha512 as i32,
			},
		}),
		LegacyNsmResponse::Attestation { document } => {
			Response::Attestation(AttestationResponse { document: document.clone() })
		}
		LegacyNsmResponse::GetRandom { random } => {
			Response::GetRandom(GetRandomResponse { random: random.clone() })
		}
		LegacyNsmResponse::Error(code) => Response::Error(NsmErrorResponse {
			code: match code {
				qos_nsm::types::NsmErrorCode::Success => {
					NsmErrorCode::Success as i32
				}
				qos_nsm::types::NsmErrorCode::InvalidArgument => {
					NsmErrorCode::InvalidArgument as i32
				}
				qos_nsm::types::NsmErrorCode::InvalidIndex => {
					NsmErrorCode::InvalidIndex as i32
				}
				qos_nsm::types::NsmErrorCode::InvalidResponse => {
					NsmErrorCode::InvalidResponse as i32
				}
				qos_nsm::types::NsmErrorCode::ReadOnlyIndex => {
					NsmErrorCode::ReadOnlyIndex as i32
				}
				qos_nsm::types::NsmErrorCode::InvalidOperation => {
					NsmErrorCode::InvalidOperation as i32
				}
				qos_nsm::types::NsmErrorCode::BufferTooSmall => {
					NsmErrorCode::BufferTooSmall as i32
				}
				qos_nsm::types::NsmErrorCode::InputTooLarge => {
					NsmErrorCode::InputTooLarge as i32
				}
				qos_nsm::types::NsmErrorCode::InternalError => {
					NsmErrorCode::InternalError as i32
				}
			},
		}),
	};
	NsmResponse { response: Some(response) }
}

fn proto_to_nsm_response(v: &NsmResponse) -> Result<LegacyNsmResponse, &'static str> {
	use qos_proto::nsm_response::Response;
	let response = v.response.as_ref().ok_or("missing response")?;
	Ok(match response {
		Response::DescribePcr(r) => {
			LegacyNsmResponse::DescribePCR { lock: r.lock, data: r.data.clone() }
		}
		Response::ExtendPcr(r) => {
			LegacyNsmResponse::ExtendPCR { data: r.data.clone() }
		}
		Response::LockPcr(_) => LegacyNsmResponse::LockPCR,
		Response::LockPcrs(_) => LegacyNsmResponse::LockPCRs,
		Response::DescribeNsm(r) => LegacyNsmResponse::DescribeNSM {
			version_major: r.version_major as u16,
			version_minor: r.version_minor as u16,
			version_patch: r.version_patch as u16,
			module_id: r.module_id.clone(),
			max_pcrs: r.max_pcrs as u16,
			locked_pcrs: r.locked_pcrs.iter().map(|x| *x as u16).collect(),
			digest: match NsmDigest::try_from(r.digest) {
				Ok(NsmDigest::Sha256) => qos_nsm::types::NsmDigest::SHA256,
				Ok(NsmDigest::Sha384) => qos_nsm::types::NsmDigest::SHA384,
				Ok(NsmDigest::Sha512) => qos_nsm::types::NsmDigest::SHA512,
				_ => qos_nsm::types::NsmDigest::SHA256,
			},
		},
		Response::Attestation(r) => {
			LegacyNsmResponse::Attestation { document: r.document.clone() }
		}
		Response::GetRandom(r) => {
			LegacyNsmResponse::GetRandom { random: r.random.clone() }
		}
		Response::Error(r) => {
			let code = match NsmErrorCode::try_from(r.code) {
				Ok(NsmErrorCode::InvalidArgument) => {
					qos_nsm::types::NsmErrorCode::InvalidArgument
				}
				Ok(NsmErrorCode::InvalidIndex) => {
					qos_nsm::types::NsmErrorCode::InvalidIndex
				}
				Ok(NsmErrorCode::InvalidResponse) => {
					qos_nsm::types::NsmErrorCode::InvalidResponse
				}
				Ok(NsmErrorCode::ReadOnlyIndex) => {
					qos_nsm::types::NsmErrorCode::ReadOnlyIndex
				}
				Ok(NsmErrorCode::InvalidOperation) => {
					qos_nsm::types::NsmErrorCode::InvalidOperation
				}
				Ok(NsmErrorCode::BufferTooSmall) => {
					qos_nsm::types::NsmErrorCode::BufferTooSmall
				}
				Ok(NsmErrorCode::InputTooLarge) => {
					qos_nsm::types::NsmErrorCode::InputTooLarge
				}
				Ok(NsmErrorCode::InternalError) | _ => {
					qos_nsm::types::NsmErrorCode::InternalError
				}
			};
			LegacyNsmResponse::Error(code)
		}
	})
}

// ============================================================================
// Conversions: Protocol Message
// ============================================================================

use qos_proto::protocol_msg::Msg;

impl From<&legacy::ProtocolMsg> for ProtocolMsg {
	fn from(v: &legacy::ProtocolMsg) -> Self {
		let msg = match v {
			legacy::ProtocolMsg::ProtocolErrorResponse(e) => {
				Msg::ErrorResponse(ProtocolError::from(e))
			}
			legacy::ProtocolMsg::StatusRequest => {
				Msg::StatusRequest(StatusRequest {})
			}
			legacy::ProtocolMsg::StatusResponse(phase) => {
				Msg::StatusResponse(StatusResponse {
					phase: ProtocolPhase::from(phase) as i32,
				})
			}
			legacy::ProtocolMsg::BootStandardRequest { manifest_envelope, pivot } => {
				Msg::BootStandardRequest(BootStandardRequest {
					manifest_envelope: Some(ManifestEnvelope::from(
						manifest_envelope.as_ref(),
					)),
					pivot: pivot.clone(),
				})
			}
			legacy::ProtocolMsg::BootStandardResponse { nsm_response } => {
				Msg::BootStandardResponse(BootStandardResponse {
					nsm_response: Some(nsm_response_to_proto(nsm_response)),
				})
			}
			legacy::ProtocolMsg::BootGenesisRequest { set, dr_key } => {
				Msg::BootGenesisRequest(BootGenesisRequest {
					set: Some(GenesisSet::from(set)),
					dr_key: dr_key.clone(),
				})
			}
			legacy::ProtocolMsg::BootGenesisResponse {
				nsm_response,
				genesis_output,
			} => Msg::BootGenesisResponse(BootGenesisResponse {
				nsm_response: Some(nsm_response_to_proto(nsm_response)),
				genesis_output: Some(GenesisOutput::from(genesis_output.as_ref())),
			}),
			legacy::ProtocolMsg::ProvisionRequest { share, approval } => {
				Msg::ProvisionRequest(ProvisionRequest {
					share: share.clone(),
					approval: Some(Approval::from(approval)),
				})
			}
			legacy::ProtocolMsg::ProvisionResponse { reconstructed } => {
				Msg::ProvisionResponse(ProvisionResponse {
					reconstructed: *reconstructed,
				})
			}
			legacy::ProtocolMsg::ProxyRequest { data } => {
				Msg::ProxyRequest(ProxyRequest { data: data.clone() })
			}
			legacy::ProtocolMsg::ProxyResponse { data } => {
				Msg::ProxyResponse(ProxyResponse { data: data.clone() })
			}
			legacy::ProtocolMsg::LiveAttestationDocRequest => {
				Msg::LiveAttestationDocRequest(LiveAttestationDocRequest {})
			}
			legacy::ProtocolMsg::LiveAttestationDocResponse {
				nsm_response,
				manifest_envelope,
			} => Msg::LiveAttestationDocResponse(LiveAttestationDocResponse {
				nsm_response: Some(nsm_response_to_proto(nsm_response)),
				manifest_envelope: manifest_envelope
					.as_ref()
					.map(|e| ManifestEnvelope::from(e.as_ref())),
			}),
			legacy::ProtocolMsg::BootKeyForwardRequest { manifest_envelope, pivot } => {
				Msg::BootKeyForwardRequest(BootKeyForwardRequest {
					manifest_envelope: Some(ManifestEnvelope::from(
						manifest_envelope.as_ref(),
					)),
					pivot: pivot.clone(),
				})
			}
			legacy::ProtocolMsg::BootKeyForwardResponse { nsm_response } => {
				Msg::BootKeyForwardResponse(BootKeyForwardResponse {
					nsm_response: Some(nsm_response_to_proto(nsm_response)),
				})
			}
			legacy::ProtocolMsg::ExportKeyRequest {
				manifest_envelope,
				cose_sign1_attestation_doc,
			} => Msg::ExportKeyRequest(ExportKeyRequest {
				manifest_envelope: Some(ManifestEnvelope::from(
					manifest_envelope.as_ref(),
				)),
				cose_sign1_attestation_doc: cose_sign1_attestation_doc.clone(),
			}),
			legacy::ProtocolMsg::ExportKeyResponse {
				encrypted_quorum_key,
				signature,
			} => Msg::ExportKeyResponse(ExportKeyResponse {
				encrypted_quorum_key: encrypted_quorum_key.clone(),
				signature: signature.clone(),
			}),
			legacy::ProtocolMsg::InjectKeyRequest {
				encrypted_quorum_key,
				signature,
			} => Msg::InjectKeyRequest(InjectKeyRequest {
				encrypted_quorum_key: encrypted_quorum_key.clone(),
				signature: signature.clone(),
			}),
			legacy::ProtocolMsg::InjectKeyResponse => {
				Msg::InjectKeyResponse(InjectKeyResponse {})
			}
			legacy::ProtocolMsg::ManifestEnvelopeRequest => {
				Msg::ManifestEnvelopeRequest(ManifestEnvelopeRequest {})
			}
			legacy::ProtocolMsg::ManifestEnvelopeResponse { manifest_envelope } => {
				Msg::ManifestEnvelopeResponse(ManifestEnvelopeResponse {
					manifest_envelope: manifest_envelope
						.as_ref()
						.as_ref()
						.map(ManifestEnvelope::from),
				})
			}
		};
		Self { msg: Some(msg) }
	}
}

impl TryFrom<&ProtocolMsg> for legacy::ProtocolMsg {
	type Error = &'static str;

	fn try_from(v: &ProtocolMsg) -> Result<Self, Self::Error> {
		let msg = v.msg.as_ref().ok_or("missing msg")?;
		Ok(match msg {
			Msg::ErrorResponse(_) => {
				// Can't convert proto error back to legacy with full fidelity
				legacy::ProtocolMsg::ProtocolErrorResponse(
					legacy::ProtocolError::InvalidMsg,
				)
			}
			Msg::StatusRequest(_) => legacy::ProtocolMsg::StatusRequest,
			Msg::StatusResponse(r) => {
				let phase = ProtocolPhase::try_from(r.phase)
					.unwrap_or(ProtocolPhase::Unspecified);
				legacy::ProtocolMsg::StatusResponse(phase.into())
			}
			Msg::BootStandardRequest(r) => legacy::ProtocolMsg::BootStandardRequest {
				manifest_envelope: Box::new(
					r.manifest_envelope
						.as_ref()
						.ok_or("missing manifest_envelope")
						.and_then(legacy::ManifestEnvelope::try_from)?,
				),
				pivot: r.pivot.clone(),
			},
			Msg::BootStandardResponse(r) => legacy::ProtocolMsg::BootStandardResponse {
				nsm_response: r
					.nsm_response
					.as_ref()
					.ok_or("missing nsm_response")
					.and_then(proto_to_nsm_response)?,
			},
			Msg::BootGenesisRequest(r) => legacy::ProtocolMsg::BootGenesisRequest {
				set: r
					.set
					.as_ref()
					.map(legacy::GenesisSet::from)
					.ok_or("missing set")?,
				dr_key: r.dr_key.clone(),
			},
			Msg::BootGenesisResponse(r) => legacy::ProtocolMsg::BootGenesisResponse {
				nsm_response: r
					.nsm_response
					.as_ref()
					.ok_or("missing nsm_response")
					.and_then(proto_to_nsm_response)?,
				genesis_output: Box::new(
					r.genesis_output
						.as_ref()
						.ok_or("missing genesis_output")
						.and_then(legacy::GenesisOutput::try_from)?,
				),
			},
			Msg::ProvisionRequest(r) => legacy::ProtocolMsg::ProvisionRequest {
				share: r.share.clone(),
				approval: r
					.approval
					.as_ref()
					.ok_or("missing approval")
					.and_then(legacy::Approval::try_from)?,
			},
			Msg::ProvisionResponse(r) => legacy::ProtocolMsg::ProvisionResponse {
				reconstructed: r.reconstructed,
			},
			Msg::ProxyRequest(r) => {
				legacy::ProtocolMsg::ProxyRequest { data: r.data.clone() }
			}
			Msg::ProxyResponse(r) => {
				legacy::ProtocolMsg::ProxyResponse { data: r.data.clone() }
			}
			Msg::LiveAttestationDocRequest(_) => {
				legacy::ProtocolMsg::LiveAttestationDocRequest
			}
			Msg::LiveAttestationDocResponse(r) => {
				legacy::ProtocolMsg::LiveAttestationDocResponse {
					nsm_response: r
						.nsm_response
						.as_ref()
						.ok_or("missing nsm_response")
						.and_then(proto_to_nsm_response)?,
					manifest_envelope: r
						.manifest_envelope
						.as_ref()
						.map(|e| legacy::ManifestEnvelope::try_from(e).map(Box::new))
						.transpose()?,
				}
			}
			Msg::BootKeyForwardRequest(r) => {
				legacy::ProtocolMsg::BootKeyForwardRequest {
					manifest_envelope: Box::new(
						r.manifest_envelope
							.as_ref()
							.ok_or("missing manifest_envelope")
							.and_then(legacy::ManifestEnvelope::try_from)?,
					),
					pivot: r.pivot.clone(),
				}
			}
			Msg::BootKeyForwardResponse(r) => {
				legacy::ProtocolMsg::BootKeyForwardResponse {
					nsm_response: r
						.nsm_response
						.as_ref()
						.ok_or("missing nsm_response")
						.and_then(proto_to_nsm_response)?,
				}
			}
			Msg::ExportKeyRequest(r) => legacy::ProtocolMsg::ExportKeyRequest {
				manifest_envelope: Box::new(
					r.manifest_envelope
						.as_ref()
						.ok_or("missing manifest_envelope")
						.and_then(legacy::ManifestEnvelope::try_from)?,
				),
				cose_sign1_attestation_doc: r.cose_sign1_attestation_doc.clone(),
			},
			Msg::ExportKeyResponse(r) => legacy::ProtocolMsg::ExportKeyResponse {
				encrypted_quorum_key: r.encrypted_quorum_key.clone(),
				signature: r.signature.clone(),
			},
			Msg::InjectKeyRequest(r) => legacy::ProtocolMsg::InjectKeyRequest {
				encrypted_quorum_key: r.encrypted_quorum_key.clone(),
				signature: r.signature.clone(),
			},
			Msg::InjectKeyResponse(_) => legacy::ProtocolMsg::InjectKeyResponse,
			Msg::ManifestEnvelopeRequest(_) => {
				legacy::ProtocolMsg::ManifestEnvelopeRequest
			}
			Msg::ManifestEnvelopeResponse(r) => {
				legacy::ProtocolMsg::ManifestEnvelopeResponse {
					manifest_envelope: Box::new(
						r.manifest_envelope
							.as_ref()
							.map(legacy::ManifestEnvelope::try_from)
							.transpose()?,
					),
				}
			}
		})
	}
}

/// Encode a legacy ProtocolMsg to protobuf bytes.
pub fn encode_proto_msg(msg: &legacy::ProtocolMsg) -> Vec<u8> {
	use prost::Message;
	let proto_msg = ProtocolMsg::from(msg);
	proto_msg.encode_to_vec()
}

/// Decode protobuf bytes to a legacy ProtocolMsg.
pub fn decode_proto_msg(
	bytes: &[u8],
) -> Result<legacy::ProtocolMsg, &'static str> {
	use prost::Message;
	let proto_msg =
		ProtocolMsg::decode(bytes).map_err(|_| "failed to decode proto msg")?;
	legacy::ProtocolMsg::try_from(&proto_msg)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn roundtrip_quorum_member() {
		let legacy = legacy::QuorumMember {
			alias: "test".to_string(),
			pub_key: vec![1, 2, 3],
		};

		let proto = QuorumMember::from(&legacy);
		let back = legacy::QuorumMember::from(&proto);

		assert_eq!(legacy.alias, back.alias);
		assert_eq!(legacy.pub_key, back.pub_key);
	}

	#[test]
	fn roundtrip_namespace() {
		let legacy = legacy::Namespace {
			name: "test-ns".to_string(),
			nonce: 42,
			quorum_key: vec![4, 5, 6],
		};

		let proto = Namespace::from(&legacy);
		let back = legacy::Namespace::from(&proto);

		assert_eq!(legacy.name, back.name);
		assert_eq!(legacy.nonce, back.nonce);
		assert_eq!(legacy.quorum_key, back.quorum_key);
	}

	#[test]
	fn roundtrip_nitro_config() {
		let legacy = legacy::NitroConfig {
			pcr0: vec![1; 32],
			pcr1: vec![2; 32],
			pcr2: vec![3; 32],
			pcr3: vec![4; 32],
			aws_root_certificate: vec![5, 6, 7],
			qos_commit: "abc123".to_string(),
		};

		let proto = NitroConfig::from(&legacy);
		let back = legacy::NitroConfig::from(&proto);

		assert_eq!(legacy.pcr0, back.pcr0);
		assert_eq!(legacy.pcr1, back.pcr1);
		assert_eq!(legacy.pcr2, back.pcr2);
		assert_eq!(legacy.pcr3, back.pcr3);
		assert_eq!(legacy.aws_root_certificate, back.aws_root_certificate);
		assert_eq!(legacy.qos_commit, back.qos_commit);
	}
}

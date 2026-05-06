//! Standard boot logic and types.

use std::fmt;

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::{P256Pair, P256Public};

use crate::protocol::{services::attestation, ProtocolError, ProtocolState};

pub mod env;
pub mod manifest;
pub use env::{
	PivotEnv, PivotEnvValue, PivotEnvVarName, MAX_PIVOT_ENV_NAME_LEN,
	MAX_PIVOT_ENV_VALUE_LEN, MAX_PIVOT_ENV_VARS,
};
pub use manifest::v0::{ManifestEnvelopeV0, ManifestV0, PivotConfigV0};
pub use manifest::v1::{ManifestEnvelopeV1, ManifestV1, PivotConfigV1};
pub use manifest::v2::{ManifestEnvelopeV2, ManifestV2, PivotConfigV2};
pub use manifest::{
	ManifestVersion, VersionedManifest, VersionedManifestEnvelope,
};

/// Enclave configuration specific to AWS Nitro.
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct NitroConfig {
	/// The hash of the enclave image file
	#[serde(with = "qos_hex::serde")]
	pub pcr0: Vec<u8>,
	/// The hash of the Linux kernel and bootstrap
	#[serde(with = "qos_hex::serde")]
	pub pcr1: Vec<u8>,
	/// The hash of the application
	#[serde(with = "qos_hex::serde")]
	pub pcr2: Vec<u8>,
	/// The hash of the Amazon resource name (ARN) of the IAM role that's
	/// associated with the EC2 instance.
	#[serde(with = "qos_hex::serde")]
	pub pcr3: Vec<u8>,
	/// DER encoded X509 AWS root certificate
	#[serde(with = "qos_hex::serde")]
	pub aws_root_certificate: Vec<u8>,
	/// Reference to the commit QOS was built off of.
	pub qos_commit: String,
}

impl fmt::Debug for NitroConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("NitroConfig")
			.field("pcr0", &qos_hex::encode(&self.pcr0))
			.field("pcr1", &qos_hex::encode(&self.pcr1))
			.field("pcr2", &qos_hex::encode(&self.pcr2))
			.field("pcr3", &qos_hex::encode(&self.pcr3))
			.field("qos_commit", &self.qos_commit)
			.finish_non_exhaustive()
	}
}

/// Policy for restarting the pivot binary.
#[derive(
	PartialEq,
	Eq,
	Clone,
	Copy,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub enum RestartPolicy {
	/// Never restart the pivot application
	#[cfg_attr(any(feature = "mock", test), default)]
	Never,
	/// Always restart the pivot application
	Always,
}

impl fmt::Debug for RestartPolicy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Never => write!(f, "RestartPolicy::Never")?,
			Self::Always => write!(f, "RestartPolicy::Always")?,
		}
		Ok(())
	}
}

impl TryFrom<String> for RestartPolicy {
	type Error = ProtocolError;

	fn try_from(s: String) -> Result<RestartPolicy, Self::Error> {
		match s.to_ascii_lowercase().as_str() {
			"never" => Ok(Self::Never),
			"always" => Ok(Self::Always),
			_ => Err(ProtocolError::FailedToParseFromString),
		}
	}
}

/// Pivot bridge host configuration, ipv4 only
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	serde::Serialize,
	serde::Deserialize,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum BridgeConfig {
	/// Server hosting bridge, connections go INTO the enclave app on given port and host binding
	Server {
		/// The port to listen on, matching on host and app sides
		#[serde(with = "qos_json::string_number")]
		port: u16,
		/// The host ip to listen on, use `0.0.0.0` for any
		host: String,
	},
	/// Client connecting bridge, connections go OUT of the enclave app via given port, connecting
	/// to the provided hostname. If `None` it will use the transparent protocol.
	/// *NOTE*: currently **unimplemented** and results in boot panic if set.
	Client {
		/// Port to connect to when app initiates outgoing connections.
		#[serde(with = "qos_json::string_number")]
		port: u16,
		/// Host name to connect to when app initiates outgoing connections.
		/// If `None` an internal protocol is used to determine the destination (**unimplemented**)
		host: Option<String>,
	},
}

impl Default for BridgeConfig {
	fn default() -> Self {
		Self::Server {
			port: DEFAULT_APP_HOST_PORT,
			host: DEFAULT_APP_HOST_IP.into(),
		}
	}
}

impl BridgeConfig {
	/// Helper to extract port from either variant
	#[must_use]
	pub fn port(&self) -> u16 {
		match self {
			Self::Server { port, host: _ } | Self::Client { port, host: _ } => {
				*port
			}
		}
	}
}

/// A quorum member's alias and public key.
#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Eq,
	PartialOrd,
	Ord,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct QuorumMember {
	/// A human readable alias to identify the member. The alias is not
	/// cryptographically guaranteed and thus should not be trusted without
	/// verification.
	pub alias: String,
	/// `P256Public` as bytes
	#[serde(with = "qos_hex::serde")]
	pub pub_key: Vec<u8>,
}

impl fmt::Debug for QuorumMember {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("QuorumMember")
			.field("alias", &self.alias)
			.field("pub_key", &qos_hex::encode(&self.pub_key))
			.finish()
	}
}

/// The Manifest Set.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ManifestSet {
	/// The threshold, K, of signatures necessary to have quorum.
	#[serde(with = "qos_json::string_number")]
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// The set of share keys that can post shares.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct ShareSet {
	/// The threshold, K, of signatures necessary to have quorum.
	#[serde(with = "qos_json::string_number")]
	pub threshold: u32,
	/// Members composing the set. The length of this, N, must be gte to the
	/// `threshold`, K.
	pub members: Vec<QuorumMember>,
}

/// A member of a quorum set identified solely by their public key.
#[derive(
	PartialEq,
	PartialOrd,
	Ord,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct MemberPubKey {
	/// Public key of the member
	#[serde(with = "qos_hex::serde")]
	pub pub_key: Vec<u8>,
}

impl fmt::Debug for MemberPubKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MemberPubKey")
			.field("pub_key", &qos_hex::encode(&self.pub_key))
			.finish()
	}
}

/// The set of share keys that can post shares.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PatchSet {
	/// The threshold, K, of signatures necessary to have quorum.
	#[serde(with = "qos_json::string_number")]
	pub threshold: u32,
	/// Public keys of members composing the set. The length of this, N, must
	/// be gte to the `threshold`, K.
	pub members: Vec<MemberPubKey>,
}

/// A Namespace and its relative nonce.
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct Namespace {
	/// The namespace. This should be unique relative to other namespaces the
	/// organization running `QuorumOs` has.
	pub name: String,
	/// A monotonically increasing value, used to identify the order in which
	/// manifests for this namespace have been created. This is used to prevent
	/// downgrade attacks - quorum members should only approve a manifest that
	/// has the highest nonce.
	#[serde(with = "qos_json::string_number")]
	pub nonce: u32,
	/// Quorum Key
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
}

impl fmt::Debug for Namespace {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Namespace")
			.field("name", &self.name)
			.field("nonce", &self.nonce)
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.finish()
	}
}

/// Default port to use for host bridge in server mode
pub const DEFAULT_APP_HOST_PORT: u16 = 3000;
/// Default host ip string for host bridge in server mode
pub const DEFAULT_APP_HOST_IP: &str = "0.0.0.0";

/// An approval by a Quorum Member.
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct Approval {
	/// Quorum Member's signature.
	#[serde(with = "qos_hex::serde")]
	pub signature: Vec<u8>,
	/// Description of the Quorum Member
	pub member: QuorumMember,
}

impl fmt::Debug for Approval {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Approval")
			.field("signature", &qos_hex::encode(&self.signature))
			.field("member", &self.member)
			.finish()
	}
}

impl Approval {
	/// Verify that the approval is a valid a signature for the given `msg`.
	pub(crate) fn verify(&self, msg: &[u8]) -> Result<(), ProtocolError> {
		let pub_key = P256Public::from_bytes(&self.member.pub_key)?;

		if pub_key.verify(msg, &self.signature).is_ok() {
			Ok(())
		} else {
			Err(ProtocolError::CouldNotVerifyApproval)
		}
	}
}

pub(in crate::protocol::services) fn put_manifest_and_pivot(
	state: &mut ProtocolState,
	manifest_envelope: &VersionedManifestEnvelope,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError> {
	// 1. Check signatures over the manifest envelope.
	manifest_envelope.check_approvals()?;
	if !manifest_envelope.share_set_approvals().is_empty() {
		return Err(ProtocolError::BadShareSetApprovals);
	}
	let actual_hash = sha_256(pivot);
	let expected_hash = manifest_envelope.manifest().pivot_hash().to_owned();
	if actual_hash != expected_hash {
		return Err(ProtocolError::InvalidPivotHash {
			expected: qos_hex::encode(&expected_hash),
			actual: qos_hex::encode(&actual_hash),
		});
	}

	// 2. Generate an Ephemeral Key.
	let ephemeral_key = P256Pair::generate()?;
	state.handles.put_ephemeral_key(&ephemeral_key)?;
	state.handles.put_pivot(pivot)?;
	state.handles.put_manifest_envelope(manifest_envelope)?;

	// 3. Make an attestation request, placing the manifest hash in the
	// `user_data` field and the Ephemeral Key public key in the `public_key`
	// field.
	let nsm_response = attestation::get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_key.public_key().to_bytes(),
		manifest_envelope.qos_hash().to_vec(),
	);

	// 4. Return the NSM Response containing COSE Sign1 encoded attestation
	// document.
	Ok(nsm_response)
}

pub(in crate::protocol) fn boot_standard<E>(
	state: &mut ProtocolState,
	manifest_envelope: E,
	pivot: &[u8],
) -> Result<NsmResponse, ProtocolError>
where
	E: Into<VersionedManifestEnvelope>,
{
	let manifest_envelope = manifest_envelope.into();
	let nsm_response =
		put_manifest_and_pivot(state, &manifest_envelope, pivot)?;
	Ok(nsm_response)
}

#[cfg(test)]
mod test {
	use std::path::Path;

	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{handles::Handles, protocol::QosHash};

	fn get_manifest() -> (ManifestV1, Vec<(P256Pair, QuorumMember)>, Vec<u8>) {
		let quorum_pair = P256Pair::generate().unwrap();
		let member1_pair = P256Pair::generate().unwrap();
		let member2_pair = P256Pair::generate().unwrap();
		let member3_pair = P256Pair::generate().unwrap();

		let pivot = b"this is a pivot binary".to_vec();

		let quorum_members = vec![
			QuorumMember {
				alias: "member1".to_string(),
				pub_key: member1_pair.public_key().to_bytes(),
			},
			QuorumMember {
				alias: "member2".to_string(),
				pub_key: member2_pair.public_key().to_bytes(),
			},
			QuorumMember {
				alias: "member3".to_string(),
				pub_key: member3_pair.public_key().to_bytes(),
			},
		];

		let member_with_keys = vec![
			(member1_pair, quorum_members.first().unwrap().clone()),
			(member2_pair, quorum_members.get(1).unwrap().clone()),
			(member3_pair, quorum_members.get(2).unwrap().clone()),
		];

		let manifest = ManifestV1 {
			namespace: Namespace {
				nonce: 420,
				name: "vape lord".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			},
			pivot: PivotConfigV1 {
				hash: sha_256(&pivot),
				restart: RestartPolicy::Always,
				args: vec![],
				..Default::default()
			},
			manifest_set: ManifestSet { threshold: 2, members: quorum_members },
			share_set: ShareSet { threshold: 2, members: vec![] },
			..Default::default()
		};

		(manifest, member_with_keys, pivot)
	}

	#[test]
	fn manifest_hash() {
		let (manifest, _members, _pivot) = get_manifest();

		let hashes: Vec<_> = (0..10).map(|_| manifest.qos_hash()).collect();
		let is_valid = (1..10).all(|i| hashes[i] == hashes[0]);
		assert!(is_valid);
	}

	#[test]
	fn boot_standard_accepts_approved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let approvals = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_accepts_approved_manifest.pivot".to_string();
		let ephemeral_file =
			"boot_standard_accepts_approved_manifest_eph.secret".to_string();
		let manifest_file =
			"boot_standard_accepts_approved_manifest.manifest".to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file.clone(),
			pivot_file.clone(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let _nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap();

		assert!(Path::new(&pivot_file).exists());
		assert!(Path::new(&ephemeral_file).exists());

		assert_eq!(
			handles.get_manifest_envelope().unwrap(),
			VersionedManifestEnvelope::V1(manifest_envelope)
		);

		std::fs::remove_file(pivot_file).unwrap();
		std::fs::remove_file(ephemeral_file).unwrap();
		std::fs::remove_file(manifest_file).unwrap();
	}

	#[test]
	fn boot_standard_rejects_manifest_if_not_enough_approvals() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let approvals = members
				[0usize..manifest.manifest_set.threshold as usize - 1]
				.iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member: member.clone(),
				})
				.collect();

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.pivot"
				.to_string();
		let ephemeral_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.secret"
				.to_string();
		let manifest_file =
			"boot_standard_rejects_manifest_if_not_enough_approvals.manifest"
				.to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file,
			pivot_file,
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot);

		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
		assert!(!Path::new(&ephemeral_file).exists());
		assert!(nsm_resposne.is_err());
	}

	#[test]
	fn boot_standard_rejects_unapproved_manifest() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let approvals = members
				.into_iter()
				.map(|(_pair, member)| Approval {
					signature: vec![0, 0],
					member,
				})
				.collect();

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals,
				share_set_approvals: vec![],
			}
		};

		let pivot_file =
			"boot_standard_rejects_unapproved_manifest.pivot".to_string();
		let ephemeral_file =
			"boot_standard_rejects_unapproved_manifest.secret".to_string();
		let manifest_file =
			"boot_standard_rejects_unapproved_manifest.manifest".to_string();
		let handles = Handles::new(
			ephemeral_file.clone(),
			"quorum_key".to_string(),
			manifest_file,
			pivot_file,
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles.clone(), None);

		let nsm_resposne =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot);

		assert!(!handles.manifest_envelope_exists());
		assert!(!handles.pivot_exists());
		assert!(!Path::new(&ephemeral_file).exists());
		assert!(nsm_resposne.is_err());
	}

	#[test]
	fn boot_standard_rejects_manifest_envelope_with_share_set_approvals() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![approvals.remove(0)],
			}
		};

		let pivot_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals.pivot".into();
		let ephemeral_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals_eph.secret".into();
		let manifest_file: PathWrapper =
			"boot_standard_rejects_manifest_envelope_with_share_set_approvals.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			"quorum_key".to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles, None);

		let error =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap_err();

		assert_eq!(error, ProtocolError::BadShareSetApprovals);

		assert!(!Path::new(&*pivot_file).exists());
		assert!(!Path::new(&*ephemeral_file).exists());
		assert!(!Path::new(&*manifest_file).exists());
	}

	#[test]
	fn boot_standard_rejects_approval_from_non_manifest_set_member() {
		let (manifest, members, pivot) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			let mut approvals: Vec<_> = members
				.into_iter()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			// Change a member so that are not recognized as part of the
			// manifest set.
			let approval = approvals.get_mut(0).unwrap();
			let pair = P256Pair::generate().unwrap();
			approval.member.pub_key = pair.public_key().to_bytes();
			approval.signature = pair.sign(&manifest.qos_hash()).unwrap();

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![],
			}
		};

		let pivot_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.pivot"
				.into();
		let ephemeral_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.secret".into();
		let manifest_file: PathWrapper =
			"boot_standard_rejects_approval_from_non_manifest_set_member.manifest".into();

		let handles = Handles::new(
			(*ephemeral_file).to_string(),
			"quorum_key".to_string(),
			(*manifest_file).to_string(),
			(*pivot_file).to_string(),
		);
		let mut protocol_state =
			ProtocolState::new(Box::new(MockNsm), handles, None);

		let error =
			boot_standard(&mut protocol_state, &manifest_envelope, &pivot)
				.unwrap_err();

		assert_eq!(error, ProtocolError::NotManifestSetMember);

		assert!(!Path::new(&*pivot_file).exists());
		assert!(!Path::new(&*ephemeral_file).exists());
		assert!(!Path::new(&*manifest_file).exists());
	}

	#[test]
	fn check_approvals_rejects_duplicates() {
		let (manifest, members, ..) = get_manifest();

		let manifest_envelope = {
			let manifest_hash = manifest.qos_hash();
			// Just make 1 approval
			let mut approvals: Vec<_> = members[..1]
				.iter()
				.cloned()
				.map(|(pair, member)| Approval {
					signature: pair.sign(&manifest_hash).unwrap(),
					member,
				})
				.collect();

			// Duplicate the approval and add it
			let duplicate_approval = approvals[0].clone();
			approvals.push(duplicate_approval);

			ManifestEnvelopeV1 {
				manifest,
				manifest_set_approvals: approvals.clone(),
				share_set_approvals: vec![],
			}
		};

		let err = manifest_envelope.check_approvals().unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateApproval);
	}

	#[test]
	fn try_from_slice_compat_works() {
		let bytes = std::fs::read("./fixtures/old_manifest").unwrap();

		let manifest = ManifestV1::try_from_slice_compat(&bytes).unwrap();

		assert_eq!(manifest.namespace.name, "quit-coding-to-vape");
		assert_eq!(manifest.pivot.bridge_config.len(), 0);
	}

	#[test]
	fn versioned_manifest_v0_fixture_decodes_and_hashes_via_borsh() {
		let bytes = std::fs::read("./fixtures/old_manifest").unwrap();

		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();
		match &decoded {
			VersionedManifest::V0(m) => {
				assert_eq!(m.namespace.name, "quit-coding-to-vape");
			}
			other => panic!("expected V0, got {other:?}"),
		}

		// v0 hashes via Borsh of the v0 type, not via re-encoding.
		match decoded {
			VersionedManifest::V0(m) => {
				let expected = qos_crypto::sha_256(&borsh::to_vec(&m).unwrap());
				assert_eq!(
					VersionedManifest::V0(m.clone()).qos_hash(),
					expected
				);
			}
			_ => unreachable!(),
		}
	}

	#[test]
	fn versioned_manifest_v1_borsh_round_trips_and_hashes_via_borsh() {
		use borsh::BorshDeserialize;

		let (manifest, ..) = get_manifest();
		let bytes = borsh::to_vec(&manifest).unwrap();
		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();

		assert!(matches!(decoded, VersionedManifest::V1(_)));
		// Hashes via Borsh, equal to direct ManifestV1 borsh hash.
		assert_eq!(decoded.qos_hash(), manifest.qos_hash());
		// And to a freshly-decoded ManifestV1 borsh hash.
		let direct = ManifestV1::try_from_slice(&bytes).unwrap();
		assert_eq!(direct.qos_hash(), manifest.qos_hash());
	}

	#[test]
	fn versioned_manifest_v1_json_round_trips_and_hashes_via_borsh() {
		let (manifest, ..) = get_manifest();
		let bytes = serde_json::to_vec(&manifest).unwrap();
		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();

		assert!(matches!(decoded, VersionedManifest::V1(_)));
		assert_eq!(decoded.qos_hash(), manifest.qos_hash());
	}

	#[test]
	fn versioned_manifest_reads_v2_json_and_hashes_with_json() {
		let (manifest, ..) = get_manifest();
		let mut env = PivotEnv::new();
		env.insert(
			PivotEnvVarName::new("FOO".to_string()).unwrap(),
			PivotEnvValue::plain("bar".to_string()).unwrap(),
		)
		.unwrap();
		let v2 = ManifestV2 {
			version: ManifestVersion::V2,
			namespace: manifest.namespace,
			pivot: PivotConfigV2 {
				hash: manifest.pivot.hash,
				restart: manifest.pivot.restart,
				bridge_config: manifest.pivot.bridge_config,
				debug_mode: manifest.pivot.debug_mode,
				args: manifest.pivot.args,
				env,
			},
			manifest_set: manifest.manifest_set,
			share_set: manifest.share_set,
			enclave: manifest.enclave,
			patch_set: manifest.patch_set,
		};
		let bytes = qos_json::to_vec(&v2).unwrap();
		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();

		assert!(matches!(decoded, VersionedManifest::V2(_)));
		assert_eq!(
			decoded.qos_hash(),
			qos_crypto::sha_256(&qos_json::to_vec(&v2).unwrap())
		);
	}

	#[test]
	fn versioned_manifest_envelope_reads_v1_json_before_borsh_fallbacks() {
		let (manifest, members, _) = get_manifest();
		let manifest_hash = manifest.qos_hash();
		let approvals = members
			.into_iter()
			.take(2)
			.map(|(pair, member)| Approval {
				signature: pair.sign(&manifest_hash).unwrap(),
				member,
			})
			.collect();
		let envelope = ManifestEnvelopeV1 {
			manifest,
			manifest_set_approvals: approvals,
			share_set_approvals: vec![],
		};

		let json_bytes = serde_json::to_vec(&envelope).unwrap();
		let decoded =
			VersionedManifestEnvelope::try_from_slice_compat(&json_bytes)
				.unwrap();
		assert!(matches!(decoded, VersionedManifestEnvelope::V1(_)));
		decoded.check_approvals().unwrap();

		let borsh_bytes = borsh::to_vec(&envelope).unwrap();
		let decoded =
			VersionedManifestEnvelope::try_from_slice_compat(&borsh_bytes)
				.unwrap();
		assert!(matches!(decoded, VersionedManifestEnvelope::V1(_)));
		decoded.check_approvals().unwrap();
	}

	#[test]
	fn versioned_manifest_envelope_reads_v2_json_and_hashes_with_json() {
		let (manifest, members, _) = get_manifest();
		let v2 = ManifestV2 {
			version: ManifestVersion::V2,
			namespace: manifest.namespace,
			pivot: PivotConfigV2 {
				hash: manifest.pivot.hash,
				restart: manifest.pivot.restart,
				bridge_config: manifest.pivot.bridge_config,
				debug_mode: manifest.pivot.debug_mode,
				args: manifest.pivot.args,
				env: PivotEnv::new(),
			},
			manifest_set: manifest.manifest_set,
			share_set: manifest.share_set,
			enclave: manifest.enclave,
			patch_set: manifest.patch_set,
		};
		let manifest_hash =
			qos_crypto::sha_256(&qos_json::to_vec(&v2).unwrap());
		let approvals = members
			.into_iter()
			.take(2)
			.map(|(pair, member)| Approval {
				signature: pair.sign(&manifest_hash).unwrap(),
				member,
			})
			.collect();
		let envelope = ManifestEnvelopeV2 {
			manifest: v2,
			manifest_set_approvals: approvals,
			share_set_approvals: vec![],
		};
		let bytes = qos_json::to_vec(&envelope).unwrap();
		let decoded =
			VersionedManifestEnvelope::try_from_slice_compat(&bytes).unwrap();

		assert!(matches!(decoded, VersionedManifestEnvelope::V2(_)));
		assert_eq!(decoded.qos_hash(), manifest_hash);
		decoded.check_approvals().unwrap();
		assert_eq!(decoded.to_storage_vec().unwrap(), bytes);
	}
}

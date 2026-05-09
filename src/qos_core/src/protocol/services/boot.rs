//! Standard boot logic and types.

use qos_crypto::sha_256;
use qos_nsm::types::NsmResponse;
use qos_p256::P256Pair;

use crate::protocol::{services::attestation, ProtocolError, ProtocolState};

pub mod env;
pub mod manifest;
pub use env::{
	PivotEnv, PivotEnvValue, PivotEnvVarName, MAX_PIVOT_ENV_NAME_LEN,
	MAX_PIVOT_ENV_VALUE_LEN, MAX_PIVOT_ENV_VARS,
};
pub use manifest::v0::{
	Approval, ManifestEnvelopeV0, ManifestSet, ManifestV0, MemberPubKey,
	Namespace, NitroConfig, PatchSet, PivotConfigV0, QuorumMember,
	RestartPolicy, ShareSet,
};
pub use manifest::v1::{
	BridgeConfig, ManifestEnvelopeV1, ManifestV1, PivotConfigV1,
	DEFAULT_APP_HOST_IP, DEFAULT_APP_HOST_PORT,
};
pub use manifest::v2::{ManifestEnvelopeV2, ManifestV2, PivotConfigV2};
pub use manifest::{
	ManifestVersion, VersionedManifest, VersionedManifestEnvelope,
};

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
	use serde_json::Value;

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

	fn manifest_v2_from_v1(manifest: ManifestV1, env: PivotEnv) -> ManifestV2 {
		ManifestV2 {
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
		}
	}

	fn numericize_field(obj: &mut Value, path: &[&str]) {
		let mut current = obj;
		for key in &path[..path.len() - 1] {
			current = current.get_mut(*key).unwrap_or_else(|| {
				panic!("missing key {key} in path {path:?}")
			});
		}

		let leaf = current
			.get_mut(path[path.len() - 1])
			.unwrap_or_else(|| panic!("missing leaf in path {path:?}"));
		let num = match leaf {
			Value::String(s) => s.parse::<u64>().unwrap_or_else(|_| {
				panic!("leaf is not a decimal string: {s}")
			}),
			Value::Number(n) => n.as_u64().unwrap_or_else(|| {
				panic!("leaf is not an unsigned number: {n}")
			}),
			other => {
				panic!("leaf is not a string for path {path:?}: {other:?}")
			}
		};
		*leaf = Value::Number(num.into());
	}

	fn numericize_manifest_json(manifest: &mut Value) {
		for path in [
			["namespace", "nonce"],
			["manifestSet", "threshold"],
			["shareSet", "threshold"],
			["patchSet", "threshold"],
		] {
			numericize_field(manifest, &path);
		}

		for bridge in manifest["pivot"]["bridgeConfig"]
			.as_array_mut()
			.expect("pivot.bridgeConfig should be an array")
		{
			numericize_field(bridge, &["port"]);
		}
	}

	fn assert_json_number(obj: &Value, path: &[&str]) {
		let mut current = obj;
		for key in path {
			current = match current {
				Value::Object(map) => map.get(*key).unwrap_or_else(|| {
					panic!("missing key {key} in path {path:?}")
				}),
				Value::Array(values) => {
					let index = key.parse::<usize>().unwrap_or_else(|_| {
						panic!("invalid array index {key} in path {path:?}")
					});
					values.get(index).unwrap_or_else(|| {
						panic!("missing index {index} in path {path:?}")
					})
				}
				other => {
					panic!("cannot descend into non-container value {other:?}")
				}
			};
		}
		assert!(
			current.is_number(),
			"expected JSON number at {path:?}, got {current:?}"
		);
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
	fn versioned_manifest_reads_legacy_v1_numeric_json() {
		let (mut manifest, ..) = get_manifest();
		manifest.pivot.bridge_config = vec![BridgeConfig::Server {
			port: 3000,
			host: "0.0.0.0".to_string(),
		}];
		manifest.pivot.debug_mode = true;
		manifest.pivot.args = vec!["--foo".to_string(), "bar".to_string()];

		let mut json = serde_json::to_value(&manifest).unwrap();
		numericize_manifest_json(&mut json);
		let bytes = serde_json::to_vec(&json).unwrap();

		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();
		match decoded {
			VersionedManifest::V1(decoded) => assert_eq!(decoded, manifest),
			other => {
				panic!("expected V1 for legacy numeric JSON, got {other:?}")
			}
		}
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
		let v2 = manifest_v2_from_v1(manifest, env);
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
	fn versioned_manifest_envelope_reads_legacy_v1_numeric_json() {
		let (mut manifest, members, _) = get_manifest();
		manifest.pivot.bridge_config = vec![BridgeConfig::Server {
			port: 3000,
			host: "0.0.0.0".to_string(),
		}];
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

		let mut json = serde_json::to_value(&envelope).unwrap();
		numericize_manifest_json(
			json.get_mut("manifest")
				.expect("envelope should have manifest field"),
		);
		let bytes = serde_json::to_vec(&json).unwrap();

		let decoded = VersionedManifestEnvelope::try_from_slice_compat(&bytes)
			.expect("legacy numeric envelope JSON should decode");
		match decoded {
			VersionedManifestEnvelope::V1(decoded) => {
				assert_eq!(decoded, envelope);
			}
			other => {
				panic!("expected V1 for legacy numeric JSON, got {other:?}")
			}
		}
	}

	#[test]
	fn versioned_manifest_envelope_v1_storage_uses_legacy_json_numbers() {
		let (mut manifest, members, _) = get_manifest();
		manifest.pivot.bridge_config = vec![BridgeConfig::Server {
			port: 3000,
			host: "0.0.0.0".to_string(),
		}];
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

		let bytes =
			VersionedManifestEnvelope::V1(envelope).to_storage_vec().unwrap();
		let json: Value = serde_json::from_slice(&bytes).unwrap();
		assert_json_number(&json, &["manifest", "namespace", "nonce"]);
		assert_json_number(&json, &["manifest", "manifestSet", "threshold"]);
		assert_json_number(&json, &["manifest", "shareSet", "threshold"]);
		assert_json_number(&json, &["manifest", "patchSet", "threshold"]);
		assert_json_number(
			&json,
			&["manifest", "pivot", "bridgeConfig", "0", "port"],
		);
	}

	#[test]
	fn versioned_manifest_envelope_v0_storage_uses_legacy_json_numbers() {
		let bytes = std::fs::read("./fixtures/old_manifest").unwrap();
		let manifest =
			match VersionedManifest::try_from_slice_compat(&bytes).unwrap() {
				VersionedManifest::V0(manifest) => manifest,
				other => panic!("expected v0 fixture decode, got {other:?}"),
			};
		let envelope = ManifestEnvelopeV0 {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};

		let bytes =
			VersionedManifestEnvelope::V0(envelope).to_storage_vec().unwrap();
		let json: Value = serde_json::from_slice(&bytes).unwrap();
		assert_json_number(&json, &["manifest", "namespace", "nonce"]);
		assert_json_number(&json, &["manifest", "manifestSet", "threshold"]);
		assert_json_number(&json, &["manifest", "shareSet", "threshold"]);
		assert_json_number(&json, &["manifest", "patchSet", "threshold"]);
	}

	#[test]
	fn versioned_manifest_envelope_reads_v2_json_and_hashes_with_json() {
		let (manifest, members, _) = get_manifest();
		let v2 = manifest_v2_from_v1(manifest, PivotEnv::new());
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

//! Artifact approval verification.

use std::collections::HashSet;

use qos_core::protocol::services::boot::ManifestSet;
use qos_p256::P256Public;

use super::{errors::PivotWasmError, protocol::PivotWasmArtifactEnvelope};

pub fn verify_artifact_envelope(
	envelope: &PivotWasmArtifactEnvelope,
	artifact_set: &ManifestSet,
) -> Result<(), PivotWasmError> {
	if artifact_set.threshold == 0 {
		return Err(PivotWasmError::Approval(
			"artifact approval threshold must be greater than zero".into(),
		));
	}

	let payload_hash = envelope.artifact.approval_payload_hash();
	let mut unique_approvers = HashSet::new();

	for approval in &envelope.approvals {
		if !artifact_set.members.contains(&approval.member) {
			return Err(PivotWasmError::Approval(format!(
				"approval from non-member {}",
				approval.member.alias
			)));
		}

		let public_key = P256Public::from_bytes(&approval.member.pub_key)
			.map_err(|e| {
				PivotWasmError::Approval(format!(
					"invalid approver public key for {}: {e:?}",
					approval.member.alias
				))
			})?;

		public_key.verify(&payload_hash, &approval.signature).map_err(|e| {
			PivotWasmError::Approval(format!(
				"invalid approval signature from {}: {e:?}",
				approval.member.alias
			))
		})?;

		if !unique_approvers.insert(approval.member.pub_key.clone()) {
			return Err(PivotWasmError::Approval(format!(
				"duplicate approval from {}",
				approval.member.alias
			)));
		}
	}

	if unique_approvers.len() < artifact_set.threshold as usize {
		return Err(PivotWasmError::Approval(format!(
			"not enough artifact approvals: got {}, need {}",
			unique_approvers.len(),
			artifact_set.threshold
		)));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use qos_core::protocol::services::boot::{
		Approval, ManifestSet, QuorumMember,
	};
	use qos_p256::P256Pair;

	use super::*;
	use crate::pivot_wasm::protocol::{
		PivotWasmArtifact, PivotWasmArtifactEnvelope, PivotWasmArtifactKind,
	};

	fn member(alias: &str, pair: &P256Pair) -> QuorumMember {
		QuorumMember {
			alias: alias.into(),
			pub_key: pair.public_key().to_bytes(),
		}
	}

	fn approval(
		artifact: &PivotWasmArtifact,
		pair: &P256Pair,
		member: QuorumMember,
	) -> Approval {
		Approval {
			signature: pair.sign(&artifact.approval_payload_hash()).unwrap(),
			member,
		}
	}

	#[test]
	fn threshold_approvals_verify() {
		let pair1 = P256Pair::generate().unwrap();
		let pair2 = P256Pair::generate().unwrap();
		let member1 = member("user1", &pair1);
		let member2 = member("user2", &pair2);
		let set = ManifestSet {
			threshold: 2,
			members: vec![member1.clone(), member2.clone()],
		};
		let artifact = PivotWasmArtifact::new(
			PivotWasmArtifactKind::Function,
			"reverse",
			"0.1.0",
			b"wasm",
			b"meta",
		);
		let envelope = PivotWasmArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				approval(&artifact, &pair1, member1),
				approval(&artifact, &pair2, member2),
			],
		};

		assert!(verify_artifact_envelope(&envelope, &set).is_ok());
	}

	#[test]
	fn duplicate_approver_is_rejected() {
		let pair = P256Pair::generate().unwrap();
		let member = member("user1", &pair);
		let set = ManifestSet { threshold: 2, members: vec![member.clone()] };
		let artifact = PivotWasmArtifact::new(
			PivotWasmArtifactKind::Policy,
			"policy",
			"0.1.0",
			b"wasm",
			b"meta",
		);
		let envelope = PivotWasmArtifactEnvelope {
			artifact: artifact.clone(),
			approvals: vec![
				approval(&artifact, &pair, member.clone()),
				approval(&artifact, &pair, member),
			],
		};

		assert!(matches!(
			verify_artifact_envelope(&envelope, &set),
			Err(PivotWasmError::Approval(_))
		));
	}
}

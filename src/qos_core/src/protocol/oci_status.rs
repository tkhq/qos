//! Non-secret Manifest V3 workload status records.

use std::{
	collections::BTreeMap,
	sync::{Arc, RwLock},
};

use super::services::boot::{ManifestV3, OciDigest, OciName};

/// Status shared by the protocol server and workload manager.
pub(crate) type SharedOciStatus = Arc<RwLock<OciStatus>>;

/// The initial start of the Manifest V3 workload group.
#[derive(
	Debug,
	Clone,
	Copy,
	Default,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum OciStartup {
	/// No Manifest V3 boot was accepted: the enclave runs no OCI workloads.
	#[default]
	Inactive,
	/// A Manifest V3 boot was accepted, and not every workload has started.
	Starting,
	/// Every workload has started. The node is ready; later exits follow
	/// each workload's restart policy.
	Started,
	/// A workload failed to prepare or start, so the node boot failed.
	Failed,
}

#[derive(Debug, Default)]
pub(crate) struct OciStatus {
	pub(crate) startup: OciStartup,
	pub(crate) workloads: BTreeMap<OciName, OciWorkloadStatus>,
}

impl OciStatus {
	/// Record an accepted Manifest V3 boot: the group is starting, and each
	/// workload waits for its verified image. Only the first call counts.
	pub(crate) fn begin(&mut self, manifest: &ManifestV3) {
		if self.startup != OciStartup::Inactive {
			return;
		}
		self.startup = OciStartup::Starting;
		self.workloads = manifest
			.workloads
			.iter()
			.map(|(name, workload)| {
				(
					name.clone(),
					OciWorkloadStatus::pending(
						name.clone(),
						workload.image().digest().clone(),
					),
				)
			})
			.collect();
	}
}

/// Initial supported workload kind.
#[derive(
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum OciWorkloadType {
	/// OCI image workload.
	Oci,
}

/// Workload lifecycle state.
#[derive(
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum OciWorkloadState {
	/// Not started or waiting for restart backoff.
	Waiting,
	/// Process is executing.
	Running,
	/// Process exited and will not restart.
	Terminated,
}

/// Signed image verification state.
#[derive(
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum OciVerificationState {
	/// Artifact has not yet been verified.
	Pending,
	/// Artifact passed verification.
	Verified,
	/// Artifact verification failed.
	Failed,
}

/// Exact process termination result.
#[derive(
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum OciTermination {
	/// Normal process exit code.
	ExitCode(#[serde(with = "qos_json::string_or_numeric")] i32),
	/// Terminating signal number.
	Signal(#[serde(with = "qos_json::string_or_numeric")] i32),
}

/// Public status for one required OCI workload.
#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciWorkloadStatus {
	/// Signed workload name.
	pub name: OciName,
	/// Initial workload type.
	pub workload_type: OciWorkloadType,
	/// Current lifecycle state.
	pub state: OciWorkloadState,
	/// Completed restart attempts.
	#[serde(with = "qos_json::string_or_numeric")]
	pub restart_count: u64,
	/// Last bounded, non-secret error.
	pub last_error: Option<String>,
	/// Signed OCI image-manifest digest.
	pub image_digest: OciDigest,
	/// Image verification state.
	pub image_verification: OciVerificationState,
	/// Parent-QOS PID while running.
	#[serde(default, with = "qos_json::string_or_numeric")]
	pub pid: Option<i32>,
	/// Active restart delay while waiting.
	#[serde(default, with = "qos_json::string_or_numeric")]
	pub backoff: Option<u64>,
	/// Exact result for a non-restarting workload.
	pub termination: Option<OciTermination>,
}

impl OciWorkloadStatus {
	/// Create the pre-verification waiting record.
	#[must_use]
	pub fn pending(name: OciName, image_digest: OciDigest) -> Self {
		Self {
			name,
			workload_type: OciWorkloadType::Oci,
			state: OciWorkloadState::Waiting,
			restart_count: 0,
			last_error: None,
			image_digest,
			image_verification: OciVerificationState::Pending,
			pid: None,
			backoff: None,
			termination: None,
		}
	}

	/// Record verified image content.
	pub fn verified(&mut self) {
		self.image_verification = OciVerificationState::Verified;
	}

	/// Record a running process, started after `restart_count` restart
	/// attempts.
	pub fn running(&mut self, pid: i32, restart_count: u64) {
		self.state = OciWorkloadState::Running;
		self.restart_count = restart_count;
		self.pid = Some(pid);
		self.backoff = None;
		self.termination = None;
		self.last_error = None;
	}

	/// Record restart waiting and its next delay.
	pub fn restarting(&mut self, count: u64, delay: std::time::Duration) {
		self.state = OciWorkloadState::Waiting;
		self.restart_count = count;
		self.pid = None;
		self.backoff = Some(delay.as_millis().try_into().unwrap_or(u64::MAX));
	}

	/// Record permanent process termination.
	pub fn terminated(&mut self, termination: OciTermination) {
		self.state = OciWorkloadState::Terminated;
		self.pid = None;
		self.backoff = None;
		self.termination = Some(termination);
	}

	/// Record a bounded, non-secret failure description.
	pub fn failed(
		&mut self,
		error: &impl std::fmt::Display,
		verification: bool,
	) {
		if verification {
			self.image_verification = OciVerificationState::Failed;
		}
		self.last_error = Some(error.to_string().chars().take(512).collect());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::services::boot::manifest::v3::minimal_manifest;

	#[test]
	fn a_boot_begins_the_group_once() {
		let digest: OciDigest =
			format!("sha256:{}", "0".repeat(64)).try_into().unwrap();
		let manifest = minimal_manifest(&digest);
		let name: OciName = "app".to_owned().try_into().unwrap();

		let mut status = OciStatus::default();
		assert_eq!(status.startup, OciStartup::Inactive);
		status.begin(&manifest);
		assert_eq!(status.startup, OciStartup::Starting);
		let pending = status.workloads[&name].clone();
		assert_eq!(pending.state, OciWorkloadState::Waiting);
		assert_eq!(pending.image_verification, OciVerificationState::Pending);

		status.startup = OciStartup::Started;
		status.workloads.get_mut(&name).unwrap().running(7, 2);
		status.begin(&manifest);
		assert_eq!(status.startup, OciStartup::Started);
		let running = &status.workloads[&name];
		assert_eq!((running.pid, running.restart_count), (Some(7), 2));
	}

	#[test]
	fn canonical_json_status_roundtrip() {
		let mut status = OciWorkloadStatus::pending(
			"postgres".to_owned().try_into().unwrap(),
			format!("sha256:{}", "0".repeat(64)).try_into().unwrap(),
		);
		status.verified();
		status.terminated(OciTermination::ExitCode(0));
		let encoded = qos_json::to_vec(&status).unwrap();
		assert_eq!(
			qos_json::from_slice::<OciWorkloadStatus>(&encoded).unwrap(),
			status
		);
	}
}

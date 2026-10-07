//! Untrusted host-provided peer list. The guest does not verify it.

use std::{collections::BTreeSet, fs, io, net::IpAddr, path::PathBuf};

/// Guest file holding the peer IP addresses as a newline-separated list.
pub const UNTRUSTED_PEERS_FILE: &str = "/run/qos/untrusted_host_provided_peers";

/// The published peer list.
pub(crate) struct Peers {
	ips: BTreeSet<IpAddr>,
	path: PathBuf,
}

impl Peers {
	pub(crate) fn new(path: PathBuf) -> Self {
		Self { ips: BTreeSet::new(), path }
	}

	/// Apply `change` and publish the result. On error the list is unchanged.
	pub(crate) fn update(
		&mut self,
		change: impl FnOnce(&mut BTreeSet<IpAddr>),
	) -> io::Result<()> {
		let mut ips = self.ips.clone();
		change(&mut ips);
		if let Some(directory) = self.path.parent() {
			fs::create_dir_all(directory)?;
		}
		// Rename over the file so readers never see a partial list.
		let temporary = self.path.with_extension("tmp");
		fs::write(
			&temporary,
			ips.iter().map(|ip| ip.to_string() + "\n").collect::<String>(),
		)?;
		fs::rename(temporary, &self.path)?;
		self.ips = ips;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		handles::Handles,
		protocol::{
			ProtocolError, ProtocolPhase, ProtocolState,
			msg::ProtocolMsg,
			processor::ProtocolProcessor,
			services::boot::{
				ManifestBuilder, ManifestEnvelopeV2, ManifestSet, Namespace,
				NitroConfig, PeerDiscoveryConfig, ShareSet, VersionedManifest,
			},
		},
		server::RequestProcessor,
	};
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	#[tokio::test(flavor = "multi_thread")]
	async fn host_adds_and_removes_peers_once_enabled() {
		let root =
			PathWrapper::from(std::env::temp_dir().join(format!(
				"qos-peer-discovery-test-{}",
				std::process::id()
			)));
		fs::create_dir_all(&root).unwrap();
		let path = |name: &str| root.join(name).display().to_string();
		let handles = Handles::new(
			path("ephemeral"),
			path("quorum"),
			path("manifest"),
			path("pivot"),
		);
		let mut state = ProtocolState::new(
			Box::new(MockNsm::new()),
			handles.clone(),
			Some(ProtocolPhase::QuorumKeyProvisioned),
		);
		state.peers = Peers::new(root.join("peers"));
		let processor = ProtocolProcessor::new(state.shared());
		let send = async |request: &[u8]| {
			ProtocolMsg::from_wire_any(&processor.process(request).await)
				.unwrap()
		};
		let add = br#"{"addPeersRequest":{"ips":["2001:db8::1","192.0.2.1","192.0.2.1"]}}"#;
		let remove = br#"{"removePeersRequest":{"ips":["192.0.2.1"]}}"#;
		let peers = || fs::read_to_string(root.join("peers")).unwrap();

		assert!(matches!(
			send(add).await,
			ProtocolMsg::ProtocolErrorResponse(ProtocolError::NoMatchingRoute(
				_
			))
		));

		let VersionedManifest::V2(manifest) = ManifestBuilder::v2()
			.namespace(Namespace {
				name: "peer-test".into(),
				nonce: 1,
				quorum_key: vec![],
			})
			.pivot_hash([0; 32])
			.manifest_set(ManifestSet { threshold: 1, members: vec![] })
			.share_set(ShareSet { threshold: 1, members: vec![] })
			.enclave(NitroConfig {
				pcr0: vec![],
				pcr1: vec![],
				pcr2: vec![],
				pcr3: vec![],
				aws_root_certificate: vec![],
				qos_commit: String::new(),
			})
			.peer_discovery(PeerDiscoveryConfig { enabled: true })
			.build()
			.unwrap()
		else {
			unreachable!()
		};
		handles
			.put_manifest_envelope(ManifestEnvelopeV2 {
				manifest,
				manifest_set_approvals: vec![],
				share_set_approvals: vec![],
			})
			.unwrap();

		for _ in 0..2 {
			assert_eq!(send(add).await, ProtocolMsg::AddPeersResponse);
			assert_eq!(peers(), "192.0.2.1\n2001:db8::1\n");
		}
		for _ in 0..2 {
			assert_eq!(send(remove).await, ProtocolMsg::RemovePeersResponse);
			assert_eq!(peers(), "2001:db8::1\n");
		}
	}
}

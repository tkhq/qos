//! Quorum Key provisioning logic and types.
use crate::protocol::{ProtocolError, ProtocolPhase, ProtocolState};

type Secret = Vec<u8>;
type Share = Vec<u8>;
type Shares = Vec<Share>;

/// Shamir Secret builder.
pub(crate) struct SecretBuilder {
	shares: Shares,
}

impl SecretBuilder {
	/// Create a instance of [`Self`].
	pub fn new() -> Self {
		Self { shares: Vec::new() }
	}

	/// Add a share to later be used to reconstruct.
	pub(crate) fn add_share(
		&mut self,
		share: Share,
	) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}

		self.shares.push(share);
		Ok(())
	}

	/// Attempt to reconstruct the secret from the
	pub(crate) fn build(&self) -> Result<Secret, ProtocolError> {
		let secret = qos_crypto::shamir::shares_reconstruct(&self.shares);

		if secret.is_empty() {
			return Err(ProtocolError::ReconstructionError);
		}

		Ok(secret)
	}

	/// The count of shares.
	pub(crate) fn count(&self) -> usize {
		self.shares.len()
	}

	fn clear(&mut self) {
		self.shares = vec![];
	}
}

pub(in crate::protocol) fn provision(
	encrypted_share: &[u8],
	state: &mut ProtocolState,
) -> Result<bool, ProtocolError> {
	let ephemeral_key = state.handles.get_ephemeral_key()?;

	let share = ephemeral_key
		.envelope_decrypt(encrypted_share)
		.map_err(|_| ProtocolError::DecryptionFailed)?;

	let mut provisioner = state.provisioner.write().unwrap();
	provisioner.add_share(share)?;

	let manifest = state.handles.get_manifest_envelope()?.manifest;
	let quorum_threshold = manifest.quorum_set.threshold as usize;
	if provisioner.count() < quorum_threshold {
		// Nothing else to do if we don't have the threshold to reconstruct
		return Ok(false);
	}

	let private_key_der = provisioner.build()?;
	let pair = qos_crypto::RsaPair::from_der(&private_key_der)
		.map_err(|_| ProtocolError::InvalidPrivateKey)?;
	let public_key_der = pair.public_key_to_der()?;

	if public_key_der != manifest.quorum_key {
		// We did not construct the intended key
		// Something went wrong, so clear the existing shares just to be
		// careful.
		provisioner.clear();
		return Err(ProtocolError::ReconstructionError);
	}

	state.handles.put_quorum_key(&pair)?;

	ProtocolPhase::update(&state.phase, ProtocolPhase::QuorumKeyProvisioned)?;
	Ok(true)
}

#[cfg(test)]
mod test {
	use std::{
		path::Path,
		sync::{Arc, RwLock},
	};

	use qos_crypto::{sha_256, shamir::shares_generate, RsaPair};

	use crate::{
		client::Client,
		handles::Handles,
		io::SocketAddress,
		protocol::{
			attestor::mock::MockNsm,
			services::{
				boot::{
					Manifest, ManifestEnvelope, Namespace, NitroConfig,
					PivotConfig, QuorumSet, RestartPolicy,
				},
				provision::{self, provision},
			},
			ProtocolError, ProtocolPhase, ProtocolState,
		},
	};

	fn setup(
		eph_file: &str,
		quorum_file: &str,
		manifest_file: &str,
	) -> (RsaPair, RsaPair, usize, ProtocolState) {
		let handles = Handles::new(
			eph_file.to_string(),
			quorum_file.to_string(),
			manifest_file.to_string(),
			"pivot".to_string(),
		);
		// 1) Create and write eph key
		let eph_pair = RsaPair::generate().unwrap();
		handles.put_ephemeral_key(&eph_pair).unwrap();

		// 2) Create and write manifest with threshold and quorum key
		let quorum_pair = RsaPair::generate().unwrap();
		let threshold = 3usize;
		let pivot = b"this is a pivot binary";
		let manifest = Manifest {
			namespace: Namespace { nonce: 420, name: "vape-space".to_string() },
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![2; 32],
				pcr2: vec![0; 32],
				aws_root_certificate: b"cert lord".to_vec(),
			},
			pivot: PivotConfig {
				hash: sha_256(pivot),
				restart: RestartPolicy::Always,
				args: vec![],
			},
			quorum_key: quorum_pair.public_key_to_der().unwrap(),
			quorum_set: QuorumSet {
				threshold: threshold.try_into().unwrap(),
				members: vec![],
			},
		};
		let manifest_envelope =
			ManifestEnvelope { manifest, approvals: vec![] };
		handles.put_manifest_envelope(&manifest_envelope).unwrap();

		// 3) Create state with eph key and manifest
		let state = ProtocolState {
			provisioner: Arc::new(RwLock::new(provision::SecretBuilder::new())),
			attestor: Arc::new(Box::new(MockNsm)),
			phase: Arc::new(RwLock::new(ProtocolPhase::WaitingForQuorumShards)),
			handles,
			app_client: Client::new(SocketAddress::new_unix("./never.sock")),
		};

		(quorum_pair, eph_pair, threshold, state)
	}

	#[test]
	fn provision_works() {
		let quorum_file = "./provision_works.quorum.key";
		let eph_file = "./provision_works.eph.key";
		let manifest_file = "./provision_works.manifest";

		let (quorum_pair, eph_pair, threshold, mut state) =
			setup(eph_file, quorum_file, manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.private_key_to_der().unwrap();
		let encrypted_shares: Vec<_> =
			shares_generate(&quorum_key, 4, threshold as usize)
				.iter()
				.map(|shard| eph_pair.envelope_encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for share in &encrypted_shares[..threshold - 1] {
			assert_eq!(provision(share, &mut state), Ok(false));
			assert!(!Path::new(quorum_file).exists());
			assert_eq!(
				*state.phase.read().unwrap(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) For shard K, call provision, make sure returns true and writes
		// quorum key as a ready only file
		let share = &encrypted_shares[threshold];
		assert_eq!(provision(share, &mut state), Ok(true));
		let quorum_key = std::fs::read(quorum_file).unwrap();
		assert_eq!(quorum_key, quorum_pair.private_key_to_pem().unwrap());
		assert_eq!(
			*state.phase.read().unwrap(),
			ProtocolPhase::QuorumKeyProvisioned
		);

		std::fs::remove_file(eph_file).unwrap();
		std::fs::remove_file(quorum_file).unwrap();
		std::fs::remove_file(manifest_file).unwrap();
	}

	#[test]
	fn provision_rejects_the_wrong_key() {
		let eph_file = "./provision_rejects_the_wrong_key.eph.key";
		let quorum_file = "./provision_rejects_the_wrong_key.quorum.key";
		let manifest_file = "./provision_rejects_the_wrong_key.manifest";

		let (_quorum_pair, eph_pair, threshold, mut state) =
			setup(eph_file, quorum_file, manifest_file);

		// 4) Create shards of a RANDOM KEY and encrypt them to eph key
		let random_key =
			RsaPair::generate().unwrap().private_key_to_der().unwrap();
		let encrypted_shares: Vec<_> =
			shares_generate(&random_key, 4, threshold as usize)
				.iter()
				.map(|shard| eph_pair.envelope_encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for share in &encrypted_shares[..threshold - 1] {
			assert_eq!(provision(share, &mut state), Ok(false));
			assert!(!Path::new(quorum_file).exists());
			assert_eq!(
				*state.phase.read().unwrap(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) Add Kth shard of the random key
		let share = &encrypted_shares[threshold];
		assert_eq!(
			provision(share, &mut state),
			Err(ProtocolError::ReconstructionError)
		);
		assert!(!Path::new(quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(
			*state.phase.read().unwrap(),
			ProtocolPhase::WaitingForQuorumShards
		);

		std::fs::remove_file(eph_file).unwrap();
		std::fs::remove_file(manifest_file).unwrap();
	}

	#[test]
	fn provision_rejects_if_a_shard_is_invalid() {
		let eph_file = "./provision_rejects_if_a_shard_is_invalid.eph.key";
		let quorum_file =
			"./provision_rejects_if_a_shard_is_invalid.quorum.key";
		let manifest_file =
			"./provision_rejects_if_a_shard_is_invalid.manifest";
		let (quorum_pair, eph_pair, threshold, mut state) =
			setup(eph_file, quorum_file, manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.private_key_to_der().unwrap();
		let encrypted_shares: Vec<_> =
			shares_generate(&quorum_key, 4, threshold as usize)
				.iter()
				.map(|shard| eph_pair.envelope_encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for share in &encrypted_shares[..threshold - 1] {
			assert_eq!(provision(share, &mut state), Ok(false));
			assert!(!Path::new(quorum_file).exists());
			assert_eq!(
				*state.phase.read().unwrap(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) Add a bogus shard as the Kth shard
		let bogus_share = &[69u8; 2349];
		let encrypted_bogus_share =
			eph_pair.envelope_encrypt(bogus_share).unwrap();
		assert_eq!(
			provision(&encrypted_bogus_share, &mut state),
			Err(ProtocolError::InvalidPrivateKey)
		);
		assert!(!Path::new(quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(
			*state.phase.read().unwrap(),
			ProtocolPhase::WaitingForQuorumShards
		);

		std::fs::remove_file(eph_file).unwrap();
		std::fs::remove_file(manifest_file).unwrap();
	}
}

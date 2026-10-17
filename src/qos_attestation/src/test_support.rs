//! Test fixtures shared by the modules' unit tests.

use std::{
	collections::BTreeMap,
	path::{Path, PathBuf},
	sync::{
		Mutex,
		atomic::{AtomicU64, Ordering},
	},
};

use aws_nitro_enclaves_cose::{
	CoseSign1,
	crypto::{
		Hash, MessageDigest, SignatureAlgorithm, SigningPrivateKey,
		SigningPublicKey,
	},
	error::CoseError,
	header_map::HeaderMap,
};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use qos_core::protocol::services::boot::{
	ManifestBuilder, ManifestEnvelope, ManifestEnvelopeV0, ManifestEnvelopeV2,
	ManifestSet, ManifestV0, MemberPubKey, Namespace, NitroConfig, PatchSet,
	PivotConfigV0, QuorumMember, RestartPolicy, ShareSet, VersionedManifest,
	VersionedManifestEnvelope,
};
use qos_nsm::{
	NsmProvider,
	mock::MockNsm,
	nitro::{self, AttestError},
	types::{NsmRequest, NsmResponse},
};
use qos_p256::P256Pair;
use qos_test_primitives::PathWrapper;
use serde_bytes::ByteBuf;

use crate::AttestationInputs;

/// Deterministic inputs; different `n` give different keys, hashes and PCRs.
pub(crate) fn sample_inputs(n: u8) -> AttestationInputs {
	let pcr = |i: u8| vec![n.wrapping_mul(4).wrapping_add(i); 48];
	AttestationInputs {
		ephemeral_public_key: vec![n; 130],
		manifest_hash: [n; 32],
		pcr0: pcr(0),
		pcr1: pcr(1),
		pcr2: pcr(2),
		pcr3: pcr(3),
	}
}

fn live_commitment(inputs: &AttestationInputs) -> Vec<u8> {
	nitro::expected_manifest_commitment_pcr::<nitro::Live>(
		&inputs.manifest_hash,
		&inputs.ephemeral_public_key,
	)
	.unwrap()
	.to_vec()
}

fn manifest_only_commitment(inputs: &AttestationInputs) -> Vec<u8> {
	nitro::expected_manifest_only_commitment_pcr(&inputs.manifest_hash)
		.unwrap()
		.to_vec()
}

/// A mock NSM in the state QOS leaves it in after booting with `inputs`:
/// PCR0-3 measured, the live commitment in PCR17 and, if asked, the
/// manifest-only commitment in PCR18.
pub(crate) fn enclave_mock_nsm(
	inputs: &AttestationInputs,
	pcr18: bool,
) -> MockNsm {
	let nsm = MockNsm::new()
		.with_pcr(0, inputs.pcr0.clone())
		.with_pcr(1, inputs.pcr1.clone())
		.with_pcr(2, inputs.pcr2.clone())
		.with_pcr(3, inputs.pcr3.clone())
		.with_pcr(17, live_commitment(inputs));
	if pcr18 { nsm.with_pcr(18, manifest_only_commitment(inputs)) } else { nsm }
}

fn unsigned_doc(inputs: &AttestationInputs) -> AttestationDoc {
	let mut pcrs = BTreeMap::new();
	for index in 0..usize::from(nitro::ATTESTABLE_PCR_COUNT) {
		pcrs.insert(index, ByteBuf::from(vec![0u8; nitro::PCR_SHA384_LEN]));
	}
	for index in [16, 17, 18] {
		pcrs.insert(
			index,
			ByteBuf::from(nitro::MANIFEST_COMMITMENT_INITIAL_PCR.to_vec()),
		);
	}
	for (index, pcr) in [&inputs.pcr0, &inputs.pcr1, &inputs.pcr2, &inputs.pcr3]
		.into_iter()
		.enumerate()
	{
		pcrs.insert(index, ByteBuf::from(pcr.clone()));
	}
	AttestationDoc {
		module_id: "test-module".into(),
		digest: Digest::SHA384,
		timestamp: 1,
		pcrs,
		certificate: ByteBuf::new(),
		cabundle: vec![],
		public_key: Some(ByteBuf::from(inputs.ephemeral_public_key.clone())),
		user_data: Some(ByteBuf::from(inputs.manifest_hash.to_vec())),
		nonce: None,
	}
}

/// A parsed, unsigned document that binds correctly to `inputs`.
pub(crate) fn bound_doc(
	inputs: &AttestationInputs,
	pcr18: bool,
) -> AttestationDoc {
	let mut doc = unsigned_doc(inputs);
	doc.pcrs.insert(17, ByteBuf::from(live_commitment(inputs)));
	if pcr18 {
		doc.pcrs.insert(18, ByteBuf::from(manifest_only_commitment(inputs)));
	}
	doc
}

/// A document from before provisioning: only the setup commitment (PCR16).
pub(crate) fn setup_key_doc(inputs: &AttestationInputs) -> AttestationDoc {
	let mut doc = unsigned_doc(inputs);
	let setup = nitro::expected_manifest_commitment_pcr::<nitro::Setup>(
		&inputs.manifest_hash,
		&inputs.ephemeral_public_key,
	)
	.unwrap();
	doc.pcrs.insert(16, ByteBuf::from(setup.to_vec()));
	doc
}

/// An NSM that records every request, delegating to a mock or replying
/// with a fixed response.
pub(crate) struct RecordingNsm {
	inner: Option<MockNsm>,
	reply: Option<NsmResponse>,
	requests: Mutex<Vec<NsmRequest>>,
}

impl RecordingNsm {
	pub(crate) fn new(inner: MockNsm) -> Self {
		Self { inner: Some(inner), reply: None, requests: Mutex::default() }
	}

	pub(crate) fn replying(reply: NsmResponse) -> Self {
		Self { inner: None, reply: Some(reply), requests: Mutex::default() }
	}

	pub(crate) fn requests(&self) -> Vec<NsmRequest> {
		self.requests.lock().unwrap().clone()
	}
}

impl NsmProvider for RecordingNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		self.requests.lock().unwrap().push(request.clone());
		match (&self.inner, &self.reply) {
			(Some(inner), _) => inner.nsm_process_request(request),
			(None, Some(reply)) => reply.clone(),
			(None, None) => unreachable!("constructed with one of them"),
		}
	}

	fn timestamp_ms(&self) -> Result<u64, AttestError> {
		self.inner.as_ref().map_or(Ok(1), MockNsm::timestamp_ms)
	}

	fn attestation_root_ca_der(&self) -> Vec<u8> {
		self.inner.as_ref().map_or_else(
			|| nitro::cert_from_pem(nitro::AWS_ROOT_CERT_PEM).unwrap(),
			MockNsm::attestation_root_ca_der,
		)
	}
}

/// A temporary directory, removed on drop.
pub(crate) struct TempDir(PathWrapper<PathBuf>);

impl TempDir {
	pub(crate) fn new(name: &str) -> Self {
		static NEXT: AtomicU64 = AtomicU64::new(0);
		let path = std::env::temp_dir().join(format!(
			"qos_attestation_{}_{name}_{}",
			std::process::id(),
			NEXT.fetch_add(1, Ordering::Relaxed)
		));
		std::fs::create_dir_all(&path).unwrap();
		Self(PathWrapper::from(path))
	}

	pub(crate) fn path(&self) -> &Path {
		&self.0
	}
}

pub(crate) fn write_key(dir: &TempDir, pair: &P256Pair) -> PathBuf {
	let path = dir.path().join("ephemeral.key");
	pair.to_hex_file(&path).unwrap();
	path
}

pub(crate) fn write_manifest(
	dir: &TempDir,
	envelope: &VersionedManifestEnvelope,
) -> PathBuf {
	let path = dir.path().join("manifest");
	std::fs::write(&path, envelope.to_storage_vec().unwrap()).unwrap();
	path
}

fn namespace(nonce: u32) -> Namespace {
	Namespace {
		name: "test/attestation".to_string(),
		nonce,
		quorum_key: vec![3; 65],
	}
}

fn members() -> Vec<QuorumMember> {
	vec![QuorumMember { alias: "alice".to_string(), pub_key: vec![2; 65] }]
}

fn nitro_config() -> NitroConfig {
	NitroConfig {
		pcr0: vec![0x10; 48],
		pcr1: vec![0x11; 48],
		pcr2: vec![0x12; 48],
		pcr3: vec![0x13; 48],
		aws_root_certificate: vec![],
		qos_commit: "test".to_string(),
	}
}

/// A v2 manifest envelope; different nonces give different manifest hashes.
pub(crate) fn v2_envelope_with_nonce(nonce: u32) -> VersionedManifestEnvelope {
	let VersionedManifest::V2(manifest) = ManifestBuilder::v2()
		.namespace(namespace(nonce))
		.pivot_hash([1; 32])
		.manifest_set(ManifestSet { threshold: 1, members: members() })
		.share_set(ShareSet { threshold: 1, members: members() })
		.enclave(nitro_config())
		.build()
		.unwrap()
	else {
		unreachable!("built as v2")
	};
	VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
		manifest,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	})
}

pub(crate) fn v2_envelope() -> VersionedManifestEnvelope {
	v2_envelope_with_nonce(1)
}

fn patch_set() -> PatchSet {
	PatchSet {
		threshold: 1,
		members: vec![MemberPubKey { pub_key: vec![2; 65] }],
	}
}

pub(crate) fn v1_envelope() -> VersionedManifestEnvelope {
	let VersionedManifest::V1(manifest) = ManifestBuilder::v1()
		.namespace(namespace(1))
		.pivot_hash([1; 32])
		.manifest_set(ManifestSet { threshold: 1, members: members() })
		.share_set(ShareSet { threshold: 1, members: members() })
		.enclave(nitro_config())
		.patch_set(patch_set())
		.build()
		.unwrap()
	else {
		unreachable!("built as v1")
	};
	VersionedManifestEnvelope::V1(ManifestEnvelope {
		manifest,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	})
}

pub(crate) fn v0_envelope() -> VersionedManifestEnvelope {
	VersionedManifestEnvelope::V0(ManifestEnvelopeV0 {
		manifest: ManifestV0 {
			namespace: namespace(1),
			pivot: PivotConfigV0 {
				hash: [1; 32],
				restart: RestartPolicy::Never,
				args: vec![],
			},
			manifest_set: ManifestSet { threshold: 1, members: members() },
			share_set: ShareSet { threshold: 1, members: members() },
			enclave: nitro_config(),
			patch_set: patch_set(),
		},
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	})
}

/// A document shaped like QEMU's: it binds correctly, but its signature,
/// certificate and CA bundle are all zero bytes, so no root can verify it.
pub(crate) fn qemu_shaped_document(
	inputs: &AttestationInputs,
	pcr18: bool,
) -> Vec<u8> {
	let mut doc = bound_doc(inputs, pcr18);
	doc.timestamp = 1_800_000_000_000;
	doc.certificate = ByteBuf::from(vec![0; 64]);
	doc.cabundle = vec![ByteBuf::from(vec![0; 64])];
	signed_with_zeros(&doc)
}

pub(crate) fn signed_with_zeros(doc: &AttestationDoc) -> Vec<u8> {
	CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &ZeroSigner)
		.unwrap()
		.as_bytes(false)
		.unwrap()
}

struct ZeroSigner;

impl SigningPrivateKey for ZeroSigner {
	fn sign(&self, _digest: &[u8]) -> Result<Vec<u8>, CoseError> {
		Ok(vec![0; 96])
	}
}

impl SigningPublicKey for ZeroSigner {
	fn get_parameters(
		&self,
	) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
		Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
	}

	fn verify(
		&self,
		_digest: &[u8],
		_signature: &[u8],
	) -> Result<bool, CoseError> {
		Ok(false)
	}
}

struct Sha2;

impl Hash for Sha2 {
	fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
		use sha2::Digest as _;
		match digest {
			MessageDigest::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
			MessageDigest::Sha384 => Ok(sha2::Sha384::digest(data).to_vec()),
			MessageDigest::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
		}
	}
}

/// An NSM that answers every attestation request with the same document.
#[cfg(feature = "cache")]
pub(crate) struct FixedDocNsm(pub(crate) Vec<u8>);

#[cfg(feature = "cache")]
impl NsmProvider for FixedDocNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		match request {
			NsmRequest::Attestation { .. } => {
				NsmResponse::Attestation { document: self.0.clone() }
			}
			_ => NsmResponse::Error(
				qos_nsm::types::NsmErrorCode::InvalidOperation,
			),
		}
	}

	fn timestamp_ms(&self) -> Result<u64, AttestError> {
		Ok(1_800_000_000_000)
	}
}

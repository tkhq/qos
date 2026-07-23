use std::time::Duration;

use qos_nsm::{
	NsmProvider,
	mock::{
		MOCK_ATTESTATION_DOC_TIMESTAMP, MOCK_ROOT_CERT_DER,
		MOCK_SECONDS_SINCE_EPOCH, MockNsm,
	},
	nitro,
	types::{NsmRequest, NsmResponse},
};
use qos_p256::P256Pair;

use super::{
	AttestationPolicy, ManifestCommitmentKind, ManifestEnvelopeTrust,
	ManifestPolicy, ManifestSet, NoncePolicy, ShareSet,
	VerificationExpectations, VerifyError, VersionedManifestEnvelope,
	check_attestation_freshness, verify_attestation_and_manifest_at_time,
	verify_attestation_and_manifest_envelope_at_time,
};
use crate::protocol::{
	ProtocolError,
	services::boot::{
		Approval, ManifestEnvelopeV2, ManifestV2, ManifestVersion, Namespace,
		NitroConfig, PivotConfigV2, PivotEnv, QuorumMember, RestartPolicy,
	},
};

fn test_member(alias: &str) -> (QuorumMember, P256Pair) {
	let pair = P256Pair::generate().expect("key should generate");
	let member = QuorumMember {
		alias: alias.to_string(),
		pub_key: pair.public_key().to_bytes(),
	};
	(member, pair)
}

fn test_envelope(
	manifest_set: ManifestSet,
	approvers: &[(QuorumMember, P256Pair)],
) -> VersionedManifestEnvelope {
	let manifest = ManifestV2 {
		version: ManifestVersion::V2,
		namespace: Namespace {
			name: "test-namespace".to_string(),
			nonce: 1,
			quorum_key: P256Pair::generate()
				.expect("key should generate")
				.public_key()
				.to_bytes(),
		},
		pivot: PivotConfigV2 {
			hash: [7; 32],
			restart: RestartPolicy::Never,
			bridge_config: vec![],
			debug_mode: false,
			args: vec![],
			env: PivotEnv::new(),
		},
		manifest_set,
		share_set: ShareSet {
			threshold: 1,
			members: vec![test_member("share-member").0],
		},
		enclave: NitroConfig {
			pcr0: vec![0; 48],
			pcr1: vec![1; 48],
			pcr2: vec![2; 48],
			pcr3: vec![3; 48],
			aws_root_certificate: vec![],
			qos_commit: "test-qos-commit".to_string(),
		},
		dns: None,
	};
	let mut envelope = ManifestEnvelopeV2 {
		manifest,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	};
	let manifest_hash =
		VersionedManifestEnvelope::V2(envelope.clone()).manifest_hash();
	envelope.manifest_set_approvals = approvers
		.iter()
		.map(|(member, pair)| Approval {
			signature: pair
				.sign(&manifest_hash)
				.expect("approval signing should not fail"),
			member: member.clone(),
		})
		.collect();
	VersionedManifestEnvelope::V2(envelope)
}

fn approved_envelope(
	approvers: &[(QuorumMember, P256Pair)],
) -> VersionedManifestEnvelope {
	let manifest_set = ManifestSet {
		threshold: u32::try_from(approvers.len())
			.expect("approver count should fit in u32"),
		members: approvers.iter().map(|(m, _)| m.clone()).collect(),
	};
	test_envelope(manifest_set, approvers)
}

struct TrustChain {
	envelope: VersionedManifestEnvelope,
	attestation_doc: Vec<u8>,
	ephemeral_key: P256Pair,
}

impl TrustChain {
	fn new() -> Self {
		Self::with_envelope(approved_envelope(&[test_member("member")]))
	}

	fn with_envelope(envelope: VersionedManifestEnvelope) -> Self {
		let ephemeral_key = P256Pair::generate().expect("key should generate");
		let user_data = envelope.manifest_hash().to_vec();
		let attestation_doc = attest(
			&envelope,
			Some(user_data),
			Some(ephemeral_key.public_key().to_bytes()),
			None,
		);
		Self { envelope, attestation_doc, ephemeral_key }
	}

	fn verify(
		&self,
		expectations: &VerificationExpectations,
	) -> Result<Vec<u8>, VerifyError> {
		verify_envelope(
			&self.attestation_doc,
			&self.envelope,
			ManifestCommitmentKind::Setup,
			expectations,
		)
	}
}

fn attestation_policy(
	commitment_kind: ManifestCommitmentKind,
) -> AttestationPolicy<'static> {
	AttestationPolicy::new(
		MOCK_ROOT_CERT_DER,
		Duration::from_secs(5 * 60),
		commitment_kind,
	)
}

fn mock_current_time() -> Duration {
	Duration::from_secs(MOCK_SECONDS_SINCE_EPOCH)
}

fn verify_envelope(
	attestation_doc: &[u8],
	manifest_envelope: &VersionedManifestEnvelope,
	commitment_kind: ManifestCommitmentKind,
	manifest_policy: &dyn ManifestPolicy,
) -> Result<Vec<u8>, VerifyError> {
	verify_attestation_and_manifest_envelope_at_time(
		attestation_doc,
		manifest_envelope,
		ManifestEnvelopeTrust::ManifestHash(manifest_envelope.manifest_hash()),
		&attestation_policy(commitment_kind),
		manifest_policy,
		mock_current_time(),
	)
	.map(|verified| verified.ephemeral_key.to_bytes())
}

fn attest(
	envelope: &VersionedManifestEnvelope,
	user_data: Option<Vec<u8>>,
	public_key: Option<Vec<u8>>,
	nonce: Option<Vec<u8>>,
) -> Vec<u8> {
	let manifest = envelope.clone().manifest();
	let enclave = manifest.enclave();
	let mut nsm = MockNsm::new()
		.with_pcr(0, enclave.pcr0.clone())
		.with_pcr(1, enclave.pcr1.clone())
		.with_pcr(2, enclave.pcr2.clone())
		.with_pcr(3, enclave.pcr3.clone());
	if let (Some(user_data), Some(public_key)) = (&user_data, &public_key) {
		let pcr16 = nitro::expected_manifest_commitment_pcr(
			ManifestCommitmentKind::Setup,
			user_data,
			public_key,
		)
		.expect("commitment PCR should compute");
		nsm = nsm.with_pcr(16, pcr16.to_vec());
	}
	match nsm.nsm_process_request(NsmRequest::Attestation {
		user_data,
		nonce,
		public_key,
	}) {
		NsmResponse::Attestation { document } => document,
		other => panic!("unexpected NSM response: {other:?}"),
	}
}

#[test]
fn manifest_verification_does_not_require_an_envelope() {
	let chain = TrustChain::new();
	let manifest = chain.envelope.clone().manifest();

	let verified = verify_attestation_and_manifest_at_time(
		&chain.attestation_doc,
		&manifest,
		&attestation_policy(ManifestCommitmentKind::Setup),
		&VerificationExpectations::new(),
		mock_current_time(),
	)
	.expect("manifest and attestation document should verify");

	assert_eq!(
		verified.ephemeral_key.to_bytes(),
		chain.ephemeral_key.public_key().to_bytes()
	);
	assert_eq!(verified.manifest_hash, manifest.manifest_hash());
	assert_eq!(verified.commitment_kind, ManifestCommitmentKind::Setup);
	assert_eq!(
		verified.attestation_timestamp_ms,
		MOCK_ATTESTATION_DOC_TIMESTAMP
	);
}

#[test]
fn full_expectations_pass_and_return_the_ephemeral_key() {
	let chain = TrustChain::new();
	let manifest = chain.envelope.clone().manifest();

	let key_bytes = chain
		.verify(
			&VerificationExpectations::new()
				.namespace_name(&manifest.namespace().name)
				.nonce(manifest.namespace().nonce)
				.quorum_key(manifest.namespace().quorum_key.clone())
				.pcr0(manifest.enclave().pcr0.clone())
				.pcr1(manifest.enclave().pcr1.clone())
				.pcr2(manifest.enclave().pcr2.clone())
				.pcr3(manifest.enclave().pcr3.clone())
				.pivot_hash(*manifest.pivot_hash())
				.manifest_hash(chain.envelope.manifest_hash())
				.manifest_set(manifest.manifest_set().clone())
				.share_set(manifest.share_set().clone()),
		)
		.expect("full expectations should verify");

	assert_eq!(key_bytes, chain.ephemeral_key.public_key().to_bytes());
}

#[test]
fn envelope_hash_anchor_allows_empty_additional_policy() {
	let chain = TrustChain::new();

	let key_bytes = chain
		.verify(&VerificationExpectations::new())
		.expect("trust chain should verify without expectations");

	assert_eq!(key_bytes, chain.ephemeral_key.public_key().to_bytes());
}

#[test]
fn each_supplied_expectation_is_checked() {
	let chain = TrustChain::new();

	for (expectations, name) in [
		(
			VerificationExpectations::new().namespace_name("other-namespace"),
			"namespace name",
		),
		(VerificationExpectations::new().nonce(1337), "nonce"),
		(VerificationExpectations::new().quorum_key(vec![9; 65]), "quorum key"),
		(VerificationExpectations::new().pcr0(vec![9; 48]), "pcr0"),
		(VerificationExpectations::new().pcr1(vec![9; 48]), "pcr1"),
		(VerificationExpectations::new().pcr2(vec![9; 48]), "pcr2"),
		(VerificationExpectations::new().pcr3(vec![9; 48]), "pcr3"),
		(VerificationExpectations::new().pivot_hash([9; 32]), "pivot hash"),
		(
			VerificationExpectations::new().manifest_hash([9; 32]),
			"manifest hash",
		),
		(
			VerificationExpectations::new()
				.manifest_set(ManifestSet::default()),
			"manifest set",
		),
		(
			VerificationExpectations::new().share_set(ShareSet::default()),
			"share set",
		),
	] {
		let err = chain
			.verify(&expectations)
			.expect_err(&format!("wrong {name} should fail"));
		let matched = matches!(
			(name, &err),
			("namespace name", VerifyError::NamespaceNameMismatch { .. })
				| ("nonce", VerifyError::NonceMismatch { .. })
				| ("quorum key", VerifyError::QuorumKeyMismatch { .. })
				| ("pcr0", VerifyError::PcrMismatch { index: 0, .. })
				| ("pcr1", VerifyError::PcrMismatch { index: 1, .. })
				| ("pcr2", VerifyError::PcrMismatch { index: 2, .. })
				| ("pcr3", VerifyError::PcrMismatch { index: 3, .. })
				| ("pivot hash", VerifyError::PivotHashMismatch { .. })
				| ("manifest hash", VerifyError::ManifestHashMismatch { .. })
				| ("manifest set", VerifyError::ManifestSetMismatch { .. })
				| ("share set", VerifyError::ShareSetMismatch { .. })
		);
		assert!(matched, "wrong {name} should map to its own error: {err:?}");
	}
}

#[test]
fn attestation_doc_user_data_must_match_the_manifest_hash() {
	let envelope = approved_envelope(&[test_member("member")]);
	let ephemeral_key = P256Pair::generate().expect("key should generate");
	let attestation_doc = attest(
		&envelope,
		Some(vec![9; 32]),
		Some(ephemeral_key.public_key().to_bytes()),
		None,
	);

	let err = verify_envelope(
		&attestation_doc,
		&envelope,
		ManifestCommitmentKind::Setup,
		&VerificationExpectations::new(),
	)
	.expect_err("mismatched user data should fail");

	assert!(matches!(err, VerifyError::AttestationManifest(_)));
}

#[test]
fn attestation_doc_pcrs_must_match_the_manifest() {
	let envelope = approved_envelope(&[test_member("member")]);
	let ephemeral_key = P256Pair::generate().expect("key should generate");
	let nsm = MockNsm::new();
	let attestation_doc =
		match nsm.nsm_process_request(NsmRequest::Attestation {
			user_data: Some(envelope.manifest_hash().to_vec()),
			nonce: None,
			public_key: Some(ephemeral_key.public_key().to_bytes()),
		}) {
			NsmResponse::Attestation { document } => document,
			other => panic!("unexpected NSM response: {other:?}"),
		};

	let err = verify_envelope(
		&attestation_doc,
		&envelope,
		ManifestCommitmentKind::Setup,
		&VerificationExpectations::new(),
	)
	.expect_err("attestation PCRs differing from the manifest should fail");

	assert!(matches!(err, VerifyError::AttestationManifest(_)));
}

#[test]
fn attestation_doc_must_verify_against_the_root_ca() {
	let chain = TrustChain::new();

	let policy = AttestationPolicy::new(
		MOCK_ROOT_CERT_DER,
		Duration::from_secs(5 * 60),
		ManifestCommitmentKind::Setup,
	);
	let err = verify_attestation_and_manifest_envelope_at_time(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestEnvelopeTrust::ManifestHash(chain.envelope.manifest_hash()),
		&policy,
		&VerificationExpectations::new(),
		Duration::from_secs(
			MOCK_SECONDS_SINCE_EPOCH + 60 * 60 * 24 * 365 * 100,
		),
	)
	.expect_err("expired certificate chain should fail");

	assert!(matches!(err, VerifyError::AttestationDoc(_)));
}

#[test]
fn manifest_commitment_pcr_is_checked_for_the_boot_phase() {
	let chain = TrustChain::new();

	let err = verify_envelope(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestCommitmentKind::Live,
		&VerificationExpectations::new(),
	)
	.expect_err("setup attestation should not verify as live");

	assert!(matches!(err, VerifyError::AttestationManifest(_)));
}

#[test]
fn manifest_set_approvals_must_meet_the_threshold() {
	let (member_a, pair_a) = test_member("member-a");
	let (member_b, _) = test_member("member-b");
	let chain = TrustChain::with_envelope(test_envelope(
		ManifestSet { threshold: 2, members: vec![member_a.clone(), member_b] },
		&[(member_a, pair_a)],
	));
	let err = chain
		.verify(&VerificationExpectations::new())
		.expect_err("sub-threshold approvals should fail");

	assert!(matches!(
		err,
		VerifyError::ManifestSetApprovals(ProtocolError::NotEnoughApprovals)
	));
}

#[test]
fn approvals_from_outside_the_manifest_set_fail() {
	let outsider = test_member("outsider");
	let chain = TrustChain::with_envelope(test_envelope(
		ManifestSet { threshold: 1, members: vec![test_member("insider").0] },
		&[outsider],
	));

	let err = chain
		.verify(&VerificationExpectations::new())
		.expect_err("approval from a non-member should fail");

	assert!(matches!(
		err,
		VerifyError::ManifestSetApprovals(ProtocolError::NotManifestSetMember)
	));
}

#[test]
fn envelope_must_match_the_external_trust_anchor() {
	let chain = TrustChain::new();

	let err = verify_attestation_and_manifest_envelope_at_time(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestEnvelopeTrust::ManifestHash([9; 32]),
		&attestation_policy(ManifestCommitmentKind::Setup),
		&VerificationExpectations::new(),
		mock_current_time(),
	)
	.expect_err("an untrusted manifest should fail");

	assert!(matches!(err, VerifyError::ManifestHashMismatch { .. }));
}

#[test]
fn envelope_manifest_set_anchor_is_order_independent() {
	let approvers = [test_member("member-a"), test_member("member-b")];
	let chain = TrustChain::with_envelope(approved_envelope(&approvers));
	let mut trusted_set = chain.envelope.manifest_set().clone();
	trusted_set.members.reverse();

	let verified = verify_attestation_and_manifest_envelope_at_time(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestEnvelopeTrust::ManifestSet(&trusted_set),
		&attestation_policy(ManifestCommitmentKind::Setup),
		&VerificationExpectations::new(),
		mock_current_time(),
	)
	.expect("member ordering should not affect manifest-set trust");

	assert_eq!(
		verified.ephemeral_key.to_bytes(),
		chain.ephemeral_key.public_key().to_bytes()
	);
}

#[test]
fn custom_manifest_policy_can_reject_a_manifest() {
	struct RejectManifest;

	impl ManifestPolicy for RejectManifest {
		fn verify(
			&self,
			_manifest: &super::VersionedManifest,
		) -> Result<(), VerifyError> {
			Err(VerifyError::ManifestPolicy("rejected for test".to_string()))
		}
	}

	let chain = TrustChain::new();
	let err = verify_envelope(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestCommitmentKind::Setup,
		&RejectManifest,
	)
	.expect_err("the custom manifest policy should run");

	assert!(matches!(err, VerifyError::ManifestPolicy(_)));
}

#[test]
fn absent_nonce_policy_rejects_a_nonce() {
	let envelope = approved_envelope(&[test_member("member")]);
	let ephemeral_key = P256Pair::generate().expect("key should generate");
	let attestation_doc = attest(
		&envelope,
		Some(envelope.manifest_hash().to_vec()),
		Some(ephemeral_key.public_key().to_bytes()),
		Some(vec![1, 2, 3]),
	);

	let err = verify_envelope(
		&attestation_doc,
		&envelope,
		ManifestCommitmentKind::Setup,
		&VerificationExpectations::new(),
	)
	.expect_err("a nonce should fail the default absent-nonce policy");

	assert!(matches!(
		err,
		VerifyError::AttestationManifest(
			nitro::AttestError::UnexpectedAttestationDocNonce
		)
	));
}

#[test]
fn exact_nonce_policy_requires_the_expected_nonce() {
	let envelope = approved_envelope(&[test_member("member")]);
	let ephemeral_key = P256Pair::generate().expect("key should generate");
	let nonce = vec![1, 2, 3];
	let attestation_doc = attest(
		&envelope,
		Some(envelope.manifest_hash().to_vec()),
		Some(ephemeral_key.public_key().to_bytes()),
		Some(nonce.clone()),
	);
	let policy = attestation_policy(ManifestCommitmentKind::Setup)
		.nonce(NoncePolicy::Exact(nonce));

	let verified = verify_attestation_and_manifest_envelope_at_time(
		&attestation_doc,
		&envelope,
		ManifestEnvelopeTrust::ManifestHash(envelope.manifest_hash()),
		&policy,
		&VerificationExpectations::new(),
		mock_current_time(),
	)
	.expect("the expected nonce should verify");

	assert_eq!(
		verified.ephemeral_key.to_bytes(),
		ephemeral_key.public_key().to_bytes()
	);
}

#[test]
fn stale_attestation_is_rejected() {
	let chain = TrustChain::new();
	let policy = AttestationPolicy::new(
		MOCK_ROOT_CERT_DER,
		Duration::from_secs(1),
		ManifestCommitmentKind::Setup,
	);

	let err = verify_attestation_and_manifest_envelope_at_time(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestEnvelopeTrust::ManifestHash(chain.envelope.manifest_hash()),
		&policy,
		&VerificationExpectations::new(),
		Duration::from_millis(MOCK_ATTESTATION_DOC_TIMESTAMP + 10_000),
	)
	.expect_err("a stale attestation should fail");

	assert!(matches!(err, VerifyError::AttestationTooOld { .. }));
}

#[test]
fn attestation_beyond_future_clock_skew_is_rejected() {
	let chain = TrustChain::new();
	let policy = AttestationPolicy::new(
		MOCK_ROOT_CERT_DER,
		Duration::from_secs(5 * 60),
		ManifestCommitmentKind::Setup,
	)
	.max_future_skew(Duration::from_secs(1));

	let err = verify_attestation_and_manifest_envelope_at_time(
		&chain.attestation_doc,
		&chain.envelope,
		ManifestEnvelopeTrust::ManifestHash(chain.envelope.manifest_hash()),
		&policy,
		&VerificationExpectations::new(),
		Duration::from_millis(MOCK_ATTESTATION_DOC_TIMESTAMP - 10_000),
	)
	.expect_err("an attestation too far in the future should fail");

	assert!(matches!(err, VerifyError::AttestationFromFuture { .. }));
}

#[test]
fn freshness_duration_must_fit_in_milliseconds() {
	let policy = AttestationPolicy::new(
		MOCK_ROOT_CERT_DER,
		Duration::MAX,
		ManifestCommitmentKind::Setup,
	);

	let err = check_attestation_freshness(
		MOCK_ATTESTATION_DOC_TIMESTAMP,
		MOCK_ATTESTATION_DOC_TIMESTAMP,
		&policy,
	)
	.expect_err("an unrepresentable freshness duration should fail");

	assert!(matches!(err, VerifyError::FreshnessDurationOutOfRange));
}

#[test]
fn attestation_doc_without_a_public_key_fails() {
	let envelope = approved_envelope(&[test_member("member")]);
	let attestation_doc =
		attest(&envelope, Some(envelope.manifest_hash().to_vec()), None, None);

	let err = verify_envelope(
		&attestation_doc,
		&envelope,
		ManifestCommitmentKind::Setup,
		&VerificationExpectations::new(),
	)
	.expect_err("attestation document without a public key should fail");

	assert!(matches!(err, VerifyError::MissingPublicKey));
}

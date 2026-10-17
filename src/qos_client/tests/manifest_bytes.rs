//! Pins the exact bytes produced for manifests by the real `qos_client`
//! binary, and compares them with the library encodings that determine
//! `manifest_hash()`.

#![allow(missing_docs)]

use std::{
	path::{Path, PathBuf},
	process::{Command, Output},
};

use qos_core::protocol::services::boot::{
	Approval, BootProofBytesError, BridgeConfig, DnsConfig, Manifest,
	ManifestBuilder, ManifestEnvelope, ManifestEnvelopeV0, ManifestEnvelopeV2,
	ManifestSet, ManifestV0, ManifestV2, MemberPubKey, Namespace, NitroConfig,
	PatchSet, PivotConfigV0, PivotEnv, PivotEnvValue, PivotEnvVarName,
	QuorumMember, RestartPolicy, ShareSet, VersionedManifest,
	VersionedManifestEnvelope,
};
use qos_p256::P256Pair;
use qos_test_primitives::PathWrapper;

const QOS_CLIENT: &str = env!("CARGO_BIN_EXE_qos_client");

fn sha256(bytes: &[u8]) -> [u8; 32] {
	qos_crypto::sha_256(bytes)
}

fn hex(bytes: &[u8]) -> String {
	qos_hex::encode(bytes)
}

fn scratch_dir(name: &str) -> PathWrapper<PathBuf> {
	let dir = std::env::temp_dir().join(format!(
		"qos_client_manifest_bytes_{}_{name}",
		std::process::id()
	));
	std::fs::create_dir_all(&dir).unwrap();
	PathWrapper::from(dir)
}

/// Run the binary with stdout and stderr captured separately.
fn run_split(args: &[&str]) -> Output {
	Command::new(QOS_CLIENT).args(args).output().unwrap()
}

/// Run the binary with both streams on one pipe, like Go's `CombinedOutput`.
fn run_combined(args: &[&str]) -> Vec<u8> {
	let out = Command::new("sh")
		.arg("-c")
		.arg(r#"exec "$0" "$@" 2>&1"#)
		.arg(QOS_CLIENT)
		.args(args)
		.output()
		.unwrap();
	assert!(out.status.success());
	assert!(out.stderr.is_empty());
	out.stdout
}

fn display_args<'a>(kind: &'a str, file: &'a str) -> [&'a str; 5] {
	["display", "--display-type", kind, "--file-path", file]
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
	a.iter()
		.zip(b)
		.position(|(x, y)| x != y)
		.or_else(|| (a.len() != b.len()).then(|| a.len().min(b.len())))
}

fn excerpt(bytes: &[u8]) -> String {
	String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).into_owned()
}

fn member(alias: &str, pair: &P256Pair) -> QuorumMember {
	QuorumMember {
		alias: alias.to_string(),
		pub_key: pair.public_key().to_bytes(),
	}
}

struct Parts {
	pairs: Vec<P256Pair>,
	namespace: Namespace,
	manifest_set: ManifestSet,
	share_set: ShareSet,
	enclave: NitroConfig,
}

fn parts() -> Parts {
	let pairs: Vec<P256Pair> =
		(0..3).map(|_| P256Pair::generate().unwrap()).collect();
	let members: Vec<QuorumMember> = ["alice", "bob", "carol"]
		.into_iter()
		.zip(&pairs)
		.map(|(alias, pair)| member(alias, pair))
		.collect();
	Parts {
		namespace: Namespace {
			name: "production/signer".to_string(),
			// Above u8/u16 so the number-vs-string difference is unmistakable.
			nonce: 70_001,
			quorum_key: pairs[0].public_key().to_bytes(),
		},
		manifest_set: ManifestSet { threshold: 2, members: members.clone() },
		share_set: ShareSet { threshold: 3, members },
		enclave: NitroConfig {
			pcr0: vec![0x11; 48],
			pcr1: vec![0x22; 48],
			pcr2: vec![0x33; 48],
			pcr3: vec![0x44; 48],
			aws_root_certificate: vec![0xab; 64],
			qos_commit: "deadbeef".to_string(),
		},
		pairs,
	}
}

fn pivot_env() -> PivotEnv {
	let mut env = PivotEnv::new();
	for (name, value) in [("ZED", "last"), ("ALPHA", "first")] {
		env.insert(
			PivotEnvVarName::new(name.to_string()).unwrap(),
			PivotEnvValue::plain(value.to_string()).unwrap(),
		)
		.unwrap();
	}
	env
}

fn bridge_config() -> Vec<BridgeConfig> {
	vec![
		BridgeConfig::Server { port: 3000, host: "0.0.0.0".to_string() },
		BridgeConfig::Client { port: 8443, host: Some("example.com".into()) },
	]
}

fn v2_manifest(p: &Parts) -> ManifestV2 {
	let built = ManifestBuilder::v2()
		.namespace(p.namespace.clone())
		.pivot_hash([0x5a; 32])
		.restart_policy(RestartPolicy::Always)
		.bridge_config(bridge_config())
		.debug_mode(true)
		.pivot_args(vec!["--config".into(), "/etc/app.json".into()])
		.pivot_env(pivot_env())
		.manifest_set(p.manifest_set.clone())
		.share_set(p.share_set.clone())
		.enclave(p.enclave.clone())
		.dns(DnsConfig {
			resolvers: vec!["1.1.1.1".parse().unwrap(), "::1".parse().unwrap()],
		})
		.build()
		.unwrap();
	let VersionedManifest::V2(manifest) = built else { panic!("not v2") };
	manifest
}

fn approvals(
	pairs: &[P256Pair],
	members: &[QuorumMember],
	hash: &[u8],
) -> Vec<Approval> {
	pairs
		.iter()
		.zip(members)
		.map(|(pair, m)| Approval {
			signature: pair.sign(hash).unwrap(),
			member: m.clone(),
		})
		.collect()
}

fn v1_manifest(p: &Parts) -> Manifest {
	let built = ManifestBuilder::v1()
		.namespace(p.namespace.clone())
		.pivot_hash([0x5a; 32])
		.restart_policy(RestartPolicy::Always)
		.bridge_config(bridge_config())
		.debug_mode(true)
		.pivot_args(vec!["--config".into(), "/etc/app.json".into()])
		.manifest_set(p.manifest_set.clone())
		.share_set(p.share_set.clone())
		.enclave(p.enclave.clone())
		.patch_set(PatchSet {
			threshold: 1,
			members: vec![MemberPubKey {
				pub_key: p.pairs[0].public_key().to_bytes(),
			}],
		})
		.build()
		.unwrap();
	let VersionedManifest::V1(manifest) = built else { panic!("not v1") };
	manifest
}

#[test]
#[allow(clippy::too_many_lines)]
fn v2_display_json_differs_from_canonical_storage_bytes() {
	let p = parts();
	let manifest = v2_manifest(&p);
	let manifest_hash = qos_json::hash(&manifest).unwrap();
	let envelope = ManifestEnvelopeV2 {
		manifest: manifest.clone(),
		manifest_set_approvals: approvals(
			&p.pairs[..2],
			&p.manifest_set.members[..2],
			&manifest_hash,
		),
		share_set_approvals: approvals(
			&p.pairs,
			&p.share_set.members,
			&manifest_hash,
		),
	};
	let versioned_manifest = VersionedManifest::V2(manifest.clone());
	let versioned_envelope = VersionedManifestEnvelope::V2(envelope.clone());

	// The boot-proof helper publishes the canonical bytes, not display output.
	let boot_proof = versioned_envelope.boot_proof_manifest_bytes().unwrap();
	assert_eq!(sha256(&boot_proof.manifest), manifest_hash);
	assert_eq!(
		boot_proof.manifest,
		versioned_manifest.to_storage_vec().unwrap()
	);
	assert_eq!(
		boot_proof.envelope,
		versioned_envelope.to_storage_vec().unwrap()
	);
	assert_eq!(boot_proof.version, "v2");

	let dir = scratch_dir("v2");
	let manifest_path = dir.join("manifest.json");
	let envelope_path = dir.join("envelope.json");
	std::fs::write(
		&manifest_path,
		versioned_manifest.to_storage_vec().unwrap(),
	)
	.unwrap();
	std::fs::write(
		&envelope_path,
		versioned_envelope.to_storage_vec().unwrap(),
	)
	.unwrap();

	let cases = [
		(
			"manifest",
			&manifest_path,
			versioned_manifest.to_storage_vec().unwrap(),
		),
		(
			"manifest-envelope",
			&envelope_path,
			versioned_envelope.to_storage_vec().unwrap(),
		),
	];

	for (kind, path, canonical) in cases {
		let file = path.to_str().unwrap();
		let split =
			run_split(&[&display_args(kind, file)[..], &["--json"]].concat());
		assert!(split.status.success(), "{kind}: display failed");
		assert!(
			split.stderr.is_empty(),
			"{kind}: display writes nothing to stderr"
		);
		let stdout = split.stdout;
		let combined = run_combined(
			&[&display_args(kind, file)[..], &["--json"]].concat(),
		);
		assert_eq!(
			combined, stdout,
			"{kind}: merged output equals stdout when stderr is empty"
		);

		// Exactly what serde_json emits for the decoded value, plus one `\n`.
		let expected_serde = if kind == "manifest" {
			serde_json::to_string(&versioned_manifest).unwrap()
		} else {
			serde_json::to_string(&versioned_envelope).unwrap()
		};
		assert_eq!(
			stdout,
			format!("{expected_serde}\n").into_bytes(),
			"{kind}: display is plain serde_json plus a trailing newline"
		);
		assert_eq!(stdout.last(), Some(&b'\n'));
		let no_newline = &stdout[..stdout.len() - 1];

		assert_ne!(no_newline, canonical, "{kind}: forms are not byte-equal");
		assert_ne!(stdout.len(), canonical.len());

		let canonical_text = std::str::from_utf8(&canonical).unwrap();
		let display_text = std::str::from_utf8(no_newline).unwrap();

		// Key order: canonical is sorted; display follows struct field order.
		let first_key = |s: &str, from: usize| -> String {
			s[from..].split('"').nth(1).unwrap().to_string()
		};
		assert_eq!(
			first_key(canonical_text, 0),
			if kind == "manifest" { "dns" } else { "manifest" }
		);
		assert_eq!(
			first_key(display_text, 0),
			if kind == "manifest" { "version" } else { "manifest" }
		);
		assert!(!canonical_text.ends_with('\n'));

		// Numbers: canonical writes integers as strings, display as numbers.
		assert!(canonical_text.contains(r#""threshold":"2""#));
		assert!(display_text.contains(r#""threshold":2"#));
		assert!(canonical_text.contains(r#""nonce":"70001""#));
		assert!(display_text.contains(r#""nonce":70001"#));
		assert!(canonical_text.contains(r#""port":"3000""#));
		assert!(display_text.contains(r#""port":3000"#));

		// Both forms hold the same data once parsed.
		let a: serde_json::Value =
			serde_json::from_str(canonical_text).unwrap();
		let b: serde_json::Value = serde_json::from_str(display_text).unwrap();
		assert_ne!(a, b, "{kind}: numbers differ from strings as JSON values");

		let diff = first_diff(no_newline, &canonical).unwrap();
		println!(
			"[{kind}] display(stdout)={}B canonical={}B first_diff_offset={diff}\n  display:   {}\n  canonical: {}",
			stdout.len(),
			canonical.len(),
			excerpt(&stdout),
			excerpt(&canonical),
		);

		// Hash: only canonical bytes satisfy `sha256(bytes) == manifest_hash`.
		let canonical_manifest_bytes = qos_json::to_vec(&manifest).unwrap();
		assert_eq!(
			sha256(&canonical_manifest_bytes),
			versioned_manifest.manifest_hash(),
			"canonical manifest bytes hash to manifest_hash"
		);
		assert_eq!(versioned_manifest.manifest_hash(), manifest_hash);
		assert_eq!(versioned_envelope.manifest_hash(), manifest_hash);
		if kind == "manifest" {
			assert_ne!(sha256(&stdout), manifest_hash, "display w/ newline");
			assert_ne!(
				sha256(no_newline),
				manifest_hash,
				"display w/o newline"
			);
			println!(
				"  manifest_hash={} sha256(canonical)={} sha256(display+nl)={} sha256(display)={}",
				hex(&manifest_hash),
				hex(&sha256(&canonical_manifest_bytes)),
				hex(&sha256(&stdout)),
				hex(&sha256(no_newline)),
			);
		}

		// Decoding: every form is accepted and re-hashes to `manifest_hash`.
		for (label, bytes) in [
			("canonical", canonical.as_slice()),
			("display with newline", stdout.as_slice()),
			("display without newline", no_newline),
		] {
			if kind == "manifest" {
				let decoded =
					VersionedManifest::try_from_slice_compat(bytes).unwrap();
				assert_eq!(decoded, versioned_manifest, "{label}");
				assert_eq!(decoded.manifest_hash(), manifest_hash, "{label}");
			} else {
				let decoded =
					VersionedManifestEnvelope::try_from_slice_compat(bytes)
						.unwrap();
				assert_eq!(decoded, versioned_envelope, "{label}");
				assert_eq!(decoded.manifest_hash(), manifest_hash, "{label}");
				assert!(decoded.check_approvals().is_ok(), "{label}");
			}
		}
	}
}

/// Run `json-to-borsh` and return the bytes it wrote.
fn json_to_borsh(dir: &Path, kind: &str, json: &[u8], name: &str) -> Output {
	let input = dir.join(format!("{name}.json"));
	let output = dir.join(format!("{name}.borsh"));
	std::fs::write(&input, json).unwrap();
	run_split(&[
		"json-to-borsh",
		"--display-type",
		kind,
		"--file-path",
		input.to_str().unwrap(),
		"--output-path",
		output.to_str().unwrap(),
	])
}

#[test]
fn v1_json_to_borsh_matches_library_borsh_and_manifest_hash() {
	let p = parts();
	let manifest = v1_manifest(&p);
	let versioned = VersionedManifest::V1(manifest.clone());
	let dir = scratch_dir("v1");

	let storage = versioned.to_storage_vec().unwrap();
	// v1 storage is plain serde_json: bridge port is a number.
	assert!(std::str::from_utf8(&storage).unwrap().contains(r#""port":3000"#));

	let out = json_to_borsh(&dir, "manifest", &storage, "manifest");
	assert!(out.status.success());
	assert!(out.stdout.is_empty() && out.stderr.is_empty());
	let cli_bytes = std::fs::read(dir.join("manifest.borsh")).unwrap();

	assert_eq!(
		cli_bytes,
		borsh::to_vec(&manifest).unwrap(),
		"json-to-borsh equals borsh of the manifest"
	);
	assert_eq!(
		cli_bytes,
		borsh::to_vec(&versioned).unwrap(),
		"json-to-borsh equals borsh via VersionedManifest"
	);
	assert_eq!(
		sha256(&cli_bytes),
		versioned.manifest_hash(),
		"sha256 of json-to-borsh output is manifest_hash"
	);
	assert_eq!(
		VersionedManifest::try_from_slice_compat(&cli_bytes).unwrap(),
		versioned,
		"borsh output decodes back to the same v1 manifest"
	);

	// Envelope, same property.
	let manifest_hash = versioned.manifest_hash();
	let envelope = ManifestEnvelope {
		manifest,
		manifest_set_approvals: approvals(
			&p.pairs[..2],
			&p.manifest_set.members[..2],
			&manifest_hash,
		),
		share_set_approvals: vec![],
	};
	let versioned_envelope = VersionedManifestEnvelope::V1(envelope.clone());
	let out = json_to_borsh(
		&dir,
		"manifest-envelope",
		&versioned_envelope.to_storage_vec().unwrap(),
		"envelope",
	);
	assert!(out.status.success());
	let cli_bytes = std::fs::read(dir.join("envelope.borsh")).unwrap();
	assert_eq!(cli_bytes, borsh::to_vec(&envelope).unwrap());
	assert_eq!(cli_bytes, borsh::to_vec(&versioned_envelope).unwrap());

	// The boot-proof helper emits exactly what json-to-borsh writes.
	let boot_proof = versioned_envelope.boot_proof_manifest_bytes().unwrap();
	assert_eq!(boot_proof.envelope, cli_bytes);
	assert_eq!(
		boot_proof.manifest,
		std::fs::read(dir.join("manifest.borsh")).unwrap()
	);
	assert_eq!(sha256(&boot_proof.manifest), manifest_hash);
	assert_eq!(boot_proof.version, "v1");
}

#[test]
fn v0_json_to_borsh_converts_to_v1_so_hash_differs_from_v0() {
	let p = parts();
	let v1 = v1_manifest(&p);
	let v0 = ManifestV0 {
		namespace: v1.namespace.clone(),
		pivot: PivotConfigV0 {
			hash: v1.pivot.hash,
			restart: v1.pivot.restart,
			args: v1.pivot.args.clone(),
		},
		manifest_set: v1.manifest_set.clone(),
		share_set: v1.share_set.clone(),
		enclave: v1.enclave.clone(),
		patch_set: v1.patch_set.clone(),
	};
	let versioned_v0 = VersionedManifest::V0(v0.clone());
	let dir = scratch_dir("v0");

	let storage = versioned_v0.to_storage_vec().unwrap();
	assert!(matches!(
		VersionedManifest::try_from_slice_compat(&storage).unwrap(),
		VersionedManifest::V0(_)
	));

	let out = json_to_borsh(&dir, "manifest", &storage, "v0");
	assert!(out.status.success());
	let cli_bytes = std::fs::read(dir.join("v0.borsh")).unwrap();

	let converted = Manifest::from(v0.clone());
	assert_eq!(cli_bytes, borsh::to_vec(&converted).unwrap());
	assert_ne!(
		cli_bytes,
		borsh::to_vec(&v0).unwrap(),
		"output is v1 borsh, not v0 borsh"
	);
	assert_ne!(
		sha256(&cli_bytes),
		versioned_v0.manifest_hash(),
		"converted bytes hash differently from the v0 manifest hash"
	);
	assert_eq!(
		sha256(&cli_bytes),
		VersionedManifest::V1(converted).manifest_hash()
	);

	// So the boot-proof helper refuses v0 instead of emitting those bytes.
	let envelope = VersionedManifestEnvelope::V0(ManifestEnvelopeV0 {
		manifest: v0,
		manifest_set_approvals: vec![],
		share_set_approvals: vec![],
	});
	assert_eq!(
		envelope.boot_proof_manifest_bytes(),
		Err(BootProofBytesError::UnsupportedManifestVersion("v0"))
	);
}

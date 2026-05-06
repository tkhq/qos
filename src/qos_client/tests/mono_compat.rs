#![allow(missing_docs)]

use std::{
	path::{Path, PathBuf},
	process::{Command, Output},
	time::{SystemTime, UNIX_EPOCH},
};

use qos_test_primitives::PathWrapper;
use serde_json::{json, Value};

const QOS_CLIENT: &str = env!("CARGO_BIN_EXE_qos_client");

struct Fixture {
	_tmp: PathWrapper<'static>,
	root: PathBuf,
	manifest_set: PathBuf,
	share_set: PathBuf,
	patch_set: PathBuf,
	approvals_dir: PathBuf,
	manifest_path: PathBuf,
	envelope_path: PathBuf,
	borsh_manifest_path: PathBuf,
	pivot_path: PathBuf,
	pivot_hash_path: PathBuf,
	qos_release_dir: PathBuf,
	pcr3_preimage_path: PathBuf,
	quorum_key_path: PathBuf,
	secret_path: PathBuf,
}

impl Fixture {
	fn new(test_name: &str) -> Self {
		let nanos =
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
		let root = std::env::temp_dir().join(format!(
			"qos_client_mono_compat_{test_name}_{}_{}",
			std::process::id(),
			nanos
		));
		let tmp: PathWrapper<'static> = root.display().to_string().into();

		let manifest_set = root.join("manifest-set");
		let share_set = root.join("share-set");
		let patch_set = root.join("patch-set");
		let approvals_dir = root.join("approvals");
		let qos_release_dir = root.join("dist");
		for dir in [
			&manifest_set,
			&share_set,
			&patch_set,
			&approvals_dir,
			&qos_release_dir,
		] {
			std::fs::create_dir_all(dir).unwrap();
		}

		let manifest_path = root.join("manifest");
		let envelope_path = approvals_dir.join("manifest_envelope");
		let borsh_manifest_path = root.join("manifest.borsh");
		let pivot_path = root.join("pivot.bin");
		let pivot_hash_path = root.join("pivot.hash");
		let pcr3_preimage_path = root.join("pcr3_preimage");
		let quorum_key_path = root.join("quorum_key.pub");

		let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let primary_pub = manifest_dir.join("tests/mock/primary.pub");
		let secret_path = manifest_dir.join("tests/mock/primary.secret.keep");
		let integration_dist =
			manifest_dir.join("../integration/mock/dist/aws-x86_64.pcrs");
		let integration_pcr3 = manifest_dir
			.join("../integration/mock/namespaces/pcr3-preimage.txt");

		for set_dir in [&manifest_set, &share_set, &patch_set] {
			std::fs::write(set_dir.join("quorum_threshold"), b"1\n").unwrap();
			std::fs::copy(&primary_pub, set_dir.join("dev.pub")).unwrap();
		}
		std::fs::copy(&primary_pub, &quorum_key_path).unwrap();
		std::fs::copy(
			integration_dist,
			qos_release_dir.join("aws-x86_64.pcrs"),
		)
		.unwrap();
		std::fs::copy(integration_pcr3, &pcr3_preimage_path).unwrap();

		let pivot = b"mono compat pivot bytes";
		std::fs::write(&pivot_path, pivot).unwrap();
		std::fs::write(
			&pivot_hash_path,
			qos_hex::encode(&qos_crypto::sha_256(pivot)),
		)
		.unwrap();

		Self {
			_tmp: tmp,
			root,
			manifest_set,
			share_set,
			patch_set,
			approvals_dir,
			manifest_path,
			envelope_path,
			borsh_manifest_path,
			pivot_path,
			pivot_hash_path,
			qos_release_dir,
			pcr3_preimage_path,
			quorum_key_path,
			secret_path,
		}
	}

	fn generate_manifest(&self) {
		let bridge_config =
			r#"[{"type":"server","port":"3000","host":"0.0.0.0"}]"#;
		assert_success(run_qos_client([
			"generate-manifest",
			"--nonce",
			"31",
			"--namespace",
			"production/signer",
			"--restart-policy",
			"always",
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-args",
			"[--config,/etc/config.json]",
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--debug-mode",
			"true",
			"--bridge-config",
			bridge_config,
		]));
	}

	fn approve_manifest(&self) {
		assert_success(run_qos_client([
			"approve-manifest",
			"--alias",
			"dev",
			"--manifest-approvals-dir",
			self.approvals_dir.to_str().unwrap(),
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--secret-path",
			self.secret_path.to_str().unwrap(),
			"--unsafe-auto-confirm",
		]));
	}
}

fn run_qos_client<const N: usize>(args: [&str; N]) -> Output {
	Command::new(QOS_CLIENT).args(args).output().unwrap()
}

fn assert_success(output: Output) {
	assert!(
		output.status.success(),
		"qos_client failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
		output.status.code(),
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
}

fn assert_success_with_stdout(output: Output) -> String {
	assert!(
		output.status.success(),
		"qos_client failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
		output.status.code(),
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
	String::from_utf8(output.stdout).unwrap()
}

fn display_manifest_json(path: &Path) -> Value {
	let stdout = assert_success_with_stdout(run_qos_client([
		"display",
		"--display-type",
		"manifest",
		"--file-path",
		path.to_str().unwrap(),
		"--json",
	]));
	serde_json::from_str(&stdout).unwrap()
}

fn mono_visible_manifest_fields(manifest: &Value) -> Value {
	json!({
		"namespace": manifest["namespace"].clone(),
		"pivot": {
			"hash": manifest["pivot"]["hash"].clone(),
			"restart": manifest["pivot"]["restart"].clone(),
			"args": manifest["pivot"]["args"].clone(),
		},
		"manifestSet": manifest["manifestSet"].clone(),
		"shareSet": manifest["shareSet"].clone(),
		"enclave": manifest["enclave"].clone(),
	})
}

#[test]
fn mono_compat_pivot_hash_writes_expected_sha256_hex() {
	let fixture = Fixture::new("pivot_hash");
	let output_path = fixture.root.join("pivot_hash_output");

	assert_success(run_qos_client([
		"pivot-hash",
		"--output-path",
		output_path.to_str().unwrap(),
		"--pivot-path",
		fixture.pivot_path.to_str().unwrap(),
	]));

	let pivot = std::fs::read(&fixture.pivot_path).unwrap();
	let expected = qos_hex::encode(&qos_crypto::sha_256(&pivot));
	assert_eq!(std::fs::read_to_string(output_path).unwrap(), expected);
}

#[test]
fn mono_compat_display_manifest_json_exposes_mono_visible_shape() {
	let fixture = Fixture::new("display_manifest");
	fixture.generate_manifest();

	let manifest = display_manifest_json(&fixture.manifest_path);
	assert_eq!(manifest["namespace"]["name"], "production/signer");
	assert_eq!(manifest["namespace"]["nonce"], "31");
	assert_eq!(manifest["pivot"]["restart"], "Always");
	assert_eq!(
		manifest["pivot"]["args"],
		json!(["--config", "/etc/config.json"])
	);
	assert_eq!(manifest["pivot"]["debugMode"], true);
	assert_eq!(
		manifest["pivot"]["bridgeConfig"],
		json!([{ "type": "server", "port": "3000", "host": "0.0.0.0" }])
	);
	assert!(manifest.get("version").is_none());
	assert!(manifest["pivot"].get("env").is_none());

	let mono_visible = mono_visible_manifest_fields(&manifest);
	for key in ["namespace", "pivot", "manifestSet", "shareSet", "enclave"] {
		assert!(mono_visible.get(key).is_some(), "missing {key}");
	}
}

#[test]
fn mono_compat_json_to_borsh_manifest_round_trips_display_json() {
	let fixture = Fixture::new("json_to_borsh_manifest");
	fixture.generate_manifest();

	let json_manifest = display_manifest_json(&fixture.manifest_path);
	assert_success(run_qos_client([
		"json-to-borsh",
		"--file-path",
		fixture.manifest_path.to_str().unwrap(),
		"--display-type",
		"manifest",
		"--output-path",
		fixture.borsh_manifest_path.to_str().unwrap(),
	]));
	let borsh_manifest = display_manifest_json(&fixture.borsh_manifest_path);

	assert_eq!(
		mono_visible_manifest_fields(&json_manifest),
		mono_visible_manifest_fields(&borsh_manifest)
	);
}

#[test]
fn mono_compat_generate_manifest_defaults_to_v1_without_env() {
	let fixture = Fixture::new("generate_manifest");
	fixture.generate_manifest();

	let manifest: Value =
		serde_json::from_slice(&std::fs::read(&fixture.manifest_path).unwrap())
			.unwrap();
	assert!(manifest.get("version").is_none());
	assert!(manifest["pivot"].get("env").is_none());
	assert_eq!(
		manifest["pivot"]["args"],
		json!(["--config", "/etc/config.json"])
	);
	assert_eq!(manifest["pivot"]["debugMode"], true);
	assert_eq!(
		manifest["pivot"]["bridgeConfig"],
		json!([{ "type": "server", "port": "3000", "host": "0.0.0.0" }])
	);
}

#[test]
fn mono_compat_generate_manifest_envelope_uses_default_output_path() {
	let fixture = Fixture::new("generate_manifest_envelope");
	fixture.generate_manifest();
	fixture.approve_manifest();

	assert!(!fixture.envelope_path.exists());
	assert_success(run_qos_client([
		"generate-manifest-envelope",
		"--manifest-approvals-dir",
		fixture.approvals_dir.to_str().unwrap(),
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
	]));

	assert!(fixture.envelope_path.exists());
	let stdout = assert_success_with_stdout(run_qos_client([
		"display",
		"--display-type",
		"manifest-envelope",
		"--file-path",
		fixture.envelope_path.to_str().unwrap(),
		"--json",
	]));
	let envelope: Value = serde_json::from_str(&stdout).unwrap();
	assert_eq!(envelope["manifest"]["namespace"]["name"], "production/signer");
	assert_eq!(envelope["manifestSetApprovals"].as_array().unwrap().len(), 1);
}

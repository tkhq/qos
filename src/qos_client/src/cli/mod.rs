//! CLI for `qos_client`.
//!
//! All command parsing goes through [`clap`]. The `--use-qos-version` flag
//! selects between v1 (default) and v2 manifest behavior for commands that
//! support both.

use std::collections::HashSet;

use clap::{Args, Parser, Subcommand, ValueEnum};
use qos_core::protocol::{
	msg::ProtocolMsg,
	services::boot::{BridgeConfig, RestartPolicy},
};

mod services;

#[cfg(feature = "smartcard")]
pub use services::advanced_provision_yubikey;
pub use services::generate_file_key;
pub use services::PairOrYubi;

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum DisplayType {
	Manifest,
	ManifestEnvelope,
	GenesisOutput,
}

fn parse_qos_version(s: &str) -> Result<u32, String> {
	let v: u32 = s
		.parse()
		.map_err(|_| "--use-qos-version requires an integer".to_string())?;
	if v > 2 {
		return Err(format!("unsupported QOS manifest version: {v}"));
	}
	Ok(v)
}

fn parse_pivot_args(value: &str) -> Vec<String> {
	let mut chars = value.chars();
	assert_eq!(
		chars.next().unwrap(),
		'[',
		"Pivot args must start with a \"[\""
	);
	assert_eq!(
		chars.next_back().unwrap(),
		']',
		"Pivot args must end with a \"]\""
	);

	if chars.clone().count() > 0 {
		chars.as_str().split(',').map(String::from).collect()
	} else {
		vec![]
	}
}

fn parse_bridge_config(json: Option<&str>) -> Vec<BridgeConfig> {
	let Some(json_str) = json else {
		return Vec::new();
	};

	let result: Vec<BridgeConfig> = serde_json::from_str(json_str)
		.expect("invalid bridge configuration json");
	let mut ports = HashSet::new();
	for bc in &result {
		assert!(
			ports.insert(bc.port()),
			"duplicate bridge port: {}",
			bc.port()
		);
	}

	result
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
	/// QOS manifest schema version. Defaults to 1; pass 2 to opt into v2
	/// manifest behavior for commands that support it.
	#[arg(long, global = true, value_parser = parse_qos_version)]
	use_qos_version: Option<u32>,
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "kebab-case")]
enum Command {
	/// Query the health endpoint of the enclave host server.
	HostHealth(HostHealthOpts),
	/// Query the status of the enclave.
	EnclaveStatus(EnclaveStatusOpts),
	/// Generate a Setup Key for use in the Genesis ceremony.
	GenerateFileKey(GenerateFileKeyOpts),
	/// Run the Boot Genesis logic to generate and shard a Quorum Key.
	BootGenesis(BootGenesisOpts),
	/// Decrypt the Personal Key and Personal Share from the Genesis Ceremony.
	AfterGenesis(AfterGenesisOpts),
	/// Verify the Disaster Recovery artifacts against a master seed.
	VerifyGenesis(VerifyGenesisOpts),
	/// Using the given Personal Keys as the Manifest Set, generate a manifest.
	GenerateManifest(GenerateManifestOpts),
	/// Sign a trusted Manifest. Outputs a manifest `Approval`.
	ApproveManifest(ApproveManifestOpts),
	/// Start booting an enclave with a manifest envelope.
	BootStandard(BootStandardOpts),
	/// Get the attestation document from an enclave.
	GetAttestationDoc(GetAttestationDocOpts),
	/// Extract the ephemeral public key from an attestation doc.
	GetEphemeralKeyHex(GetEphemeralKeyHexOpts),
	/// Re-encrypt a local share to the enclave's ephemeral key.
	ProxyReEncryptShare(ProxyReEncryptShareOpts),
	/// Submit an encrypted share to an enclave.
	PostShare(PostShareOpts),
	/// Generate a manifest envelope from a manifest and approvals.
	GenerateManifestEnvelope(GenerateManifestEnvelopeOpts),
	/// **Never use in production**. Pivot the enclave to a binary.
	DangerousDevBoot(DangerousDevBootOpts),
	/// Provision a `YubiKey` with signing and encryption keys.
	ProvisionYubikey(ProvisionYubikeyOpts),
	/// Provision a `YubiKey` by importing a master seed.
	AdvancedProvisionYubikey(AdvancedProvisionYubikeyOpts),
	/// Create a dummy pivot build fingerprints with a correct hash.
	PivotHash(PivotHashOpts),
	/// Split a secret into shares with Shamir Secret Sharing.
	ShamirSplit(ShamirSplitOpts),
	/// Reconstruct a secret from Shamir shares.
	ShamirReconstruct(ShamirReconstructOpts),
	/// Sign a hex encoded payload with the `YubiKey`.
	YubikeySign(YubikeySignOpts),
	/// Get the public key of a `YubiKey`.
	YubikeyPublic,
	/// Reset the `YubiKey` PIV app. Destructive.
	YubikeyPivReset,
	/// Change the `YubiKey` PIV PIN.
	YubikeyChangePin(YubikeyChangePinOpts),
	/// Display some borsh encoded type in an easy to read format.
	Display(DisplayOpts),
	/// Convert a JSON manifest or envelope to Borsh format.
	JsonToBorsh(JsonToBorshOpts),
	/// Send the boot instruction to start key forwarding.
	BootKeyFwd(BootKeyFwdOpts),
	/// Request a quorum key from a fully-provisioned enclave.
	ExportKey(ExportKeyOpts),
	/// Inject a quorum key into a non-fully-provisioned enclave.
	InjectKey(InjectKeyOpts),
	/// Verify a `qos_p256` signature.
	P256Verify(P256VerifyOpts),
	/// Sign with a `qos_p256` keypair.
	P256Sign(P256SignOpts),
	/// Encrypt to a `qos_p256` public key.
	P256AsymmetricEncrypt(P256AsymmetricEncryptOpts),
	/// Decrypt a payload encrypted to a `qos_p256` public key.
	P256AsymmetricDecrypt(P256AsymmetricDecryptOpts),
}

#[derive(Args, Debug)]
struct HostOpts {
	/// IP address this server should listen on.
	#[arg(long, allow_hyphen_values = true)]
	host_ip: String,
	/// Port this server should listen on.
	#[arg(long, allow_hyphen_values = true)]
	host_port: String,
	/// Base path for all endpoints. e.g. <BASE>/enclave-health
	#[arg(long, allow_hyphen_values = true)]
	endpoint_base_path: Option<String>,
}

impl HostOpts {
	fn path(&self, uri: &str) -> String {
		let base = self.endpoint_base_path.as_deref().unwrap_or("qos");
		format!("http://{}:{}/{}/{}", self.host_ip, self.host_port, base, uri)
	}

	fn path_message(&self) -> String {
		self.path("message")
	}
}

#[derive(Args, Debug)]
struct HostHealthOpts {
	#[command(flatten)]
	host: HostOpts,
}

#[derive(Args, Debug)]
struct EnclaveStatusOpts {
	#[command(flatten)]
	host: HostOpts,
}

#[derive(Args, Debug)]
struct GenerateFileKeyOpts {
	#[arg(long, allow_hyphen_values = true)]
	master_seed_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pub_path: String,
}

#[derive(Args, Debug)]
struct BootGenesisOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	namespace_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	share_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long, allow_hyphen_values = true)]
	qos_release_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	dr_key_path: Option<String>,
	#[arg(long)]
	unsafe_skip_attestation: bool,
}

#[derive(Args, Debug)]
struct AfterGenesisOpts {
	#[arg(long)]
	yubikey: bool,
	#[arg(long, conflicts_with = "yubikey", allow_hyphen_values = true)]
	secret_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	share_path: String,
	#[arg(long, allow_hyphen_values = true)]
	alias: String,
	#[arg(long, allow_hyphen_values = true)]
	namespace_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	qos_release_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long)]
	unsafe_skip_attestation: bool,
	#[arg(long, allow_hyphen_values = true)]
	current_pin_path: Option<String>,
	#[arg(long)]
	validation_time_override: Option<u64>,
}

#[derive(Args, Debug)]
struct VerifyGenesisOpts {
	#[arg(long, allow_hyphen_values = true)]
	namespace_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	master_seed_path: String,
}

#[derive(Args, Debug)]
struct GenerateManifestOpts {
	#[arg(long)]
	nonce: u32,
	#[arg(long, allow_hyphen_values = true)]
	namespace: String,
	#[arg(long, allow_hyphen_values = true)]
	pivot_hash_path: String,
	#[arg(long, allow_hyphen_values = true)]
	restart_policy: String,
	#[arg(long, allow_hyphen_values = true)]
	qos_release_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	share_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	patch_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	quorum_key_path: String,
	#[arg(
		long,
		num_args = 0..=1,
		default_value = "[]",
		default_missing_value = "[]"
	)]
	pivot_args: String,
	#[arg(long, allow_hyphen_values = true)]
	bridge_config: Option<String>,
	#[arg(
		long,
		num_args = 0..=1,
		default_value = "false",
		default_missing_value = "true"
	)]
	debug_mode: bool,
}

#[derive(Args, Debug)]
struct ApproveManifestOpts {
	#[arg(long)]
	yubikey: bool,
	#[arg(long, conflicts_with = "yubikey", allow_hyphen_values = true)]
	secret_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	manifest_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_approvals_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	qos_release_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pivot_hash_path: String,
	#[arg(long, allow_hyphen_values = true)]
	alias: String,
	#[arg(long, allow_hyphen_values = true)]
	quorum_key_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	share_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	patch_set_dir: String,
	#[arg(long)]
	unsafe_auto_confirm: bool,
}

#[derive(Args, Debug)]
struct BootStandardOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	pivot_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long)]
	unsafe_skip_attestation: bool,
}

#[derive(Args, Debug)]
struct GetAttestationDocOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	attestation_doc_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
}

#[derive(Args, Debug)]
struct GetEphemeralKeyHexOpts {
	#[arg(long, allow_hyphen_values = true)]
	attestation_doc_path: String,
	#[arg(long, allow_hyphen_values = true)]
	ephemeral_key_path: String,
}

#[derive(Args, Debug)]
struct ProxyReEncryptShareOpts {
	#[arg(long)]
	yubikey: bool,
	#[arg(long, conflicts_with = "yubikey", allow_hyphen_values = true)]
	secret_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	share_path: String,
	#[arg(long, allow_hyphen_values = true)]
	approval_path: String,
	#[arg(long, allow_hyphen_values = true)]
	eph_wrapped_share_path: String,
	#[arg(long, allow_hyphen_values = true)]
	attestation_doc_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pcr3_preimage_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_set_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	alias: String,
	#[arg(long)]
	unsafe_skip_attestation: bool,
	#[arg(long, allow_hyphen_values = true)]
	unsafe_eph_path_override: Option<String>,
	#[arg(long)]
	unsafe_auto_confirm: bool,
	#[arg(long, allow_hyphen_values = true)]
	current_pin_path: Option<String>,
}

#[derive(Args, Debug)]
struct PostShareOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	approval_path: String,
	#[arg(long, allow_hyphen_values = true)]
	eph_wrapped_share_path: String,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_field_names)]
struct GenerateManifestEnvelopeOpts {
	#[arg(long, allow_hyphen_values = true)]
	manifest_approvals_dir: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_path: String,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
}

#[derive(Args, Debug)]
struct DangerousDevBootOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	pivot_path: String,
	#[arg(long, allow_hyphen_values = true)]
	restart_policy: String,
	#[arg(
		long,
		num_args = 0..=1,
		default_value = "[]",
		default_missing_value = "[]"
	)]
	pivot_args: String,
	#[arg(long, allow_hyphen_values = true)]
	unsafe_eph_path_override: Option<String>,
}

#[derive(Args, Debug)]
struct ProvisionYubikeyOpts {
	#[arg(long, allow_hyphen_values = true)]
	pub_path: String,
	#[arg(long)]
	yubikey: bool,
}

#[derive(Args, Debug)]
struct AdvancedProvisionYubikeyOpts {
	#[arg(long, allow_hyphen_values = true)]
	master_seed_path: String,
	#[arg(long, allow_hyphen_values = true)]
	current_pin_path: Option<String>,
}

#[derive(Args, Debug)]
struct PivotHashOpts {
	#[arg(long, allow_hyphen_values = true)]
	output_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pivot_path: String,
}

#[derive(Args, Debug)]
struct ShamirSplitOpts {
	#[arg(long, allow_hyphen_values = true)]
	secret_path: String,
	#[arg(long)]
	total_shares: usize,
	#[arg(long)]
	threshold: usize,
	#[arg(long, allow_hyphen_values = true)]
	output_dir: String,
}

#[derive(Args, Debug)]
struct ShamirReconstructOpts {
	#[arg(long, action = clap::ArgAction::Append, required = true, allow_hyphen_values = true)]
	share: Vec<String>,
	#[arg(long, allow_hyphen_values = true)]
	output_path: String,
}

#[derive(Args, Debug)]
struct YubikeySignOpts {
	#[arg(long, allow_hyphen_values = true)]
	payload: String,
}

#[derive(Args, Debug)]
struct YubikeyChangePinOpts {
	#[arg(long, allow_hyphen_values = true)]
	current_pin_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	new_pin_path: String,
}

#[derive(Args, Debug)]
struct DisplayOpts {
	#[arg(long, allow_hyphen_values = true)]
	file_path: String,
	#[arg(long)]
	display_type: DisplayType,
	#[arg(long)]
	json: bool,
}

#[derive(Args, Debug)]
struct JsonToBorshOpts {
	#[arg(long, allow_hyphen_values = true)]
	file_path: String,
	#[arg(long)]
	display_type: DisplayType,
	#[arg(long, allow_hyphen_values = true)]
	output_path: String,
}

#[derive(Args, Debug)]
struct BootKeyFwdOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	pivot_path: String,
	#[arg(long, allow_hyphen_values = true)]
	attestation_doc_path: String,
}

#[derive(Args, Debug)]
struct ExportKeyOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	manifest_envelope_path: Option<String>,
	#[arg(long, allow_hyphen_values = true)]
	attestation_doc_path: String,
	#[arg(long, allow_hyphen_values = true)]
	encrypted_quorum_key_path: String,
}

#[derive(Args, Debug)]
struct InjectKeyOpts {
	#[command(flatten)]
	host: HostOpts,
	#[arg(long, allow_hyphen_values = true)]
	encrypted_quorum_key_path: String,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_field_names)]
struct P256VerifyOpts {
	#[arg(long, allow_hyphen_values = true)]
	payload_path: String,
	#[arg(long, allow_hyphen_values = true)]
	signature_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pub_path: String,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_field_names)]
struct P256SignOpts {
	#[arg(long, allow_hyphen_values = true)]
	payload_path: String,
	#[arg(long, allow_hyphen_values = true)]
	signature_path: String,
	#[arg(long, allow_hyphen_values = true)]
	master_seed_path: String,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_field_names)]
struct P256AsymmetricEncryptOpts {
	#[arg(long, allow_hyphen_values = true)]
	plaintext_path: String,
	#[arg(long, allow_hyphen_values = true)]
	ciphertext_path: String,
	#[arg(long, allow_hyphen_values = true)]
	pub_path: String,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_field_names)]
struct P256AsymmetricDecryptOpts {
	#[arg(long, allow_hyphen_values = true)]
	plaintext_path: String,
	#[arg(long, allow_hyphen_values = true)]
	ciphertext_path: String,
	#[arg(long, allow_hyphen_values = true)]
	master_seed_path: String,
	#[arg(long)]
	output_hex: bool,
}

/// Client command line interface.
pub struct CLI;

impl CLI {
	/// Execute this command line interface.
	pub fn execute() {
		let cli = Cli::parse();
		dispatch(cli);
	}
}

fn dispatch(cli: Cli) {
	let version = cli.use_qos_version.unwrap_or(1);
	match cli.command {
		Command::HostHealth(opts) => handlers::host_health(&opts),
		Command::EnclaveStatus(opts) => handlers::enclave_status(&opts),
		Command::GenerateFileKey(opts) => handlers::generate_file_key(&opts),
		Command::BootGenesis(opts) => handlers::boot_genesis(&opts),
		Command::AfterGenesis(opts) => handlers::after_genesis(opts),
		Command::VerifyGenesis(opts) => handlers::verify_genesis(&opts),
		Command::GenerateManifest(opts) => {
			if version >= 2 {
				handlers::generate_manifest_v2(opts);
			} else {
				handlers::generate_manifest(opts);
			}
		}
		Command::ApproveManifest(opts) => handlers::approve_manifest(opts),
		Command::BootStandard(opts) => handlers::boot_standard(opts),
		Command::GetAttestationDoc(opts) => {
			handlers::get_attestation_doc(&opts);
		}
		Command::GetEphemeralKeyHex(opts) => {
			handlers::get_ephemeral_key_hex(opts);
		}
		Command::ProxyReEncryptShare(opts) => {
			handlers::proxy_re_encrypt_share(opts);
		}
		Command::PostShare(opts) => handlers::post_share(opts),
		Command::GenerateManifestEnvelope(opts) => {
			handlers::generate_manifest_envelope(opts);
		}
		Command::DangerousDevBoot(opts) => handlers::dangerous_dev_boot(opts),
		Command::ProvisionYubikey(opts) => handlers::provision_yubikey(opts),
		Command::AdvancedProvisionYubikey(opts) => {
			handlers::advanced_provision_yubikey(opts);
		}
		Command::PivotHash(opts) => handlers::pivot_hash(&opts),
		Command::ShamirSplit(opts) => handlers::shamir_split(opts),
		Command::ShamirReconstruct(opts) => handlers::shamir_reconstruct(opts),
		Command::YubikeySign(opts) => handlers::yubikey_sign(&opts),
		Command::YubikeyPublic => handlers::yubikey_public(),
		Command::YubikeyPivReset => handlers::yubikey_piv_reset(),
		Command::YubikeyChangePin(opts) => handlers::yubikey_change_pin(opts),
		Command::Display(opts) => handlers::display(&opts),
		Command::JsonToBorsh(opts) => handlers::json_to_borsh(&opts),
		Command::BootKeyFwd(opts) => handlers::boot_key_fwd(opts),
		Command::ExportKey(opts) => handlers::export_key(opts),
		Command::InjectKey(opts) => handlers::inject_key(opts),
		Command::P256Verify(opts) => handlers::p256_verify(opts),
		Command::P256Sign(opts) => handlers::p256_sign(opts),
		Command::P256AsymmetricEncrypt(opts) => {
			handlers::p256_asymmetric_encrypt(opts);
		}
		Command::P256AsymmetricDecrypt(opts) => {
			handlers::p256_asymmetric_decrypt(opts);
		}
	}
}

mod handlers {
	use super::{
		parse_bridge_config, parse_pivot_args, services,
		AdvancedProvisionYubikeyOpts, AfterGenesisOpts, ApproveManifestOpts,
		BootGenesisOpts, BootKeyFwdOpts, BootStandardOpts,
		DangerousDevBootOpts, DisplayOpts, EnclaveStatusOpts, ExportKeyOpts,
		GenerateFileKeyOpts, GenerateManifestEnvelopeOpts,
		GenerateManifestOpts, GetAttestationDocOpts, GetEphemeralKeyHexOpts,
		HostHealthOpts, InjectKeyOpts, JsonToBorshOpts,
		P256AsymmetricDecryptOpts, P256AsymmetricEncryptOpts, P256SignOpts,
		P256VerifyOpts, PairOrYubi, PivotHashOpts, PostShareOpts, ProtocolMsg,
		ProvisionYubikeyOpts, ProxyReEncryptShareOpts, RestartPolicy,
		ShamirReconstructOpts, ShamirSplitOpts, VerifyGenesisOpts,
		YubikeyChangePinOpts, YubikeySignOpts,
	};
	use crate::request;

	fn parse_restart(value: &str) -> RestartPolicy {
		RestartPolicy::try_from(value.to_string())
			.expect("Could not parse `--restart-policy`")
	}

	pub(super) fn pivot_hash(opts: &PivotHashOpts) {
		let pivot = std::fs::read(&opts.pivot_path).unwrap_or_else(|e| {
			panic!(
				"pivot_hash: Could not read pivot file from {:?}: {e}",
				opts.pivot_path
			)
		});

		let hash = qos_crypto::sha_256(&pivot);
		let hex_hash = qos_hex::encode(&hash);

		std::fs::write(&opts.output_path, hex_hash.as_bytes()).unwrap_or_else(
			|e| {
				panic!(
					"pivot_hash: Could not write pivot hash to {:?}: {e}",
					opts.output_path
				)
			},
		);
	}

	pub(super) fn host_health(opts: &HostHealthOpts) {
		let path = opts.host.path("host-health");
		if let Ok(response) = request::get(&path) {
			println!("{response}");
		} else {
			panic!("Error...")
		}
	}

	pub(super) fn enclave_status(opts: &EnclaveStatusOpts) {
		let path = opts.host.path_message();

		let response = request::post(&path, &ProtocolMsg::StatusRequest)
			.map_err(|e| println!("{e:?}"))
			.expect("Enclave request failed");

		match response {
			ProtocolMsg::StatusResponse(phase) => {
				println!("Enclave phase: {phase:?}");
			}
			other => panic!("Unexpected response {other:?}"),
		}
	}

	pub(super) fn generate_file_key(opts: &GenerateFileKeyOpts) {
		services::generate_file_key(&opts.master_seed_path, &opts.pub_path);
	}

	pub(super) fn provision_yubikey(opts: ProvisionYubikeyOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			let _ = opts;
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::provision_yubikey(opts.pub_path) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn advanced_provision_yubikey(
		opts: AdvancedProvisionYubikeyOpts,
	) {
		#[cfg(not(feature = "smartcard"))]
		{
			let _ = opts;
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::advanced_provision_yubikey(
				opts.master_seed_path,
				opts.current_pin_path,
			) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_sign(opts: &YubikeySignOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			let _ = opts;
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::yubikey_sign(&opts.payload) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_public() {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::yubikey_public() {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_piv_reset() {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = crate::yubikey::yubikey_piv_reset() {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_change_pin(opts: YubikeyChangePinOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			let _ = opts;
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			let current_pin = services::pin_from_path(
				opts.current_pin_path
					.expect("Missing `--current-pin-path` arg"),
			);
			let new_pin = services::pin_from_path(opts.new_pin_path);

			if let Err(e) = crate::yubikey::yubikey_change_pin(
				&current_pin[..],
				&new_pin[..],
			) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn boot_genesis(opts: &BootGenesisOpts) {
		if let Err(e) = services::boot_genesis(services::BootGenesisArgs {
			uri: &opts.host.path_message(),
			namespace_dir: opts.namespace_dir.clone(),
			share_set_dir: opts.share_set_dir.clone(),
			qos_release_dir_path: opts.qos_release_dir.clone(),
			pcr3_preimage_path: opts.pcr3_preimage_path.clone(),
			dr_key_path: opts.dr_key_path.clone(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation,
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn after_genesis(opts: AfterGenesisOpts) {
		let pair = match PairOrYubi::from_inputs(
			opts.yubikey,
			opts.secret_path,
			opts.current_pin_path,
		) {
			Err(e) => {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
			Ok(p) => p,
		};
		if let Err(e) = services::after_genesis(services::AfterGenesisArgs {
			pair,
			share_path: opts.share_path,
			alias: opts.alias,
			namespace_dir: opts.namespace_dir,
			qos_release_dir_path: opts.qos_release_dir,
			pcr3_preimage_path: opts.pcr3_preimage_path,
			unsafe_skip_attestation: opts.unsafe_skip_attestation,
			validation_time_override: opts.validation_time_override,
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn verify_genesis(opts: &VerifyGenesisOpts) {
		if let Err(e) = services::verify_genesis(
			opts.namespace_dir.clone(),
			opts.master_seed_path.clone(),
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn generate_manifest(opts: GenerateManifestOpts) {
		let pivot_args = parse_pivot_args(&opts.pivot_args);
		let bridge_config = parse_bridge_config(opts.bridge_config.as_deref());
		let restart_policy = parse_restart(&opts.restart_policy);

		if let Err(e) =
			services::generate_manifest(services::GenerateManifestArgs {
				nonce: opts.nonce,
				namespace: opts.namespace,
				restart_policy,
				pivot_hash_path: opts.pivot_hash_path,
				qos_release_dir_path: opts.qos_release_dir,
				pcr3_preimage_path: opts.pcr3_preimage_path,
				manifest_path: opts.manifest_path,
				pivot_args,
				share_set_dir: opts.share_set_dir,
				manifest_set_dir: opts.manifest_set_dir,
				patch_set_dir: opts.patch_set_dir,
				quorum_key_path: opts.quorum_key_path,
				bridge_config,
				debug_mode: opts.debug_mode,
			}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn generate_manifest_v2(opts: GenerateManifestOpts) {
		let pivot_args = parse_pivot_args(&opts.pivot_args);
		let bridge_config = parse_bridge_config(opts.bridge_config.as_deref());
		let restart_policy = parse_restart(&opts.restart_policy);

		if let Err(e) =
			services::generate_manifest_v2(services::GenerateManifestArgs {
				nonce: opts.nonce,
				namespace: opts.namespace,
				restart_policy,
				pivot_hash_path: opts.pivot_hash_path,
				qos_release_dir_path: opts.qos_release_dir,
				pcr3_preimage_path: opts.pcr3_preimage_path,
				manifest_path: opts.manifest_path,
				pivot_args,
				share_set_dir: opts.share_set_dir,
				manifest_set_dir: opts.manifest_set_dir,
				patch_set_dir: opts.patch_set_dir,
				quorum_key_path: opts.quorum_key_path,
				bridge_config,
				debug_mode: opts.debug_mode,
			}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn approve_manifest(opts: ApproveManifestOpts) {
		let pair =
			match PairOrYubi::from_inputs(opts.yubikey, opts.secret_path, None)
			{
				Err(e) => {
					eprintln!("Error: {e:?}");
					std::process::exit(1);
				}
				Ok(p) => p,
			};

		if let Err(e) =
			services::approve_manifest(services::ApproveManifestArgs {
				pair,
				manifest_path: opts.manifest_path,
				manifest_approvals_dir: opts.manifest_approvals_dir,
				qos_release_dir_path: opts.qos_release_dir,
				pcr3_preimage_path: opts.pcr3_preimage_path,
				pivot_hash_path: opts.pivot_hash_path,
				quorum_key_path: opts.quorum_key_path,
				manifest_set_dir: opts.manifest_set_dir,
				share_set_dir: opts.share_set_dir,
				patch_set_dir: opts.patch_set_dir,
				alias: opts.alias,
				unsafe_auto_confirm: opts.unsafe_auto_confirm,
			}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn boot_standard(opts: BootStandardOpts) {
		let envelope_path = opts
			.manifest_envelope_path
			.expect("Missing `--manifest-envelope-path`");
		if let Err(e) = services::boot_standard(services::BootStandardArgs {
			uri: opts.host.path_message(),
			pivot_path: opts.pivot_path,
			manifest_envelope_path: envelope_path,
			pcr3_preimage_path: opts.pcr3_preimage_path,
			unsafe_skip_attestation: opts.unsafe_skip_attestation,
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn get_attestation_doc(opts: &GetAttestationDocOpts) {
		let envelope_path = opts
			.manifest_envelope_path
			.clone()
			.expect("Missing `--manifest-envelope-path`");
		services::get_attestation_doc(
			&opts.host.path_message(),
			opts.attestation_doc_path.clone(),
			envelope_path,
		);
	}

	pub(super) fn get_ephemeral_key_hex(opts: GetEphemeralKeyHexOpts) {
		services::get_ephemeral_key_hex(
			opts.attestation_doc_path,
			opts.ephemeral_key_path,
		);
	}

	pub(super) fn proxy_re_encrypt_share(opts: ProxyReEncryptShareOpts) {
		let pair = match PairOrYubi::from_inputs(
			opts.yubikey,
			opts.secret_path,
			opts.current_pin_path,
		) {
			Err(e) => {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
			Ok(p) => p,
		};

		let envelope_path = opts
			.manifest_envelope_path
			.expect("Missing `--manifest-envelope-path`");
		if let Err(e) = services::proxy_re_encrypt_share(
			services::ProxyReEncryptShareArgs {
				pair,
				share_path: opts.share_path,
				manifest_envelope_path: envelope_path,
				approval_path: opts.approval_path,
				eph_wrapped_share_path: opts.eph_wrapped_share_path,
				attestation_doc_path: opts.attestation_doc_path,
				pcr3_preimage_path: opts.pcr3_preimage_path,
				alias: opts.alias,
				manifest_set_dir: opts.manifest_set_dir,
				unsafe_skip_attestation: opts.unsafe_skip_attestation,
				unsafe_eph_path_override: opts.unsafe_eph_path_override,
				unsafe_auto_confirm: opts.unsafe_auto_confirm,
			},
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn post_share(opts: PostShareOpts) {
		if let Err(e) = services::post_share(
			&opts.host.path_message(),
			opts.eph_wrapped_share_path,
			opts.approval_path,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn display(opts: &DisplayOpts) {
		if let Err(e) = services::display(
			opts.display_type,
			opts.file_path.clone(),
			opts.json,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn json_to_borsh(opts: &JsonToBorshOpts) {
		if let Err(e) = services::json_to_borsh(
			opts.display_type,
			opts.file_path.clone(),
			opts.output_path.clone(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn dangerous_dev_boot(opts: DangerousDevBootOpts) {
		let pivot_args = parse_pivot_args(&opts.pivot_args);
		let restart_policy = parse_restart(&opts.restart_policy);
		services::dangerous_dev_boot(
			&opts.host.path_message(),
			opts.pivot_path,
			restart_policy,
			pivot_args,
			Vec::new(),
			opts.unsafe_eph_path_override.as_deref(),
		);
	}

	pub(super) fn generate_manifest_envelope(
		opts: GenerateManifestEnvelopeOpts,
	) {
		if let Err(e) = services::generate_manifest_envelope(
			opts.manifest_approvals_dir,
			opts.manifest_path,
			opts.manifest_envelope_path,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn shamir_split(opts: ShamirSplitOpts) {
		if let Err(e) = services::shamir_split(
			opts.secret_path,
			opts.total_shares,
			opts.threshold,
			&opts.output_dir,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn shamir_reconstruct(opts: ShamirReconstructOpts) {
		if let Err(e) =
			services::shamir_reconstruct(opts.share, &opts.output_path)
		{
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn boot_key_fwd(opts: BootKeyFwdOpts) {
		let envelope_path = opts
			.manifest_envelope_path
			.expect("Missing `--manifest-envelope-path`");
		if let Err(e) = services::boot_key_fwd(
			&opts.host.path_message(),
			envelope_path,
			opts.pivot_path,
			opts.attestation_doc_path,
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn export_key(opts: ExportKeyOpts) {
		let envelope_path = opts
			.manifest_envelope_path
			.expect("Missing `--manifest-envelope-path`");
		if let Err(e) = services::export_key(
			&opts.host.path_message(),
			envelope_path,
			opts.attestation_doc_path,
			opts.encrypted_quorum_key_path,
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn inject_key(opts: InjectKeyOpts) {
		if let Err(e) = services::inject_key(
			&opts.host.path_message(),
			opts.encrypted_quorum_key_path,
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_verify(opts: P256VerifyOpts) {
		if let Err(e) = services::p256_verify(
			opts.payload_path,
			opts.signature_path,
			opts.pub_path,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_sign(opts: P256SignOpts) {
		if let Err(e) = services::p256_sign(
			&opts.payload_path,
			opts.signature_path,
			opts.master_seed_path,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_asymmetric_encrypt(opts: P256AsymmetricEncryptOpts) {
		if let Err(e) = services::p256_asymmetric_encrypt(
			opts.plaintext_path,
			opts.ciphertext_path,
			opts.pub_path,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_asymmetric_decrypt(opts: P256AsymmetricDecryptOpts) {
		if let Err(e) = services::p256_asymmetric_decrypt(
			opts.plaintext_path,
			opts.ciphertext_path,
			opts.master_seed_path,
			opts.output_hex,
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn parse(args: &[&str]) -> Cli {
		Cli::try_parse_from(args.iter().copied()).unwrap_or_else(|e| {
			panic!("parse failed for {args:?}: {e}");
		})
	}

	#[test]
	fn use_qos_version_defaults_to_none() {
		let cli = parse(&[
			"qos_client",
			"host-health",
			"--host-ip",
			"1",
			"--host-port",
			"2",
		]);
		assert_eq!(cli.use_qos_version, None);
	}

	#[test]
	fn use_qos_version_accepts_0_1_2() {
		for v in [0u32, 1, 2] {
			let cli = parse(&[
				"qos_client",
				"--use-qos-version",
				&v.to_string(),
				"host-health",
				"--host-ip",
				"1",
				"--host-port",
				"2",
			]);
			assert_eq!(cli.use_qos_version, Some(v));
		}
	}

	#[test]
	fn use_qos_version_rejects_invalid() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"--use-qos-version",
			"99",
			"host-health",
			"--host-ip",
			"1",
			"--host-port",
			"2",
		])
		.is_err());

		assert!(Cli::try_parse_from([
			"qos_client",
			"--use-qos-version",
			"abc",
			"host-health",
			"--host-ip",
			"1",
			"--host-port",
			"2",
		])
		.is_err());
	}

	#[test]
	fn host_health_parses() {
		let cli = parse(&[
			"qos_client",
			"host-health",
			"--host-ip",
			"127.0.0.1",
			"--host-port",
			"3000",
		]);
		assert!(matches!(cli.command, Command::HostHealth(_)));
	}

	#[test]
	fn host_health_requires_host_ip() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"host-health",
			"--host-port",
			"3000",
		])
		.is_err());
	}

	#[test]
	fn unknown_command_is_rejected() {
		assert!(Cli::try_parse_from(["qos_client", "bogus-cmd"]).is_err());
	}

	#[test]
	fn unknown_flag_is_rejected() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"host-health",
			"--host-ip",
			"1",
			"--host-port",
			"2",
			"--bogus-flag",
		])
		.is_err());
	}

	#[test]
	fn yubikey_and_secret_path_conflict() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"approve-manifest",
			"--yubikey",
			"--secret-path",
			"x",
			"--manifest-path",
			"m",
			"--manifest-approvals-dir",
			"a",
			"--qos-release-dir",
			"r",
			"--pcr3-preimage-path",
			"p",
			"--pivot-hash-path",
			"h",
			"--alias",
			"al",
			"--quorum-key-path",
			"q",
			"--manifest-set-dir",
			"ms",
			"--share-set-dir",
			"ss",
			"--patch-set-dir",
			"ps",
		])
		.is_err());
	}

	#[test]
	fn shamir_reconstruct_accepts_multiple_shares() {
		let cli = parse(&[
			"qos_client",
			"shamir-reconstruct",
			"--share",
			"a",
			"--share",
			"b",
			"--share",
			"c",
			"--output-path",
			"out",
		]);
		match cli.command {
			Command::ShamirReconstruct(opts) => {
				assert_eq!(opts.share, vec!["a", "b", "c"]);
			}
			other => panic!("unexpected command: {other:?}"),
		}
	}

	#[test]
	fn shamir_reconstruct_requires_share_at_parse_time() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"shamir-reconstruct",
			"--output-path",
			"out",
		])
		.is_err());
	}

	#[test]
	fn single_dash_values_parse_for_string_args() {
		let cli = parse(&[
			"qos_client",
			"display",
			"--file-path",
			"-manifest",
			"--display-type",
			"manifest",
		]);
		match cli.command {
			Command::Display(opts) => {
				assert_eq!(opts.file_path, "-manifest");
				assert!(matches!(opts.display_type, DisplayType::Manifest));
			}
			other => panic!("unexpected command: {other:?}"),
		}

		let cli = parse(&["qos_client", "yubikey-sign", "--payload", "-abc"]);
		match cli.command {
			Command::YubikeySign(opts) => assert_eq!(opts.payload, "-abc"),
			other => panic!("unexpected command: {other:?}"),
		}
	}

	#[test]
	fn display_type_rejects_unknown_values_at_parse_time() {
		assert!(Cli::try_parse_from([
			"qos_client",
			"display",
			"--file-path",
			"manifest",
			"--display-type",
			"bogus",
		])
		.is_err());
	}

	#[test]
	fn pivot_args_default_is_empty_brackets() {
		let cli = parse(&[
			"qos_client",
			"generate-manifest",
			"--nonce",
			"1",
			"--namespace",
			"ns",
			"--pivot-hash-path",
			"h",
			"--restart-policy",
			"never",
			"--qos-release-dir",
			"r",
			"--pcr3-preimage-path",
			"p",
			"--manifest-path",
			"m",
			"--manifest-set-dir",
			"ms",
			"--share-set-dir",
			"ss",
			"--patch-set-dir",
			"ps",
			"--quorum-key-path",
			"q",
		]);
		match cli.command {
			Command::GenerateManifest(opts) => {
				assert_eq!(opts.pivot_args, "[]");
				assert!(!opts.debug_mode);
			}
			other => panic!("unexpected command: {other:?}"),
		}
	}

	#[test]
	fn pivot_args_bare_flag_followed_by_another_flag_keeps_default() {
		let cli = parse(&[
			"qos_client",
			"dangerous-dev-boot",
			"--host-ip",
			"127.0.0.1",
			"--host-port",
			"3000",
			"--pivot-path",
			"pivot",
			"--pivot-args",
			"--restart-policy",
			"never",
		]);
		match cli.command {
			Command::DangerousDevBoot(opts) => {
				assert_eq!(opts.pivot_args, "[]");
				assert_eq!(opts.restart_policy, "never");
			}
			other => panic!("unexpected command: {other:?}"),
		}
	}

	#[test]
	fn pivot_args_explicit_value_passes_through() {
		let cli = parse(&[
			"qos_client",
			"dangerous-dev-boot",
			"--host-ip",
			"127.0.0.1",
			"--host-port",
			"3000",
			"--pivot-path",
			"pivot",
			"--pivot-args",
			"[--foo,bar]",
			"--restart-policy",
			"never",
		]);
		match cli.command {
			Command::DangerousDevBoot(opts) => {
				assert_eq!(opts.pivot_args, "[--foo,bar]");
			}
			other => panic!("unexpected command: {other:?}"),
		}
	}

	#[test]
	fn endpoint_base_path_defaults_to_qos() {
		let host = HostOpts {
			host_ip: "127.0.0.1".to_string(),
			host_port: "3000".to_string(),
			endpoint_base_path: None,
		};
		assert_eq!(host.path_message(), "http://127.0.0.1:3000/qos/message");
	}

	#[test]
	fn endpoint_base_path_override_is_used() {
		let host = HostOpts {
			host_ip: "127.0.0.1".to_string(),
			host_port: "3000".to_string(),
			endpoint_base_path: Some("custom".to_string()),
		};
		assert_eq!(host.path_message(), "http://127.0.0.1:3000/custom/message");
	}
}

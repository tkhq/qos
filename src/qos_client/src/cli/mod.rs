//! `QuorumOS` client command line interface.
//!
//! See [`Command`] for all possible commands.
//!
//! The arguments for each command can be discovered by running:
//!
//! ```shell
//! cargo run --bin qos_client <command-name> --help
//! ```

use std::env;

use qos_core::{
	parser::{CommandParser, GetParserForCommand, Parser, Token},
	protocol::{msg::ProtocolMsg, services::boot},
};

mod services;

pub use services::PairOrYubi;
pub use services::{advanced_provision_yubikey, generate_file_key};

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const ALIAS: &str = "alias";
const NAMESPACE: &str = "namespace";
const NONCE: &str = "nonce";
const RESTART_POLICY: &str = "restart-policy";
const PIVOT_PATH: &str = "pivot-path";
const PIVOT_ARGS: &str = "pivot-args";
const UNSAFE_SKIP_ATTESTATION: &str = "unsafe-skip-attestation";
const UNSAFE_EPH_PATH_OVERRIDE: &str = "unsafe-eph-path-override";
const ENDPOINT_BASE_PATH: &str = "endpoint-base-path";
const QOS_REALEASE_DIR: &str = "qos-release-dir";
const PCR3_PREIMAGE_PATH: &str = "pcr3-preimage-path";
const PIVOT_HASH_PATH: &str = "pivot-hash-path";
const SHARE_SET_DIR: &str = "share-set-dir";
const MANIFEST_SET_DIR: &str = "manifest-set-dir";
const PATCH_SET_DIR: &str = "patch-set-dir";
const NAMESPACE_DIR: &str = "namespace-dir";
const UNSAFE_AUTO_CONFIRM: &str = "unsafe-auto-confirm";
const PUB_PATH: &str = "pub-path";
const POOL_SIZE: &str = "pool-size";
const CLIENT_TIMEOUT: &str = "client-timeout";
const YUBIKEY: &str = "yubikey";
const SECRET_PATH: &str = "secret-path";
const SHARE_PATH: &str = "share-path";
const OUTPUT_PATH: &str = "output-path";
const QUORUM_KEY_PATH: &str = "quorum-key-path";
const MANIFEST_APPROVALS_DIR: &str = "manifest-approvals-dir";
const MANIFEST_PATH: &str = "manifest-path";
const MANIFEST_ENVELOPE_PATH: &str = "manifest-envelope-path";
const APPROVAL_PATH: &str = "approval-path";
const EPH_WRAPPED_SHARE_PATH: &str = "eph-wrapped-share-path";
const ATTESTATION_DOC_PATH: &str = "attestation-doc-path";
const MASTER_SEED_PATH: &str = "master-seed-path";
const SHARE: &str = "share";
const OUTPUT_DIR: &str = "output-dir";
const THRESHOLD: &str = "threshold";
const TOTAL_SHARES: &str = "total-shares";
const FILE_PATH: &str = "file-path";
const DISPLAY_TYPE: &str = "display-type";
const DR_KEY_PATH: &str = "dr-key-path";
const CURRENT_PIN_PATH: &str = "current-pin-path";
const NEW_PIN_PATH: &str = "new-pin-path";
const ENCRYPTED_QUORUM_KEY_PATH: &str = "encrypted-quorum-key-path";
const PAYLOAD: &str = "payload";
const PAYLOAD_PATH: &str = "payload-path";
const SIGNATURE_PATH: &str = "signature-path";
const EPHEMERAL_KEY_PATH: &str = "ephemeral-key-path";
const CIPHERTEXT_PATH: &str = "ciphertext-path";
const PLAINTEXT_PATH: &str = "plaintext-path";
const OUTPUT_HEX: &str = "output-hex";
const VALIDATION_TIME_OVERRIDE: &str = "validation-time-override";
const JSON: &str = "json";

pub(crate) enum DisplayType {
	Manifest,
	ManifestEnvelope,
	GenesisOutput,
}

impl From<&str> for DisplayType {
	fn from(ty: &str) -> Self {
		match ty {
			"manifest" => Self::Manifest,
			"manifest-envelope" => Self::ManifestEnvelope,
			"genesis-output" => Self::GenesisOutput,
			unknown => panic!("unrecognized display type: {unknown}"),
		}
	}
}

/// Commands for the Client CLI.
///
/// To get the possible arguments for any given command pass the help flag. For
/// example, to get the arguments for [`Self::GenerateManifest`] run:
///
/// ```bash
/// cargo run --bin qos_client -- generate-manifest --help
/// ```
///
/// Note that the command name is kebab-case.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
	/// Query the health endpoint of the enclave host server.
	HostHealth,
	/// Query the status of the enclave.
	EnclaveStatus,
	/// Generate a Setup Key for use in the Genesis ceremony.
	GenerateFileKey,
	/// Run the the Boot Genesis logic to generate and shard a Quorum Key
	/// across the given Setup Keys. Each setup key will correspond to a Quorum
	/// Set Member, so N will equal the number of Setup Keys.
	///
	/// This will output `GenesisOutput` and an `AttestationDoc` embedded in a
	/// COSE Sign1 structure. The `GenesisOutput` contains the public Quorum
	/// Key, each members personal key (encrypted to setup key), and each
	/// members share (encrypted to personal key).
	BootGenesis,
	/// Decrypt the Personal Key and Personal Share share from the Genesis
	/// Ceremony outputs (`GenesisOutput` and the `AttestationDoc` is used to
	/// verify the enclave composition).
	///
	/// This will output the decrypted Personal Key associated with your Setup
	/// Key.
	AfterGenesis,
	/// Verify the Disaster Recovery artifacts against the corresponding master
	/// seed.
	///
	/// This takes a path to a file with the hex encoded master seed and the
	/// directory with the genesis output.
	VerifyGenesis,
	/// Using the given Personal Keys as the Manifest Set, generate a manifest.
	GenerateManifest,
	/// Sign a trusted Manifest.
	///
	/// This will output a manifest `Approval`.
	///
	/// Careful - only ever sign a manifest you have inspected, trust and know
	/// is the latest one for the namespace.
	ApproveManifest,
	/// Start booting an enclave.
	///
	/// Given a `Manifest` and K `Approval`s, send the boot standard
	/// instruction to the enclave.
	///
	/// This will output the COSE Sign1 structure with an embedded
	/// `AttestationDoc`.
	BootStandard,
	/// Get the attestation document from an enclave. Will also get the
	/// manifest envelope if it exists.
	GetAttestationDoc,
	/// Extract the `public_key` i.e. ephemeral key from the given attestation
	/// doc file and store it hex encoded in the given file
	GetEphemeralKeyHex,
	/// Given an attestation document from an enclave waiting for shares,
	/// re-encrypt the local share to the Ephemeral Key from the attestation
	/// doc.
	///
	/// The Ephemeral Key is pulled out of the attestation document.
	///
	/// This command will check the manifest signatures and verify that the
	/// manifest correctly lines up with the enclave document.
	///
	/// This command should only be used in highly secure environments as the
	/// quorum share momentarily in plaintext.
	ProxyReEncryptShare,
	/// Submit an encrypted share to an enclave.
	PostShare,
	/// Given a directory containing a manifest and threshold approvals for it,
	/// generate a manifest envelope and write it back to the same directory.
	GenerateManifestEnvelope,
	/// ** Never use in production**.
	///
	/// Pivot the enclave to the specified binary.
	///
	/// This command goes through the steps of generating a Quorum Key,
	/// sharding it (N=1), creating/signing/posting a Manifest, and
	/// provisioning the quorum key.
	DangerousDevBoot,
	/// Provision a yubikey with a singing and encryption key.
	ProvisionYubiKey,
	/// Provision a yubikey by generating a secret and importing it onto the
	/// key. The generated secret (master seed) is written to disk so it can be
	/// further backed up.
	AdvancedProvisionYubiKey,
	/// Create a dummy pivot build fingerprints with a correct hash
	PivotHash,
	/// Split a secret into shares with Shamir Secret Sharing.
	ShamirSplit,
	/// Reconstruct a secret from Shamir Secret Sharing shares.
	ShamirReconstruct,
	/// Sign a hex encoded payload with the yubikey.
	YubiKeySign,
	/// Get the public key of a yubikey
	YubiKeyPublic,
	/// Display some borsh encoded type in an easy to read format.
	Display,
	/// Reset the PIV app. WARNING: this is a destructive operation that will
	/// destroy all PIV keys!
	YubiKeyPivReset,
	/// Change the pin of the PIV app on the yubikey.
	YubiKeyChangePin,
	/// Send the boot instruction for the enclave to start the key forwarding
	/// process.
	BootKeyFwd,
	/// Request a quorum key from a fully provisioned enclave as part of the
	/// key forwarding flow.
	ExportKey,
	/// Inject a quorum key into a non-fully provisioned enclave
	InjectKey,
	/// Verify a signature from `qos_p256` pair.
	P256Verify,
	/// Sign with a p256 signature.
	P256Sign,
	/// Encrypt to a `qos_p256` public key.
	P256AsymmetricEncrypt,
	/// Decrypt a payload encrypted to a `qos_p256` public key.
	P256AsymmetricDecrypt,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"enclave-status" => Self::EnclaveStatus,
			"generate-file-key" => Self::GenerateFileKey,
			"generate-manifest-envelope" => Self::GenerateManifestEnvelope,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
			"verify-genesis" => Self::VerifyGenesis,
			"generate-manifest" => Self::GenerateManifest,
			"approve-manifest" => Self::ApproveManifest,
			"boot-standard" => Self::BootStandard,
			"get-attestation-doc" => Self::GetAttestationDoc,
			"get-ephemeral-key-hex" => Self::GetEphemeralKeyHex,
			"proxy-re-encrypt-share" => Self::ProxyReEncryptShare,
			"post-share" => Self::PostShare,
			"dangerous-dev-boot" => Self::DangerousDevBoot,
			"provision-yubikey" => Self::ProvisionYubiKey,
			"advanced-provision-yubikey" => Self::AdvancedProvisionYubiKey,
			"pivot-hash" => Self::PivotHash,
			"shamir-split" => Self::ShamirSplit,
			"shamir-reconstruct" => Self::ShamirReconstruct,
			"yubikey-sign" => Self::YubiKeySign,
			"yubikey-public" => Self::YubiKeyPublic,
			"yubikey-piv-reset" => Self::YubiKeyPivReset,
			"yubikey-change-pin" => Self::YubiKeyChangePin,
			"display" => Self::Display,
			"boot-key-fwd" => Self::BootKeyFwd,
			"export-key" => Self::ExportKey,
			"inject-key" => Self::InjectKey,
			"p256-verify" => Self::P256Verify,
			"p256-sign" => Self::P256Sign,
			"p256-asymmetric-encrypt" => Self::P256AsymmetricEncrypt,
			"p256-asymmetric-decrypt" => Self::P256AsymmetricDecrypt,
			_ => panic!(
				"Unrecognized command, try something like `host-health --help`"
			),
		}
	}
}

impl From<String> for Command {
	fn from(s: String) -> Self {
		Self::from(s.as_str())
	}
}

impl Command {
	fn print_all() {
		println!(
			"\thost-health, enclave-status, generate-file-key, generate-manifest-envelope, boot-genesis,\n\tafter-genesis, verify-genesis, generate-manifest, approve-manifest, boot-standard, get-attestation-doc,\n\tget-ephemeral-key-hex, proxy-re-encrypt-share, post-share, dangerous-dev-boot,\n\tprovision-yubikey, advanced-provision-yubikey, pivot-hash, shamir-split, shamir-reconstruct,\n\tyubikey-sign, yubikey-public, yubikey-piv-reset, yubikey-change-pin, display,\n\tboot-key-fwd, export-key, inject-key, p256-verify, p256-sign, p256-asymmetric-encrypt, p256-asymmetric-decrypt"
		);
	}

	fn namespace_token() -> Token {
		Token::new(NAMESPACE, "Namespace for the associated manifest.")
			.takes_value(true)
			.required(true)
	}
	fn pivot_path_token() -> Token {
		Token::new(PIVOT_PATH, "Path to the pivot binary.")
			.takes_value(true)
			.required(true)
	}
	fn restart_policy_token() -> Token {
		Token::new(RESTART_POLICY, "One of: `never`, `always`.")
			.takes_value(true)
			.required(true)
	}
	fn pivot_args_token() -> Token {
		Token::new(
			PIVOT_ARGS,
			"Comma separated, [] wrapped CLI args for pivot. e.g. `[--usock,dev.sock,--path,./path-to-file]`"
		)
		.takes_value(true)
		.default_value("[]")
	}
	fn unsafe_skip_attestation_token() -> Token {
		Token::new(
			UNSAFE_SKIP_ATTESTATION,
			"NEVER USE IN PRODUCTION! Skip all attestation document checks, including basic cert chain validation."
		)
		.takes_value(false)
	}
	fn unsafe_eph_path_override_token() -> Token {
		Token::new(
			UNSAFE_EPH_PATH_OVERRIDE,
			"NEVER USE IN PRODUCTION! Use the secret at the given path to encrypt data sent to the enclave, instead of extracting it from the attestation doc."
		)
		.takes_value(true)
	}
	fn qos_release_dir_token() -> Token {
		Token::new(
			QOS_REALEASE_DIR,
			"Path to file with QOS build fingerprints (PCR{1, 2, 3}).",
		)
		.takes_value(true)
		.required(true)
	}
	fn pcr3_preimage_path_token() -> Token {
		Token::new(
			PCR3_PREIMAGE_PATH,
			"Path to file with pcr3 preimage, the Amazon resource name (ARN) of the instance.",
		)
		.takes_value(true)
		.required(true)
	}
	fn pivot_hash_path_token() -> Token {
		Token::new(
			PIVOT_HASH_PATH,
			"Path to file with Pivot build fingerprints.",
		)
		.takes_value(true)
		.required(true)
	}
	fn manifest_set_dir_token() -> Token {
		Token::new(
			MANIFEST_SET_DIR,
			"Directory with public keys for members of the manifest set.",
		)
		.takes_value(true)
		.required(true)
	}
	fn share_set_dir_token() -> Token {
		Token::new(
			SHARE_SET_DIR,
			"Director with public keys for members of the share set.",
		)
		.takes_value(true)
		.required(true)
	}
	fn patch_set_dir_token() -> Token {
		Token::new(
			PATCH_SET_DIR,
			"Director with public keys for members of the patch set.",
		)
		.takes_value(true)
		.required(true)
	}
	fn namespace_dir_token() -> Token {
		Token::new(
			NAMESPACE_DIR,
			"Directory for the namespace this manifest will belong to.",
		)
		.takes_value(true)
		.required(true)
	}
	fn manifest_approvals_dir_token() -> Token {
		Token::new(
			MANIFEST_APPROVALS_DIR,
			"Directory where the approvals for the manifest are kept",
		)
		.takes_value(true)
		.required(true)
	}
	fn alias_token() -> Token {
		Token::new(ALIAS, "Alias for identifying the key pair")
			.takes_value(true)
			.required(true)
	}
	fn unsafe_auto_confirm_token() -> Token {
		Token::new(
			UNSAFE_AUTO_CONFIRM,
			"DO NOT USE IN PRODUCTION. Confirm all interactive prompts.",
		)
		.takes_value(false)
		.required(false)
	}
	fn pub_path_token() -> Token {
		Token::new(PUB_PATH, "Path to the public key for a YubiKey")
			.takes_value(true)
			.required(true)
	}

	fn yubikey_token() -> Token {
		Token::new(YUBIKEY, "Flag to indicate using a yubikey for signing")
			.takes_value(false)
			.required(false)
			.forbids(vec![SECRET_PATH])
	}
	fn secret_path_token() -> Token {
		Token::new(
			SECRET_PATH,
			"Path to the secret to use for signing/decryption.",
		)
		.takes_value(true)
		.required(false)
		.forbids(vec![YUBIKEY])
	}
	fn share_path_token() -> Token {
		Token::new(SHARE_PATH, "Path to the encrypted quorum key share.")
			.takes_value(true)
			.required(true)
	}
	fn output_path_token() -> Token {
		Token::new(OUTPUT_PATH, "The path to create a file at.")
			.takes_value(true)
			.required(true)
	}
	fn quorum_key_path_token() -> Token {
		Token::new(QUORUM_KEY_PATH, "The path to the quorum public key")
			.takes_value(true)
			.required(true)
	}
	fn manifest_path_token() -> Token {
		Token::new(MANIFEST_PATH, "The path to the manifest")
			.takes_value(true)
			.required(true)
	}
	fn manifest_envelope_path_token() -> Token {
		Token::new(MANIFEST_ENVELOPE_PATH, "Path to a manifest envelope")
			.takes_value(true)
			.required(false)
	}
	fn approval_path_token() -> Token {
		Token::new(APPROVAL_PATH, "Path to a approval of a manifest.")
			.takes_value(true)
			.required(true)
	}
	fn eph_wrapped_share_path_token() -> Token {
		Token::new(
			EPH_WRAPPED_SHARE_PATH,
			"Path to a Ephemeral Key wrapped share.",
		)
		.takes_value(true)
		.required(true)
	}
	fn attestation_doc_path_token() -> Token {
		Token::new(ATTESTATION_DOC_PATH, "Path to an attestation doc.")
			.takes_value(true)
			.required(true)
	}
	fn master_seed_path_token() -> Token {
		Token::new(MASTER_SEED_PATH, "Path to a master seed.")
			.takes_value(true)
			.required(true)
	}
	fn share_token() -> Token {
		Token::new(
			SHARE,
			"Paths to a share. This can be specified multiple times.",
		)
		.takes_value(true)
		.required(true)
		.allow_multiple(true)
	}
	fn threshold_token() -> Token {
		Token::new(
			THRESHOLD,
			"The threshold to reconstruct a shamir split secret.",
		)
		.takes_value(true)
		.required(true)
	}
	fn output_dir_token() -> Token {
		Token::new(OUTPUT_DIR, "The directory to write outputs.")
			.takes_value(true)
			.required(true)
	}
	fn total_shares_token() -> Token {
		Token::new(
			TOTAL_SHARES,
			"Total shares to generate with shamir secret sharing.",
		)
		.takes_value(true)
		.required(true)
	}
	fn payload_token() -> Token {
		Token::new(PAYLOAD, "A hex encoded payload to sign / verify.")
			.takes_value(true)
			.required(true)
	}
	fn payload_path_token() -> Token {
		Token::new(
			PAYLOAD_PATH,
			"A path to a payload to sign / verify a signature against.",
		)
		.takes_value(true)
		.required(true)
	}
	fn signature_path_token() -> Token {
		Token::new(SIGNATURE_PATH, "Path to a file with raw signature")
			.takes_value(true)
			.required(true)
	}
	fn ephemeral_key_path_token() -> Token {
		Token::new(EPHEMERAL_KEY_PATH, "Path to desired ephemeral key file.")
			.takes_value(true)
			.required(true)
	}
	fn file_path_token() -> Token {
		Token::new(FILE_PATH, "Path to a file.")
			.takes_value(true)
			.required(true)
	}
	fn display_type_token() -> Token {
		Token::new(
			DISPLAY_TYPE,
			"The type contained in the file (manifest, manifest-envelope, genesis-output).",
		)
		.takes_value(true)
		.required(true)
	}
	fn dr_key_path_token() -> Token {
		Token::new(DR_KEY_PATH, "Path to a DR key certificate")
			.takes_value(true)
			.required(false)
	}
	fn current_pin_path_token() -> Token {
		Token::new(
			CURRENT_PIN_PATH,
			"Path to file descriptor with current pin.",
		)
		.takes_value(true)
		.required(false)
	}
	fn new_pin_path_token() -> Token {
		Token::new(NEW_PIN_PATH, "Path to file descriptor with new pin.")
			.takes_value(true)
			.required(true)
	}
	fn encrypted_quorum_key_path_token() -> Token {
		Token::new(ENCRYPTED_QUORUM_KEY_PATH, "Path to encrypted quorum key.")
			.takes_value(true)
			.required(true)
	}
	fn plaintext_path_token() -> Token {
		Token::new(PLAINTEXT_PATH, "Path to a file with contents to encrypt")
			.takes_value(true)
			.required(true)
	}
	fn ciphertext_path_token() -> Token {
		Token::new(CIPHERTEXT_PATH, "Path to a file with encrypted data")
			.takes_value(true)
			.required(true)
	}
	fn output_hex_token() -> Token {
		Token::new(OUTPUT_HEX, "Flag to specify that the output should be hex")
			.required(false)
			.takes_value(false)
	}
	fn validation_time_override_token() -> Token {
		Token::new(
			VALIDATION_TIME_OVERRIDE,
			"Valid time for attestation doc cert chain",
		)
		.required(false)
		.takes_value(true)
	}
	fn json_token() -> Token {
		Token::new(JSON, "Include to format the output in json")
			.required(false)
			.takes_value(false)
	}

	fn pool_size() -> Token {
		Token::new(POOL_SIZE, "Socket pool size for USOCK/VSOCK")
			.required(false)
			.takes_value(true)
	}

	fn client_timeout() -> Token {
		Token::new(
			CLIENT_TIMEOUT,
			"Client timeout for enclave <-> app communication",
		)
		.required(false)
		.takes_value(true)
	}

	fn base() -> Parser {
		Parser::new()
			.token(
				Token::new(HOST_IP, "IP address this server should listen on.")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(HOST_PORT, "Port this server should listen on.")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(
					ENDPOINT_BASE_PATH,
					"base path for all endpoints. e.g. <BASE>/enclave-health",
				)
				.takes_value(true),
			)
	}

	fn pivot_build_fingerprints() -> Parser {
		Parser::new()
			.token(Self::output_path_token())
			.token(Self::pivot_path_token())
	}

	fn generate_file_key() -> Parser {
		Parser::new()
			.token(Self::master_seed_path_token())
			.token(Self::pub_path_token())
	}

	fn boot_genesis() -> Parser {
		Self::base()
			.token(Self::namespace_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::qos_release_dir_token())
			.token(Self::dr_key_path_token())
	}

	fn after_genesis() -> Parser {
		Parser::new()
			.token(Self::yubikey_token())
			.token(Self::secret_path_token())
			.token(Self::share_path_token())
			.token(Self::alias_token())
			.token(Self::namespace_dir_token())
			.token(Self::qos_release_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::current_pin_path_token())
			.token(Self::validation_time_override_token())
	}

	fn verify_genesis() -> Parser {
		Parser::new()
			.token(Self::namespace_dir_token())
			.token(Self::master_seed_path_token())
	}

	fn generate_manifest() -> Parser {
		Parser::new()
			.token(
				Token::new(
					NONCE,
					"Nonce of the manifest relative to the namespace.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(Self::namespace_token())
			.token(Self::pivot_hash_path_token())
			.token(Self::restart_policy_token())
			.token(Self::qos_release_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::manifest_path_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::patch_set_dir_token())
			.token(Self::quorum_key_path_token())
			.token(Self::pivot_args_token())
			.token(Self::pool_size())
			.token(Self::client_timeout())
	}

	fn approve_manifest() -> Parser {
		Parser::new()
			.token(Self::yubikey_token())
			.token(Self::secret_path_token())
			.token(Self::manifest_path_token())
			.token(Self::manifest_approvals_dir_token())
			.token(Self::qos_release_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::pivot_hash_path_token())
			.token(Self::alias_token())
			.token(Self::quorum_key_path_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::patch_set_dir_token())
			.token(Self::unsafe_auto_confirm_token())
	}

	fn boot_standard() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::manifest_envelope_path_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
	}

	fn get_attestation_doc() -> Parser {
		Self::base()
			.token(Self::attestation_doc_path_token())
			.token(Self::manifest_envelope_path_token())
	}

	fn proxy_re_encrypt_share() -> Parser {
		Parser::new()
			.token(Self::yubikey_token())
			.token(Self::secret_path_token())
			.token(Self::share_path_token())
			.token(Self::approval_path_token())
			.token(Self::eph_wrapped_share_path_token())
			.token(Self::attestation_doc_path_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::manifest_envelope_path_token())
			.token(Self::alias_token())
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::unsafe_eph_path_override_token())
			.token(Self::unsafe_auto_confirm_token())
	}

	fn post_share() -> Parser {
		Self::base()
			.token(Self::approval_path_token())
			.token(Self::eph_wrapped_share_path_token())
	}

	fn generate_manifest_envelope() -> Parser {
		Parser::new()
			.token(Self::manifest_approvals_dir_token())
			.token(Self::manifest_path_token())
			.token(Self::manifest_envelope_path_token())
	}

	fn dangerous_dev_boot() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::restart_policy_token())
			.token(Self::pivot_args_token())
			.token(Self::unsafe_eph_path_override_token())
	}

	fn provision_yubikey() -> Parser {
		Parser::new().token(Self::pub_path_token()).token(Self::yubikey_token())
	}

	fn advanced_provision_yubikey() -> Parser {
		Parser::new()
			.token(Self::master_seed_path_token())
			.token(Self::current_pin_path_token())
	}

	fn shamir_split() -> Parser {
		Parser::new()
			.token(Self::secret_path_token())
			.token(Self::total_shares_token())
			.token(Self::threshold_token())
			.token(Self::output_dir_token())
	}

	fn shamir_reconstruct() -> Parser {
		Parser::new()
			.token(Self::share_token())
			.token(Self::output_path_token())
	}

	fn yubikey_sign() -> Parser {
		Parser::new().token(Self::payload_token())
	}

	fn yubikey_public() -> Parser {
		Parser::new()
	}

	fn yubikey_change_pin() -> Parser {
		Parser::new()
			.token(Self::current_pin_path_token())
			.token(Self::new_pin_path_token())
	}

	fn get_ephemeral_key_hex() -> Parser {
		Parser::new()
			.token(Self::attestation_doc_path_token())
			.token(Self::ephemeral_key_path_token())
	}

	fn display() -> Parser {
		Parser::new()
			.token(Self::file_path_token())
			.token(Self::display_type_token())
			.token(Self::json_token())
	}

	fn boot_key_fwd() -> Parser {
		Self::base()
			.token(Self::manifest_envelope_path_token())
			.token(Self::pivot_path_token())
			.token(Self::attestation_doc_path_token())
	}

	fn export_key() -> Parser {
		Self::base()
			.token(Self::manifest_envelope_path_token())
			.token(Self::attestation_doc_path_token())
			.token(Self::encrypted_quorum_key_path_token())
	}

	fn inject_key() -> Parser {
		Self::base().token(Self::encrypted_quorum_key_path_token())
	}

	fn p256_verify() -> Parser {
		Parser::new()
			.token(Self::payload_path_token())
			.token(Self::signature_path_token())
			.token(Self::pub_path_token())
	}

	fn p256_sign() -> Parser {
		Parser::new()
			.token(Self::payload_path_token())
			.token(Self::signature_path_token())
			.token(Self::master_seed_path_token())
	}

	fn p256_asymmetric_encrypt() -> Parser {
		Parser::new()
			.token(Self::plaintext_path_token())
			.token(Self::ciphertext_path_token())
			.token(Self::pub_path_token())
	}

	fn p256_asymmetric_decrypt() -> Parser {
		Parser::new()
			.token(Self::plaintext_path_token())
			.token(Self::ciphertext_path_token())
			.token(Self::master_seed_path_token())
			.token(Self::output_hex_token())
	}
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth | Self::EnclaveStatus => Self::base(),
			Self::GenerateFileKey => Self::generate_file_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
			Self::VerifyGenesis => Self::verify_genesis(),
			Self::GenerateManifest => Self::generate_manifest(),
			Self::ApproveManifest => Self::approve_manifest(),
			Self::BootStandard => Self::boot_standard(),
			Self::GetAttestationDoc => Self::get_attestation_doc(),
			Self::ProxyReEncryptShare => Self::proxy_re_encrypt_share(),
			Self::GetEphemeralKeyHex => Self::get_ephemeral_key_hex(),
			Self::PostShare => Self::post_share(),
			Self::DangerousDevBoot => Self::dangerous_dev_boot(),
			Self::GenerateManifestEnvelope => {
				Self::generate_manifest_envelope()
			}
			Self::ProvisionYubiKey => Self::provision_yubikey(),
			Self::AdvancedProvisionYubiKey => {
				Self::advanced_provision_yubikey()
			}
			Self::PivotHash => Self::pivot_build_fingerprints(),
			Self::ShamirSplit => Self::shamir_split(),
			Self::ShamirReconstruct => Self::shamir_reconstruct(),
			Self::YubiKeySign => Self::yubikey_sign(),
			Self::YubiKeyPublic => Self::yubikey_public(),
			Self::YubiKeyPivReset => Parser::new(),
			Self::YubiKeyChangePin => Self::yubikey_change_pin(),
			Self::Display => Self::display(),
			Self::BootKeyFwd => Self::boot_key_fwd(),
			Self::ExportKey => Self::export_key(),
			Self::InjectKey => Self::inject_key(),
			Self::P256Verify => Self::p256_verify(),
			Self::P256Sign => Self::p256_sign(),
			Self::P256AsymmetricEncrypt => Self::p256_asymmetric_encrypt(),
			Self::P256AsymmetricDecrypt => Self::p256_asymmetric_decrypt(),
		}
	}
}

#[derive(Debug, PartialEq, Clone)]
struct ClientOpts {
	parsed: Parser,
}

impl ClientOpts {
	fn path(&self, uri: &str) -> String {
		let ip = self.parsed.single(HOST_IP).expect("required arg");
		let port = self.parsed.single(HOST_PORT).expect("required arg");

		if let Some(base) = self.parsed.single(ENDPOINT_BASE_PATH) {
			format!("http://{ip}:{port}/{base}/{uri}")
		} else {
			format!("http://{ip}:{port}/qos/{uri}")
		}
	}

	fn path_message(&self) -> String {
		self.path("message")
	}

	fn alias(&self) -> String {
		self.parsed.single(ALIAS).expect("required arg").to_string()
	}

	fn namespace(&self) -> String {
		self.parsed.single(NAMESPACE).expect("required arg").to_string()
	}

	fn pcr3_preimage_path(&self) -> String {
		self.parsed
			.single(PCR3_PREIMAGE_PATH)
			.expect("`--pcr3-preimage-path` is a required arg")
			.to_string()
	}

	fn nonce(&self) -> u32 {
		self.parsed
			.single(NONCE)
			.expect("required arg")
			.parse::<u32>()
			.expect("Could not parse `--nonce` as u32")
	}

	fn restart_policy(&self) -> boot::RestartPolicy {
		self.parsed
			.single(RESTART_POLICY)
			.expect("required arg")
			.to_string()
			.try_into()
			.expect("Could not parse `--restart-policy`")
	}

	fn pivot_path(&self) -> String {
		self.parsed.single(PIVOT_PATH).expect("required arg").to_string()
	}

	fn manifest_set_dir(&self) -> String {
		self.parsed
			.single(MANIFEST_SET_DIR)
			.expect("`--manifest-set-dir` is a required arg")
			.to_string()
	}

	fn share_set_dir(&self) -> String {
		self.parsed
			.single(SHARE_SET_DIR)
			.expect("`--share-set-dir` is a required arg")
			.to_string()
	}

	fn patch_set_dir(&self) -> String {
		self.parsed
			.single(PATCH_SET_DIR)
			.expect("`--patch-set-dir` is a required arg")
			.to_string()
	}

	fn namespace_dir(&self) -> String {
		self.parsed
			.single(NAMESPACE_DIR)
			.expect("`--namespace-dir` is a required arg")
			.to_string()
	}

	fn manifest_approvals_dir(&self) -> String {
		self.parsed
			.single(MANIFEST_APPROVALS_DIR)
			.expect("`--manifest-approval-dir` is a required arg")
			.to_string()
	}

	fn qos_release_dir(&self) -> String {
		self.parsed
			.single(QOS_REALEASE_DIR)
			.expect("qos-release-dir is a required arg")
			.to_string()
	}

	fn pivot_hash_path(&self) -> String {
		self.parsed
			.single(PIVOT_HASH_PATH)
			.expect("pivot-hash is a required arg")
			.to_string()
	}

	fn pivot_args(&self) -> Vec<String> {
		let v = self.parsed.single(PIVOT_ARGS).expect("required arg");
		let mut chars = v.chars();

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

	fn pool_size(&self) -> Option<u8> {
		self.parsed.single(POOL_SIZE).map(|s| {
			s.parse().expect("pool-size not valid integer in range <1..255>")
		})
	}

	fn client_timeout_ms(&self) -> Option<u16> {
		self.parsed.single(CLIENT_TIMEOUT).map(|s| {
			s.parse()
				.expect("client timeout invalid integer in range <0..65535>")
		})
	}

	fn pub_path(&self) -> String {
		self.parsed.single(PUB_PATH).expect("Missing `--pub-path`").to_string()
	}

	fn secret_path(&self) -> Option<String> {
		self.parsed.single(SECRET_PATH).cloned()
	}

	fn share_path(&self) -> String {
		self.parsed
			.single(SHARE_PATH)
			.expect("Missing `--share-path`")
			.to_string()
	}

	fn output_path(&self) -> String {
		self.parsed
			.single(OUTPUT_PATH)
			.expect("Missing `--output-path`")
			.to_string()
	}

	fn quorum_key_path(&self) -> String {
		self.parsed
			.single(QUORUM_KEY_PATH)
			.expect("Missing `--quorum-key-path`")
			.to_string()
	}

	fn manifest_path(&self) -> String {
		self.parsed
			.single(MANIFEST_PATH)
			.expect("Missing `--manifest-path`")
			.to_string()
	}

	fn manifest_envelope_path(&self) -> String {
		self.parsed
			.single(MANIFEST_ENVELOPE_PATH)
			.expect("Missing `--manifest-envelope-path`")
			.to_string()
	}

	fn maybe_manifest_envelope_path(&self) -> Option<String> {
		self.parsed.single(MANIFEST_ENVELOPE_PATH).map(String::to_owned)
	}

	fn approval_path(&self) -> String {
		self.parsed
			.single(APPROVAL_PATH)
			.expect("Missing `--approval-path`")
			.to_string()
	}

	fn eph_wrapped_share_path(&self) -> String {
		self.parsed
			.single(EPH_WRAPPED_SHARE_PATH)
			.expect("Missing `--eph-wrapped-share-path`")
			.to_string()
	}

	fn attestation_doc_path(&self) -> String {
		self.parsed
			.single(ATTESTATION_DOC_PATH)
			.expect("Missing `--attestation-doc-path`")
			.to_string()
	}

	fn master_seed_path(&self) -> String {
		self.parsed
			.single(MASTER_SEED_PATH)
			.expect("Missing `--master-seed-path`")
			.to_string()
	}

	fn output_dir(&self) -> String {
		self.parsed
			.single(OUTPUT_DIR)
			.expect("Missing `--output-dir`")
			.to_string()
	}

	fn shares(&self) -> Vec<String> {
		self.parsed.multiple(SHARE).expect("Missing `--share` args").to_vec()
	}

	fn total_shares(&self) -> usize {
		self.parsed
			.single(TOTAL_SHARES)
			.expect("Missing `--total-shares`")
			.parse()
			.expect("total shares not valid integer.")
	}

	fn threshold(&self) -> usize {
		self.parsed
			.single(THRESHOLD)
			.expect("Missing `--threshold`")
			.parse()
			.expect("threshold not valid integer.")
	}

	fn payload(&self) -> String {
		self.parsed.single(PAYLOAD).expect("Missing `--payload`").to_string()
	}

	fn payload_path(&self) -> String {
		self.parsed
			.single(PAYLOAD_PATH)
			.expect("Missing `--payload-path`")
			.to_string()
	}

	fn signature_path(&self) -> String {
		self.parsed
			.single(SIGNATURE_PATH)
			.expect("Missing `--signature-path`")
			.to_string()
	}

	fn ephemeral_key_path(&self) -> String {
		self.parsed
			.single(EPHEMERAL_KEY_PATH)
			.expect("Missing `--ephemeral-key-path`")
			.to_string()
	}

	fn file_path(&self) -> String {
		self.parsed
			.single(FILE_PATH)
			.expect("Missing `--file-path`")
			.to_string()
	}

	fn display_type(&self) -> DisplayType {
		self.parsed
			.single(DISPLAY_TYPE)
			.expect("Missing `--display-type`")
			.as_str()
			.into()
	}

	fn dr_key_path(&self) -> Option<String> {
		self.parsed.single(DR_KEY_PATH).map(Into::into)
	}

	fn new_pin_path(&self) -> String {
		self.parsed
			.single(NEW_PIN_PATH)
			.expect("Missing `--new-pin-path`")
			.to_string()
	}

	fn current_pin_path(&self) -> Option<String> {
		self.parsed.single(CURRENT_PIN_PATH).map(Into::into)
	}

	fn validation_time_override(&self) -> Option<u64> {
		self.parsed.single(VALIDATION_TIME_OVERRIDE).map(|t| {
			t.parse().expect("invalid u64 for `--validation-time-override`")
		})
	}

	fn encrypted_quorum_key_path(&self) -> String {
		self.parsed
			.single(ENCRYPTED_QUORUM_KEY_PATH)
			.expect("Missing `--encrypted-quorum-key-path`")
			.to_string()
	}

	fn plaintext_path(&self) -> String {
		self.parsed
			.single(PLAINTEXT_PATH)
			.expect("Missing `--plaintext-path`")
			.to_string()
	}

	fn ciphertext_path(&self) -> String {
		self.parsed
			.single(CIPHERTEXT_PATH)
			.expect("Missing `--ciphertext-path`")
			.to_string()
	}

	fn yubikey(&self) -> bool {
		self.parsed.flag(YUBIKEY).unwrap_or(false)
	}

	fn unsafe_skip_attestation(&self) -> bool {
		self.parsed.flag(UNSAFE_SKIP_ATTESTATION).unwrap_or(false)
	}

	fn unsafe_eph_path_override(&self) -> Option<String> {
		self.parsed.single(UNSAFE_EPH_PATH_OVERRIDE).map(String::from)
	}

	fn unsafe_auto_confirm(&self) -> bool {
		self.parsed.flag(UNSAFE_AUTO_CONFIRM).unwrap_or(false)
	}

	fn output_hex(&self) -> bool {
		self.parsed.flag(OUTPUT_HEX).unwrap_or(false)
	}

	fn json(&self) -> bool {
		self.parsed.flag(JSON).unwrap_or(false)
	}
}

#[derive(Clone, PartialEq, Debug)]
struct ClientRunner {
	cmd: Command,
	opts: ClientOpts,
}
impl ClientRunner {
	/// Create [`Self`] from the command line arguments.
	pub fn new(args: &mut Vec<String>) -> Self {
		let result = CommandParser::<Command>::parse(args);

		if let Ok((cmd, parsed)) = result {
			Self { cmd, opts: ClientOpts { parsed } }
		} else {
			println!("Invalid input, try using --help with any of the following commands");
			Command::print_all();

			std::process::exit(1);
		}
	}

	/// Run the given command.
	pub fn run(self) {
		if self.opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if self.opts.parsed.help() {
			println!("Command: {:?}", self.cmd);
			println!("{}", self.opts.parsed.info());
		} else {
			match self.cmd {
				Command::HostHealth => handlers::host_health(&self.opts),
				Command::EnclaveStatus => handlers::enclave_status(&self.opts),
				Command::GenerateFileKey => {
					handlers::generate_file_key(&self.opts);
				}
				Command::ProvisionYubiKey => {
					handlers::provision_yubikey(&self.opts);
				}
				Command::AdvancedProvisionYubiKey => {
					handlers::advanced_provision_yubikey(&self.opts);
				}
				Command::BootGenesis => handlers::boot_genesis(&self.opts),
				Command::AfterGenesis => handlers::after_genesis(&self.opts),
				Command::VerifyGenesis => {
					handlers::verify_genesis(&self.opts);
				}
				Command::GenerateManifest => {
					handlers::generate_manifest(&self.opts);
				}
				Command::ApproveManifest => {
					handlers::approve_manifest(&self.opts);
				}
				Command::BootStandard => handlers::boot_standard(&self.opts),
				Command::GetAttestationDoc => {
					handlers::get_attestation_doc(&self.opts);
				}
				Command::ProxyReEncryptShare => {
					handlers::proxy_re_encrypt_share(&self.opts);
				}
				Command::GetEphemeralKeyHex => {
					handlers::get_ephemeral_key_hex(&self.opts);
				}
				Command::PostShare => handlers::post_share(&self.opts),
				Command::DangerousDevBoot => {
					handlers::dangerous_dev_boot(&self.opts);
				}
				Command::GenerateManifestEnvelope => {
					handlers::generate_manifest_envelope(&self.opts);
				}
				Command::PivotHash => {
					handlers::pivot_hash(&self.opts);
				}
				Command::ShamirSplit => {
					handlers::shamir_split(&self.opts);
				}
				Command::ShamirReconstruct => {
					handlers::shamir_reconstruct(&self.opts);
				}
				Command::YubiKeySign => handlers::yubikey_sign(&self.opts),
				Command::YubiKeyPublic => handlers::yubikey_public(&self.opts),
				Command::YubiKeyPivReset => handlers::yubikey_piv_reset(),
				Command::YubiKeyChangePin => {
					handlers::yubikey_change_pin(&self.opts);
				}
				Command::Display => {
					handlers::display(&self.opts);
				}
				Command::BootKeyFwd => handlers::boot_key_fwd(&self.opts),
				Command::ExportKey => handlers::export_key(&self.opts),
				Command::InjectKey => handlers::inject_key(&self.opts),
				Command::P256Verify => handlers::p256_verify(&self.opts),
				Command::P256Sign => handlers::p256_sign(&self.opts),
				Command::P256AsymmetricEncrypt => {
					handlers::p256_asymmetric_encrypt(&self.opts);
				}
				Command::P256AsymmetricDecrypt => {
					handlers::p256_asymmetric_decrypt(&self.opts);
				}
			}
		}
	}
}

/// Client command line interface
pub struct CLI;
impl CLI {
	/// Execute this command line interface.
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();

		let runner = ClientRunner::new(&mut args);

		runner.run();
	}
}

mod handlers {
	use super::services::{ApproveManifestArgs, ProxyReEncryptShareArgs};
	use crate::{
		cli::{
			services::{self, GenerateManifestArgs, PairOrYubi},
			ClientOpts, ProtocolMsg,
		},
		request,
	};

	pub(super) fn pivot_hash(opts: &ClientOpts) {
		let pivot = std::fs::read(opts.pivot_path())
			.expect("Failed to read pivot file");

		let hash = qos_crypto::sha_256(&pivot);
		let hex_hash = qos_hex::encode(&hash);

		std::fs::write(opts.output_path(), hex_hash.as_bytes())
			.expect("Failed to write pivot hash to specified path");
	}

	pub(super) fn host_health(opts: &ClientOpts) {
		let path = &opts.path("host-health");
		if let Ok(response) = request::get(path) {
			println!("{response}");
		} else {
			panic!("Error...")
		}
	}

	pub(super) fn enclave_status(opts: &ClientOpts) {
		let path = &opts.path_message();

		let response = request::post(path, &ProtocolMsg::StatusRequest)
			.map_err(|e| println!("{e:?}"))
			.expect("Enclave request failed");

		match response {
			ProtocolMsg::StatusResponse(phase) => {
				println!("Enclave phase: {phase:?}");
			}
			other => panic!("Unexpected response {other:?}"),
		}
	}

	pub(super) fn generate_file_key(opts: &ClientOpts) {
		services::generate_file_key(&opts.master_seed_path(), &opts.pub_path());
	}

	pub(super) fn provision_yubikey(opts: &ClientOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::provision_yubikey(opts.pub_path()) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn advanced_provision_yubikey(opts: &ClientOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::advanced_provision_yubikey(
				opts.master_seed_path(),
				opts.current_pin_path(),
			) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_sign(opts: &ClientOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::yubikey_sign(&opts.payload()) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn yubikey_public(_opts: &ClientOpts) {
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

	pub(super) fn yubikey_change_pin(opts: &ClientOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			let current_pin = services::pin_from_path(
				opts.current_pin_path()
					.expect("Missing `--current-pin-path` arg"),
			);
			let new_pin = services::pin_from_path(opts.new_pin_path());

			if let Err(e) = crate::yubikey::yubikey_change_pin(
				&current_pin[..],
				&new_pin[..],
			) {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
		}
	}

	pub(super) fn boot_genesis(opts: &ClientOpts) {
		if let Err(e) = services::boot_genesis(services::BootGenesisArgs {
			uri: &opts.path_message(),
			namespace_dir: opts.namespace_dir(),
			share_set_dir: opts.share_set_dir(),
			qos_release_dir_path: opts.qos_release_dir(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			dr_key_path: opts.dr_key_path(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation(),
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn after_genesis(opts: &ClientOpts) {
		let pair = get_pair_or_yubi(opts);
		if let Err(e) = services::after_genesis(services::AfterGenesisArgs {
			pair,
			share_path: opts.share_path(),
			alias: opts.alias(),
			namespace_dir: opts.namespace_dir(),
			qos_release_dir_path: opts.qos_release_dir(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation(),
			validation_time_override: opts.validation_time_override(),
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn verify_genesis(opts: &ClientOpts) {
		if let Err(e) = services::verify_genesis(
			opts.namespace_dir(),
			opts.master_seed_path(),
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn generate_manifest(opts: &ClientOpts) {
		if let Err(e) = services::generate_manifest(GenerateManifestArgs {
			nonce: opts.nonce(),
			namespace: opts.namespace(),
			restart_policy: opts.restart_policy(),
			pivot_hash_path: opts.pivot_hash_path(),
			qos_release_dir_path: opts.qos_release_dir(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			manifest_path: opts.manifest_path(),
			pivot_args: opts.pivot_args(),
			share_set_dir: opts.share_set_dir(),
			manifest_set_dir: opts.manifest_set_dir(),
			patch_set_dir: opts.patch_set_dir(),
			quorum_key_path: opts.quorum_key_path(),
			pool_size: opts.pool_size(),
			client_timeout_ms: opts.client_timeout_ms(),
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn approve_manifest(opts: &ClientOpts) {
		let pair = get_pair_or_yubi(opts);

		if let Err(e) = services::approve_manifest(ApproveManifestArgs {
			pair,
			manifest_path: opts.manifest_path(),
			manifest_approvals_dir: opts.manifest_approvals_dir(),
			qos_release_dir_path: opts.qos_release_dir(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			pivot_hash_path: opts.pivot_hash_path(),
			quorum_key_path: opts.quorum_key_path(),
			manifest_set_dir: opts.manifest_set_dir(),
			share_set_dir: opts.share_set_dir(),
			patch_set_dir: opts.patch_set_dir(),
			alias: opts.alias(),
			unsafe_auto_confirm: opts.unsafe_auto_confirm(),
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn boot_standard(opts: &ClientOpts) {
		if let Err(e) = services::boot_standard(services::BootStandardArgs {
			uri: opts.path_message(),
			pivot_path: opts.pivot_path(),
			manifest_envelope_path: opts.manifest_envelope_path(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation(),
		}) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn get_attestation_doc(opts: &ClientOpts) {
		services::get_attestation_doc(
			&opts.path_message(),
			opts.attestation_doc_path(),
			opts.manifest_envelope_path(),
		);
	}

	pub(super) fn get_ephemeral_key_hex(opts: &ClientOpts) {
		services::get_ephemeral_key_hex(
			opts.attestation_doc_path(),
			opts.ephemeral_key_path(),
		);
	}

	pub(super) fn proxy_re_encrypt_share(opts: &ClientOpts) {
		let pair = get_pair_or_yubi(opts);

		if let Err(e) =
			services::proxy_re_encrypt_share(ProxyReEncryptShareArgs {
				pair,
				share_path: opts.share_path(),
				manifest_envelope_path: opts.manifest_envelope_path(),
				approval_path: opts.approval_path(),
				eph_wrapped_share_path: opts.eph_wrapped_share_path(),
				attestation_doc_path: opts.attestation_doc_path(),
				pcr3_preimage_path: opts.pcr3_preimage_path(),
				alias: opts.alias(),
				manifest_set_dir: opts.manifest_set_dir(),
				unsafe_skip_attestation: opts.unsafe_skip_attestation(),
				unsafe_eph_path_override: opts.unsafe_eph_path_override(),
				unsafe_auto_confirm: opts.unsafe_auto_confirm(),
			}) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn post_share(opts: &ClientOpts) {
		if let Err(e) = services::post_share(
			&opts.path_message(),
			opts.eph_wrapped_share_path(),
			opts.approval_path(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn display(opts: &ClientOpts) {
		if let Err(e) = services::display(
			&opts.display_type(),
			opts.file_path(),
			opts.json(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn dangerous_dev_boot(opts: &ClientOpts) {
		services::dangerous_dev_boot(
			&opts.path_message(),
			opts.pivot_path(),
			opts.restart_policy(),
			opts.pivot_args(),
			opts.unsafe_eph_path_override(),
		);
	}

	pub(super) fn generate_manifest_envelope(opts: &ClientOpts) {
		if let Err(e) = services::generate_manifest_envelope(
			opts.manifest_approvals_dir(),
			opts.manifest_path(),
			opts.maybe_manifest_envelope_path(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn shamir_split(opts: &ClientOpts) {
		if let Err(e) = services::shamir_split(
			opts.secret_path().expect("Missing `--secret-path`"),
			opts.total_shares(),
			opts.threshold(),
			&opts.output_dir(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn shamir_reconstruct(opts: &ClientOpts) {
		if let Err(e) =
			services::shamir_reconstruct(opts.shares(), &opts.output_path())
		{
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	fn get_pair_or_yubi(opts: &ClientOpts) -> PairOrYubi {
		match PairOrYubi::from_inputs(
			opts.yubikey(),
			opts.secret_path(),
			opts.current_pin_path(),
		) {
			Err(e) => {
				eprintln!("Error: {e:?}");
				std::process::exit(1);
			}
			Ok(p) => p,
		}
	}

	pub(super) fn boot_key_fwd(opts: &ClientOpts) {
		if let Err(e) = services::boot_key_fwd(
			&opts.path_message(),
			opts.manifest_envelope_path(),
			opts.pivot_path(),
			opts.attestation_doc_path(),
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn export_key(opts: &ClientOpts) {
		if let Err(e) = services::export_key(
			&opts.path_message(),
			opts.manifest_envelope_path(),
			opts.attestation_doc_path(),
			opts.encrypted_quorum_key_path(),
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn inject_key(opts: &ClientOpts) {
		if let Err(e) = services::inject_key(
			&opts.path_message(),
			opts.encrypted_quorum_key_path(),
		) {
			println!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_verify(opts: &ClientOpts) {
		if let Err(e) = services::p256_verify(
			opts.payload_path(),
			opts.signature_path(),
			opts.pub_path(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_sign(opts: &ClientOpts) {
		if let Err(e) = services::p256_sign(
			&opts.payload_path(),
			opts.signature_path(),
			opts.master_seed_path(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_asymmetric_encrypt(opts: &ClientOpts) {
		if let Err(e) = services::p256_asymmetric_encrypt(
			opts.plaintext_path(),
			opts.ciphertext_path(),
			opts.pub_path(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}

	pub(super) fn p256_asymmetric_decrypt(opts: &ClientOpts) {
		if let Err(e) = services::p256_asymmetric_decrypt(
			opts.plaintext_path(),
			opts.ciphertext_path(),
			opts.master_seed_path(),
			opts.output_hex(),
		) {
			eprintln!("Error: {e:?}");
			std::process::exit(1);
		}
	}
}

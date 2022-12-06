//! `QuorumOS` client command line interface.
//!
//! See [`Command`] for all possible commands.
//!
//! The arguments for each command can be discovered by running:
//!
//! ```shell
//! cargo run --bin qos_client <command-name> --help
//! ```
//!
//! ## Guides
//!
//! - [Quorum Key Generation](quorum-key-generation)
//! - [Boot Standard](boot-standard)
//!
//! **Notes:**
//!
//! * The below guides assume there is already an enclave up and running
//! with `QuorumOS`.
//! * PCR{0, 1, 2} are referenced through out the guide. Every release of
//! `QuorumOS` will have different PCRs and it is up to the CLI user to exercise
//! diligence in specifying specifying those PCRs as they are used to verify the
//! enclave is running the correct version of `QuorumOS`. Read more about PCRs
//! here: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html/>.
//!
//! ### Terms
//!
//! * **Leader**: the entity that runs a flow. In other words, this is an entity
//!   that executes the commands in flow that don't need to be executed by
//!   individual quorum members.
//! * **Approver(s)**: a quorum member that approves something by signing it.
//!
//! ### Quorum Key Generation
//!
//! `QuorumOS` requires a Quorum Key. Each member of the Share Set holds a
//! share of the Quorum Key. (The shares are created using Shamir Secret
//! Sharing) It is expected that the Quorum Key is only ever fully reconstructed
//! in an enclave.
//!
//! In order to generate a Quorum Key, `QuorumOs` has a special "genesis"
//! service. The genesis service bypasses the standard boot and pivot flow, and
//! thus is commonly referred to as boot genesis. Instead it simply generates a
//! Quorum Key and shards it across share set members. From a high level, the
//! steps to create a Quorum Key and Manifest Set with the genesis service are:
//!
//! 1) Every Share Set Member generates a Share Key.
//! 2) The genesis service is invoked with N Share Keys and a reconstruction
//! threshold, K.
//! 3) The genesis service then executes the following:
//!     1) Generates a Quorum Key.
//!     2) Splits the quorum key into N shares.
//!     3) Encrypts each share to a share key.
//!     6) Returns encrypted shares, quorum key, and an attestation document.
//! 4) Each share set member verifies the attestation document and then
//! verifies they can decrypt the correct share with their setup key.
//!
//! #### Generate Share Keys
//!
//! For each member of the Share Set, the genesis service needs a
//! corresponding Share Key as input. To produce a Share Key, a member can run
//! the [`Command::GenerateFileKey`] on a secure device:
//!
//! ```shell
//! cargo run --bin qos_client generate-share-key \
//!     --namespace our_namespace \
//!     --alias alice \
//!     --personal-dir ~/qos/our_namespace/personal
//! ```
//!
//! If successful, the `our_namespace` directory on Alice's machine will look
//! like:
//!
//! - personal
//!     - `alice.our_namespace.share_key.secret`
//!     - `alice.our_namespace.share_key.pub`
//!
//! #### Send Boot Genesis Instruction
//!
//! The genesis ceremony leader will need to have a directory that contains the
//! share keys of all the share set members. For example, if Alice was the
//! ceremony leader and members={Alice, Bob, Eve}, Alice would need to have the
//! following directory structure:
//!
//! - personal
//!     - `alice.our_namespace.share_key.secret`
//!     - `alice.our_namespace.share_key.pub`
//! - genesis
//!     - `alice.our_namespace.share_key.pub`
//!     - `bob.our_namespace.share_key.pub`
//!     - `eve.our_namespace.share_key.pub`
//!
//! Given the above directory structure, Alice can now generate the genesis
//! outputs by running [`Command::BootGenesis`] (doesn't need to be a
//! secure device because we are not holding private key material):
//!
//! ```shell
//! cargo run --bin qos_client boot-genesis \
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --threshold 2 \
//!    --genesis-dir  ~/qos/our_namespace/genesis
//!    --qos-build-fingerprints ~/qos/our_namespace/qos-build-fingerprints.txt
//! ```
//!
//! On success this will result in the following directory structure:
//!
//! - personal
//!     - `alice.our_namespace.share_key.key`
//!     - `alice.our_namespace.share_key.pub`
//! - genesis
//!     - `alice.our_namespace.share_key.pub`
//!     - `bob.our_namespace.share_key.pub`
//!     - `eve.our_namespace.share_key.pub`
//!     - `genesis_attestation_doc`
//!     - `genesis_output`
//!
//! Note that `genesis_output` is an encoded
//! [`qos_core::protocol::services::genesis::GenesisOutput`] and
//! `genesis_attestation_doc` is a COSE Sign1 structure from the Nitro Secure
//! Module used to attest to the validity of the QOS image used to run the
//! genesis service.
//!
//! #### Attest and verify genesis outputs
//!
//! **WARNING:** this command should be run on an airgapped machine as it
//! decrypts the quorum share.
//!
//! Within the [`qos_core::protocol::services::genesis::GenesisOutput`] are the
//! encrypted Quorum Shares for each member. The quorum share is encrypted to
//! the Share Key. The genesis output contains a hash of the plaintext share;
//! the below command unencrypts the share, hashes it, and uses the digest to
//! check that the local, unencrypted share matches what was created inside of
//! the enclave. The recovery permutations inside the enclave
//! references the share by hash, so it helps reinforce the case that recovery
//! is possible if we can verify the hash.
//!
//! Each member will use [`Command::AfterGenesis`] to decrypt the outputs and
//! verify the attestation document. Prior to running [`Command::AfterGenesis`],
//! each member will need a directory structure with at minimum:
//!
//! - personal
//!     - `bob.our_namespace.share_key.secret`
//! - genesis
//!     - `genesis_attestation_doc`
//!     - `genesis_output`
//!
//! Given the above directory structure, Bob can run [`Command::AfterGenesis`]:
//!
//! ```shell
//! cargo run --bin qos_client after-genesis \
//!    --genesis-dir  ~/qos/our_namespace/genesis \
//!    --personal-dir  ~/qos/our_namespace/personal \
//!    --qos-build-fingerprints ~/qos/our_namespace/qos-build-fingerprints.txt
//! ```
//!
//! [`Command::AfterGenesis`] will extract Bob's quorum share, resulting in the
//! following directory structure:
//!
//! - personal
//!     - `bob.our_namespace.share`
//!     - `bob.our_namespace.share_key.secret`
//! - genesis
//!     - `genesis_attestation_doc`
//!     - `genesis_output`
//!
//! ### Boot Standard
//!
//! Boot Standard, or just Boot, is the name of the flow for provisioning a
//! `QuorumOS` instance with a Quorum Key and Pivot Executable.
//!
//! From a high level, the boot flow for an enclave can be broken down to 3
//! steps:
//!
//! 1) Gather signatures for a [`qos_core::protocol::services::boot::Manifest`]
//! from K of the quorum members.
//! 2) Post a Manifest with K signatures and the pivot binary referenced in
//! the manifest.
//! 3) Each quorum member will post their share, encrypted to the Ephemeral Key
//! of the enclave, after they have verified the validity of an attestation
//! document from the enclave. (The attestation document should contain a
//! reference to the manifest).
//!
//! #### Generate a Manifest
//!
//! The leader for the boot standard flow will need to generate a manifest using
//! [`Command::GenerateManifest`]. Given the manifest set mentioned in the above
//! genesis guide, [`Command::GenerateManifest`] expects the following directory
//! structure:
//!
//! - boot
//! - genesis
//!    - `output.genesis`
//!
//! Given the above directory structure, the leader can run
//!
//! ```shell
//! cargo run --bin qos_client generate-manifest \
//!    --genesis-dir  ~/qos/our_namespace/genesis \
//!    --boot-dir ~/qos/our_namespace/boot \
//!    --nonce 0 \
//!    --namespace our_namespace \
//!    --pivot-hash 0xf0f0f0f0f0f0f0 \
//!    --restart-policy always \
//!    --pcr0 0xf0f0f0f0f0f0f0 \
//!    --pcr1 0xf0f0f0f0f0f0f0 \
//!    --pcr2 0xf0f0f0f0f0f0f0 \
//!    --root-cert-path ~/qos/aws_nitro_root_cert.pem
//! ```
//!
//! **Note**: For pivot's that require CLI arguments, you can use the
//! `--pivot-args` options. `--pivot-args` accepts a separated, [] wrapped CLI
//! args for pivot. e.g. `[--usock,dev.sock,--path,./path-to-file]`.
//!
//! After running the above, the directory structure will look like:
//!
//! - boot
//!    - `our_namespace.0.manifest`
//! - genesis
//!    - `output.genesis`
//!
//! #### Approve the Manifest
//!
//! K of the quorum members need to approve (sign) the manifest with their
//! personal key. A quorum member can use [`Command::ApproveManifest`] to do
//! this.
//!
//! [`Command::ApproveManifest`] expects the following directory structure on
//! Bob's personal machine:
//!
//! - personal
//!     - `bob.our_namespace.personal.key`
//! - boot
//!     - `our_namespace.0.manifest`
//!
//! Given the above directory structure, Bob can create an approval for the
//! manifest by running:
//!
//! ```shell
//! cargo run --bin qos_client generate-manifest \
//!    --personal-dir  ~/qos/our_namespace/personal \
//!    --boot-dir ~/qos/our_namespace/boot \
//!    --manifest-hash 0xf0f0f0f0f0f0f0
//! ```
//!
//! After running the above, Bob's directory structure would look like:
//!
//! - personal
//!    - `bob.our_namespace.personal.key`
//! - boot
//!    - `our_namespace.0.manifest`
//!    - `bob.our_namespace.0.approval`
//!
//! #### Send Boot Standard Instruction
//!
//! Once K approvals have been collected for a manifest, the leader can use
//! [`Command::BootStandard`] to send the boot standard instruction to start the
//! enclave.
//!
//! Given the Manifest Set referenced above, [`Command::BootStandard`] expects
//! the following directory structure:
//!
//! - boot
//!    - `our_namespace.0.manifest`
//!    - `alice.our_namespace.0.approval`
//!    - `bob.our_namespace.0.approval`
//!    - `eve.our_namespace.0.approval`
//!
//! The leader can then run:
//!
//! ```shell
//! cargo run --bin qos_client boot-standard \
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --pivot-path ~/qos/our_namespace/pivot.executable
//!    --boot-dir ~/qos/our_namespace/boot
//! ```
//!
//! After running the above, the boot directory will contain an attestation
//! document from the enclave. Importantly, the attestation document references
//! the manifest and has an ephemeral key which can be used for encrypting
//! messages to the enclave. Specifically, the leader's directory structure will
//! look like:
//!
//! - boot
//!    - `our_namespace.0.manifest`
//!    - `alice.our_namespace.0.approval`
//!    - `bob.our_namespace.0.approval`
//!    - `eve.our_namespace.0.approval`
//!    - `attestation_doc.boot`
//!
//! #### Post Quorum Shards
//!
//! Once the enclave has the pivot and manifest loaded with boot standard, K
//! share set members can independently verify the attestation document and post
//! their shares. In order to only ever re-encrypt the share on an airgapped
//! device this is split up into 3 steps: 1) fetch attestation doc, 2) verify
//! attestation doc and re-encrypt key on airgapped device, 3) post re-encrypted
//! share.
//!
//! 1) Run [`Command::GetAttestationDoc`] on Bob's production machine:
//!
//! ```shell
//! cargo run --bin qos_client get-attestation-doc
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --attestation-dir ~/qos/our_namespace/attestation
//! ```
//!
//! After running the above, the attestation directory should be populated like:
//!
//! - attestation
//!  - `boot_attestation_doc`
//!  - `manifest_envelope`
//!
//! 2) Bob transfers the personal directory and attestation directory onto
//! an airgapped machine. Bob then runs [`Command::ProxyReEncryptShare`]:
//!
//! ```shell
//! cargo run --bin qos_client proxy-re-encrypt-share
//!    --attestation-dir ~/qos/our_namespace/nonce_1/attestation \
//!    --personal-dir  ~/qos/our_namespace/personal \
//!    --manifest-hash 0xf0f0f0f0f0f0f0
//! ```
//!
//! After running the above, the attestation directory should now have the
//! attestation approval and ephemeral key encrypted share:
//!
//! - attestation
//!  - `boot_attestation_doc`
//!  - `manifest_envelope`
//!  - `attestation_approval`
//!  - `ephemeral_key_wrapped.share`
//!
//! 3) Bob then moves the ephemeral key encrypted share and attestation approval
//! back to the attestation directory on his production machine and then runs
//! [`Command::PostShare`]:
//!
//! ```shell
//! cargo run --bin qos_client post-share
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --attestation-dir ~/qos/our_namespace/attestation
//! ```
//!
//! Once the Kth share is successfully posted by a share set member, the enclave
//! will automatically pivot to running the binary.

use std::env;

use qos_core::{
	parser::{CommandParser, GetParserForCommand, Parser, Token},
	protocol::{msg::ProtocolMsg, services::boot},
};

mod services;

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const ALIAS: &str = "alias";
const NAMESPACE: &str = "namespace";
const NONCE: &str = "nonce";
const RESTART_POLICY: &str = "restart-policy";
const PIVOT_PATH: &str = "pivot-path";
const PERSONAL_DIR: &str = "personal-dir";
const PIVOT_ARGS: &str = "pivot-args";
const UNSAFE_SKIP_ATTESTATION: &str = "unsafe-skip-attestation";
const UNSAFE_EPH_PATH_OVERRIDE: &str = "unsafe-eph-path-override";
const ENDPOINT_BASE_PATH: &str = "endpoint-base-path";
const QOS_BUILD_FINGERPRINTS: &str = "qos-build-fingerprints";
const PCR3_PREIMAGE_PATH: &str = "pcr3-preimage-path";
const PIVOT_BUILD_FINGERPRINTS: &str = "pivot-build-fingerprints";
const SHARE_SET_DIR: &str = "share-set-dir";
const MANIFEST_SET_DIR: &str = "manifest-set-dir";
const NAMESPACE_DIR: &str = "namespace-dir";
const UNSAFE_AUTO_CONFIRM: &str = "unsafe-auto-confirm";
const PUB_PATH: &str = "pub-path";
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
const PAYLOAD: &str = "payload";

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
	/// Query the NSM with `NsmRequest::DescribeNsm`. Normally only useful for
	/// development.
	DescribeNsm,
	/// Query the NSM with `NsmRequest::DescribePcr` for PCR indexes 0..3.
	DescribePcr,
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
	PivotBuildFingerprints,
	/// Sign a hex encoded payload with the yubikey.
	YubiKeySign,
	/// Get the public key of a yubikey
	YubiKeyPublic,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"enclave-status" => Self::EnclaveStatus,
			"describe-nsm" => Self::DescribeNsm,
			"describe-pcr" => Self::DescribePcr,
			"generate-file-key" => Self::GenerateFileKey,
			"generate-manifest-envelope" => Self::GenerateManifestEnvelope,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
			"generate-manifest" => Self::GenerateManifest,
			"approve-manifest" => Self::ApproveManifest,
			"boot-standard" => Self::BootStandard,
			"get-attestation-doc" => Self::GetAttestationDoc,
			"proxy-re-encrypt-share" => Self::ProxyReEncryptShare,
			"post-share" => Self::PostShare,
			"dangerous-dev-boot" => Self::DangerousDevBoot,
			"provision-yubikey" => Self::ProvisionYubiKey,
			"advanced-provision-yubikey" => Self::AdvancedProvisionYubiKey,
			"pivot-build-fingerprints" => Self::PivotBuildFingerprints,
			"yubikey-sign" => Self::YubiKeySign,
			"yubikey-public" => Self::YubiKeyPublic,
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
	fn personal_dir_token() -> Token {
		Token::new(PERSONAL_DIR, "Directory (eventually) containing personal key, share, and setup key associated with 1 genesis ceremony.")
			.takes_value(true)
			.required(true)
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
	fn qos_build_fingerprints_token() -> Token {
		Token::new(
			QOS_BUILD_FINGERPRINTS,
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
	fn pivot_build_fingerprints_token() -> Token {
		Token::new(
			PIVOT_BUILD_FINGERPRINTS,
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
			.required(true)
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
	fn payload_token() -> Token {
		Token::new(PAYLOAD, "A hex-encoded payload to sign/encrypt/decrypt.")
			.takes_value(true)
			.required(true)
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
			.token(Self::alias_token())
			.token(Self::personal_dir_token())
	}

	fn boot_genesis() -> Parser {
		Self::base()
			.token(Self::namespace_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::qos_build_fingerprints_token())
	}

	fn after_genesis() -> Parser {
		Parser::new()
			.token(Self::yubikey_token())
			.token(Self::secret_path_token())
			.token(Self::share_path_token())
			.token(Self::alias_token())
			.token(Self::namespace_dir_token())
			.token(Self::qos_build_fingerprints_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
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
			.token(Self::pivot_build_fingerprints_token())
			.token(Self::restart_policy_token())
			.token(Self::qos_build_fingerprints_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::manifest_path_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::quorum_key_path_token())
			.token(Self::pivot_args_token())
	}

	fn approve_manifest() -> Parser {
		Parser::new()
			.token(Self::yubikey_token())
			.token(Self::secret_path_token())
			.token(Self::manifest_path_token())
			.token(Self::manifest_approvals_dir_token())
			.token(Self::qos_build_fingerprints_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::pivot_build_fingerprints_token())
			.token(Self::alias_token())
			.token(Self::quorum_key_path_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
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
		Self::base().token(Self::attestation_doc_path_token())
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
			.token(Self::pub_path_token())
			.token(Self::master_seed_path_token())
	}

	fn yubikey_sign() -> Parser {
		Parser::new()
			.token(Self::payload_token())
	}

	fn yubikey_public() -> Parser {
		Parser::new()
	}
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth
			| Self::DescribeNsm
			| Self::DescribePcr
			| Self::EnclaveStatus => Self::base(),
			Self::GenerateFileKey => Self::generate_file_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
			Self::GenerateManifest => Self::generate_manifest(),
			Self::ApproveManifest => Self::approve_manifest(),
			Self::BootStandard => Self::boot_standard(),
			Self::GetAttestationDoc => Self::get_attestation_doc(),
			Self::ProxyReEncryptShare => Self::proxy_re_encrypt_share(),
			Self::PostShare => Self::post_share(),
			Self::DangerousDevBoot => Self::dangerous_dev_boot(),
			Self::GenerateManifestEnvelope => {
				Self::generate_manifest_envelope()
			}
			Self::ProvisionYubiKey => Self::provision_yubikey(),
			Self::AdvancedProvisionYubiKey => {
				Self::advanced_provision_yubikey()
			}
			Self::PivotBuildFingerprints => Self::pivot_build_fingerprints(),
			Self::YubiKeySign => Self::yubikey_sign(),
			Self::YubiKeyPublic => Self::yubikey_public(),
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

	fn personal_dir(&self) -> String {
		self.parsed.single(PERSONAL_DIR).expect("required arg").to_string()
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

	fn qos_build_fingerprints(&self) -> String {
		self.parsed
			.single(QOS_BUILD_FINGERPRINTS)
			.expect("qos-build-fingerprints is a required arg")
			.to_string()
	}

	fn pivot_build_fingerprints(&self) -> String {
		self.parsed
			.single(PIVOT_BUILD_FINGERPRINTS)
			.expect("pivot-build-fingerprints is a required arg")
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

	#[cfg(feature = "smartcard")]
	fn pub_path(&self) -> String {
		self.parsed.single(PUB_PATH).expect("Missing `--pub-path`").to_string()
	}

	fn secret_path(&self) -> Option<String> {
		self.parsed.single(SECRET_PATH).map(String::clone)
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

	fn payload(&self) -> String {
		self.parsed
			.single(PAYLOAD)
			.expect("Missing `--payload`")
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
}

#[derive(Clone, PartialEq, Debug)]
struct ClientRunner {
	cmd: Command,
	opts: ClientOpts,
}
impl ClientRunner {
	/// Create [`Self`] from the command line arguments.
	pub fn new(args: &mut Vec<String>) -> Self {
		let (cmd, parsed) =
			CommandParser::<Command>::parse(args).expect("Invalid CLI args");

		Self { cmd, opts: ClientOpts { parsed } }
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
				Command::DescribeNsm => handlers::describe_nsm(&self.opts),
				Command::DescribePcr => handlers::describe_pcr(&self.opts),
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
				Command::PostShare => handlers::post_share(&self.opts),
				Command::DangerousDevBoot => {
					handlers::dangerous_dev_boot(&self.opts);
				}
				Command::GenerateManifestEnvelope => {
					handlers::generate_manifest_envelope(&self.opts);
				}
				Command::PivotBuildFingerprints => {
					handlers::pivot_build_fingerprints(&self.opts);
				}
				Command::YubiKeySign => handlers::yubikey_sign(&self.opts),
				Command::YubiKeyPublic => handlers::yubikey_public(&self.opts),
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
	use qos_core::protocol::attestor::types::{NsmRequest, NsmResponse};

	use super::services::{ApproveManifestArgs, ProxyReEncryptShareArgs};
	use crate::{
		cli::{
			services::{self, GenerateManifestArgs, PairOrYubi},
			ClientOpts, ProtocolMsg,
		},
		request,
	};

	pub(super) fn pivot_build_fingerprints(opts: &ClientOpts) {
		let pivot = std::fs::read(&opts.pivot_path())
			.expect("Failed to read pivot file");

		let hash = qos_crypto::sha_256(&pivot);
		let hex_hash = qos_hex::encode(&hash);

		let contents = format!("{hex_hash}\ndummy-commit\n");

		std::fs::write(&opts.output_path(), contents.as_bytes())
			.expect("Failed to write fingerprints to specified path");
	}

	pub(super) fn host_health(opts: &ClientOpts) {
		let path = &opts.path("host-health");
		if let Ok(response) = request::get(path) {
			println!("{}", response);
		} else {
			panic!("Error...")
		}
	}

	pub(super) fn enclave_status(opts: &ClientOpts) {
		let path = &opts.path_message();

		let response = request::post(path, &ProtocolMsg::StatusRequest)
			.map_err(|e| println!("{:?}", e))
			.expect("Enclave request failed");

		match response {
			ProtocolMsg::StatusResponse(phase) => {
				println!("Enclave phase: {:?}", phase);
			}
			other => panic!("Unexpected response {:?}", other),
		}
	}

	pub(super) fn describe_nsm(opts: &ClientOpts) {
		let path = &opts.path_message();
		match request::post(
			path,
			&ProtocolMsg::NsmRequest { nsm_request: NsmRequest::DescribeNSM },
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed")
		{
			ProtocolMsg::NsmResponse { nsm_response } => {
				println!("{:#?}", nsm_response);
			}
			other => panic!("Unexpected response {:?}", other),
		}
	}

	pub(super) fn describe_pcr(opts: &ClientOpts) {
		let path = &opts.path_message();

		for i in 0..4 {
			println!("PCR index {i}");

			match request::post(
				path,
				&ProtocolMsg::NsmRequest {
					nsm_request: NsmRequest::DescribePCR { index: i },
				},
			)
			.map_err(|e| println!("{:?}", e))
			.expect("Attestation request failed")
			{
				ProtocolMsg::NsmResponse {
					nsm_response: NsmResponse::DescribePCR { lock: _, data },
				} => {
					println!("{:#?}", qos_hex::encode(&data));
				}
				other => panic!("Unexpected response {:?}", other),
			}
		}
	}

	pub(super) fn generate_file_key(opts: &ClientOpts) {
		services::generate_file_key(&opts.alias(), opts.personal_dir());
	}

	pub(super) fn provision_yubikey(opts: &ClientOpts) {
		#[cfg(not(feature = "smartcard"))]
		{
			panic!("{}", services::SMARTCARD_FEAT_DISABLED_MSG)
		}

		#[cfg(feature = "smartcard")]
		{
			if let Err(e) = services::provision_yubikey(opts.pub_path()) {
				eprintln!("Error: {:?}", e);
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
				opts.pub_path(),
				opts.master_seed_path(),
			) {
				eprintln!("Error: {:?}", e);
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
			if let Err(e) = services::yubikey_sign(
				opts.payload()
			) {
				eprintln!("Error: {:?}", e);
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
				eprintln!("Error: {:?}", e);
				std::process::exit(1);
			}
		}
	}

	// TODO: verify PCRs
	pub(super) fn boot_genesis(opts: &ClientOpts) {
		services::boot_genesis(services::BootGenesisArgs {
			uri: &opts.path_message(),
			namespace_dir: opts.namespace_dir(),
			share_set_dir: opts.share_set_dir(),
			qos_build_fingerprints_path: opts.qos_build_fingerprints(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation(),
		});
	}

	pub(super) fn after_genesis(opts: &ClientOpts) {
		let pair = get_pair_or_yubi(opts);
		if let Err(e) = services::after_genesis(services::AfterGenesisArgs {
			pair,
			share_path: opts.share_path(),
			alias: opts.alias(),
			namespace_dir: opts.namespace_dir(),
			qos_build_fingerprints_path: opts.qos_build_fingerprints(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			unsafe_skip_attestation: opts.unsafe_skip_attestation(),
		}) {
			println!("Error: {:?}", e);
			std::process::exit(1);
		}
	}

	pub(super) fn generate_manifest(opts: &ClientOpts) {
		if let Err(e) = services::generate_manifest(GenerateManifestArgs {
			nonce: opts.nonce(),
			namespace: opts.namespace(),
			restart_policy: opts.restart_policy(),
			pivot_build_fingerprints_path: opts.pivot_build_fingerprints(),
			qos_build_fingerprints_path: opts.qos_build_fingerprints(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			manifest_path: opts.manifest_path(),
			pivot_args: opts.pivot_args(),
			share_set_dir: opts.share_set_dir(),
			manifest_set_dir: opts.manifest_set_dir(),
			quorum_key_path: opts.quorum_key_path(),
		}) {
			println!("Error: {:?}", e);
			std::process::exit(1);
		}
	}

	pub(super) fn approve_manifest(opts: &ClientOpts) {
		let pair = get_pair_or_yubi(opts);

		if let Err(e) = services::approve_manifest(ApproveManifestArgs {
			pair,
			manifest_path: opts.manifest_path(),
			manifest_approvals_dir: opts.manifest_approvals_dir(),
			qos_build_fingerprints_path: opts.qos_build_fingerprints(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			pivot_build_fingerprints_path: opts.pivot_build_fingerprints(),
			quorum_key_path: opts.quorum_key_path(),
			manifest_set_dir: opts.manifest_set_dir(),
			share_set_dir: opts.share_set_dir(),
			alias: opts.alias(),
			unsafe_auto_confirm: opts.unsafe_auto_confirm(),
		}) {
			println!("Error: {:?}", e);
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
			println!("Error: {:?}", e);
			std::process::exit(1);
		}
	}

	pub(super) fn get_attestation_doc(opts: &ClientOpts) {
		services::get_attestation_doc(
			&opts.path_message(),
			opts.attestation_doc_path(),
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
			eprintln!("Error: {:?}", e);
			std::process::exit(1);
		}
	}

	pub(super) fn post_share(opts: &ClientOpts) {
		if let Err(e) = services::post_share(
			&opts.path_message(),
			opts.eph_wrapped_share_path(),
			opts.approval_path(),
		) {
			eprintln!("Error: {:?}", e);
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
		) {
			eprintln!("Error: {:?}", e);
			std::process::exit(1);
		}
	}

	fn get_pair_or_yubi(opts: &ClientOpts) -> PairOrYubi {
		match PairOrYubi::from_inputs(opts.yubikey(), opts.secret_path()) {
			Err(e) => {
				eprintln!("Error: {:?}", e);
				std::process::exit(1);
			}
			Ok(p) => p,
		}
	}
}

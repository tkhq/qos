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
//! the [`Command::GenerateShareKey`] on a secure device:
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
//! personal key. A quorum member can use [`Command::SignManifest`] to do this.
//!
//! [`Command::SignManifest`] expects the following directory structure on Bob's
//! personal machine:
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
	protocol::{msg::ProtocolMsg, services::boot, Hash256},
};

mod services;

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const ALIAS: &str = "alias";
const NAMESPACE: &str = "namespace";
const THRESHOLD: &str = "threshold";
const NONCE: &str = "nonce";
const RESTART_POLICY: &str = "restart-policy";
const ROOT_CERT_PATH: &str = "root-cert-path";
const MANIFEST_HASH: &str = "manifest-hash";
const PIVOT_PATH: &str = "pivot-path";
const GENESIS_DIR: &str = "genesis-dir";
const BOOT_DIR: &str = "boot-dir";
const PERSONAL_DIR: &str = "personal-dir";
const PIVOT_ARGS: &str = "pivot-args";
const UNSAFE_SKIP_ATTESTATION: &str = "unsafe-skip-attestation";
const UNSAFE_EPH_PATH_OVERRIDE: &str = "unsafe-eph-path-override";
const ENDPOINT_BASE_PATH: &str = "endpoint-base-path";
const ATTESTATION_DIR: &str = "attestation-dir";
const QOS_BUILD_FINGERPRINTS: &str = "qos-build-fingerprints";
const PCR3_PREIMAGE_PATH: &str = "pcr3-preimage-path";
const PIVOT_BUILD_FINGERPRINTS: &str = "pivot-build-fingerprints";
const SHARE_SET_DIR: &str = "share-set-dir";
const MANIFEST_SET_DIR: &str = "manifest-set-dir";
const NAMESPACE_DIR: &str = "namespace-dir";

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
	GenerateShareKey,
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
	SignManifest,
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
	/// ** Never use in production**.
	///
	/// Pivot the enclave to the specified binary.
	///
	/// This command goes through the steps of generating a Quorum Key,
	/// sharding it (N=1), creating/signing/posting a Manifest, and
	/// provisioning the quorum key.
	DangerousDevBoot,
	/// Send a simple echo request to the sample secure app.
	AppEcho,
	/// Send a read QOS files request to the sample secure app.
	AppReadFiles,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"enclave-status" => Self::EnclaveStatus,
			"describe-nsm" => Self::DescribeNsm,
			"describe-pcr" => Self::DescribePcr,
			"generate-share-key" => Self::GenerateShareKey,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
			"generate-manifest" => Self::GenerateManifest,
			"sign-manifest" => Self::SignManifest,
			"boot-standard" => Self::BootStandard,
			"get-attestation-doc" => Self::GetAttestationDoc,
			"proxy-re-encrypt-share" => Self::ProxyReEncryptShare,
			"post-share" => Self::PostShare,
			"dangerous-dev-boot" => Self::DangerousDevBoot,
			"app-echo" => Self::AppEcho,
			"app-read-files" => Self::AppReadFiles,
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
	fn boot_dir_token() -> Token {
		Token::new(
			BOOT_DIR,
			"Directory (eventually) containing the manifest, K approvals, and attestation doc.",
		)
		.takes_value(true)
		.required(true)
	}
	fn manifest_hash_token() -> Token {
		Token::new(MANIFEST_HASH, "Hex encoded hash of the expected manifest.")
			.takes_value(true)
			.required(true)
	}
	fn personal_dir_token() -> Token {
		Token::new(PERSONAL_DIR, "Directory (eventually) containing personal key, share, and setup key associated with 1 genesis ceremony.")
			.takes_value(true)
			.required(true)
	}
	fn genesis_dir_token() -> Token {
		Token::new(GENESIS_DIR, "Directory (eventually) containing genesis output, setup public keys, and attestation doc.")
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
	fn attestation_dir_token() -> Token {
		Token::new(
			ATTESTATION_DIR,
			"Path to dir containing attestation flow artifacts (attestation doc, manifest envelope, EK wrapped share).",
		)
		.takes_value(true)
		.required(true)
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

	fn generate_share_key() -> Parser {
		Parser::new()
			.token(
				Token::new(
					ALIAS,
					"Alias of the Quorum Member this key will belong too.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(Self::personal_dir_token())
			.token(Self::namespace_token())
	}

	fn boot_genesis() -> Parser {
		Self::base()
			.token(Self::genesis_dir_token())
			.token(
				Token::new(THRESHOLD, "Threshold, K, for having a quorum. K shares will reconstruct the Quorum key and K signatures are considered a quorum")
				.required(true)
				.takes_value(true)
			)
			.token(
				Self::pcr3_preimage_path_token()
			)
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::qos_build_fingerprints_token())
	}

	fn after_genesis() -> Parser {
		Parser::new()
			.token(Self::genesis_dir_token())
			.token(Self::personal_dir_token())
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
			.token(
				Token::new(
					ROOT_CERT_PATH,
					"Path to file containing PEM encoded AWS root cert.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(Self::boot_dir_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
			.token(Self::pivot_args_token())
	}

	fn sign_manifest() -> Parser {
		Parser::new()
			.token(Self::manifest_hash_token())
			.token(Self::personal_dir_token())
			.token(Self::boot_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::pivot_build_fingerprints_token())
			.token(Self::manifest_set_dir_token())
			.token(Self::share_set_dir_token())
	}

	fn boot_standard() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::boot_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
	}

	fn get_attestation_doc() -> Parser {
		Self::base().token(Self::attestation_dir_token())
	}

	fn proxy_re_encrypt_share() -> Parser {
		Parser::new()
			.token(Self::attestation_dir_token())
			.token(Self::manifest_hash_token())
			.token(Self::personal_dir_token())
			.token(Self::pcr3_preimage_path_token())
			.token(Self::unsafe_skip_attestation_token())
			.token(Self::unsafe_eph_path_override_token())
	}

	fn post_share() -> Parser {
		Self::base().token(Self::attestation_dir_token())
	}

	fn dangerous_dev_boot() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::restart_policy_token())
			.token(Self::pivot_args_token())
			.token(Self::unsafe_eph_path_override_token())
	}
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth
			| Self::DescribeNsm
			| Self::DescribePcr
			| Self::AppEcho
			| Self::AppReadFiles
			| Self::EnclaveStatus => Self::base(),
			Self::GenerateShareKey => Self::generate_share_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
			Self::GenerateManifest => Self::generate_manifest(),
			Self::SignManifest => Self::sign_manifest(),
			Self::BootStandard => Self::boot_standard(),
			Self::GetAttestationDoc => Self::get_attestation_doc(),
			Self::ProxyReEncryptShare => Self::proxy_re_encrypt_share(),
			Self::PostShare => Self::post_share(),
			Self::DangerousDevBoot => Self::dangerous_dev_boot(),
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

	fn genesis_dir(&self) -> String {
		self.parsed.single(GENESIS_DIR).expect("required arg").to_string()
	}

	fn pcr3_preimage_path(&self) -> String {
		self.parsed
			.single(PCR3_PREIMAGE_PATH)
			.expect("`--pcr3-preimage-path` is a required arg")
			.to_string()
	}

	fn threshold(&self) -> u32 {
		self.parsed
			.single(THRESHOLD)
			.expect("required arg")
			.parse::<u32>()
			.expect("Could not parse `--threshold` as u32")
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

	fn root_cert_path(&self) -> String {
		self.parsed.single(ROOT_CERT_PATH).expect("required arg").to_string()
	}

	fn manifest_hash(&self) -> Hash256 {
		qos_hex::decode(
			self.parsed.single(MANIFEST_HASH).expect("required arg"),
		)
		.expect("Could not parse `--manifest-hash` to bytes")
		.try_into()
		.expect("Could not convert manifest hash to Hash256")
	}

	fn pivot_path(&self) -> String {
		self.parsed.single(PIVOT_PATH).expect("required arg").to_string()
	}

	fn boot_dir(&self) -> String {
		self.parsed.single(BOOT_DIR).expect("required arg").to_string()
	}

	fn personal_dir(&self) -> String {
		self.parsed.single(PERSONAL_DIR).expect("required arg").to_string()
	}

	fn attestation_dir(&self) -> String {
		self.parsed.single(ATTESTATION_DIR).expect("required arg").to_string()
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

	fn unsafe_skip_attestation(&self) -> bool {
		self.parsed.flag(UNSAFE_SKIP_ATTESTATION).unwrap_or(false)
	}

	fn unsafe_eph_path_override(&self) -> Option<String> {
		self.parsed.single(UNSAFE_EPH_PATH_OVERRIDE).map(String::from)
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
				Command::AppEcho => handlers::app_echo(&self.opts),
				Command::AppReadFiles => handlers::app_read_files(&self.opts),
				Command::GenerateShareKey => {
					handlers::generate_share_key(&self.opts);
				}
				Command::BootGenesis => handlers::boot_genesis(&self.opts),
				Command::AfterGenesis => handlers::after_genesis(&self.opts),
				Command::GenerateManifest => {
					handlers::generate_manifest(&self.opts);
				}
				Command::SignManifest => handlers::sign_manifest(&self.opts),
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

	use crate::{
		cli::{
			services::{self, GenerateManifestArgs},
			ClientOpts, ProtocolMsg,
		},
		request,
	};

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

	pub(super) fn app_echo(opts: &ClientOpts) {
		use borsh::{BorshDeserialize, BorshSerialize};
		use sample_app::AppMsg;

		let echo_data = "some data to echo".to_string();
		let encoded_app_req = AppMsg::EchoReq { data: echo_data.clone() }
			.try_to_vec()
			.expect("Failed to serialize app msg");
		let req = ProtocolMsg::ProxyRequest { data: encoded_app_req };
		let app_msg = match request::post(&opts.path_message(), &req)
			.map_err(|e| println!("{:?}", e))
			.expect("App echo request failed")
		{
			ProtocolMsg::ProxyResponse { data } => {
				AppMsg::try_from_slice(&data)
					.expect("Failed to deserialize app msg in proxy response")
			}
			other => panic!("Unexpected protocol response {:?}", other),
		};

		match app_msg {
			AppMsg::EchoResp { data } => {
				assert_eq!(data, echo_data, "Echoed data is not what was sent");
			}
			other => panic!("Unexpected app response {:?}", other),
		}

		println!("App echo s uccessful!");
	}

	pub(super) fn app_read_files(opts: &ClientOpts) {
		use borsh::{BorshDeserialize, BorshSerialize};
		use sample_app::AppMsg;

		let encoded_app_req = AppMsg::ReadQOSFilesReq
			.try_to_vec()
			.expect("Failed to serialize app msg");
		let req = ProtocolMsg::ProxyRequest { data: encoded_app_req };
		let resp = match request::post(&opts.path_message(), &req)
			.map_err(|e| println!("{:?}", e))
			.expect("App read QOS files request failed")
		{
			ProtocolMsg::ProxyResponse { data } => {
				AppMsg::try_from_slice(&data)
					.expect("Failed to deserialize app msg in proxy response")
			}
			other => panic!("Unexpected protocol response {:?}", other),
		};

		match resp {
			AppMsg::ReadQOSFilesResp { .. } => {}
			other => panic!("Unexpected app response {:?}", other),
		}

		println!("App read files was successful!");
		println!("Note that the files themselves where not verified.");
	}

	pub(super) fn generate_share_key(opts: &ClientOpts) {
		services::generate_share_key(
			&opts.alias(),
			&opts.namespace(),
			opts.personal_dir(),
		);
	}

	// TODO: verify PCRs
	pub(super) fn boot_genesis(opts: &ClientOpts) {
		services::boot_genesis(
			&opts.path_message(),
			opts.genesis_dir(),
			opts.threshold(),
			opts.qos_build_fingerprints(),
			opts.pcr3_preimage_path(),
			opts.unsafe_skip_attestation(),
		);
	}

	pub(super) fn after_genesis(opts: &ClientOpts) {
		services::after_genesis(
			opts.genesis_dir(),
			opts.personal_dir(),
			opts.qos_build_fingerprints(),
			opts.pcr3_preimage_path(),
			opts.unsafe_skip_attestation(),
		);
	}

	/// TODO: can we write the manifest in plain english?
	pub(super) fn generate_manifest(opts: &ClientOpts) {
		services::generate_manifest(GenerateManifestArgs {
			nonce: opts.nonce(),
			namespace: opts.namespace(),
			restart_policy: opts.restart_policy(),
			pivot_build_fingerprints_path: opts.pivot_build_fingerprints(),
			qos_build_fingerprints_path: opts.qos_build_fingerprints(),
			pcr3_preimage_path: opts.pcr3_preimage_path(),
			root_cert_path: opts.root_cert_path(),
			boot_dir: opts.boot_dir(),
			pivot_args: opts.pivot_args(),
			share_set_dir: opts.share_set_dir(),
			manifest_set_dir: opts.manifest_set_dir(),
			namespace_dir: opts.namespace_dir(),
		});
	}

	pub(super) fn sign_manifest(opts: &ClientOpts) {
		services::sign_manifest(
			opts.manifest_hash(),
			opts.personal_dir(),
			opts.boot_dir(),
		);
	}

	pub(super) fn boot_standard(opts: &ClientOpts) {
		services::boot_standard(
			&opts.path_message(),
			opts.pivot_path(),
			opts.boot_dir(),
			opts.pcr3_preimage_path(),
			opts.unsafe_skip_attestation(),
		);
	}

	pub(super) fn get_attestation_doc(opts: &ClientOpts) {
		services::get_attestation_doc(
			&opts.path_message(),
			opts.attestation_dir(),
		);
	}

	pub(super) fn proxy_re_encrypt_share(opts: &ClientOpts) {
		services::proxy_re_encrypt_share(
			opts.attestation_dir(),
			opts.manifest_hash(),
			opts.personal_dir(),
			opts.pcr3_preimage_path(),
			opts.unsafe_skip_attestation(),
			opts.unsafe_eph_path_override(),
		);
	}

	pub(super) fn post_share(opts: &ClientOpts) {
		services::post_share(&opts.path_message(), opts.attestation_dir());
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
}

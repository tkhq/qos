//! `QuorumOS` client command line interface.
//!
//! See [`Command`] for all possible commands.
//!
//! ## Quorum Key Generation
//!
//! ### Generate Setup Keys
//!
//! The enclave has a special "genesis" service to generate a quorum key and
//! shard it across the quorum members.
//!
//! For each member of the Quorum Set, the genesis service needs a corresponding
//! Setup Key as input. (This key is used to encrypt the member specific outputs
//! from the genesis ceremony). To produce the setup key, a member can run the
//! [`Command::GenerateSetupKey`] on a secure device:
//!
//! ```shell
//! cargo run --bin qos-cli generate-setup-key \
//!     --namespace our_namespace \
//!     --alias alice \
//!     --personal-dir ~/qos/our_namespace/personal
//! ```
//!
//! If successful, the `our_namespace` directory on Alice's machine will look
//! like:
//!
//! - personal
//!     - alice.our_namespace.setup.key
//!     - alice.our_namespace.setup.pub
//!
//! ### Send Boot Genesis Instruction
//!
//! The genesis ceremony leader will need to have a directory that contains the
//! setup keys of all the quorum members. For example, if Alice was the ceremony
//! leader and members={Alice, BoB, Eve}, Alice would need to have the
//! following directory structure:
//!
//! - personal
//!     - alice.our_namespace.setup.key
//!     - alice.our_namespace.setup.pub
//! - genesis
//!     - alice.our_namespace.setup.pub
//!     - bob.our_namespace.setup.pub
//!     - eve.our_namespace.setup.pub
//!
//! Given the above directory structure, Alice can now generate the genesis
//! outputs by running [`Command::BootGenesis`] (doesn't need to be a
//! secure device because we are not holding private key material):
//!
//! ```shell
//! cargo run --bin qos-cli boot-genesis \
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --threshold 2 \
//!    --genesis-dir  ~/qos/our_namespace/genesis
//! ```
//!
//! On success this will result in the following directory structure:
//!
//! - personal
//!     - alice.our_namespace.setup.key
//!     - alice.our_namespace.setup.pub
//! - genesis
//!     - alice.our_namespace.setup.pub
//!     - bob.our_namespace.setup.pub
//!     - eve.our_namespace.setup.pub
//!     - attestation_doc.genesis
//!     - output.genesis
//!
//! Note that _output.genesis_ is an encoded
//! [`qos_core::protocol::services::GenesisOutput`] and
//! _attestation_doc.genesis_ is a COSE Sign1 structure from the Nitro Secure
//! Module used to attest to the validity of the QOS image used to run the
//! genesis service.
//!
//! ### Decrypt Personal Keys
//!
//! Within the [`qos_core::protocol::services::GenesisOutput`] are the encrypted
//! Personal Keys and Quorum Shares for each member. Each member's personal key
//! is encrypted to their setup key, so they will need their setup key to decrypt the personal key.
//! The quorum share is encrypted to the personal key.
//!
//! Each member will use [`Command::AfterGenesis`] to decrypt the outputs and
//! verify the attestation document. Prior to running [`Command::AfterGenesis`],
//! each member will need a directory structure with at minimum:
//!
//! - personal
//!     - bob.our_namespace.setup.key
//! - genesis
//!     - attestation_doc.genesis
//!     - output.genesis
//!
//! Given the above directory structure, Bob can run [`Command::AfterGenesis`]:
//!
//! ```shell
//! cargo run --bin qos-cli after-genesis \
//!    --genesis-dir  ~/qos/our_namespace/genesis \
//!    --personal-dir  ~/qos/our_namespace/personal \
//!    --pcr0 0xf0f0f0f0f0f0f0 \
//!    --pcr1 0xf0f0f0f0f0f0f0 \
//!    --pcr2 0xf0f0f0f0f0f0f0 \
//! ```
//!
//! Which will extract Bob's personal key and share, resulting in the following
//! directory structure:
//!
//! - personal
//!     - bob.our_namespace.setup.key
//!     - bob.our_namespace.share
//!     - bob.our_namespace.personal.pub
//!     - bob.our_namespace.personal.key
//! - genesis
//!     - attestation_doc.genesis
//!     - output.genesis
//!
//! ## Boot Standard an Enclave
//!
//! Broadly speaking, the boot flow for an enclave can be broken down to 3
//! steps:
//!
//! 1) Gather signatures for a [`qos_core::protocol::services::boot::Manifest`]
//! from K of the quorum members.
//!
//! 2) Post a Manifest with the K signatures and the pivot binary referenced in
//! the manifest.
//!
//! 3) Each quorum member will post their share, encrypted to the Ephemeral Key
//! of the enclave, after they have verified the validity of an attestation
//! document from the enclave. (The attestation document should contain a
//! reference to the manifest).
//!
//! ### Generate a Manifest
//!
//! The leader for the standard boot will need to generate a manifest using
//! [`Command::GenerateManifest`]. Given the quorum set mentioned in the above
//! section, [`Command::GenerateManifest`] expects the following directory
//! structure:
//!
//! - boot
//! - genesis
//!    - output.genesis
//!
//! Given the above directory structure, the leader can run
//!
//! ```shell
//! cargo run --bin qos-cli generate-manifest \
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
//! After running the above, the directory structure will look like:
//!
//! - boot
//!    - our_namespace.0.manifest
//! - genesis
//!    - output.genesis
//!
//! ### Approve the Manifest
//!
//! K of the quorum members need to approve and sign the manifest with their
//! personal key. A quorum member can use [`Command::SignManifest`] to do this.
//!
//! [`Command::SignManifest`] expects the following directory structure on Bob's
//! personal machine:
//!
//! - personal
//!     - bob.our_namespace.personal.key
//! - boot
//!     - our_namespace.0.manifest
//!
//! Given the above directory structure, Bob can create an approval for the
//! manifest by running:
//!
//! ```shell
//! cargo run --bin qos-cli generate-manifest \
//!    --personal-dir  ~/qos/our_namespace/personal \
//!    --boot-dir ~/qos/our_namespace/boot \
//!    --manifest-hash 0xf0f0f0f0f0f0f0
//! ```
//!
//! After running the above, Bob's directory structure would look like:
//!
//! - personal
//!    - bob.our_namespace.personal.key
//! - boot
//!    - our_namespace.0.manifest
//!    - bob.our_namespace.0.approval
//!
//! ### Send Boot Standard Instruction
//!
//! Once K approvals have been collected for a manifest, the leader can use
//! [`Command::BootStandard`] to send the boot standard instruction to start the
//! enclave.
//!
//! Given the Quorum Set mentioned above, [`Command::BootStandard`] expects the
//! following directory structure:
//!
//! - boot
//!    - our_namespace.0.manifest
//!    - alice.our_namespace.0.approval
//!    - bob.our_namespace.0.approval
//!    - eve.our_namespace.0.approval
//!
//! The leader can then run:
//!
//! ```shell
//! cargo run --bin qos-cli boot-standard \
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --pivot-path ~/qos/our_namespace/pivot.executable
//!    --boot-dir ~/qos/our_namespace/boot
//! ```
//!
//! After running the above, the boot directory will contain an attestation
//! document from the enclave, which references the manifest and has an
//! ephemeral key which can be used for encrypting messages to the enclave.
//! Specifically, the leader's directory structure will look like:
//!
//! - boot
//!    - our_namespace.0.manifest
//!    - alice.our_namespace.0.approval
//!    - bob.our_namespace.0.approval
//!    - eve.our_namespace.0.approval
//!    - attestation_doc.boot # TODO: Just have posters request the attestation
//!      doc as they go
//!
//! ### Post Quorum Shards
//!
//! Once the enclave has the pivot and manifest loaded with boot standard, K
//! quorum members can independently verify the attestation document and post
//! their quorum share using [`Command::PostShare`].
//!
//! For Bob to post his share he would need the following directory structure:
//!
//! - personal
//!     - bob.our_namespace.share
//!     - bob.our_namespace.personal.key
//! - boot
//!    - our_namespace.0.manifest
//!    - attestation_doc.boot
//!
//! With the above directory structure, Bob can run:
//!
//! ```shell
//! cargo run --bin qos-cli boot-standard \
//!    --host-ip 127.0.0.1 \
//!    --host-port 3000 \
//!    --personal-dir ~/qos/our_namespace/personal \
//!    --boot-dir ~/qos/our_namespace/boot
//! ```
//!
//! Once the Kth share is successfully posted, the enclave will automatically
//! pivot to running the binary.

use std::env;

use qos_core::{
	hex,
	parser::{CommandParser, GetParserForCommand, Parser, Token},
	protocol::{msg::ProtocolMsg, services::boot, Hash256},
};

mod services;

const HOST_IP: &str = "host-ip";
const HOST_PORT: &str = "host-port";
const ALIAS: &str = "alias";
const NAMESPACE: &str = "namespace";
const PCR0: &str = "pcr0";
const PCR1: &str = "pcr1";
const PCR2: &str = "pcr2";
const THRESHOLD: &str = "threshold";
const NONCE: &str = "nonce";
const PIVOT_HASH: &str = "pivot-hash";
const RESTART_POLICY: &str = "restart-policy";
const ROOT_CERT_PATH: &str = "root-cert-path";
const MANIFEST_HASH: &str = "manifest-hash";
const PIVOT_PATH: &str = "pivot-path";
const GENESIS_DIR: &str = "genesis-dir";
const BOOT_DIR: &str = "boot-dir";
const PERSONAL_DIR: &str = "personal-dir";

/// Commands for the Client CLI.
///
/// To get the possible arguments for any given command pass the help flag. For
/// example, to get the arguments for [`Self::GenerateManifest`] run:
///
/// ```bash
/// cargo run --bin qos-client -- generate-manifest --help
/// ```
///
/// Note that the command name is kebab-case.
#[derive(Clone, PartialEq, Debug)]
pub enum Command {
	/// Query the health endpoint of the enclave host server.
	HostHealth,
	/// Query the NSM with `NsmRequest::DescribeNsm`. Normally only useful for
	/// development.
	DescribeNsm,
	/// Query the NSM with `NsmRequest::DescribePcr` for PCR indexes 0..3.
	DescribePcr,
	/// Generate a Setup Key for use in the Genesis ceremony.
	GenerateSetupKey,
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
	/// Using the given Personal Keys as the Quorum Set, generate a manifest.
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
	/// Post a share to enclave that is not yet provisioned, but already has a
	/// manifest.
	///
	/// This will encrypt your Personal Share to the Ephemeral Key of the
	/// enclave. The ephemeral key will be pulled out of the given Attestation
	/// Document, so use caution to only run this against an Attestation
	/// Document and Manifest you have reviewed and trust.
	PostShare,
	/// ** Never use in production**.
	///
	/// Pivot the enclave to the specified binary.
	///
	/// This command goes through the steps of generating a Quorum Key,
	/// sharding it (N=1), creating/signing/posting a Manifest, and
	/// provisioning the quorum key.
	DangerousDevBoot,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"describe-nsm" => Self::DescribeNsm,
			"describe-pcr" => Self::DescribePcr,
			"generate-setup-key" => Self::GenerateSetupKey,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
			"generate-manifest" => Self::GenerateManifest,
			"sign-manifest" => Self::SignManifest,
			"boot-standard" => Self::BootStandard,
			"post-share" => Self::PostShare,
			"dangerous-dev-boot" => Self::DangerousDevBoot,
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
	fn pcr0_token() -> Token {
		Token::new(PCR0, "Hex encoded pcr0.").takes_value(true).required(true)
	}
	fn pcr1_token() -> Token {
		Token::new(PCR1, "Hex encoded pcr0.").takes_value(true).required(true)
	}
	fn pcr2_token() -> Token {
		Token::new(PCR2, "Hex encoded pcr2.").takes_value(true).required(true)
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
	}

	fn generate_setup_key() -> Parser {
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
	}

	fn after_genesis() -> Parser {
		Parser::new()
			.token(Self::genesis_dir_token())
			.token(Self::personal_dir_token())
			.token(Self::pcr0_token())
			.token(Self::pcr1_token())
			.token(Self::pcr2_token())
	}

	fn generate_manifest() -> Parser {
		Parser::new()
			.token(
				Self::genesis_dir_token()
			)
			.token(
				Token::new(
					NONCE,
					"Nonce of the manifest relative to the namespace.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Self::namespace_token()
			)
			.token(
				Token::new(
					PIVOT_HASH,
					"Hex encoded SHA-256 hash of the pivot executable encoded as a Vec<u8>.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Self::restart_policy_token(),
			)
			.token(
				Self::pcr0_token()
			)
			.token(
				Self::pcr1_token()
			)
			.token(
				Self::pcr2_token()
			)
			.token(
				Token::new(
					ROOT_CERT_PATH,
					"Path to file containing PEM encoded AWS root cert.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Self::boot_dir_token()
			)
	}

	fn sign_manifest() -> Parser {
		Parser::new()
			.token(Self::manifest_hash_token())
			.token(Self::personal_dir_token())
			.token(Self::boot_dir_token())
	}

	fn boot_standard() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::boot_dir_token())
	}

	fn post_share() -> Parser {
		Self::base()
			.token(Self::manifest_hash_token())
			.token(Self::personal_dir_token())
			.token(Self::boot_dir_token())
	}

	fn dangerous_dev_boot() -> Parser {
		Self::base()
			.token(Self::pivot_path_token())
			.token(Self::restart_policy_token())
	}
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth | Self::DescribeNsm | Self::DescribePcr => {
				Self::base()
			}
			Self::GenerateSetupKey => Self::generate_setup_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
			Self::GenerateManifest => Self::generate_manifest(),
			Self::SignManifest => Self::sign_manifest(),
			Self::BootStandard => Self::boot_standard(),
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

		format!("http://{}:{}/{}", ip, port, uri)
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

	fn pcr0(&self) -> Vec<u8> {
		hex::decode(self.parsed.single(PCR0).expect("required arg"))
			.expect("Could not parse `--pcr0` to bytes")
	}

	fn pcr1(&self) -> Vec<u8> {
		hex::decode(self.parsed.single(PCR1).expect("required arg"))
			.expect("Could not parse `--pcr1` to bytes")
	}

	fn pcr2(&self) -> Vec<u8> {
		hex::decode(self.parsed.single(PCR2).expect("required arg"))
			.expect("Could not parse `--pcr2` to bytes")
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

	fn pivot_hash(&self) -> Vec<u8> {
		hex::decode(self.parsed.single(PIVOT_HASH).expect("required arg"))
			.expect("Could not parse `--pivot-hash` to bytes")
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
		hex::decode(self.parsed.single(MANIFEST_HASH).expect("required arg"))
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
				Command::DescribeNsm => handlers::describe_nsm(&self.opts),
				Command::DescribePcr => handlers::describe_pcr(&self.opts),
				Command::GenerateSetupKey => {
					handlers::generate_setup_key(&self.opts);
				}
				Command::BootGenesis => handlers::boot_genesis(&self.opts),
				Command::AfterGenesis => handlers::after_genesis(&self.opts),
				Command::GenerateManifest => {
					handlers::generate_manifest(&self.opts);
				}
				Command::SignManifest => handlers::sign_manifest(&self.opts),
				Command::BootStandard => handlers::boot_standard(&self.opts),
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
	use qos_core::protocol::attestor::types::NsmRequest;

	use crate::{
		cli::{
			services::{self, GenerateManifestArgs},
			ClientOpts, ProtocolMsg,
		},
		request,
	};

	pub(super) fn host_health(opts: &ClientOpts) {
		let path = &opts.path("health");
		if let Ok(response) = request::get(path) {
			println!("{}", response);
		} else {
			panic!("Error...")
		}
	}

	// TODO: get info from the status endpoint
	// Status endpoint should return
	// - ManifestEnvelope if it exists
	// - Phase
	// - Attestation doc generated at boot, if it exists
	// - Current time in enclave
	// - Data signed by quorum key

	// TODO: this should eventually be removed since it only applies to nitro
	pub(super) fn describe_nsm(opts: &ClientOpts) {
		let path = &opts.path("message");
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
		let path = &opts.path("message");

		for i in 0..3 {
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
				ProtocolMsg::NsmResponse { nsm_response } => {
					println!("{:#?}", nsm_response);
				}
				other => panic!("Unexpected response {:?}", other),
			}
		}
	}

	pub(super) fn generate_setup_key(opts: &ClientOpts) {
		services::generate_setup_key(
			&opts.alias(),
			&opts.namespace(),
			opts.personal_dir(),
		);
	}

	// TODO: verify AWS_ROOT_CERT_PEM against a checksum
	// TODO: verify PCRs
	pub(super) fn boot_genesis(opts: &ClientOpts) {
		services::boot_genesis(
			&opts.path("message"),
			opts.genesis_dir(),
			opts.threshold(),
		);
	}

	pub(super) fn after_genesis(opts: &ClientOpts) {
		services::after_genesis(
			opts.genesis_dir(),
			opts.personal_dir(),
			&opts.pcr0(),
			&opts.pcr1(),
			&opts.pcr2(),
		);
	}

	/// TODO: can we write the manifest in plain english?
	pub(super) fn generate_manifest(opts: &ClientOpts) {
		services::generate_manifest(GenerateManifestArgs {
			genesis_dir: opts.genesis_dir(),
			nonce: opts.nonce(),
			namespace: opts.namespace(),
			pivot_hash: opts.pivot_hash().try_into().unwrap(),
			restart_policy: opts.restart_policy(),
			pcr0: opts.pcr0(),
			pcr1: opts.pcr1(),
			pcr2: opts.pcr2(),
			root_cert_path: opts.root_cert_path(),
			boot_dir: opts.boot_dir(),
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
			&opts.path("message"),
			opts.pivot_path(),
			opts.boot_dir(),
		);
	}

	pub(super) fn post_share(opts: &ClientOpts) {
		services::post_share(
			&opts.path("message"),
			opts.personal_dir(),
			opts.boot_dir(),
			opts.manifest_hash(),
		);
	}

	pub(super) fn dangerous_dev_boot(opts: &ClientOpts) {
		services::dangerous_dev_boot(
			&opts.path("message"),
			opts.pivot_path(),
			opts.restart_policy(),
		);
	}
}

//! `QuorumOS` client command line interface.

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

#[derive(Clone, PartialEq, Debug)]
enum Command {
	HostHealth,
	DescribeNsm,
	DescribePcr,
	GenerateSetupKey,
	BootGenesis,
	AfterGenesis,
	GenerateManifest,
	SignManifest,
	BootStandard,
	PostShare,
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
				Token::new(RESTART_POLICY, "One of: `never`, `always`.")
					.takes_value(true)
					.required(true),
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
			.token(
				Token::new(PIVOT_PATH, "Path to the pivot binary.")
					.takes_value(true)
					.required(true),
			)
			.token(Self::boot_dir_token())
	}

	fn post_share() -> Parser {
		Self::base()
			.token(Self::manifest_hash_token())
			.token(Self::personal_dir_token())
			.token(Self::boot_dir_token())
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
}

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

const KEY_DIR: &str = "key-dir";
const ALIAS: &str = "alias";
const NAMESPACE: &str = "namespace";

const GENESIS_DIR: &str = "genesis-dir";
const SETUP_KEY_PATH: &str = "setup-key-path";
const PCR0: &str = "pcr0";
const PCR1: &str = "pcr1";
const PCR2: &str = "pcr2";

const THRESHOLD: &str = "threshold";
const OUT_DIR: &str = "out-dir";

const GENESIS_OUT_PATH: &str = "genesis-out-path";
const NONCE: &str = "nonce";
const PIVOT_HASH: &str = "pivot-hash";
const RESTART_POLICY: &str = "restart-policy";
const ROOT_CERT_PATH: &str = "root-cert-path";

const MANIFEST_HASH: &str = "manifest-hash";
const PERSONAL_KEY_PATH: &str = "personal-key-path";
const MANIFEST_PATH: &str = "manifest-path";

const PIVOT_PATH: &str = "pivot-path";
const BOOT_DIR: &str = "boot-dir";

#[derive(Clone, PartialEq, Debug)]
enum Command {
	HostHealth,
	DescribeNsm,
	GenerateSetupKey,
	BootGenesis,
	AfterGenesis,
	GenerateManifest,
	SignManifest,
	BootStandard,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"describe-nsm" => Self::DescribeNsm,
			"generate-setup-key" => Self::GenerateSetupKey,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
			"generate-manifest" => Self::GenerateManifest,
			"sign-manifest" => Self::SignManifest,
			"boot-standard" => Self::BootStandard,
			_ => panic!("Unrecognized command"),
		}
	}
}

impl From<String> for Command {
	fn from(s: String) -> Self {
		Self::from(s.as_str())
	}
}

impl Command {
	fn base() -> Parser {
		Parser::new()
			.token(
				Token::new(HOST_IP, "IP address this server should listen on")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(HOST_PORT, "Port this server should listen on")
					.takes_value(true)
					.required(true),
			)
	}

	fn generate_setup_key() -> Parser {
		Parser::new()
			.token(
				Token::new(
					ALIAS,
					"alias of the Quorum Member this key will belong too.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					KEY_DIR,
					"directory to save the generated Setup Key files.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					NAMESPACE,
					"namespace the alias and Setup Key will belong too.",
				)
				.takes_value(true)
				.required(true),
			)
	}

	fn boot_genesis() -> Parser {
		Self::base()
			.token(
				Token::new(KEY_DIR, "directory containing all the setup public keys to use for genesis.")
					.takes_value(true)
					.required(true)
				)
			.token(
				Token::new(THRESHOLD, "the threshold to be considered a quorum, K.")
					.takes_value(true)
					.required(true)
			)
			.token(
				Token::new(OUT_DIR, "directory to write all the genesis outputs too.")
					.takes_value(true)
					.required(true)
			)
	}

	fn after_genesis() -> Parser {
		Parser::new()
			.token(
				Token::new(
					GENESIS_DIR,
					"directory with outputs from running genesis.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					SETUP_KEY_PATH,
					"path to the Setup Key you used as an input to genesis.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(PCR0, "hex encoded pcr0")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(PCR1, "hex encoded pcr1")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(PCR2, "hex encoded pcr2")
					.takes_value(true)
					.required(true),
			)
	}

	fn generate_manifest() -> Parser {
		Parser::new()
			.token(
				Token::new(
					GENESIS_OUT_PATH,
					"path to file with genesis outputs to use for Quorum Set.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					NONCE,
					"nonce of the manifest relative to the namespace.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					NAMESPACE,
					"namespace this manifest will belong to.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(
					PIVOT_HASH,
					"hex encoded SHA-256 hash of the pivot executable encoded as a Vec<u8>",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(RESTART_POLICY, "one of: `never`, `always`.")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(PCR0, "hex encoded pcr0")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(PCR1, "hex encoded pcr1")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(PCR2, "hex encoded pcr2")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(
					ROOT_CERT_PATH,
					"path to file containing PEM encoded AWS root cert",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(OUT_DIR, "directory to write the manifest in.")
					.takes_value(true)
					.required(true),
			)
	}

	fn sign_manifest() -> Parser {
		Parser::new()
			.token(
				Token::new(
					MANIFEST_HASH,
					"hex encoded hash of the manifest to sign.",
				)
				.takes_value(true)
				.required(true),
			)
			.token(
				Token::new(PERSONAL_KEY_PATH, "path to personal private key.")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(MANIFEST_PATH, "path to the manifest to sign.")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(OUT_DIR, "directory to write the manifest in.")
					.takes_value(true)
					.required(true),
			)
	}

	fn boot_standard() -> Parser {
		Self::base()
			.token(
				Token::new(PIVOT_PATH, "path to the pivot binary")
					.takes_value(true)
					.required(true),
			)
			.token(
				Token::new(
					BOOT_DIR,
					"directory containing the manifest and K Approvals.",
				)
				.takes_value(true)
				.required(true),
			)
	}
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth | Self::DescribeNsm => Self::base(),
			Self::GenerateSetupKey => Self::generate_setup_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
			Self::GenerateManifest => Self::generate_manifest(),
			Self::SignManifest => Self::sign_manifest(),
			Self::BootStandard => Self::boot_standard(),
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

	// Generate setup key opts
	fn key_dir(&self) -> String {
		self.parsed.single(KEY_DIR).expect("required arg").to_string()
	}
	fn alias(&self) -> String {
		self.parsed.single(ALIAS).expect("required arg").to_string()
	}
	fn namespace(&self) -> String {
		self.parsed.single(NAMESPACE).expect("required arg").to_string()
	}

	// AfterGenesis opts
	fn genesis_dir(&self) -> String {
		self.parsed.single(GENESIS_DIR).expect("required arg").to_string()
	}
	fn setup_key_path(&self) -> String {
		self.parsed.single(SETUP_KEY_PATH).expect("required arg").to_string()
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

	// BootGenesis opts
	fn out_dir(&self) -> String {
		self.parsed.single(OUT_DIR).expect("required arg").to_string()
	}
	fn threshold(&self) -> u32 {
		self.parsed
			.single(THRESHOLD)
			.expect("required arg")
			.parse::<u32>()
			.expect("Could not parse `--threshold` as u32")
	}

	// GenerateManifest opts
	fn genesis_out_path(&self) -> String {
		self.parsed.single(GENESIS_OUT_PATH).expect("required arg").to_string()
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

	// SignManifest options
	fn personal_key_path(&self) -> String {
		self.parsed.single(PERSONAL_KEY_PATH).expect("required arg").to_string()
	}
	fn manifest_path(&self) -> String {
		self.parsed.single(MANIFEST_PATH).expect("required arg").to_string()
	}
	fn manifest_hash(&self) -> Hash256 {
		hex::decode(self.parsed.single(MANIFEST_HASH).expect("required arg"))
			.expect("Could not parse `--manifest-hash` to bytes")
			.try_into()
			.expect("Could not convert manifest hash to Hash256")
	}

	// BootStandard options
	fn pivot_path(&self) -> String {
		self.parsed.single(PIVOT_PATH).expect("required arg").to_string()
	}
	fn boot_dir(&self) -> String {
		self.parsed.single(BOOT_DIR).expect("required arg").to_string()
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

	pub(super) fn generate_setup_key(opts: &ClientOpts) {
		services::generate_setup_key(
			&opts.alias(),
			&opts.namespace(),
			opts.key_dir(),
		);
	}

	// TODO: verify AWS_ROOT_CERT_PEM against a checksum
	// TODO: verify PCRs
	pub(super) fn boot_genesis(opts: &ClientOpts) {
		services::boot_genesis(
			&opts.path("message"),
			opts.out_dir(),
			opts.key_dir(),
			opts.threshold(),
		);
	}

	pub(super) fn after_genesis(opts: &ClientOpts) {
		services::after_genesis(
			opts.genesis_dir(),
			opts.setup_key_path(),
			&opts.pcr0(),
			&opts.pcr1(),
			&opts.pcr2(),
		);
	}

	/// Generate a manifest with given inputs
	/// TODO: can we write the manifest in plain english?
	pub(super) fn generate_manifest(opts: &ClientOpts) {
		services::generate_manifest(GenerateManifestArgs {
			genesis_out_path: opts.genesis_out_path(),
			nonce: opts.nonce(),
			namespace: opts.namespace(),
			pivot_hash: opts.pivot_hash().try_into().unwrap(),
			restart_policy: opts.restart_policy(),
			pcr0: opts.pcr0(),
			pcr1: opts.pcr1(),
			pcr2: opts.pcr2(),
			root_cert_path: opts.root_cert_path(),
			out_dir: opts.out_dir(),
		});
	}

	/// Sign a manifest, writing the signature++member ID to file.
	///
	/// Verifies that the manifest corresponds to expected in inputs.
	pub(super) fn sign_manifest(opts: &ClientOpts) {
		services::sign_manifest(
			opts.manifest_hash(),
			opts.personal_key_path(),
			opts.manifest_path(),
			opts.out_dir(),
		);
	}

	/// # Arguments
	///
	/// * path to manifest
	/// * various manifest verification params
	/// * directory containing signatures++member ID over manifests
	pub(super) fn boot_standard(opts: &ClientOpts) {
		// path to directory with manifest and approvals
		services::boot_standard(
			&opts.path("message"),
			opts.pivot_path(),
			opts.boot_dir(),
		);
	}
}

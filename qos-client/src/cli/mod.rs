//! `QuorumOS` client command line interface.

use std::env;

use qos_core::{
	hex,
	parser::{CommandParser, GetParserForCommand, Parser, Token},
	protocol::msg::ProtocolMsg,
};
use qos_crypto::RsaPair;

use crate::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
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

#[derive(Clone, PartialEq, Debug)]
enum Command {
	HostHealth,
	DescribeNsm,
	GenerateSetupKey,
	BootGenesis,
	AfterGenesis,
}

impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"host-health" => Self::HostHealth,
			"describe-nsm" => Self::DescribeNsm,
			"generate-setup-key" => Self::GenerateSetupKey,
			"boot-genesis" => Self::BootGenesis,
			"after-genesis" => Self::AfterGenesis,
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
				Token::new(
					HOST_PORT,
					"IP address this server should listen on",
				)
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
				Token::new(THRESHOLD, "directory containing all the setup public keys to use for genesis.")
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
					"path to the setup key you used as an input to genesis.",
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
}

impl GetParserForCommand for Command {
	fn parser(&self) -> Parser {
		match self {
			Self::HostHealth | Self::DescribeNsm => Self::base(),
			Self::GenerateSetupKey => Self::generate_setup_key(),
			Self::BootGenesis => Self::boot_genesis(),
			Self::AfterGenesis => Self::after_genesis(),
		}
	}
}

#[derive(Debug, PartialEq, Clone)]
struct ClientOptions {
	parsed: Parser,
}

impl ClientOptions {
	fn path(&self, uri: &str) -> String {
		let ip = self.parsed.single(HOST_IP).expect("required arg");
		let port = self.parsed.single(HOST_PORT).expect("required arg");

		format!("http://{}:{}/{}", ip, port, uri)
	}

	// Generate setup key options
	fn key_dir(&self) -> String {
		self.parsed.single(KEY_DIR).expect("required arg").to_string()
	}
	fn alias(&self) -> String {
		self.parsed.single(ALIAS).expect("required arg").to_string()
	}
	fn namespace(&self) -> String {
		self.parsed.single(NAMESPACE).expect("required arg").to_string()
	}

	// AfterGenesis options
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

	// BootGenesis options
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
}

#[derive(Clone, PartialEq, Debug)]
struct ClientRunner {
	cmd: Command,
	opts: ClientOptions,
}
impl ClientRunner {
	/// Create [`Self`] from the command line arguments.
	pub fn new(args: &mut Vec<String>) -> Self {
		let (cmd, parsed) =
			CommandParser::<Command>::parse(args).expect("Invalid CLI args");

		Self { cmd, opts: ClientOptions { parsed } }
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

	use super::services;
	use crate::{
		cli::{ClientOptions, ProtocolMsg},
		request,
	};

	pub(super) fn host_health(options: &ClientOptions) {
		let path = &options.path("health");
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
	pub(super) fn describe_nsm(options: &ClientOptions) {
		let path = &options.path("message");
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

	pub(super) fn generate_setup_key(options: &ClientOptions) {
		services::generate_setup_key(
			&options.alias(),
			&options.namespace(),
			options.key_dir(),
		);
	}

	// TODO: verify AWS_ROOT_CERT_PEM against a checksum
	// TODO: verify PCRs
	pub(super) fn boot_genesis(options: &ClientOptions) {
		services::boot_genesis(
			&options.path("message"),
			options.out_dir(),
			options.key_dir(),
			options.threshold(),
		);
	}

	pub(super) fn after_genesis(options: &ClientOptions) {
		services::after_genesis(
			options.genesis_dir(),
			options.setup_key_path(),
			&options.pcr0(),
			&options.pcr1(),
			&options.pcr2(),
		);
	}
}

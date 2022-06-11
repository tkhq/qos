use std::env;

use borsh::BorshSerialize;
use qos_core::protocol::{
	Echo, NsmRequestWrapper, NsmResponseWrapper, ProtocolMsg,
};
use qos_crypto::RsaPair;
use qos_host::cli::HostOptions;

use crate::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT,
};

#[derive(Clone, PartialEq, Debug)]
enum Command {
	Health,
	Echo,
	DescribeNsm,
	MockAttestation,
	Attestation,
	GenerateSetupKey,
	GenerateGenesisConfiguration,
	BootGenesis,
}
impl Command {
	fn run(&self, options: ClientOptions) {
		match self {
			Self::Health => handlers::health(options),
			Self::Echo => handlers::echo(options),
			Self::DescribeNsm => handlers::describe_nsm(options),
			Self::MockAttestation => handlers::mock_attestation(options),
			Self::Attestation => handlers::attestation(options),
			Self::GenerateSetupKey => handlers::generate_setup_key(options),
			Self::GenerateGenesisConfiguration => {
				handlers::generate_genesis_configuration(options)
			}
			Self::BootGenesis => handlers::boot_genesis(options),
		}
	}
}
impl From<&str> for Command {
	fn from(s: &str) -> Self {
		match s {
			"health" => Self::Health,
			"echo" => Self::Echo,
			"describe-nsm" => Self::DescribeNsm,
			"mock-attestation" => Self::MockAttestation,
			"attestation" => Self::Attestation,
			"generate-setup-key" => Self::GenerateSetupKey,
			"generate-genesis-configuration" => {
				Self::GenerateGenesisConfiguration
			}
			"boot-genesis" => Self::BootGenesis,
			_ => panic!("Unrecognized command"),
		}
	}
}

#[derive(Clone, PartialEq, Debug)]
struct ClientOptions {
	cmd: Command,
	host: HostOptions,
	echo: EchoOptions,
	generate_setup_key: GenerateSetupKeyOptions,
	generate_genesis_configuration: GenerateGenesisConfiguration,
	boot_genesis: BootGenesisOptions,
	// ... other options
}
impl ClientOptions {
	/// Create `ClientOptions` from the command line arguments.
	pub fn from(mut args: Vec<String>) -> Self {
		// Remove the executable name
		let mut options = Self {
			host: HostOptions::new(),
			echo: EchoOptions::new(),
			generate_setup_key: GenerateSetupKeyOptions::new(),
			generate_genesis_configuration: GenerateGenesisConfiguration::new(),
			boot_genesis: BootGenesisOptions::new(),
			cmd: Self::extract_command(&mut args),
		};

		let mut chunks = args.chunks_exact(2);
		if chunks.remainder().len() > 0 {
			panic!("Unexpected number of arguments");
		}

		while let Some([cmd, arg]) = chunks.next() {
			options.host.parse(&cmd, &arg);
			match options.cmd {
				Command::Echo => options.echo.parse(&cmd, arg),
				Command::GenerateSetupKey => {
					options.generate_setup_key.parse(&cmd, arg)
				}
				Command::GenerateGenesisConfiguration => {
					options.generate_genesis_configuration.parse(&cmd, arg)
				}
				Command::Health => {}
				Command::DescribeNsm => {}
				Command::MockAttestation => {}
				Command::Attestation => {}
				Command::BootGenesis => options.boot_genesis.parse(&cmd, arg),
			}
		}

		options
	}

	/// Run the given given command.
	pub fn run(self) {
		self.cmd.clone().run(self)
	}

	/// Helper function to extract the command from arguments.
	/// WARNING: this removes the first two items from `args`
	fn extract_command(args: &mut Vec<String>) -> Command {
		args.remove(0);
		let command: Command =
			args.get(0).expect("No command provided").as_str().into();
		// Remove the command
		args.remove(0);

		command
	}
}

#[derive(Clone, PartialEq, Debug)]
struct EchoOptions {
	data: Option<String>,
}
impl EchoOptions {
	fn new() -> Self {
		Self { data: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--data" => self.data = Some(arg.to_string()),
			_ => {}
		};
	}
	fn data(&self) -> String {
		self.data.clone().expect("No `--data` given for echo request")
	}
}

#[derive(Clone, PartialEq, Debug)]
struct GenerateSetupKeyOptions {
	path: Option<String>,
	alias: Option<String>,
	namespace: Option<String>,
}
impl GenerateSetupKeyOptions {
	fn new() -> Self {
		Self { alias: None, namespace: None, path: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--path" => self.path = Some(arg.to_string()),
			"--namespace" => self.namespace = Some(arg.to_string()),
			"--alias" => self.alias = Some(arg.to_string()),
			_ => {}
		}
	}
	fn alias(&self) -> String {
		self.alias.clone().expect("No `--alias` provided")
	}
	fn namespace(&self) -> String {
		self.namespace.clone().expect("No `--namespace` provided")
	}
	fn path(&self) -> String {
		self.path.clone().expect("No `--path` provided")
	}
}

#[derive(Clone, PartialEq, Debug)]
struct GenerateGenesisConfiguration {
	path: Option<String>,
	threshold: Option<u32>,
}
impl GenerateGenesisConfiguration {
	fn new() -> Self {
		Self { path: None, threshold: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--path" => self.path = Some(arg.to_string()),
			"--threshold" => {
				self.threshold =
					Some(arg.parse::<u32>().expect(
						"Could not parse provided value for `--threshold`",
					))
			}
			_ => {}
		}
	}
	fn path(&self) -> String {
		self.path.clone().expect("No `--path` provided")
	}
	fn threshold(&self) -> u32 {
		self.threshold.clone().expect("No `--threshold` provided")
	}
}

#[derive(Clone, PartialEq, Debug)]
struct BootGenesisOptions {
	genesis_set_path: Option<String>,
}
impl BootGenesisOptions {
	fn new() -> Self {
		Self { genesis_set_path: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		if cmd == "--genesis-set-path" {
			self.genesis_set_path = Some(arg.to_string())
		}
	}
	fn genesis_set_path(&self) -> String {
		self.genesis_set_path.clone().expect("No `--genesis-set-path` provided")
	}
}

pub struct CLI;
impl CLI {
	pub fn execute() {
		let args: Vec<String> = env::args().collect();
		let options = ClientOptions::from(args);
		options.run();
	}
}

mod handlers {
	use borsh::BorshDeserialize;
	use qos_core::protocol::{
		BootInstruction, GenesisSet, NsmRequest, NsmResponse, SetupMember,
	};
	use qos_crypto::RsaPub;
	use serde_bytes::ByteBuf;

	use super::*;
	use crate::{attest, request};

	pub(super) fn health(options: ClientOptions) {
		let path = &options.host.path("health");
		if let Ok(response) = request::get(path) {
			println!("{}", response);
		} else {
			panic!("Error...")
		}
	}

	pub(super) fn echo(options: ClientOptions) {
		let path = &options.host.path("message");
		let msg = options.echo.data().into_bytes();
		let response =
			request::post(path, ProtocolMsg::EchoRequest(Echo { data: msg }))
				.map_err(|e| println!("{:?}", e))
				.expect("Echo message failed");

		match response {
			ProtocolMsg::EchoResponse(Echo { data }) => {
				let resp_msg = std::str::from_utf8(&data[..])
					.expect("Couldn't convert Echo to UTF-8");
				println!("{}", resp_msg);
			}
			_ => {
				panic!("Unexpected Echo response")
			}
		};
	}

	pub(super) fn describe_nsm(options: ClientOptions) {
		let path = &options.host.path("message");
		match request::post(
			path,
			ProtocolMsg::NsmRequest(NsmRequestWrapper(NsmRequest::DescribeNSM)),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed")
		{
			ProtocolMsg::NsmResponse(description) => {
				println!("{:#?}", description)
			}
			other => panic!("Unexpected response {:?}", other),
		}
	}

	pub(super) fn attestation(options: ClientOptions) {
		let path = &options.host.path("message");
		let response = request::post(
			path,
			ProtocolMsg::NsmRequest(NsmRequestWrapper(
				NsmRequest::Attestation {
					user_data: None,
					nonce: None,
					public_key: None,
				},
			)),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponseWrapper(
				NsmResponse::Attestation { document },
			)) => {
				let root_cert =
					cert_from_pem(AWS_ROOT_CERT).expect("Invalid root cert");
				let now = std::time::SystemTime::now();
				let seconds_since_epoch = now
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs();
				match attestation_doc_from_der(
					&document,
					&root_cert[..],
					seconds_since_epoch,
				) {
					Ok(_) => println!("Attestation doc verified!"),
					Err(e) => panic!("{:?}", e),
				};
			}
			_ => panic!("Not an attestation response"),
		}
	}

	pub(super) fn mock_attestation(options: ClientOptions) {
		let path = &options.host.path("message");

		let response = request::post(
			path,
			ProtocolMsg::NsmRequest(NsmRequestWrapper(
				NsmRequest::Attestation {
					user_data: None,
					nonce: None,
					public_key: Some(ByteBuf::from(
						RsaPair::generate()
							.unwrap()
							.public_key_to_pem()
							.unwrap(),
					)),
				},
			)),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponseWrapper(
				NsmResponse::Attestation { document },
			)) => {
				use attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
				let root_cert =
					cert_from_pem(AWS_ROOT_CERT).expect("Invalid root cert");
				match attestation_doc_from_der(
					&document,
					&root_cert[..],
					MOCK_SECONDS_SINCE_EPOCH,
				) {
					Ok(_) => println!("Attestation doc verified!"),
					Err(e) => panic!("{:?}", e),
				};
			}
			_ => panic!("Not an attestation response"),
		}
	}

	pub(super) fn generate_setup_key(options: ClientOptions) {
		let alias = options.generate_setup_key.alias();
		let namespace = options.generate_setup_key.namespace();
		let key_directory = options.generate_setup_key.path();

		let key_directory_path = std::path::Path::new(&key_directory);

		if !key_directory_path.is_dir() {
			panic!("Provided path is not valid");
		}

		let private_key_file_name =
			format!("{}.{}.setup.key", alias, namespace);
		let private_key_file_path =
			key_directory_path.join(private_key_file_name);
		let public_key_file_name = format!("{}.{}.setup.pub", alias, namespace);
		let public_key_file_path =
			key_directory_path.join(public_key_file_name);

		let setup_key = RsaPair::generate().expect("RSA key generation failed");
		let private_key_content = setup_key
			.private_key_to_pem()
			.expect("Private key PEM conversion failed");
		let public_key_content = setup_key
			.public_key_to_pem()
			.expect("Public key PEM conversion failed");

		std::fs::write(private_key_file_path, private_key_content)
			.expect("Writing private key failed");
		std::fs::write(public_key_file_path, public_key_content)
			.expect("Writing public key failed");

		println!("Setup keys generated!");
	}

	pub(super) fn generate_genesis_configuration(options: ClientOptions) {
		let threshold = options.generate_genesis_configuration.threshold();
		let key_directory = options.generate_genesis_configuration.path();

		let key_directory_path = std::path::Path::new(&key_directory);
		if !key_directory_path.is_dir() {
			panic!("Provided path is not valid");
		}

		let key_iter = std::fs::read_dir(key_directory_path)
			.expect("Failed to read key directory");
		let members: Vec<SetupMember> = key_iter
			.map(|key_path| {
				let path = key_path.unwrap().path();
				let file_name = path.file_name();
				let split: Vec<_> =
					file_name.unwrap().to_str().unwrap().split(".").collect();
				let alias = split.get(0).unwrap().to_string();

				let public_key = RsaPub::from_pem_file(path).unwrap();

				SetupMember {
					alias,
					pub_key: public_key.public_key_to_der().unwrap(),
				}
			})
			.collect();

		println!("Threshold: {}", threshold);
		println!("Members:");
		for member in members.clone() {
			let pem = RsaPub::from_der(&member.pub_key)
				.unwrap()
				.public_key_to_pem()
				.unwrap();
			println!("  Alias: {}", member.alias);
			println!("  Public Key: \n{}", String::from_utf8_lossy(&pem));
		}

		let genesis_set = GenesisSet { members, threshold };
		let current_dir = std::env::current_dir().unwrap();
		let genesis_configuration_file =
			current_dir.join("genesis.configuration");

		std::fs::write(
			genesis_configuration_file,
			genesis_set.try_to_vec().unwrap(),
		)
		.unwrap();
	}

	pub(super) fn boot_genesis(options: ClientOptions) {
		let uri = &options.host.path("message");

		let genesis_set = options.boot_genesis.genesis_set_path();

		let genesis_set = {
			let genesis_set =
				std::fs::read(genesis_set).expect("Could not open file");
			GenesisSet::try_from_slice(&genesis_set)
				.expect("Could not Deserialize `GenesisSet`")
		};

		let req = ProtocolMsg::BootRequest(BootInstruction::Genesis {
			set: genesis_set,
		});

		match request::post(uri, req).unwrap() {
			ProtocolMsg::BootGenesisResponse {
				attestation_doc,
				genesis_output,
			} => {
				// TODO
				// - where should we writ the attestation doc?
				// - where should we write the genesis output?
			}
			_ => panic!("Unexpected response"),
		}
	}
}

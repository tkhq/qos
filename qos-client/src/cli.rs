use std::env;

use borsh::BorshSerialize;
use qos_core::protocol::{Echo, ProtocolMsg};
use qos_crypto::RsaPair;
use qos_host::cli::HostOptions;

use crate::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
};

#[derive(Clone, PartialEq, Debug)]
enum Command {
	Health,
	Echo,
	DescribeNsm,
	MockAttestation,
	Attestation,
	GenerateSetupKey,
	// GenerateGenesisConfig,
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
			// Self::GenerateGenesisConfig => {
			// 	handlers::generate_genesis_config(options)
			// }
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
			// "generate-genesis-config" => Self::GenerateGenesisConfig,
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
	// generate_genesis_config: GenerateGenesisConfigOptions,
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
			// generate_genesis_config: GenerateGenesisConfigOptions::new(),
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
				// Command::GenerateGenesisConfig => {
				// 	options.generate_genesis_config.parse(&cmd, arg)
				// }
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
	key_dir: Option<String>,
	alias: Option<String>,
	namespace: Option<String>,
}
impl GenerateSetupKeyOptions {
	fn new() -> Self {
		Self { alias: None, namespace: None, key_dir: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--key-dir" => self.key_dir = Some(arg.to_string()),
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
	fn key_dir(&self) -> String {
		self.key_dir.clone().expect("No `--key-dir` provided")
	}
}

// #[derive(Clone, PartialEq, Debug)]
// struct GenerateGenesisConfigOptions {
// 	key_dir: Option<String>,
// 	threshold: Option<u32>,
// }
// impl GenerateGenesisConfigOptions {
// 	fn new() -> Self {
// 		Self { key_dir: None, threshold: None }
// 	}
// 	fn parse(&mut self, cmd: &str, arg: &str) {
// 		match cmd {
// 			"--key-dir" => self.key_dir = Some(arg.to_string()),
// 			"--threshold" => {
// 				self.threshold =
// 					Some(arg.parse::<u32>().expect(
// 						"Could not parse provided value for `--threshold`",
// 					))
// 			}
// 			_ => {}
// 		}
// 	}
// 	fn key_dir(&self) -> String {
// 		self.key_dir.clone().expect("No `--key-dir` provided")
// 	}
// 	fn threshold(&self) -> u32 {
// 		self.threshold.clone().expect("No `--threshold` provided")
// 	}
// }

#[derive(Clone, PartialEq, Debug)]
struct BootGenesisOptions {
	key_dir: Option<String>,
	out_dir: Option<String>,
	threshold: Option<u32>,
}
impl BootGenesisOptions {
	fn new() -> Self {
		Self { key_dir: None, out_dir: None, threshold: None }
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--key-dir" => self.key_dir = Some(arg.to_string()),
			"--threshold" => {
				self.threshold =
					Some(arg.parse::<u32>().expect(
						"Could not parse provided value for `--threshold`",
					))
			}
			"--out-dir" => self.out_dir = Some(arg.to_string()),
			_ => {}
		}
	}
	fn out_dir(&self) -> String {
		self.out_dir.clone().expect("No `--out-dir` provided")
	}
	fn key_dir(&self) -> String {
		self.key_dir.clone().expect("No `--key-dir` provided")
	}
	fn threshold(&self) -> u32 {
		self.threshold.clone().expect("No `--threshold` provided")
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
	use std::path::Path;

	use qos_core::protocol::{
		BootInstruction, GenesisSet, NsmRequest, NsmResponse, SetupMember,
	};
	use qos_crypto::RsaPub;

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
			ProtocolMsg::NsmRequest(NsmRequest::DescribeNSM),
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
			ProtocolMsg::NsmRequest(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: None,
			}),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponse::Attestation { document }) => {
				let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM)
					.expect("Invalid root cert");
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
			ProtocolMsg::NsmRequest(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(
					RsaPair::generate().unwrap().public_key_to_pem().unwrap(),
				),
			}),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponse::Attestation { document }) => {
				// use attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
				// let root_cert =
				// 	cert_from_pem(AWS_ROOT_CERT_PEM).expect("Invalid root cert");
				// match attestation_doc_from_der(
				// 	&document,
				// 	&root_cert[..],
				// 	MOCK_SECONDS_SINCE_EPOCH,
				// ) {
				// 	Ok(_) => println!("Attestation doc verified!"),
				// 	Err(e) => panic!("{:?}", e),
				// };
			}
			_ => panic!("Not an attestation response"),
		}
	}

	pub(super) fn generate_setup_key(options: ClientOptions) {
		let alias = options.generate_setup_key.alias();
		let namespace = options.generate_setup_key.namespace();
		let key_dir = options.generate_setup_key.key_dir();

		let key_dir_path = std::path::Path::new(&key_dir);

		if !key_dir_path.is_dir() {
			panic!("Provided `--key-dir` does not exist is not valid");
		}

		let private_key_file_name =
			format!("{}.{}.setup.key", alias, namespace);
		let private_key_file_path = key_dir_path.join(private_key_file_name);
		let public_key_file_name = format!("{}.{}.setup.pub", alias, namespace);
		let public_key_file_path = key_dir_path.join(public_key_file_name);

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

	// pub(super) fn generate_genesis_config(options: ClientOptions) {
	// 	let threshold = options.generate_genesis_config.threshold();
	// 	let key_dir = options.generate_genesis_config.key_dir();

	// 	let key_dir_path = std::path::Path::new(&key_dir);
	// 	if !key_dir_path.is_dir() {
	// 		panic!("Provided path is not a valid directory");
	// 	}

	// 	let key_iter = std::fs::read_dir(key_dir_path)
	// 		.expect("Failed to read key directory");

	// 	let mut members = vec![];
	// 	for key_path in key_iter {
	// 		let path = key_path.unwrap().path();
	// 		let file_name = path.file_name();
	// 		let split: Vec<_> =
	// 			file_name.unwrap().to_str().unwrap().split(".").collect();

	// 		if *split.last().unwrap() != "pub" {
	// 			println!("A non `.pub` file was found in the setup key directory -
	// skipping."); 			continue
	// 		}
	// 		let alias = split.get(0).unwrap().to_string();

	// 		let public_key = RsaPub::from_pem_file(path)
	// 			.expect("Failed to read in rsa pub key.");

	// 		members.push(SetupMember {
	// 			alias,
	// 			pub_key: public_key.public_key_to_der().unwrap(),
	// 		});
	// 	}

	// 	println!("Threshold: {}", threshold);
	// 	println!("Members:");
	// 	for member in members.clone() {
	// 		let pem = RsaPub::from_der(&member.pub_key)
	// 			.unwrap()
	// 			.public_key_to_pem()
	// 			.unwrap();
	// 		println!("  Alias: {}", member.alias);
	// 		println!("  Public Key: \n{}", String::from_utf8_lossy(&pem));
	// 	}

	// 	let genesis_set = GenesisSet { members, threshold };
	// 	let current_dir = std::env::current_dir().unwrap();
	// 	let genesis_configuration_file =
	// 		current_dir.join("genesis.configuration");

	// 	std::fs::write(
	// 		genesis_configuration_file,
	// 		genesis_set.try_to_vec().unwrap(),
	// 	)
	// 	.unwrap();
	// }

	pub(super) fn boot_genesis(options: ClientOptions) {
		let uri = &options.host.path("message");

		let genesis_set = create_genesis_set(&options);
		let output_dir = options.boot_genesis.out_dir();
		let output_dir = Path::new(&output_dir);

		let req = ProtocolMsg::BootRequest(BootInstruction::Genesis {
			set: genesis_set.clone(),
		});

		// TODO verify AWS_ROOT_CERT_PEM against a checksum

		let (nsm_response, genesis_output) =
			match request::post(uri, req).unwrap() {
				ProtocolMsg::BootGenesisResponse {
					attestation_doc, // TODO: rename to nsm_response
					genesis_output,
				} => (attestation_doc, genesis_output),
				_ => panic!("Unexpected response"),
			};

		let cose_sign1_der = match nsm_response {
			NsmResponse::Attestation { document } => document,
			_ => panic!("NSM response was not an attestation document"),
		};

		#[cfg(feature = "mock")]
		let validation_time = attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
		#[cfg(not(feature = "mock"))]
		let validation_time = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs();
		let _ = attestation_doc_from_der(
			&cose_sign1_der,
			&cert_from_pem(AWS_ROOT_CERT_PEM)
				.expect("AWS ROOT CERT is not valid PEM"),
			validation_time,
		)
		.unwrap();
		// TODO more verify attestation doc logic
		// - should we have an input attestation doc? Or just CLI args?
		// - verify PCRs .. what else? (cert chain is already verified)

		// - write the attestation doc?

		// - sanity check the genesis output
		assert!(
					genesis_set.members.len() == genesis_output.member_outputs.len(),
					 "Output of genesis ceremony does not have same members as Setup Set"
				);
		assert!(genesis_output.member_outputs.iter().all(|member_out|
					genesis_set.members.contains(&member_out.setup_member)
				), "Output of genesis ceremony does not have same members as Setup Set");

		let attestation_doc_path = output_dir.join("attestation_doc.genesis");
		let genesis_output_path = output_dir.join("output.genesis");
		std::fs::create_dir_all(&output_dir).unwrap();
		std::fs::write(&attestation_doc_path, cose_sign1_der)
			.expect("Failed to write attestation doc.");
		std::fs::write(
			&genesis_output_path,
			genesis_output.try_to_vec().unwrap(),
		)
		.expect("Failed to write genesis output");

		println!(
			"Attestation document written to {}",
			attestation_doc_path.as_os_str().to_os_string().to_str().unwrap()
		);
		println!(
			"Genesis output written to {}",
			genesis_output_path.as_os_str().to_os_string().to_str().unwrap()
		);
	}

	fn create_genesis_set(options: &ClientOptions) -> GenesisSet {
		let threshold = options.boot_genesis.threshold();
		let key_dir = options.boot_genesis.key_dir();

		let key_dir_path = std::path::Path::new(&key_dir);
		if !key_dir_path.is_dir() {
			panic!("Provided path is not a valid directory");
		}

		let key_iter = std::fs::read_dir(key_dir_path)
			.expect("Failed to read key directory");

		let mut members = vec![];
		for key_path in key_iter {
			let path = key_path.unwrap().path();
			let file_name = path.file_name();
			let split: Vec<_> =
				file_name.unwrap().to_str().unwrap().split(".").collect();

			if *split.last().unwrap() != "pub" {
				println!("A non `.pub` file was found in the setup key directory - skipping.");
				continue
			}
			let alias = split.get(0).unwrap().to_string();

			let public_key = RsaPub::from_pem_file(path)
				.expect("Failed to read in rsa pub key.");

			members.push(SetupMember {
				alias,
				pub_key: public_key.public_key_to_der().unwrap(),
			});
		}

		println!("Threshold: {}", threshold);
		println!("Members:");
		for member in members.clone() {
			println!("  Alias: {}", member.alias);
			// let pem = RsaPub::from_der(&member.pub_key)
			// 	.unwrap()
			// 	.public_key_to_pem()
			// 	.unwrap();
			// println!("  Public Key: \n{}", String::from_utf8_lossy(&pem));
		}

		GenesisSet { members, threshold }
	}
}

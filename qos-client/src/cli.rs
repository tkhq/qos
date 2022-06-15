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
			ProtocolMsg::NsmResponse(NsmResponse::Attestation {
				document: _,
			}) => {
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

		let setup_key = RsaPair::generate().expect("RSA key generation failed");
		// Write the setup key secret
		{
			let private_key_file_path =
				key_dir_path.join(format!("{}.{}.setup.key", alias, namespace));
			let private_key_content = setup_key
				.private_key_to_pem()
				.expect("Private key PEM conversion failed");
			std::fs::write(private_key_file_path, private_key_content)
				.expect("Writing private key failed");
		}
		// Write the setup key public key
		{
			let public_key_file_path =
				key_dir_path.join(format!("{}.{}.setup.pub", alias, namespace));
			let public_key_content = setup_key
				.public_key_to_pem()
				.expect("Public key PEM conversion failed");
			std::fs::write(public_key_file_path, public_key_content)
				.expect("Writing public key failed");
		}

		println!("Setup keys generated!");
	}

	// TODO: verify AWS_ROOT_CERT_PEM against a checksum
	// TODO: verify PCRs
	pub(super) fn boot_genesis(options: ClientOptions) {
		let uri = &options.host.path("message");

		let genesis_set = create_genesis_set(&options);
		let output_dir = options.boot_genesis.out_dir();
		let output_dir = Path::new(&output_dir);

		let req = ProtocolMsg::BootRequest(BootInstruction::Genesis {
			set: genesis_set.clone(),
		});

		let (nsm_response, genesis_output) =
			match request::post(uri, req).unwrap() {
				ProtocolMsg::BootGenesisResponse {
					nsm_response,
					genesis_output,
				} => (nsm_response, genesis_output),
				_ => panic!("Unexpected response"),
			};
		let cose_sign1_der = match nsm_response {
			NsmResponse::Attestation { document } => document,
			_ => panic!("NSM response was not an attestation document"),
		};

		// Sanity check the genesis output
		{
			assert!(
				genesis_set.members.len() == genesis_output.member_outputs.len(),
					"Output of genesis ceremony does not have same members as Setup Set"
			);
			assert!(genesis_output.member_outputs.iter().all(|member_out|
						genesis_set.members.contains(&member_out.setup_member)
					), "Output of genesis ceremony does not have same members as Setup Set");
		}
		// Check the attestation document
		{
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
		}

		let genesis_output_path = output_dir.join("output.genesis");
		std::fs::create_dir_all(&output_dir).unwrap();

		// Write the attestation doc
		{
			let attestation_doc_path =
				output_dir.join("attestation_doc.genesis");
			std::fs::write(&attestation_doc_path, cose_sign1_der)
				.expect("Failed to write attestation doc.");
			println!(
				"Attestation document written to {}",
				attestation_doc_path
					.as_os_str()
					.to_os_string()
					.to_str()
					.unwrap()
			);
		}
		// Write the genesis output
		{
			std::fs::write(
				&genesis_output_path,
				genesis_output.try_to_vec().unwrap(),
			)
			.expect("Failed to write genesis output");
			println!(
				"Genesis output written to {}",
				genesis_output_path
					.as_os_str()
					.to_os_string()
					.to_str()
					.unwrap()
			);
		}
	}

	fn create_genesis_set(options: &ClientOptions) -> GenesisSet {
		let threshold = options.boot_genesis.threshold();
		let key_dir = options.boot_genesis.key_dir();

		// Get all the files in the key directory
		let key_files = {
			let key_dir_path = std::path::Path::new(&key_dir);
			if !key_dir_path.is_dir() {
				panic!("Provided path is not a valid directory");
			};
			std::fs::read_dir(key_dir_path)
				.expect("Failed to read key directory")
		};

		// Assemble the genesis members from all the public keys in the key
		// directory
		let members: Vec<_> = key_files
			.map(|maybe_key_path| maybe_key_path.unwrap().path())
			.filter_map(|key_path| {
				let file_name =
					key_path.file_name().map(|f| f.to_string_lossy()).unwrap();
				let split: Vec<_> = file_name.split(".").collect();

				// TODO: do we want to dissallow having anything in this folder
				// that is not a public key for the quorum set?
				if *split.last().unwrap() != "pub" {
					println!("A non `.pub` file was found in the setup key directory - skipping.");
					return None
				}

				let public_key = RsaPub::from_pem_file(key_path.clone())
					.expect("Failed to read in rsa pub key.");

				Some(SetupMember {
					alias: split.get(0).unwrap().to_string(),
					pub_key: public_key.public_key_to_der().unwrap(),
				})
			})
			.collect();

		println!("Threshold: {}", threshold);
		println!("N: {}", members.len());
		println!("Members:");
		for member in members.clone() {
			println!("  Alias: {}", member.alias);
		}

		GenesisSet { members, threshold }
	}
}

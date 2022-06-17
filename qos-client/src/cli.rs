//! `QuorumOS` client command line interface.

use std::env;

use qos_core::{
	hex,
	protocol::{msg::ProtocolMsg, QosHash},
};
use qos_crypto::RsaPair;
use qos_host::cli::HostOptions;

use crate::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
};

#[derive(Clone, PartialEq, Debug)]
enum Command {
	HostHealth,
	DescribeNsm,
	GenerateSetupKey,
	BootGenesis,
	AfterGenesis,
}
impl Command {
	fn run(&self, options: &ClientOptions) {
		match self {
			Self::HostHealth => handlers::host_health(options),
			Self::DescribeNsm => handlers::describe_nsm(options),
			Self::GenerateSetupKey => handlers::generate_setup_key(options),
			Self::BootGenesis => handlers::boot_genesis(options),
			Self::AfterGenesis => handlers::after_genesis(options),
		}
	}
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

#[derive(Clone, PartialEq, Debug)]
struct ClientOptions {
	cmd: Command,
	host: HostOptions,
	generate_setup_key: GenerateSetupKeyOptions,
	boot_genesis: BootGenesisOptions,
	after_genesis: AfterGenesisOptions,
	// ... other options
}
impl ClientOptions {
	/// Create `ClientOptions` from the command line arguments.
	pub fn from(mut args: Vec<String>) -> Self {
		// Remove the executable name
		let mut options = Self {
			host: HostOptions::new(),
			generate_setup_key: GenerateSetupKeyOptions::new(),
			boot_genesis: BootGenesisOptions::new(),
			after_genesis: AfterGenesisOptions::new(),
			cmd: Self::extract_command(&mut args),
		};

		let mut chunks = args.chunks_exact(2);
		assert!(
			chunks.remainder().is_empty(),
			"Unexpected number of arguments"
		);

		while let Some([cmd, arg]) = chunks.next() {
			options.host.parse(cmd, arg);
			match options.cmd {
				Command::GenerateSetupKey => {
					options.generate_setup_key.parse(cmd, arg);
				}
				Command::BootGenesis => options.boot_genesis.parse(cmd, arg),
				Command::AfterGenesis => options.after_genesis.parse(cmd, arg),
				Command::HostHealth | Command::DescribeNsm => {}
			}
		}

		options
	}

	/// Run the given given command.
	pub fn run(self) {
		self.cmd.run(&self);
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
				self.threshold = Some(arg.parse::<u32>().expect(
					"Could not parse provided value for `--threshold`",
				));
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
		self.threshold.expect("No `--threshold` provided")
	}
}

#[derive(Default, Clone, PartialEq, Debug)]
struct AfterGenesisOptions {
	/// The directory containing the genesis ceremony output and attestation
	/// doc. Exact same contents as the out dir in the boot genesis command.
	genesis_dir: Option<String>,
	/// Path to the file containing the setup key.
	setup_key_path: Option<String>,
	pcr0: Option<Vec<u8>>,
	pcr1: Option<Vec<u8>>,
	pcr2: Option<Vec<u8>>,
}
impl AfterGenesisOptions {
	fn new() -> Self {
		Self::default()
	}
	fn parse(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--genesis-dir" => self.genesis_dir = Some(arg.to_string()),
			"--setup-key-path" => {
				self.setup_key_path = Some(arg.to_string());
			}
			"--pcr0" => {
				self.pcr0 = Some(hex::decode(arg).expect("pcr0: Invalid hex"));
			}
			"--pcr1" => {
				self.pcr1 = Some(hex::decode(arg).expect("pcr1: Invalid hex"));
			}
			"--pcr2" => {
				self.pcr2 = Some(hex::decode(arg).expect("pcr2: Invalid hex"));
			}
			_ => {}
		}
	}
	fn genesis_dir(&self) -> String {
		self.genesis_dir.clone().expect("No `--genesis-dir` provided")
	}
	fn setup_key_path(&self) -> String {
		self.setup_key_path.clone().expect("No `--setup-key-path` provided")
	}
	fn pcr0(&self) -> Vec<u8> {
		self.pcr0.as_ref().unwrap().clone()
	}
	fn pcr1(&self) -> Vec<u8> {
		self.pcr1.as_ref().unwrap().clone()
	}
	fn pcr2(&self) -> Vec<u8> {
		self.pcr2.as_ref().unwrap().clone()
	}
}

/// Client command line interface
pub struct CLI;
impl CLI {
	/// Execute this command line interface.
	pub fn execute() {
		let args: Vec<String> = env::args().collect();
		let options = ClientOptions::from(args);
		options.run();
	}
}

mod handlers {
	use std::path::Path;

	use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
	use borsh::{BorshDeserialize, BorshSerialize};
	use qos_core::protocol::{
		attestor::types::{NsmRequest, NsmResponse},
		services::genesis::{GenesisOutput, GenesisSet, SetupMember},
	};
	use qos_crypto::RsaPub;

	use super::QosHash;
	use crate::{
		attest,
		cli::{
			attestation_doc_from_der, cert_from_pem, ClientOptions,
			ProtocolMsg, RsaPair, AWS_ROOT_CERT_PEM,
		},
		request,
	};

	const GENESIS_ATTESTATION_DOC_FILE: &str = "attestation_doc.genesis";
	const GENESIS_OUTPUT_FILE: &str = "output.genesis";
	const SETUP_PUB_EXT: &str = ".setup.pub";
	const SETUP_PRIV_EXT: &str = ".setup.key";
	const SHARE_EXT: &str = ".share";
	const PERSONAL_KEY_PUB_EXT: &str = ".personal.pub";
	const PERSONAL_KEY_PRIV_EXT: &str = ".personal.key";

	pub(super) fn host_health(options: &ClientOptions) {
		let path = &options.host.path("health");
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
		let path = &options.host.path("message");
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
		let alias = options.generate_setup_key.alias();
		let namespace = options.generate_setup_key.namespace();
		let key_dir = options.generate_setup_key.key_dir();
		let key_dir_path = std::path::Path::new(&key_dir);

		assert!(
			key_dir_path.is_dir(),
			"Provided `--key-dir` does not exist is not valid"
		);

		let setup_key = RsaPair::generate().expect("RSA key generation failed");
		// Write the setup key secret
		let private_key_file_path = key_dir_path
			.join(format!("{}.{}{}", alias, namespace, SETUP_PRIV_EXT));
		write_with_msg(
			&private_key_file_path,
			&setup_key
				.private_key_to_pem()
				.expect("Private key PEM conversion failed"),
			"Setup Private Key",
		);
		// Write the setup key public key
		let public_key_file_path = key_dir_path
			.join(format!("{}.{}{}", alias, namespace, SETUP_PUB_EXT));

		write_with_msg(
			&public_key_file_path,
			&setup_key
				.public_key_to_pem()
				.expect("Public key PEM conversion failed"),
			"Setup Public Key",
		);
	}

	// TODO: verify AWS_ROOT_CERT_PEM against a checksum
	// TODO: verify PCRs
	pub(super) fn boot_genesis(options: &ClientOptions) {
		let uri = &options.host.path("message");

		let genesis_set = create_genesis_set(options);
		let output_dir = options.boot_genesis.out_dir();
		let output_dir = Path::new(&output_dir);

		let req = ProtocolMsg::BootGenesisRequest { set: genesis_set.clone() };

		let (nsm_response, genesis_output) =
			match request::post(uri, &req).unwrap() {
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
		assert!(
				genesis_set.members.len() == genesis_output.member_outputs.len(),
					"Output of genesis ceremony does not have same members as Setup Set"
			);
		assert!(genesis_output.member_outputs.iter().all(|member_out|
						genesis_set.members.contains(&member_out.setup_member)
					), "Output of genesis ceremony does not have same members as Setup Set");

		// Check the attestation document
		drop(extract_attestation_doc(&cose_sign1_der));

		let genesis_output_path = output_dir.join(GENESIS_OUTPUT_FILE);
		std::fs::create_dir_all(&output_dir).unwrap();

		// Write the attestation doc
		let attestation_doc_path =
			output_dir.join(GENES©4IS_ATTESTATION_DOC_FILE);
		write_with_msg(
			&attestation_doc_path,
			&cose_sign1_der,
			"COSE Sign1 Attestation Doc",
		);

		// Write the genesis output
		write_with_msg(
			&genesis_output_path,
			&genesis_output.try_to_vec().unwrap(),
			"`GenesisOutput`",
		);
	}

	fn create_genesis_set(options: &ClientOptions) -> GenesisSet {
		let threshold = options.boot_genesis.threshold();
		let key_dir = options.boot_genesis.key_dir();

		// Get all the files in the key directory
		let key_files = {
			let key_dir_path = std::path::Path::new(&key_dir);
			assert!(
				key_dir_path.is_dir(),
				"Provided path is not a valid directory"
			);
			std::fs::read_dir(key_dir_path)
				.expect("Failed to read key directory")
		};

		// Assemble the genesis members from all the public keys in the key
		// directory
		let members: Vec<_> = key_files
			.map(|maybe_key_path| maybe_key_path.unwrap().path())
			.filter_map(|key_path| {
				let file_name = key_path
					.file_name()
					.map(std::ffi::OsStr::to_string_lossy)
					.unwrap();
				let split: Vec<_> = file_name.split('.').collect();

				// TODO: do we want to dissallow having anything in this folder
				// that is not a public key for the quorum set?
				if *split.last().unwrap() != "pub" {
					println!("A non `.pub` file was found in the setup key directory - skipping.");
					return None;
				}

				let public_key = RsaPub::from_pem_file(key_path.clone())
					.expect("Failed to read in rsa pub key.");

				Some(SetupMember {
					alias: (*split.get(0).unwrap()).to_string(),
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

	pub(super) fn after_genesis(options: &ClientOptions) {
		let genesis_dir = &options.after_genesis.genesis_dir();
		let genesis_dir = Path::new(genesis_dir);
		let attestation_doc_path =
			genesis_dir.join(GENESIS_ATTESTATION_DOC_FILE);
		let genesis_set_path = genesis_dir.join(GENESIS_OUTPUT_FILE);
		let setup_key_path = &options.after_genesis.setup_key_path();
		let setup_key_path = Path::new(setup_key_path);

		// Read in the setup key
		let setup_pair = RsaPair::from_pem_file(&setup_key_path)
			.expect("Failed to read Setup Key");
		// Get the alias from the setup key file name
		let (alias, namespace) = {
			let split = split_file_name(setup_key_path);
			(
				(*split.get(0).unwrap()).to_string(),
				(*split.get(1).unwrap()).to_string(),
			)
		};
		println!("Alias: {}, Namespace: {}", alias, namespace);

		// Read in the attestation doc from the genesis directory
		let cose_sign1 = std::fs::read(attestation_doc_path)
		.expect("Could not read attestation_doc");
		let attestation_doc = extract_attestation_doc(&cose_sign1);

		// Read in the genesis output from the genesis directory
		let genesis_output = GenesisOutput::try_from_slice(
			&std::fs::read(genesis_set_path)
			.expect("Failed to read genesis set"),
		)
		.expect("Could not deserialize the genesis set");

		// Check the attestation document
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			&genesis_output.qos_hash(),
			&options.after_genesis.pcr0(),
			&options.after_genesis.pcr1(),
			&options.after_genesis.pcr2(),
		);

		// Get the members specific output based on alias & setup key
		let setup_public =
			setup_pair.public_key_to_der().expect("Invalid setup key");
		let member_output = genesis_output
			.member_outputs
			.iter()
			.find(|m| {
				m.setup_member.pub_key == setup_public
					&& m.setup_member.alias == alias
			})
			.expect(
				"Could not find a member output associated with the setup key",
			);

		// Decrypt the Personal Key with the Setup Key
		let personal_pair = {
			let personal_key = setup_pair
				.envelope_decrypt(&member_output.encrypted_personal_key)
				.expect("Failed to decrypt personal key");
			RsaPair::from_der(&personal_key)
				.expect("Failed to create RsaPair from decrypted personal key")
		};

		// Make sure we can decrypt the Share with the Personal Key
		drop(
			personal_pair
				.envelope_decrypt(&member_output.encrypted_quorum_key_share)
				.expect("Share could not be decrypted with personal key"),
		);

		// Store the encrypted share
		let share_path =
			genesis_dir.join(format!("{}.{}{}", alias, namespace, SHARE_EXT));
		write_with_msg(
			share_path.as_path(),
			&member_output.encrypted_quorum_key_share,
			"Encrypted Quorum Share",
		);

		// Store the Personal Key, TODO: password encrypt the private key
		// Public
		let personal_key_pub_path = genesis_dir
			.join(format!("{}.{}{}", alias, namespace, PERSONAL_KEY_PUB_EXT));
		write_with_msg(
			personal_key_pub_path.as_path(),
			&personal_pair
				.public_key_to_pem()
				.expect("Could not create public key from personal pair"),
			"Personal Public Key",
		);
		// Private
		let personal_key_priv_path = genesis_dir
			.join(format!("{}.{}{}", alias, namespace, PERSONAL_KEY_PRIV_EXT));
		write_with_msg(
			personal_key_priv_path.as_path(),
			&personal_pair
				.private_key_to_pem()
				.expect("Could not create private key from personal pair"),
			"Personal Private Key",
		);
	}

	fn write_with_msg(path: &Path, buf: &[u8], item_name: &str) {
		let path_str = path.as_os_str().to_string_lossy();
		// let path_str = p.to_str().unwrap();
		std::fs::write(path, buf).unwrap_or_else(|_| {
			panic!("Failed writing {} to file", path_str.clone())
		});
		println!("{} written to: {}", item_name, path_str);
	}

	/// Panics if verification fails
	fn verify_attestation_doc_against_user_input(
		attestation_doc: &AttestationDoc,
		_user_data: &[u8],
		pcr0: &[u8],
		pcr1: &[u8],
		pcr2: &[u8],
	) {
		// TODO: this is a hack - we should instead have more realistic
		// mock attestation docs
		#[cfg(not(feature = "mock"))]
		{
			// user data is hash of genesis output
			assert_eq!(
				_user_data,
				attestation_doc.user_data.as_ref().unwrap().to_vec(),
				"Attestation doc does not have hash of genesis output."
			);
			// public key is none
			assert_eq!(
				attestation_doc.public_key, None,
				"Attestation doc has a public_key when none was expected."
			);
		}
		#[cfg(feature = "mock")]
		println!(
			"WARNING: SKIPPING ATTESTATION DOC CHECK. DO NOT USE IN PRODUCTION"
		);

		// nonce is none
		assert_eq!(
			attestation_doc.nonce, None,
			"Attestation doc has a nonce when none was expected."
		);

		// pcr0 matches
		assert_eq!(
			pcr0,
			attestation_doc
				.pcrs
				.get(&0)
				.expect("pcr0 not found")
				.clone()
				.into_vec(),
			"pcr0 does not match attestation doc"
		);

		// pcr1 matches
		assert_eq!(
			pcr1,
			attestation_doc
				.pcrs
				.get(&1)
				.expect("pcr1 not found")
				.clone()
				.into_vec(),
			"pcr1 does not match attestation doc"
		);

		// pcr2 matches
		assert_eq!(
			pcr2,
			attestation_doc
				.pcrs
				.get(&2)
				.expect("pcr2 not found")
				.clone()
				.into_vec(),
			"pcr2 does not match attestation doc"
		);
		// - TODO: how do we want to validate the module id?
	}

	/// Panics if extraction or validation fails.
	fn extract_attestation_doc(cose_sign1_der: &[u8]) -> AttestationDoc {
		#[cfg(feature = "mock")]
		let validation_time = attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
		#[cfg(not(feature = "mock"))]
		// TODO: we should probably insert the validation time into the genesis
		// doc?
		let validation_time = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs();
		attestation_doc_from_der(
			cose_sign1_der,
			&cert_from_pem(AWS_ROOT_CERT_PEM)
				.expect("AWS ROOT CERT is not valid PEM"),
			validation_time,
		)
		.expect("Issue extracting and verifying attestation doc")
	}

	// Get the file name from a path and split on `"."`.
	fn split_file_name(p: &Path) -> Vec<String> {
		let file_name =
			p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();
		file_name.split('.').map(String::from).collect()
	}
}

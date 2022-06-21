//! `QuorumOS` client command line interface.

use std::env;

use qos_core::{
	hex,
	parser::{GetParserForCommand, Parser, Token, CommandParser},
	protocol::{msg::ProtocolMsg, QosHash, },
};
use qos_crypto::RsaPair;

use crate::attest::nitro::{
	attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
};

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
					"alias of the Quorum Member this key belongs too.",
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
					"namespace the alias and Setup Key belong too.",
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
		self.parsed.single(THRESHOLD).expect("required arg").parse::<u32>().expect("Could not parse `--threshold` as u32")
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
			todo!()
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
		let alias = options.alias();
		let namespace = options.namespace();
		let key_dir = options.key_dir();
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
		let uri = &options.path("message");

		let genesis_set = create_genesis_set(options);
		let output_dir = options.out_dir();
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
			output_dir.join(GENESIS_ATTESTATION_DOC_FILE);
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
		let threshold = options.threshold();
		let key_dir = options.key_dir();

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
		let genesis_dir = &options.genesis_dir();
		let genesis_dir = Path::new(genesis_dir);
		let attestation_doc_path =
			genesis_dir.join(GENESIS_ATTESTATION_DOC_FILE);
		let genesis_set_path = genesis_dir.join(GENESIS_OUTPUT_FILE);
		let setup_key_path = &options.setup_key_path();
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
			&options.pcr0(),
			&options.pcr1(),
			&options.pcr2(),
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
		std::fs::write(path, buf).unwrap_or_else(|_| {
			panic!("Failed writing {} to file", path_str.clone())
		});
		println!("{} written to: {}", item_name, path_str);
	}

	/// Panics if verification fails
	fn verify_attestation_doc_against_user_input(
		attestation_doc: &AttestationDoc,
		user_data: &[u8],
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
				user_data,
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
		let validation_time = crate::attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
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

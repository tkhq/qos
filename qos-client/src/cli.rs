use std::env;

use qos_core::protocol::{Echo, ProtocolMsg};
use qos_host::cli::HostOptions;

#[derive(Clone, PartialEq, Debug)]
enum Command {
	Health,
	Echo,
	DescribeNsm,
}
impl Command {
	fn run(&self, options: ClientOptions) {
		match self {
			Command::Health => handlers::health(options),
			Command::Echo => handlers::echo(options),
			Command::DescribeNsm => handlers::describe_nsm(options),
		}
	}
}
impl Into<Command> for &str {
	fn into(self) -> Command {
		match self {
			"health" => Command::Health,
			"echo" => Command::Echo,
			"describe-nsm" => Command::DescribeNsm,
			_ => panic!("Unrecognized command"),
		}
	}
}

#[derive(Clone, PartialEq, Debug)]
struct ClientOptions {
	cmd: Command,
	host: HostOptions,
	echo: EchoOptions,
	// ... other options
}
impl ClientOptions {
	/// Create `ClientOptions` from the command line arguments.
	pub fn from(mut args: Vec<String>) -> Self {
		// Remove the executable name
		let mut options = Self {
			host: HostOptions::new(),
			echo: EchoOptions::new(),
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
				Command::Health => {}
				Command::DescribeNsm => {}
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

pub struct CLI;
impl CLI {
	pub fn execute() {
		let args: Vec<String> = env::args().collect();
		let options = ClientOptions::from(args);
		options.run();
	}
}

mod handlers {
	use openssl::{
		bn::BigNumContext,
		ec::{EcGroup, EcKey, EcPoint},
		nid::Nid,
	};
	use qos_core::protocol::{NsmRequest, NsmResponse};

	use super::*;
	use crate::request;

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

		let response = request::post(
			path,
			ProtocolMsg::NsmRequest(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: None,
			}),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Echo message failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponse::Attestation { document }) => {
				use aws_nitro_enclaves_cose::CoseSign1;
				use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
				// TODO: semantic verification from: https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

				let cose_sign1 = CoseSign1::from_bytes(&document[..]).unwrap();
				let encoded_document = cose_sign1.get_payload(None).unwrap();
				let decoded_document =
					AttestationDoc::from_binary(&encoded_document[..]).unwrap();

				let pcrs = decoded_document.pcrs;

				let module = decoded_document.module_id;
				// println!("module id: {:?}", module);

				if let Some(public_key) = decoded_document.public_key {
					// println!("public key: {:?}", public_key);
				}

				let cabundle = decoded_document.cabundle;
				// println!("CA bundle: {:?}", cabundle);

				// Target Certificate in
				// let certificate = decoded_document.certificate;
				// println!("Certificate: {:?}", certificate);

				// let c = std::str::from_utf8(&certificate);
				// println!("Certificate:");
				// println!("{:?}", c);

				//

				// Trying to do... Certificate -> Public Key
				// Certificate & CA bundle verification example: https://github.com/ppmag/aws-nitro-enclaves-attestation/blob/83ca87233298c302973a5bdbbb394c36cd7eb6e6/src/lib.rs#L233-L235
				match x509_parser::parse_x509_certificate(
					&decoded_document.certificate.clone(),
				) {
					Ok((remaining_input, certificate)) => {
						assert!(
							remaining_input.len() == 0,
							"certificate was not valid DER encoding"
						);

						assert!(
							certificate.tbs_certificate.version()
								== x509_parser::x509::X509Version::V3,
							"Wrong certificate version"
						);

						let extracted_key = {
							let pub_key = certificate
								.tbs_certificate
								.subject_pki
								.subject_public_key
								.data;

							let group =
								EcGroup::from_curve_name(Nid::SECP384R1)
									.unwrap();
							let mut ctx = BigNumContext::new().unwrap();
							let point =
								EcPoint::from_bytes(&group, &pub_key, &mut ctx)
									.unwrap();
							let ec_key =
								EcKey::from_public_key(&group, &point).unwrap();

							openssl::pkey::PKey::try_from(ec_key).expect("EC Key could not be converted to open ssl primitive")
						};

						assert!(
							cose_sign1.verify_signature(&extracted_key).unwrap(),
							"Could not verify attestation document with target certificate"
						);
						println!("Verified att_doc target cert signature!")
					}
					Err(_) => panic!("Could not parse target certificate"),
				}

				// use openssl::ec::EcKey;
				// let key = EcKey::public_key_from_der(&certificate);
				// println!("Public Key: {:?}", key);

				////
				// Truths:
				////

				// 1. AWS Nitro Enclaves use ES384 algorithm to sign the document
				// 2. Certificate is DER-encoded
				//

				// Verification Flow:
				// 1. Check signature from the Certificate over the AttestationDocument
				// 2. Verify the CA Bundle using the known root of trust and Certificate
				//   - Assume ROT is known ahead of time
				// 3. Business logic
				//   - Is the application that is being run (as evidenced by the PCRs) the expected application to have possession of *this* key?
				//   - (Human): How do I know that this build artifact is correct?
			}
			_ => panic!("Not an attestation response"),
		}
	}
}

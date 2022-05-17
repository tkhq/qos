use std::env;

use qos_core::protocol::{Echo, ProtocolMsg};
use qos_host::cli::HostOptions;

use std::time::*;

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
	use super::*;
	use crate::request;
	use qos_core::protocol::{NsmDigest, NsmRequest, NsmResponse};

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
				use aws_nitro_enclaves_nsm_api::api::Digest;
				use openssl::{
					bn::BigNumContext,
					ec::{EcGroup, EcKey, EcPoint},
					nid::Nid,
				};
				use x509_parser::pem::Pem;
				static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
					&webpki::ECDSA_P256_SHA256,
					&webpki::ECDSA_P256_SHA384,
					&webpki::ECDSA_P384_SHA256,
					&webpki::ECDSA_P384_SHA384,
					&webpki::ED25519,
					#[cfg(feature = "alloc")]
					&webpki::RSA_PKCS1_2048_8192_SHA256,
					#[cfg(feature = "alloc")]
					&webpki::RSA_PKCS1_2048_8192_SHA384,
					#[cfg(feature = "alloc")]
					&webpki::RSA_PKCS1_2048_8192_SHA512,
					#[cfg(feature = "alloc")]
					&webpki::RSA_PKCS1_3072_8192_SHA384,
				];
				////
				// Truths:
				////

				// 1. AWS Nitro Enclaves use ES384 algorithm to sign the
				// document 2. Certificate is DER-encoded
				//

				// Verification Flow:
				// 1. Check signature from the Certificate over the
				// AttestationDocument 2. Verify the CA Bundle using the known
				// root of trust and Certificate
				//   - Assume ROT is known ahead of time
				// 3. Business logic
				//   - Is the application that is being run (as evidenced by the
				//     PCRs) the expected application to have possession of
				//     *this* key?
				//   - (Human): How do I know that this build artifact is
				//     correct?
				// TODO: semantic verification from: https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

				let cose_sign1 = CoseSign1::from_bytes(&document[..]).unwrap();
				let raw_attestation_doc = cose_sign1.get_payload(None).unwrap();
				let attestation_doc =
					AttestationDoc::from_binary(&raw_attestation_doc[..])
						.expect("Attestation doc could not be decoded.");

				// Basic syntactic validation
				{
					assert!(
						attestation_doc.module_id.len() > 0,
						"Invalid Module ID"
					);
					assert!(
						attestation_doc.digest == Digest::SHA384,
						"Invalid Digest"
					);

					// let ts_start = Utc.ymd(2020, 1, 1).and_hms(0, 0, 0);
					// let ts_end = Utc::now() + Duration::days(1);
					// (attestation_doc.timestamp > ts_start &&
					// attestation_doc.timestamp < ts_end)

					//TODO: add all validations as specified in https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#32-syntactical-validation
				}

				// CA bundle verification
				{
					const AWS_ROOT_CERT: &'static [u8] =
						std::include_bytes!("./aws_root_cert.pem");
					// aws root cert checksum:
					// 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c

					// Bundle starts with root certificate - we want to replace the root
					// with our hardcoded known certificate, so we remove the root (first element)
					let intermediate_certs: Vec<_> = attestation_doc.cabundle
						[1..]
						.into_iter()
						.map(|x| x.as_slice())
						.collect();

					let mut pem_iter = Pem::iter_from_buffer(AWS_ROOT_CERT);
					let root_cert = pem_iter
						.next()
						.expect("Hardcoded aws root cert should be valid PEM")
						.expect("Hardcoded aws root cert should be valid PEM");
					assert!(
						pem_iter.next().is_none(),
						"More then 1 cert detected in hardcoded aws root"
					);

					let anchor = webpki::TrustAnchor::try_from_cert_der(
						&root_cert.contents[..],
					)
					.expect("Could not decode DER cabundle");
					let anchors = vec![anchor];
					let anchors = webpki::TlsServerTrustAnchors(&anchors);

					// let second_since_epoch = std::time::SystemTime::now()
					// 	.duration_since(std::time::SystemTime::UNIX_EPOCH)
					// 	.unwrap().as_secs()
					let seconds_since_epoch = 1652756400;
					let time = webpki::Time::from_seconds_since_unix_epoch(
						seconds_since_epoch,
					);

					// Cert
					let ee_raw: &[u8] = attestation_doc.certificate.as_ref();
					let cert = webpki::EndEntityCert::try_from(ee_raw)
						.expect("Could not decode target cert");

					cert.verify_is_valid_tls_server_cert(
						ALL_SIGALGS,
						&anchors,
						&intermediate_certs,
						time,
					)
					.expect("Invalid CA bundle");
				}

				// Certificate & CA bundle verification example: https://github.com/ppmag/aws-nitro-enclaves-attestation/blob/83ca87233298c302973a5bdbbb394c36cd7eb6e6/src/lib.rs#L233-L235
				{
					let (remaining_input, certificate) =
						x509_parser::parse_x509_certificate(
							&attestation_doc.certificate,
						)
						.expect("Could not parse target certificate");

					// Basic semantic checks
					assert!(
						remaining_input.len() == 0,
						"certificate was not valid DER encoding"
					);
					assert!(
						certificate.tbs_certificate.version()
							== x509_parser::x509::X509Version::V3,
						"Wrong certificate version"
					);

					// Get the public key the cose sign1 object was signed with
					// https://github.com/briansmith/webpki/issues/85
					let extracted_key = {
						let pub_key = certificate
							.tbs_certificate
							.subject_pki
							.subject_public_key
							.data;

						let group =
							EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
						let mut ctx = BigNumContext::new().unwrap();
						let point =
							EcPoint::from_bytes(&group, &pub_key, &mut ctx)
								.unwrap();
						let ec_key =
							EcKey::from_public_key(&group, &point).unwrap();

						openssl::pkey::PKey::try_from(ec_key).expect("EC Key could not be converted to open ssl primitive")
					};

					// Verify the signature against the extracted public key
					assert!(
							cose_sign1.verify_signature(&extracted_key).expect("Error with cose signature verification."),
							"Could not verify attestation document with target certificate"
						);
				}
			}
			_ => panic!("Not an attestation response"),
		}
	}
}

use std::env;

use qos_core::protocol::{Echo, ProtocolMsg, NsmRequestWrapper, NsmResponseWrapper};
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
}
impl Command {
	fn run(&self, options: ClientOptions) {
		match self {
			Command::Health => handlers::health(options),
			Command::Echo => handlers::echo(options),
			Command::DescribeNsm => handlers::describe_nsm(options),
			Command::MockAttestation => handlers::mock_attestation(options),
			Command::Attestation => handlers::attestation(options),
		}
	}
}
impl Into<Command> for &str {
	fn into(self) -> Command {
		match self {
			"health" => Command::Health,
			"echo" => Command::Echo,
			"describe-nsm" => Command::DescribeNsm,
			"mock-attestation" => Command::MockAttestation,
			"attestation" => Command::Attestation,
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
				Command::MockAttestation => {}
				Command::Attestation => {}
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

	use qos_core::protocol::{NsmRequest, NsmResponse};
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
			ProtocolMsg::NsmRequest(NsmRequestWrapper(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: None,
			})),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponseWrapper(NsmResponse::Attestation { document })) => {
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
			ProtocolMsg::NsmRequest(NsmRequestWrapper(NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(ByteBuf::from(
					RsaPair::generate().unwrap().public_key_to_pem().unwrap(),
				)),
			})),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Attestation request failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponseWrapper(NsmResponse::Attestation { document })) => {
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
}

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
			ProtocolMsg::NsmRequest(NsmRequest::DescribeNSM),
		)
		.map_err(|e| println!("{:?}", e))
		.expect("Echo message failed");

		match response {
			ProtocolMsg::NsmResponse(NsmResponse::Attestation {
				ref document,
			}) => {
				use std::fs::File;
				use std::io::Write;
				let mut file =
					File::create("/home/tk/attest_document").unwrap();
				let output = format!("{:?}", document);
				file.write_all(&output.as_bytes()).unwrap();
			}
			_ => panic!("Not an attestation response"),
		}

		match response {
			ProtocolMsg::NsmResponse(describe_nsm_response) => {
				println!("{:?}", describe_nsm_response)
			}
			_ => panic!("Unexpected describe nsm response"),
		}
	}
}

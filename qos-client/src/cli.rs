use std::env;

use qos_core::protocol::{Echo, ProtocolMsg};
use qos_host::cli::HostOptions;

enum Command {
	Health,
	Echo,
}
impl Command {
	fn run(&self, options: ClientOptions) {
		match self {
			Command::Health => handlers::health(options),
			Command::Echo => handlers::echo(options),
		}
	}
}
impl Into<Command> for &str {
	fn into(self) -> Command {
		match self {
			"health" => Command::Health,
			"echo" => Command::Echo,
			_ => panic!("Unrecognized command"),
		}
	}
}

#[derive(Clone, PartialEq, Debug)]
struct ClientOptions {
	host: HostOptions,
	echo: EchoOptions,
	// ... other options
}
impl ClientOptions {
	fn new() -> Self {
		Self { host: HostOptions::new(), echo: EchoOptions::new() }
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
			"--echo-data" => self.data = Some(arg.to_string()),
			_ => {}
		};
	}
	fn data(&self) -> String {
		self.data.clone().expect("No `--echo-data` given for echo request")
	}
}

pub struct CLI;
impl CLI {
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		// Remove the executable name
		args.remove(0);

		let command: Command =
			args.get(0).expect("No command provided").as_str().into();
		// Remove the command
		args.remove(0);

		let options = parse_args(args);
		command.run(options);
	}
}

fn parse_args(args: Vec<String>) -> ClientOptions {
	let mut options = ClientOptions::new();
	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexpected number of arguments");
	}

	while let Some([cmd, arg]) = chunks.next() {
		options.host.parse(&cmd, &arg);
		options.echo.parse(&cmd, arg);
	}

	options
}

mod handlers {
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
}

use qos_core::protocol::{Echo, ProtocolMsg};
use qos_host::cli::{
	host_addr_from_options, parse_ip, parse_port, HostOptions,
};
use std::env;

enum Command {
	Health,
	Echo,
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

impl Command {
	fn run(&self, options: HostOptions) {
		match self {
			Command::Health => handlers::health(options),
			Command::Echo => handlers::echo(options),
		}
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
		let addr = host_addr_from_options(options.clone());
		command.run(options);
	}
}

fn parse_args(args: Vec<String>) -> HostOptions {
	let mut options = HostOptions::new();
	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexpected number of arguments");
	}

	while let Some([cmd, arg]) = chunks.next() {
		parse_ip(&cmd, &arg, &mut options);
		parse_port(&cmd, &arg, &mut options);
	}

	options
}

mod handlers {
	use super::*;
	use crate::request;

	pub fn health(options: HostOptions) {
		let path = &options.path("health");
		if let Ok(response) = request::get(path) {
			println!("{}", response);
		} else {
			panic!("Error...")
		}
	}

	pub fn echo(options: HostOptions) {
		let path = &options.path("message");
		let msg = b"Hello, world!".to_vec();
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
			_ => { panic!("Unexpected Echo response")}
		};
	}
}

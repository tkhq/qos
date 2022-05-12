use std::env;

use crate::{
	io::SocketAddress,
	protocol::{Executor, MockNsm},
	server::SocketServer,
};

#[derive(Debug, PartialEq)]
struct CLIOptions {
	cid: Option<u32>,
	port: Option<u32>,
	usock: Option<String>,
}

impl CLIOptions {
	pub fn new() -> Self {
		Self { cid: None, port: None, usock: None }
	}
}

pub struct CLI {}
impl CLI {
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);

		let options = parse_args(args);
		let addr = addr_from_options(options);
		let executor = Executor::new(MockNsm {});

		SocketServer::listen(addr, executor).unwrap();
	}
}

fn parse_args(args: Vec<String>) -> CLIOptions {
	let mut options = CLIOptions::new();

	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexepected number of arguments")
	}
	while let Some([cmd, arg]) = chunks.next() {
		match cmd.as_str() {
			"--cid" => match arg.parse::<u32>() {
				Ok(cid) => options.cid = Some(cid),
				_ => {
					panic!("Could not parse provided value for `--cid`")
				}
			},
			"--port" => match arg.parse::<u32>() {
				Ok(port) => options.port = Some(port),
				_ => {
					panic!("Could not parse provided value for `--port`")
				}
			},
			"--usock" => options.usock = Some(arg.clone()),
			_ => {
				panic!("Could not parse command...")
			}
		}
	}

	options
}

fn addr_from_options(options: CLIOptions) -> SocketAddress {
	match options {
		#[cfg(feature = "vm")]
		CLIOptions { cid: Some(c), port: Some(p), usock: None } => {
			SocketAddress::new_vsock(c, p)
		}
		CLIOptions { cid: None, port: None, usock: Some(u) } => {
			SocketAddress::new_unix(&u)
		}
		_ => panic!("Invalid options..."),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_cid_and_port() {
		let args = vec!["--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = parse_args(args);

		assert_eq!(
			options,
			CLIOptions { cid: Some(6), port: Some(3999), usock: None }
		)
	}

	#[test]
	fn parse_usock() {
		let args = vec!["--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = parse_args(args);

		assert_eq!(
			options,
			CLIOptions {
				cid: None,
				port: None,
				usock: Some("./test.sock".to_string())
			}
		)
	}

	#[test]
	#[should_panic]
	fn panic_on_too_many_options() {
		let options = CLIOptions {
			cid: Some(1),
			port: Some(3000),
			usock: Some("./test.sock".to_string()),
		};
		addr_from_options(options);
	}

	#[test]
	#[should_panic]
	fn panic_on_not_enough_options() {
		let options = CLIOptions { cid: None, port: Some(3000), usock: None };
		addr_from_options(options);
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let options =
			CLIOptions { cid: Some(3), port: Some(3000), usock: None };
		match addr_from_options(options) {
			SocketAddress::Vsock(_) => {}
			_ => {
				panic!("Can't build SocketAddress:Vsock from options")
			}
		}
	}

	#[test]
	fn build_usock() {
		let options = CLIOptions {
			cid: None,
			port: None,
			usock: Some("./dev.sock".to_string()),
		};
		match addr_from_options(options) {
			SocketAddress::Unix(_) => {}
			_ => {
				panic!("Can't build SocketAddress:Unix from options")
			}
		}
	}

	#[test]
	#[should_panic]
	fn panic_when_mistyped_cid() {
		let args = vec!["--cid", "notanint", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = parse_args(args);
	}

	#[test]
	#[should_panic]
	fn panic_when_mistyped_port() {
		let args = vec!["--cid", "123", "--port", "notanint"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = parse_args(args);
	}
}

use std::env;

use crate::{
	io::SocketAddress,
	protocol::{Executor, MockNsm},
	server::SocketServer,
};

#[derive(Clone, Debug, PartialEq)]
pub struct EnclaveOptions {
	cid: Option<u32>,
	port: Option<u32>,
	usock: Option<String>,
}

impl EnclaveOptions {
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

fn parse_args(args: Vec<String>) -> EnclaveOptions {
	let mut options = EnclaveOptions::new();

	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexepected number of arguments")
	}
	while let Some([cmd, arg]) = chunks.next() {
		parse_enclave_options(cmd.clone(), arg.clone(), &mut options);
	}

	options
}

pub fn parse_enclave_options(
	cmd: String,
	arg: String,
	options: &mut EnclaveOptions,
) {
	parse_cid(&cmd, &arg, options);
	parse_port(&cmd, &arg, options);
	parse_usock(&cmd, &arg, options);
}

pub fn parse_cid(cmd: &String, arg: &String, options: &mut EnclaveOptions) {
	match cmd.as_str() {
		"--cid" => {
			options.cid = arg
				.parse::<u32>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--cid`")
				})
				.ok();
		}
		_ => {}
	}
}

pub fn parse_port(cmd: &String, arg: &String, options: &mut EnclaveOptions) {
	match cmd.as_str() {
		"--port" => {
			options.port = arg
				.parse::<u32>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--port`")
				})
				.ok();
		}
		_ => {}
	}
}

pub fn parse_usock(cmd: &String, arg: &String, options: &mut EnclaveOptions) {
	match cmd.as_str() {
		"--usock" => options.usock = Some(arg.clone()),
		_ => {}
	}
}

pub fn addr_from_options(options: EnclaveOptions) -> SocketAddress {
	match options {
		#[cfg(feature = "vm")]
		EnclaveOptions { cid: Some(c), port: Some(p), usock: None } => {
			SocketAddress::new_vsock(c, p)
		}
		EnclaveOptions { cid: None, port: None, usock: Some(u) } => {
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
			EnclaveOptions { cid: Some(6), port: Some(3999), usock: None }
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
			EnclaveOptions {
				cid: None,
				port: None,
				usock: Some("./test.sock".to_string())
			}
		)
	}

	#[test]
	#[should_panic]
	fn panic_on_too_many_options() {
		let options = EnclaveOptions {
			cid: Some(1),
			port: Some(3000),
			usock: Some("./test.sock".to_string()),
		};
		addr_from_options(options);
	}

	#[test]
	#[should_panic]
	fn panic_on_not_enough_options() {
		let options =
			EnclaveOptions { cid: None, port: Some(3000), usock: None };
		addr_from_options(options);
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let options =
			EnclaveOptions { cid: Some(3), port: Some(3000), usock: None };
		match addr_from_options(options) {
			SocketAddress::Vsock(_) => {}
			_ => {
				panic!("Can't build SocketAddress:Vsock from options")
			}
		}
	}

	#[test]
	fn build_usock() {
		let options = EnclaveOptions {
			cid: None,
			port: None,
			usock: Some("./dev.sock".to_string()),
		};
		match addr_from_options(options) {
			SocketAddress::Unix(_) => {}
			#[cfg(feature = "vm")]
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

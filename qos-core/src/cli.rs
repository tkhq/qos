use std::env;

use crate::{
	io::SocketAddress,
	protocol::{Executor, MockNsm, Nsm, NsmProvider},
	server::SocketServer,
};

#[derive(Clone, Debug, PartialEq)]
pub struct EnclaveOptions {
	cid: Option<u32>,
	port: Option<u32>,
	usock: Option<String>,
	mock: bool,
}

impl EnclaveOptions {
	pub fn new() -> Self {
		Self { cid: None, port: None, usock: None, mock: false }
	}

	fn from(args: Vec<String>) -> EnclaveOptions {
		let mut options = EnclaveOptions::new();

		let mut chunks = args.chunks_exact(2);
		if chunks.remainder().len() > 0 {
			panic!("Unexepected number of arguments")
		}

		while let Some([cmd, arg]) = chunks.next() {
			options.parse(cmd, arg);
		}

		options
	}

	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_cid(cmd, arg);
		self.parse_port(cmd, arg);
		self.parse_usock(cmd, arg);
		self.parse_mock(cmd, arg)
	}

	pub fn parse_cid(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--cid" => {
				self.cid = arg
					.parse::<u32>()
					.map_err(|_| {
						panic!("Could not parse provided value for `--cid`")
					})
					.ok();
			}
			_ => {}
		}
	}

	pub fn parse_port(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--port" => {
				self.port = arg
					.parse::<u32>()
					.map_err(|_| {
						panic!("Could not parse provided value for `--port`")
					})
					.ok();
			}
			_ => {}
		}
	}

	pub fn parse_usock(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--usock" => self.usock = Some(arg.to_string()),
			_ => {}
		}
	}

	pub fn parse_mock(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--mock" => self.mock = arg == "true",
			_ => {}
		}
	}

	pub fn addr(&self) -> SocketAddress {
		match self.clone() {
			#[cfg(feature = "vm")]
			EnclaveOptions {
				cid: Some(c), port: Some(p), usock: None, ..
			} => SocketAddress::new_vsock(c, p),
			EnclaveOptions {
				cid: None, port: None, usock: Some(u), ..
			} => SocketAddress::new_unix(&u),
			_ => panic!("Invalid options..."),
		}
	}

	pub fn nsm(&self) -> Box<dyn NsmProvider> {
		if self.mock {
			Box::new(MockNsm)
		} else {
			Box::new(Nsm)
		}
	}
}

pub struct CLI {}
impl CLI {
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);

		let options = EnclaveOptions::from(args);

		let addr = options.addr();
		let nsm = options.nsm();
		let executor = Executor::new(nsm);

		SocketServer::listen(addr, executor).unwrap();
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
		let options = EnclaveOptions::from(args);

		assert_eq!(
			options,
			EnclaveOptions {
				cid: Some(6),
				port: Some(3999),
				usock: None,
				mock: false
			}
		)
	}

	#[test]
	fn parse_usock() {
		let args = vec!["--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::from(args);

		assert_eq!(
			options,
			EnclaveOptions {
				cid: None,
				port: None,
				usock: Some("./test.sock".to_string()),
				mock: false
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
			mock: false,
		};
		options.addr();
	}

	#[test]
	#[should_panic]
	fn panic_on_not_enough_options() {
		let options = EnclaveOptions {
			cid: None,
			port: Some(3000),
			usock: None,
			mock: false,
		};
		options.addr();
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let options = EnclaveOptions {
			cid: Some(3),
			port: Some(3000),
			usock: None,
			mock: false,
		};
		match options.addr() {
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
			mock: false,
		};
		match options.addr() {
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
		let _options = EnclaveOptions::from(args);
	}

	#[test]
	#[should_panic]
	fn panic_when_mistyped_port() {
		let args = vec!["--cid", "123", "--port", "notanint"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = EnclaveOptions::from(args);
	}
}

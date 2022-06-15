use std::env;

use crate::{
	coordinator::Coordinator,
	io::SocketAddress,
	protocol::{MockNsm, Nsm, NsmProvider},
	EPHEMERAL_KEY_FILE, PIVOT_FILE, SECRET_FILE,
};

/// CLI options for starting up the enclave server.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct EnclaveOptions {
	cid: Option<u32>,
	port: Option<u32>,
	usock: Option<String>,
	mock: bool,
	secret_file: String,
	pivot_file: String,
	ephemeral_key_file: String,
}

impl EnclaveOptions {
	/// Create a new instance of [`Self`] with some defaults.
	#[must_use] pub fn new() -> Self {
		Self {
			cid: None,
			port: None,
			usock: None,
			mock: false,
			secret_file: SECRET_FILE.to_owned(),
			pivot_file: PIVOT_FILE.to_owned(),
			ephemeral_key_file: EPHEMERAL_KEY_FILE.to_owned(),
		}
	}

	fn from_args(args: &[String]) -> EnclaveOptions {
		let mut options = EnclaveOptions::new();

		let mut chunks = args.chunks_exact(2);
		assert!(chunks.remainder().is_empty(), "Unexepected number of arguments");

		while let Some([cmd, arg]) = chunks.next() {
			options.parse(cmd, arg);
		}

		options
	}

	/// Parse a set of command and argument.
	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_cid(cmd, arg);
		self.parse_port(cmd, arg);
		self.parse_usock(cmd, arg);
		self.parse_mock(cmd, arg);
		self.parse_secret_file(cmd, arg);
		self.parse_pivot_file(cmd, arg);
		self.parse_ephemeral_key_file(cmd, arg);
	}

	fn parse_cid(&mut self, cmd: &str, arg: &str) {
		if cmd == "--cid" {
			self.cid = arg
				.parse::<u32>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--cid`")
				})
				.ok();
		}
	}

	fn parse_port(&mut self, cmd: &str, arg: &str) {
		if cmd == "--port" {
			self.port = arg
				.parse::<u32>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--port`")
				})
				.ok();
		}
	}

	fn parse_usock(&mut self, cmd: &str, arg: &str) {
		if cmd == "--usock" {
			self.usock = Some(arg.to_string());
		}
	}

	fn parse_mock(&mut self, cmd: &str, arg: &str) {
		if cmd == "--mock" {
			self.mock = arg == "true";
		};
	}

	fn parse_secret_file(&mut self, cmd: &str, arg: &str) {
		if cmd == "--secret-file" {
			self.secret_file = arg.to_owned();
		}
	}

	fn parse_pivot_file(&mut self, cmd: &str, arg: &str) {
		if cmd == "--pivot-file" {
			self.pivot_file = arg.to_owned();
		}
	}

	fn parse_ephemeral_key_file(&mut self, cmd: &str, arg: &str) {
		if cmd == "--ephemeral-key-file" {
			self.ephemeral_key_file = arg.to_owned();
		}
	}

	/// Get the `SocketAddress` for the enclave server.
	///
	/// # Panics
	///
	/// Panics if the options are not valid for exactly one of unix or vsock.
	#[must_use] pub fn addr(&self) -> SocketAddress {
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

	/// Get the [`NsmProvider`]
	#[must_use] pub fn nsm(&self) -> Box<dyn NsmProvider> {
		if self.mock {
			Box::new(MockNsm)
		} else {
			Box::new(Nsm)
		}
	}

	/// Defaults to [`SECRET_FILE`] if not explicitly specified
	#[must_use] pub fn secret_file(&self) -> String {
		self.secret_file.clone()
	}

	/// Defaults to [`PIVOT_FILE`] if not explicitly specified
	#[must_use] pub fn pivot_file(&self) -> String {
		self.pivot_file.clone()
	}

	/// Defaults to [`EPHEMERAL_KEY_FILE`] if not explicitly specified
	#[must_use] pub fn ephemeral_key_file(&self) -> String {
		self.ephemeral_key_file.clone()
	}
}

impl From<Vec<String>> for EnclaveOptions {
	fn from(args: Vec<String>) -> Self {
		Self::from_args(&args)
	}
}

/// Enclave server CLI.
pub struct CLI {}
impl CLI {
	/// Execute the enclave server CLI with the environment args.
	pub fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);

		let options = EnclaveOptions::from_args(&args);

		Coordinator::execute(options);
	}
}

#[cfg(test)]
mod test {
	use super::*;

	// TODO: add tests for parsing file paths - verify that file paths are valid
	// on unix.

	#[test]
	fn parse_cid_and_port() {
		let args: Vec<_> = vec!["--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::from_args(&args);

		assert_eq!(
			options,
			EnclaveOptions {
				cid: Some(6),
				port: Some(3999),
				usock: None,
				mock: false,
				pivot_file: PIVOT_FILE.to_string(),
				secret_file: SECRET_FILE.to_string(),
				ephemeral_key_file: EPHEMERAL_KEY_FILE.to_string(),
			}
		);
	}

	#[test]
	fn parse_pivot_file_and_secret_file() {
		let pivot = "pivot.file";
		let secret = "secret.file";
		let ephemeral = "ephemeral.file";
		let args: Vec<_> = vec![
			"--cid",
			"6",
			"--port",
			"3999",
			"--secret-file",
			secret,
			"--pivot-file",
			pivot,
			"--ephemeral-key-file",
			ephemeral,
		]
		.into_iter()
		.map(String::from)
		.collect();
		let options = EnclaveOptions::from_args(&args);

		assert_eq!(
			options,
			EnclaveOptions {
				cid: Some(6),
				port: Some(3999),
				usock: None,
				mock: false,
				pivot_file: pivot.to_string(),
				secret_file: secret.to_string(),
				ephemeral_key_file: ephemeral.to_string()
			}
		);
	}

	#[test]
	fn parse_usock() {
		let args: Vec<_> = vec!["--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let options = EnclaveOptions::from_args(&args);

		assert_eq!(
			options,
			EnclaveOptions {
				cid: None,
				port: None,
				usock: Some("./test.sock".to_string()),
				mock: false,
				pivot_file: PIVOT_FILE.to_string(),
				secret_file: SECRET_FILE.to_string(),
				ephemeral_key_file: EPHEMERAL_KEY_FILE.to_string()
			}
		);
	}

	#[test]
	#[should_panic]
	fn panic_on_too_many_options() {
		let options = EnclaveOptions {
			cid: Some(1),
			port: Some(3000),
			usock: Some("./test.sock".to_string()),
			mock: false,
			pivot_file: PIVOT_FILE.to_string(),
			secret_file: SECRET_FILE.to_string(),
			ephemeral_key_file: EPHEMERAL_KEY_FILE.to_string(),
		};
		let _ = options.addr();
	}

	#[test]
	#[should_panic]
	fn panic_on_not_enough_options() {
		let options = EnclaveOptions {
			cid: None,
			port: Some(3000),
			usock: None,
			mock: false,
			pivot_file: PIVOT_FILE.to_string(),
			secret_file: SECRET_FILE.to_string(),
			ephemeral_key_file: EPHEMERAL_KEY_FILE.to_string(),
		};
		let _ = options.addr();
	}

	#[test]
	#[cfg(feature = "vm")]
	fn build_vsock() {
		let options = EnclaveOptions {
			cid: Some(3),
			port: Some(3000),
			usock: None,
			mock: false,
			pivot_file: PIVOT_FILE.to_string(),
			secret_file: SECRET_FILE.to_string(),
		};
		match options.addr() {
			SocketAddress::Vsock(_) => {}
			_ => {
				panic!("Can't build SocketAddress:Vsock from options")
			}
		};
	}

	#[test]
	fn build_usock() {
		let options = EnclaveOptions {
			cid: None,
			port: None,
			usock: Some("./dev.sock".to_string()),
			mock: false,
			pivot_file: PIVOT_FILE.to_string(),
			secret_file: SECRET_FILE.to_string(),
			ephemeral_key_file: EPHEMERAL_KEY_FILE.to_string(),
		};
		match options.addr() {
			SocketAddress::Unix(_) => {}
			#[cfg(feature = "vm")]
			_ => {
				panic!("Can't build SocketAddress:Unix from options")
			}
		};
	}

	#[test]
	#[should_panic]
	fn panic_when_mistyped_cid() {
		let args: Vec<_> = vec!["--cid", "notanint", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = EnclaveOptions::from_args(&args);
	}

	#[test]
	#[should_panic]
	fn panic_when_mistyped_port() {
		let args: Vec<_> = vec!["--cid", "123", "--port", "notanint"]
			.into_iter()
			.map(String::from)
			.collect();
		let _options = EnclaveOptions::from_args(&args);
	}
}

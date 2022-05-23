// Enclave socket address
// Port/Host bindings
use std::{
	env,
	net::{IpAddr, Ipv4Addr, SocketAddr},
};

use qos_core::cli::EnclaveOptions;

use crate::HostServer;

#[derive(Clone, Debug, PartialEq)]
pub struct HostServerOptions {
	enclave: EnclaveOptions,
	host: HostOptions,
}

impl HostServerOptions {
	fn new() -> Self {
		Self { enclave: EnclaveOptions::new(), host: HostOptions::new() }
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct HostOptions {
	ip: Option<Ipv4Addr>,
	port: Option<u16>,
}

impl HostOptions {
	pub fn new() -> Self {
		Self { ip: None, port: None }
	}

	pub fn url(&self) -> String {
		if let Self { ip: Some(ip), port: Some(port) } = self.clone() {
			return format!("http://{}:{}", ip.to_string(), port);
		} else {
			panic!("Couldn't parse URL from options.")
		}
	}

	pub fn path(&self, path: &str) -> String {
		let url = self.url();
		format!("{}/{}", url, path)
	}

	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_ip(cmd, arg);
		self.parse_port(cmd, arg);
	}

	pub fn parse_ip(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--host-ip" => {
				self.ip = Some(
					arg.parse()
						.expect("Could not parse value from `--host-ip`"),
				)
			}
			_ => {}
		}
	}

	pub fn parse_port(&mut self, cmd: &str, arg: &str) {
		match cmd {
			"--host-port" => {
				self.port = arg
					.parse::<u16>()
					.map_err(|_| {
						panic!("Could not parse provided value for `--port`")
					})
					.ok();
			}
			_ => {}
		}
	}
}

/// Host server command line interface.
///
/// # Options
///
/// * `--host-port` - the port for the host server to bind (ex: `3000`).
/// * `--host-ip` - the ip address the host server will bind to (ex:
///   `127.0.0.1`)
/// * `--port` - the port the enclave socket is listening on (only for VSOCK)
/// * `--cid` - context identifier for the enclave socket (only for VSOCK)
/// * `--usock` - name of the socket file (ex: `dev.sock`) (only for unix
///   sockets)
pub struct CLI;
impl CLI {
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);
		let options = parse_args(args);
		let addr = host_addr_from_options(options.host.clone());
		let enclave_addr = options.enclave.addr();
		HostServer::new(enclave_addr, addr).serve().await.unwrap();
	}
}

pub fn parse_args(args: Vec<String>) -> HostServerOptions {
	let mut options = HostServerOptions::new();

	let mut chunks = args.chunks_exact(2);
	if chunks.remainder().len() > 0 {
		panic!("Unexepected number of arguments")
	}
	while let Some([cmd, arg]) = chunks.next() {
		options.host.parse(cmd, arg);
		options.enclave.parse(cmd, arg);
	}

	options
}

pub fn host_addr_from_options(options: HostOptions) -> SocketAddr {
	if let HostOptions { ip: Some(ip), port: Some(port), .. } = options {
		SocketAddr::new(IpAddr::V4(ip), port)
	} else {
		panic!("Invalid host address options")
	}
}

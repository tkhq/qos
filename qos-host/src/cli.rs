//! Command line interface for running a QOS Host server.

use std::{
	env,
	net::{IpAddr, Ipv4Addr, SocketAddr},
};

use qos_core::cli::EnclaveOptions;

use crate::HostServer;

/// CLI options for starting a host server.
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

/// CLI options for host IP address and Port.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct HostOptions {
	ip: Option<Ipv4Addr>,
	port: Option<u16>,
}

impl HostOptions {
	/// Create a new instance of [`self`].
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Get the host server url.
	///
	/// # Panics
	///
	/// Panics if the url cannot be parsed from options
	#[must_use]
	pub fn url(&self) -> String {
		if let Self { ip: Some(ip), port: Some(port) } = *self {
			return format!("http://{}:{}", ip, port);
		}

		panic!("Couldn't parse URL from options.")
	}

	/// Get the resource path.
	#[must_use]
	pub fn path(&self, path: &str) -> String {
		let url = self.url();
		format!("{}/{}", url, path)
	}

	/// Parse host options.
	pub fn parse(&mut self, cmd: &str, arg: &str) {
		self.parse_ip(cmd, arg);
		self.parse_port(cmd, arg);
	}

	fn parse_ip(&mut self, cmd: &str, arg: &str) {
		if cmd == "--host-ip" {
			self.ip = Some(
				arg.parse().expect("Could not parse value from `--host-ip`"),
			);
		}
	}

	fn parse_port(&mut self, cmd: &str, arg: &str) {
		if cmd == "--host-port" {
			self.port = arg
				.parse::<u16>()
				.map_err(|_| {
					panic!("Could not parse provided value for `--port`")
				})
				.ok();
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
	/// Execute the command line interface.
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		args.remove(0);
		let options = parse_args(&args);
		let addr = host_addr_from_options(options.host);
		let enclave_addr = options.enclave.addr();
		HostServer::new(enclave_addr, addr).serve().await;
	}
}

fn parse_args(args: &[String]) -> HostServerOptions {
	let mut options = HostServerOptions::new();

	let mut chunks = args.chunks_exact(2);
	assert!(chunks.remainder().is_empty(), "Unexepected number of arguments");
	while let Some([cmd, arg]) = chunks.next() {
		options.host.parse(cmd, arg);
		options.enclave.parse(cmd, arg);
	}

	options
}

fn host_addr_from_options(options: HostOptions) -> SocketAddr {
	if let HostOptions { ip: Some(ip), port: Some(port), .. } = options {
		SocketAddr::new(IpAddr::V4(ip), port)
	} else {
		panic!("Invalid host address options")
	}
}

//! Command line interface for running a QOS Host server.

use std::env;

use qos_core::{
	cli::{CID, USOCK},
	io::{IOError, SocketAddress},
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
};

const CONTROL_URL: &str = "control-url";
const HOST_PORT_OVERRIDE: &str = "host-port-override";
const VSOCK_TO_HOST: &str = "vsock-to-host";
const EGRESS_HOST: &str = "egress-host";

struct HostParser;
impl GetParserForOptions for HostParser {
	fn parser() -> Parser {
		Parser::new().token(
			Token::new(
				CONTROL_URL,
				"full url of qos-host to get manifest information from, including the base path, e.g. http://localhost:3001/qos",
			)
			.takes_value(true)
			.required(false),
		)
			.token(
				Token::new(CID, "context identifier for the enclave socket (only for VSOCK)")
					.takes_value(true)
					.forbids(vec![USOCK])
			)
			.token(
				Token::new(USOCK, "name of the socket file (ex: `dev.sock`) (only for unix sockets)")
					.takes_value(true)
					.forbids(vec![CID])
			)
			.token(
				Token::new(HOST_PORT_OVERRIDE, "override for manifest value of host port, mostly for localhost testing")
					.takes_value(true)
			)
			.token(
				Token::new(VSOCK_TO_HOST, "override for manifest value of host port, mostly for localhost testing")
					.takes_value(true)
					.required(false)
					.forbids(vec![USOCK])
			)
			.token(
				Token::new(EGRESS_HOST, "run in enclave egress in host mode")
					.takes_value(false)
			)
	}
}

/// CLI options for starting a host server.
#[derive(Clone, Debug, PartialEq)]
pub struct HostOpts {
	parsed: Parser,
}

impl HostOpts {
	#[must_use]
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<HostParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// The qos-host URL
	/// # Panics
	/// Panics if no control-url is provided
	#[must_use]
	pub fn control_url(&self) -> String {
		self.parsed
			.single(CONTROL_URL)
			.expect("no control-url provided")
			.clone()
	}

	/// Wether to run in egress host mode (e.g. in qos bridge on the host)
	#[must_use]
	pub fn egress_host(&self) -> bool {
		self.parsed.flag(EGRESS_HOST).unwrap_or(false)
	}

	/// overrides the host portion of the bridge with given port, ignoring the manifest value
	/// NOTE: used for localhost testing, since we can't bind the same port twice
	#[must_use]
	pub fn host_port_override(&self) -> Option<u16> {
		self.parsed.single(HOST_PORT_OVERRIDE).and_then(|v| v.parse().ok())
	}

	/// Create a new `StreamPool` using the list of `SocketAddress` for the qos host.
	#[cfg_attr(target_os = "macos", allow(clippy::unnecessary_wraps))]
	pub(crate) fn enclave_socket(&self) -> Result<SocketAddress, IOError> {
		match (self.parsed.single(CID), self.parsed.single(USOCK)) {
			#[cfg(not(target_os = "macos"))]
			(Some(c), None) => {
				let c =
					c.parse().map_err(|_| IOError::ConnectAddressInvalid)?;
				let p = 3001; // placeholder port, overridden when we read the manifest

				Ok(SocketAddress::new_vsock(c, p, self.to_host_flag()))
			}
			(None, Some(u)) => Ok(SocketAddress::new_unix(u)),

			_ => panic!("Invalid socket opts"),
		}
	}

	#[allow(unused)]
	fn cid(&self) -> u32 {
		self.parsed
			.single(CID)
			.expect("no cid provided")
			.parse()
			.expect("unable to parse cid")
	}

	#[cfg(not(target_os = "macos"))]
	fn to_host_flag(&self) -> u8 {
		let include = self
			.parsed
			.single(VSOCK_TO_HOST)
			.as_ref()
			.map(|s| s.parse())
			.is_none_or(|r| {
				r.expect(
					"could not parse `--vsock-to-host`. Valid args are true or false",
				)
			});

		if include {
			println!("Configuring vsock with VMADDR_FLAG_TO_HOST.");
			qos_core::io::VMADDR_FLAG_TO_HOST
		} else {
			println!("Configuring vsock with VMADDR_NO_FLAGS.");
			qos_core::io::VMADDR_NO_FLAGS
		}
	}
}

/// Host server command line interface.
pub struct Cli;
impl Cli {
	/// Execute the commandline interface for `qos_bridge` egress
	/// # Panics
	/// panics on socket errors on wrong cli input
	pub fn execute_egress() {
		let mut args: Vec<String> = env::args().collect();
		let options = HostOpts::new(&mut args);

		if options.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if options.parsed.help() {
			println!("{}", options.parsed.info());
		} else if options.egress_host() {
			#[cfg(feature = "egress")]
			qos_core::egress::host_egress(
				options.cid(),
				qos_core::egress::EGRESS_VSOCK_PORT,
				options.to_host_flag(),
			);

			#[cfg(not(feature = "egress"))]
			panic!(
				"unable to run enclave-egress without egress feature support"
			);
		} else {
			#[cfg(feature = "egress")]
			qos_core::egress::enclave_egress(
				options.cid(),
				qos_core::egress::EGRESS_VSOCK_PORT,
				options.to_host_flag(),
			);

			#[cfg(not(feature = "egress"))]
			panic!(
				"unable to run enclave-egress without egress feature support"
			);
		}
	}

	/// Execute the command line interface for `qos_bridge` ingress host
	/// # Panics
	/// If pool creation fails, cli errors or if manifest parsing fails
	pub async fn execute_ingress() {
		let mut args: Vec<String> = env::args().collect();
		let options = HostOpts::new(&mut args);

		if options.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if options.parsed.help() {
			println!("{}", options.parsed.info());
		} else {
			crate::host::BridgeServer::new(
				options
					.enclave_socket()
					.expect("failed to create enclave socket placeholder"),
				options.control_url(),
				options.host_port_override(),
			)
			.serve()
			.await;

			eprintln!("qos_bridge: bridge running, press ctrl+c to quit");
			let _ = tokio::signal::ctrl_c().await;
		}
	}
}

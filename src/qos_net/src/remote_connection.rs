//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use std::net::{AddrParseError, IpAddr, SocketAddr, TcpStream};

use hickory_resolver::{
	config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
	Resolver,
};
use rand::Rng;

use crate::error::ProtocolError;

/// Struct representing a remote connection
pub struct RemoteConnection {
	/// Unsigned integer with the connection ID. This is a random positive
	/// integer
	pub id: u32,
	/// IP address for the remote host
	pub ip: String,
	/// TCP stream object
	pub tcp_stream: TcpStream,
}

impl RemoteConnection {
	/// Create a new `RemoteConnection` from a name. This results in a DNS
	/// request + TCP connection
	pub fn new_from_name(
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<RemoteConnection, ProtocolError> {
		let ip = resolve_hostname(hostname, dns_resolvers, dns_port)?;

		// Generate a new random u32 to get an ID. We'll use it to name our
		// socket. This will be our connection ID.
		let mut rng = rand::thread_rng();
		let connection_id: u32 = rng.gen::<u32>();

		let tcp_addr = SocketAddr::new(ip, port);
		let tcp_stream = TcpStream::connect(tcp_addr)?;

		Ok(RemoteConnection {
			id: connection_id,
			ip: ip.to_string(),
			tcp_stream,
		})
	}

	/// Create a new `RemoteConnection` from an IP address. This results in a
	/// new TCP connection
	pub fn new_from_ip(
		ip: String,
		port: u16,
	) -> Result<RemoteConnection, ProtocolError> {
		// Generate a new random u32 to get an ID. We'll use it to name our
		// socket. This will be our connection ID.
		let mut rng = rand::thread_rng();
		let connection_id: u32 = rng.gen::<u32>();

		let ip_addr = ip.parse()?;
		let tcp_addr = SocketAddr::new(ip_addr, port);
		let tcp_stream = TcpStream::connect(tcp_addr)?;

		Ok(RemoteConnection { id: connection_id, ip, tcp_stream })
	}
}

// Resolve a name into an IP address
fn resolve_hostname(
	hostname: String,
	resolver_addrs: Vec<String>,
	port: u16,
) -> Result<IpAddr, ProtocolError> {
	let resolver_parsed_addrs = resolver_addrs
		.iter()
		.map(|resolver_address| {
			let ip_addr: Result<IpAddr, AddrParseError> =
				resolver_address.parse();
			ip_addr
		})
		.collect::<Result<Vec<IpAddr>, AddrParseError>>()?;

	let resolver_config = ResolverConfig::from_parts(
		None,
		vec![],
		NameServerConfigGroup::from_ips_clear(
			&resolver_parsed_addrs,
			port,
			true,
		),
	);
	let resolver = Resolver::new(resolver_config, ResolverOpts::default())?;
	let response = resolver.lookup_ip(hostname.clone())?;
	response.iter().next().ok_or_else(|| {
		ProtocolError::DNSResolutionError(format!(
			"Empty response when querying for host {hostname}"
		))
	})
}

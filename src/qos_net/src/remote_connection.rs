//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use std::{
	io::{Read, Write},
	net::{AddrParseError, IpAddr, SocketAddr, TcpStream},
};

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
	tcp_stream: TcpStream,
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
		println!(
			"done. Now persisting TcpStream with connection ID {}",
			connection_id
		);
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

impl Read for RemoteConnection {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		self.tcp_stream.read(buf)
	}
}

impl Write for RemoteConnection {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		self.tcp_stream.write(buf)
	}
	fn flush(&mut self) -> std::io::Result<()> {
		self.tcp_stream.flush()
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

#[cfg(test)]
mod test {

	use std::{
		io::{ErrorKind, Read, Write},
		sync::Arc,
	};

	use rustls::RootCertStore;

	use super::*;

	#[test]
	fn can_fetch_tls_content_with_remote_connection_struct() {
		let host = "api.turnkey.com";
		let path = "/health";

		let mut remote_connection = RemoteConnection::new_from_name(
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
		)
		.unwrap();

		let root_store =
			RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };

		let server_name: rustls::pki_types::ServerName<'_> =
			host.try_into().unwrap();
		let config: rustls::ClientConfig = rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth();
		let mut conn =
			rustls::ClientConnection::new(Arc::new(config), server_name)
				.unwrap();
		let mut tls = rustls::Stream::new(&mut conn, &mut remote_connection);

		let http_request = format!(
			"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
		);
		println!("=== making HTTP request: \n{http_request}");

		tls.write_all(http_request.as_bytes()).unwrap();
		let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

		println!("=== current ciphersuite: {:?}", ciphersuite.suite());
		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes);

		// Ignore eof errors: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
		assert!(
			read_to_end_result.is_ok()
				|| (read_to_end_result
					.is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof))
		);
		println!("{}", std::str::from_utf8(&response_bytes).unwrap());
	}
}

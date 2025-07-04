//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use crate::error::QosNetError;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{
	config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
	Resolver,
};
use std::{
	io::{Read, Write},
	net::{AddrParseError, IpAddr, SocketAddr, TcpStream},
};
use tokio::runtime::Runtime;

/// Struct representing a TCP connection held on our proxy
pub struct ProxyConnection {
	/// IP address of the remote host
	pub ip: String,
	/// TCP stream object
	tcp_stream: TcpStream,
}

impl ProxyConnection {
	/// Create a new `ProxyConnection` from a name. This results in a DNS
	/// request + TCP connection
	pub fn new_from_name(
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
		tokio_runtime_context: &Runtime,
	) -> Result<ProxyConnection, QosNetError> {
		let ip = resolve_hostname(
			hostname,
			dns_resolvers,
			dns_port,
			tokio_runtime_context,
		)?;
		let tcp_addr = SocketAddr::new(ip, port);
		let tcp_stream = TcpStream::connect(tcp_addr)?;

		Ok(ProxyConnection { ip: ip.to_string(), tcp_stream })
	}

	/// Create a new `ProxyConnection` from an IP address. This results in a
	/// new TCP connection
	pub fn new_from_ip(
		ip: String,
		port: u16,
	) -> Result<ProxyConnection, QosNetError> {
		let ip_addr = ip.parse()?;
		let tcp_addr = SocketAddr::new(ip_addr, port);
		let tcp_stream = TcpStream::connect(tcp_addr)?;

		Ok(ProxyConnection { ip, tcp_stream })
	}

	/// Closes the underlying TCP connection (`Shutdown::Both`)
	pub fn shutdown(&mut self) -> Result<(), QosNetError> {
		if let Err(e) = self.tcp_stream.shutdown(std::net::Shutdown::Both) {
			if e.kind() == std::io::ErrorKind::NotConnected {
				return Ok(());
			}
			return Err(QosNetError::from(e));
		}
		Ok(())
	}
}

impl Read for ProxyConnection {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		self.tcp_stream.read(buf)
	}
}

impl Write for ProxyConnection {
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
	tokio_runtime_context: &Runtime,
) -> Result<IpAddr, QosNetError> {
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

	let mut resolver_builder = Resolver::builder_with_config(
		resolver_config,
		TokioConnectionProvider::default(),
	);
	let mut resolver_options = ResolverOpts::default();
	// this validates DNSSEC in responses if DNSSEC is present
	// it still allows responses without DNSSEC to succeed, limiting its effectiveness
	// against on-path MITM attackers, but is preferrable to not checking response validity
	resolver_options.validate = true;

	// enable case randomization for improved security
	// see https://developers.google.com/speed/public-dns/docs/security#randomize_case
	resolver_options.case_randomization = true;

	// set our improved resolver options
	*resolver_builder.options_mut() = resolver_options;

	let resolver = resolver_builder.build();

	// needed for borrowing in async block
	let cloned_hostname = hostname.clone();
	let response = tokio_runtime_context
		.block_on(async move { resolver.lookup_ip(cloned_hostname).await })
		.map_err(QosNetError::from)?;

	response.iter().next().ok_or_else(|| {
		QosNetError::DNSResolutionError(format!(
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

	use rustls::{RootCertStore, SupportedCipherSuite};

	use super::*;

	#[test]
	fn can_fetch_tls_content_with_proxy_connection() {
		let host = "api.turnkey.com";
		let path = "/health";

		// manually set up a Tokio runtime
		let runtime = Runtime::new().expect("Failed to create tokio runtime");

		let mut remote_connection = ProxyConnection::new_from_name(
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
			&runtime,
		)
		.unwrap();

		drop(runtime);

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

		tls.write_all(http_request.as_bytes()).unwrap();
		let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
		assert!(matches!(ciphersuite, SupportedCipherSuite::Tls13(_)));

		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes);

		// Ignore eof errors: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
		assert!(
			read_to_end_result.is_ok()
				|| (read_to_end_result
					.is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof))
		);

		let response_text = std::str::from_utf8(&response_bytes).unwrap();
		assert!(response_text.contains("HTTP/1.1 200 OK"));
		assert!(response_text.contains("currentTime"));
	}
}

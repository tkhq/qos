//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use std::{
	net::{AddrParseError, IpAddr, SocketAddr},
	time::Duration,
};

use hickory_resolver::{
	config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
	name_server::TokioConnectionProvider,
	TokioResolver,
};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
};

use crate::error::QosNetError;

/// Struct representing a TCP connection held on our proxy
pub struct ProxyConnection {
	/// IP address of the remote host
	pub ip: String,
	/// TCP stream object
	pub(crate) tcp_stream: TcpStream,
}

impl ProxyConnection {
	/// Create a new `ProxyConnection` from a name. This results in a DNS
	/// request + TCP connection
	pub async fn new_from_name(
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<ProxyConnection, QosNetError> {
		let ip = resolve_hostname(hostname, dns_resolvers, dns_port).await?;

		let tcp_addr = SocketAddr::new(ip, port);
		let tcp_stream = TcpStream::connect(tcp_addr).await?;
		Ok(ProxyConnection { ip: ip.to_string(), tcp_stream })
	}

	/// Create a new `ProxyConnection` from an IP address. This results in a
	/// new TCP connection
	pub async fn new_from_ip(
		ip: String,
		port: u16,
	) -> Result<ProxyConnection, QosNetError> {
		let ip_addr = ip.parse()?;
		let tcp_addr = SocketAddr::new(ip_addr, port);
		let tcp_stream = TcpStream::connect(tcp_addr).await?;

		Ok(ProxyConnection { ip, tcp_stream })
	}
}

impl ProxyConnection {
	pub async fn read(
		&mut self,
		buf: &mut [u8],
	) -> Result<usize, std::io::Error> {
		self.tcp_stream.read(buf).await
	}

	pub async fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		self.tcp_stream.write(buf).await
	}

	pub async fn flush(&mut self) -> std::io::Result<()> {
		self.tcp_stream.flush().await
	}
}

// Resolve a name into an IP address
pub async fn resolve_hostname(
	hostname: String,
	resolver_addrs: Vec<String>,
	port: u16,
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

	// ensure the resolve call will be < 5s for our socket timeout (so we return a meaningful error and don't hog the socket)
	// this means attempts * timeout < 5s
	let mut resolver_opts = ResolverOpts::default();
	resolver_opts.timeout = Duration::from_secs(1);
	resolver_opts.attempts = 1;

	let resolver = TokioResolver::builder_with_config(
		resolver_config,
		TokioConnectionProvider::default(),
	)
	.with_options(resolver_opts)
	.build();

	let response = resolver
		.lookup_ip(hostname.clone())
		.await
		.map_err(QosNetError::from)?;
	response.iter().next().ok_or_else(|| {
		QosNetError::DNSResolutionError(format!(
			"Empty response when querying for host {hostname}"
		))
	})
}

#[cfg(test)]
mod test {

	use std::{io::ErrorKind, sync::Arc};

	use rustls::RootCertStore;
	use tokio_rustls::TlsConnector;

	use super::*;

	#[tokio::test]
	async fn can_fetch_tls_content_with_proxy_connection() {
		let host = "api.turnkey.com";
		let path = "/health";

		let mut remote_connection = ProxyConnection::new_from_name(
			host.to_string(),
			443,
			vec!["8.8.8.8".to_string()],
			53,
		)
		.await
		.unwrap();

		let root_store =
			RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };

		let server_name: rustls::pki_types::ServerName<'_> =
			host.try_into().unwrap();
		let config: rustls::ClientConfig = rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth();
		let conn = TlsConnector::from(Arc::new(config));
		let stream = &mut remote_connection.tcp_stream;
		let mut tls = conn.connect(server_name, stream).await.unwrap();

		let http_request = format!(
			"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
		);

		tls.write_all(http_request.as_bytes()).await.unwrap();

		let mut response_bytes = Vec::new();
		let read_to_end_result = tls.read_to_end(&mut response_bytes).await;

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

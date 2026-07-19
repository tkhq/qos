//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use std::{
	collections::HashMap,
	net::{AddrParseError, IpAddr, SocketAddr},
	sync::{Arc, Mutex, OnceLock},
	time::Duration,
};

use hickory_resolver::{
	TokioResolver,
	config::{
		ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig,
		ResolverOpts,
	},
	net::runtime::TokioRuntimeProvider,
};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
};

use crate::error::QosNetError;

type ResolverKey = (Vec<IpAddr>, u16);

static RESOLVERS: OnceLock<Mutex<HashMap<ResolverKey, Arc<TokioResolver>>>> =
	OnceLock::new();

/// Struct representing a TCP connection held on our proxy
pub struct ProxyConnection {
	/// IP address of the remote host
	pub ip: String,
	/// TCP stream object
	pub(crate) tcp_stream: TcpStream,
}

impl ProxyConnection {
	/// Create a new `ProxyConnection` from a name. This results in a DNS
	/// request + TCP connection.
	///
	/// # Errors
	///
	/// Returns [`QosNetError`] if DNS resolution or TCP connection fails.
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
	/// new TCP connection.
	///
	/// # Errors
	///
	/// Returns [`QosNetError`] if the IP cannot be parsed or the TCP
	/// connection fails.
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
	/// Read data from the TCP stream into the buffer.
	///
	/// # Errors
	///
	/// Returns [`std::io::Error`] if the read fails.
	pub async fn read(
		&mut self,
		buf: &mut [u8],
	) -> Result<usize, std::io::Error> {
		self.tcp_stream.read(buf).await
	}

	/// Write data to the TCP stream.
	///
	/// # Errors
	///
	/// Returns [`std::io::Error`] if the write fails.
	pub async fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		self.tcp_stream.write(buf).await
	}

	/// Flush any buffered data to the TCP stream.
	///
	/// # Errors
	///
	/// Returns [`std::io::Error`] if the flush fails.
	pub async fn flush(&mut self) -> std::io::Result<()> {
		self.tcp_stream.flush().await
	}
}

/// Resolve a hostname into an IP address using the specified DNS resolvers.
///
/// # Errors
///
/// Returns [`QosNetError`] if the resolver addresses cannot be parsed or
/// DNS resolution fails.
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

	let resolver = cached_resolver(resolver_parsed_addrs, port)?;
	let response =
		resolver.lookup_ip(&hostname).await.map_err(QosNetError::from)?;
	response.iter().next().ok_or_else(|| {
		QosNetError::DNSResolutionError(format!(
			"Empty response when querying for host {hostname}"
		))
	})
}

fn resolver_cache() -> &'static Mutex<HashMap<ResolverKey, Arc<TokioResolver>>>
{
	RESOLVERS.get_or_init(Default::default)
}

fn cached_resolver(
	resolver_parsed_addrs: Vec<IpAddr>,
	port: u16,
) -> Result<Arc<TokioResolver>, QosNetError> {
	let key = (resolver_parsed_addrs, port);
	if let Some(resolver) = resolver_cache()
		.lock()
		.map_err(|_| {
			QosNetError::DNSResolutionError(
				"Resolver cache lock poisoned".to_string(),
			)
		})?
		.get(&key)
		.cloned()
	{
		return Ok(resolver);
	}

	let resolver = Arc::new(build_resolver(&key.0, key.1)?);
	let mut resolvers = resolver_cache().lock().map_err(|_| {
		QosNetError::DNSResolutionError(
			"Resolver cache lock poisoned".to_string(),
		)
	})?;
	Ok(resolvers.entry(key).or_insert(resolver).clone())
}

fn build_resolver(
	resolver_parsed_addrs: &[IpAddr],
	port: u16,
) -> Result<TokioResolver, QosNetError> {
	let name_servers = resolver_parsed_addrs
		.iter()
		.copied()
		.map(|ip| {
			let mut udp = ConnectionConfig::udp();
			udp.port = port;
			let mut tcp = ConnectionConfig::tcp();
			tcp.port = port;

			NameServerConfig::new(ip, true, vec![udp, tcp])
		})
		.collect();

	let resolver_config =
		ResolverConfig::from_parts(None, vec![], name_servers);

	let mut resolver_opts = ResolverOpts::default();
	// Keep attempts * timeout below the proxy socket budget.
	resolver_opts.timeout = Duration::from_secs(1);
	resolver_opts.attempts = 1;
	// Clamp long-lived records so cached answers do not stay stale too long.
	resolver_opts.positive_max_ttl = Some(Duration::from_secs(300));
	// Currently we only check the first address and downstream code assumes its Ipv4;
	// this setting ensures that the resolver always resolves an Ipv4 address first.
	resolver_opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;

	TokioResolver::builder_with_config(
		resolver_config,
		TokioRuntimeProvider::default(),
	)
	.with_options(resolver_opts)
	.build()
	.map_err(QosNetError::from)
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
		let config: rustls::ClientConfig =
			rustls::ClientConfig::builder_with_provider(Arc::new(
				rustls::crypto::aws_lc_rs::default_provider(),
			))
			.with_safe_default_protocol_versions()
			.unwrap()
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

	#[tokio::test]
	async fn invalid_dns_resolver_address_returns_parse_error() {
		let err = resolve_hostname(
			"api.turnkey.com".to_string(),
			vec!["not-an-ip-address".to_string()],
			53,
		)
		.await
		.unwrap_err();

		assert!(matches!(err, QosNetError::ParseError(_)));
	}

	#[test]
	fn cached_resolver_reuses_resolver_for_same_dns_config() {
		let resolver_addrs = vec!["127.0.0.1".parse().unwrap()];
		let first = cached_resolver(resolver_addrs.clone(), 53).unwrap();
		let second = cached_resolver(resolver_addrs.clone(), 53).unwrap();
		let different_port = cached_resolver(resolver_addrs, 54).unwrap();

		assert!(Arc::ptr_eq(&first, &second));
		assert!(!Arc::ptr_eq(&first, &different_port));

		let opts = first.options();
		assert_eq!(opts.timeout, Duration::from_secs(1));
		assert_eq!(opts.attempts, 1);
		assert_eq!(opts.positive_max_ttl, Some(Duration::from_secs(300)));
		assert_eq!(opts.ip_strategy, LookupIpStrategy::Ipv4thenIpv6);
	}
}

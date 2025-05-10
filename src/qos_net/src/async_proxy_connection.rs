//! Contains logic for remote connection establishment: DNS resolution and TCP
//! connection.
use std::net::{AddrParseError, IpAddr, SocketAddr};

use hickory_resolver::{
	config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
	TokioAsyncResolver,
};
use rand::Rng;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
};

use crate::error::QosNetError;

/// Struct representing a TCP connection held on our proxy
pub struct AsyncProxyConnection {
	/// Unsigned integer with the connection ID (random positive int)
	pub id: u32,
	/// IP address of the remote host
	pub ip: String,
	/// TCP stream object
	tcp_stream: TcpStream,
}

impl AsyncProxyConnection {
	/// Create a new `ProxyConnection` from a name. This results in a DNS
	/// request + TCP connection
	pub async fn new_from_name(
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<AsyncProxyConnection, QosNetError> {
		let ip = resolve_hostname(hostname, dns_resolvers, dns_port).await?;

		// Generate a new random u32 to get an ID. We'll use it to name our
		// socket. This will be our connection ID.
		let mut rng = rand::thread_rng();
		let connection_id: u32 = rng.gen::<u32>();

		let tcp_addr = SocketAddr::new(ip, port);
		let tcp_stream = TcpStream::connect(tcp_addr).await?;
		Ok(AsyncProxyConnection {
			id: connection_id,
			ip: ip.to_string(),
			tcp_stream,
		})
	}

	/// Create a new `ProxyConnection` from an IP address. This results in a
	/// new TCP connection
	pub async fn new_from_ip(
		ip: String,
		port: u16,
	) -> Result<AsyncProxyConnection, QosNetError> {
		// Generate a new random u32 to get an ID. We'll use it to name our
		// socket. This will be our connection ID.
		let mut rng = rand::thread_rng();
		let connection_id: u32 = rng.gen::<u32>();

		let ip_addr = ip.parse()?;
		let tcp_addr = SocketAddr::new(ip_addr, port);
		let tcp_stream = TcpStream::connect(tcp_addr).await?;

		Ok(AsyncProxyConnection { id: connection_id, ip, tcp_stream })
	}
}

impl AsyncProxyConnection {
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
async fn resolve_hostname(
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
	let resolver =
		TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
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

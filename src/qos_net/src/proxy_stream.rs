//! Contains an abstraction to implement the standard library's Read/Write
//! traits with `ProxyMsg`s.
use std::pin::Pin;

use borsh::BorshDeserialize;
use qos_core::io::{PoolGuard, Stream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{error::QosNetError, proxy_msg::ProxyMsg};

/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
/// and plugged into the tokio-rustls via the AsyncWrite and AsyncRead traits
pub struct ProxyStream<'pool> {
	/// Stream we hold for this connection
	stream: PoolGuard<'pool>,
	/// The remote host this connection points to
	pub remote_hostname: Option<String>,
	/// The remote IP this connection points to
	pub remote_ip: String,
}

impl<'pool> ProxyStream<'pool> {
	/// Create a new `ProxyStream` by targeting a hostname
	///
	/// # Arguments
	///
	/// * `stream` - the `Stream` picked from a `StreamPool` behind a `MutexGuard` (e.g. from `pool.get().await`)
	/// * `hostname` - the hostname to connect to (the remote qos_net proxy will
	///   resolve DNS)
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	/// * `dns_resolvers` - array of resolvers to use to resolve `hostname`
	/// * `dns_port` - DNS port to use while resolving DNS (typically: 53 or
	///   853)
	pub async fn connect_by_name(
		mut stream: PoolGuard<'pool>,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByNameRequest {
			hostname: hostname.clone(),
			port,
			dns_resolvers,
			dns_port,
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { remote_ip } => Ok(Self {
					stream,
					remote_ip,
					remote_hostname: Some(hostname),
				}),
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Create a new ProxyStream by targeting an IP address directly.
	///
	/// # Arguments
	/// * `stream` - the `Stream` picked from a `StreamPool` behind a `MutexGuard` (e.g. from `pool.get().await`)
	/// * `ip` - the IP the remote qos_net proxy should connect to
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	pub async fn connect_by_ip(
		mut stream: PoolGuard<'pool>,
		ip: String,
		port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByIpRequest { ip, port })
			.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { remote_ip } => {
					Ok(Self { stream, remote_ip, remote_hostname: None })
				}
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Refresh this connection after a request has been completed. This MUST be called
	/// after each successful rustls session.
	pub async fn refresh(&mut self) -> Result<(), QosNetError> {
		self.stream.reconnect().await?;

		Ok(())
	}
}

impl AsyncRead for ProxyStream<'_> {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_read(cx, buf)
	}
}

impl AsyncWrite for ProxyStream<'_> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_write(cx, buf)
	}

	fn poll_flush(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_flush(cx)
	}

	fn poll_shutdown(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		Pin::<&mut Stream>::new(&mut self.stream).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod test {

	use std::{
		io::{ErrorKind, Read},
		sync::Arc,
	};

	use chunked_transfer::Decoder;
	use httparse::Response;
	use rustls::RootCertStore;
	use serde_json::Value;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio_rustls::TlsConnector;

	use crate::proxy_connection::ProxyConnection;

	#[tokio::test]
	async fn can_fetch_and_parse_chunked_json_over_tls_with_local_stream() {
		let host = "www.googleapis.com";
		let path = "/oauth2/v3/certs";

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

		match read_to_end_result {
			Ok(read_size) => assert!(read_size > 0),

			Err(e) => {
				// Only EOF errors are expected. This means the connection was
				// closed by the remote server https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
				assert_eq!(e.kind(), ErrorKind::UnexpectedEof)
			}
		}

		// Parse headers with httparse
		let mut headers = [httparse::EMPTY_HEADER; 16];
		let mut response = Response::new(&mut headers);
		let res = httparse::ParserConfig::default()
			.parse_response(&mut response, &response_bytes);
		assert!(matches!(res, Ok(httparse::Status::Complete(..))));
		assert_eq!(response.code, Some(200));
		let header_byte_size = res.unwrap().unwrap();

		// Assert that the response is chunk-encoded
		let transfer_encoding_header =
			response.headers.iter().find(|h| h.name == "Transfer-Encoding");
		assert!(transfer_encoding_header.is_some());
		assert_eq!(
			transfer_encoding_header.unwrap().value,
			"chunked".as_bytes()
		);

		// Decode the chunked content
		let mut decoded = String::new();
		let mut decoder = Decoder::new(&response_bytes[header_byte_size..]);
		let res = decoder.read_to_string(&mut decoded);
		assert!(res.is_ok());

		// Parse the JSON response body and make sure there is a proper "keys"
		// array in it
		let json_content: Value = serde_json::from_str(&decoded).unwrap();
		assert!(json_content["keys"].is_array());
	}
}

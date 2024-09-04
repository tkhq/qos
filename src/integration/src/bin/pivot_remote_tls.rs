use core::panic;
use std::{
	io::{ErrorKind, Read, Write},
	sync::Arc,
};

use borsh::BorshDeserialize;
use integration::PivotRemoteTlsMsg;
use qos_core::{
	io::{SocketAddress, TimeVal},
	server::{RequestProcessor, SocketServer},
};
use qos_net::proxy_stream::ProxyStream;
use rustls::RootCertStore;

struct Processor {
	net_proxy: SocketAddress,
}

impl Processor {
	fn new(proxy_address: String) -> Self {
		Processor { net_proxy: SocketAddress::new_unix(&proxy_address) }
	}
}

impl RequestProcessor for Processor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		let msg = PivotRemoteTlsMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken!");

		match msg {
			PivotRemoteTlsMsg::RemoteTlsRequest { host, path } => {
				let timeout = TimeVal::new(1, 0);
				let mut stream = ProxyStream::connect_by_name(
					&self.net_proxy,
					timeout,
					host.clone(),
					443,
					vec!["8.8.8.8".to_string()],
					53,
				)
				.unwrap();

				let root_store = RootCertStore {
					roots: webpki_roots::TLS_SERVER_ROOTS.into(),
				};

				let server_name: rustls::pki_types::ServerName<'_> =
					host.clone().try_into().unwrap();
				let config: rustls::ClientConfig =
					rustls::ClientConfig::builder()
						.with_root_certificates(root_store)
						.with_no_client_auth();
				let mut conn = rustls::ClientConnection::new(
					Arc::new(config),
					server_name,
				)
				.unwrap();
				let mut tls = rustls::Stream::new(&mut conn, &mut stream);

				let http_request = format!(
					"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
				);

				tls.write_all(http_request.as_bytes()).unwrap();

				let mut response_bytes = Vec::new();
				let read_to_end_result = tls.read_to_end(&mut response_bytes);
				match read_to_end_result {
					Ok(read_size) => {
						assert!(read_size > 0);
						// Close the connection
						let closed = stream.close();
						closed.unwrap();
					}
					Err(e) => {
						// Only EOF errors are expected. This means the
						// connection was closed by the remote server https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
						if e.kind() != ErrorKind::UnexpectedEof {
							panic!(
								"unexpected error trying to read_to_end: {e:?}"
							);
						}
					}
				}

				let fetched_content =
					std::str::from_utf8(&response_bytes).unwrap();
				borsh::to_vec(&PivotRemoteTlsMsg::RemoteTlsResponse(format!(
					"Content fetched successfully: {fetched_content}"
				)))
				.expect("RemoteTlsResponse is valid borsh")
			}
			PivotRemoteTlsMsg::RemoteTlsResponse(_) => {
				panic!("Unexpected RemoteTlsResponse - test is broken")
			}
		}
	}
}

fn main() {
	// Parse args:
	// - first argument is the socket to bind to (normal server server)
	// - second argument is the socket to use for remote proxying
	let args: Vec<String> = std::env::args().collect();

	let socket_path: &String = &args[1];
	let proxy_path: &String = &args[2];

	SocketServer::listen(
		SocketAddress::new_unix(socket_path),
		Processor::new(proxy_path.to_string()),
	)
	.unwrap();
}

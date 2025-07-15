use core::panic;
use std::{io::ErrorKind, sync::Arc};

use borsh::BorshDeserialize;
use integration::PivotRemoteTlsMsg;
use qos_core::{
	async_server::{AsyncRequestProcessor, AsyncSocketServer},
	io::{AsyncStreamPool, SharedAsyncStreamPool, SocketAddress},
};
use qos_net::async_proxy_stream::AsyncProxyStream;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[derive(Clone)]
struct Processor {
	net_pool: SharedAsyncStreamPool,
}

impl Processor {
	fn new(net_pool: SharedAsyncStreamPool) -> Self {
		Processor { net_pool }
	}
}

impl AsyncRequestProcessor for Processor {
	async fn process(&self, request: Vec<u8>) -> Vec<u8> {
		let msg = PivotRemoteTlsMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken!");

		match msg {
			PivotRemoteTlsMsg::RemoteTlsRequest { host, path } => {
				let pool = self.net_pool.read().await;
				let mut stream = AsyncProxyStream::connect_by_name(
					pool.get().await,
					host.clone(),
					443,
					vec!["8.8.8.8".to_string()],
					53,
				)
				.await
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
				let conn = TlsConnector::from(Arc::new(config));
				let mut tls = conn
					.connect(server_name, &mut stream)
					.await
					.expect("tls unable to establish connection");

				let http_request =
					format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

				tls.write_all(http_request.as_bytes()).await.unwrap();

				let mut response_bytes = Vec::new();
				let read_to_end_result =
					tls.read_to_end(&mut response_bytes).await;
				match read_to_end_result {
					Ok(read_size) => {
						assert!(read_size > 0);
						// Refresh the connection for additional calls
						stream.refresh().await.unwrap();
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

#[tokio::main]
async fn main() {
	// Parse args:
	// - first argument is the socket to bind to (normal server server)
	// - second argument is the socket to use for remote proxying
	let args: Vec<String> = std::env::args().collect();

	let socket_path: &String = &args[1];
	let proxy_path: &String = &args[2];

	let enclave_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(socket_path), 1)
			.expect("unable to create async stream pool");

	let proxy_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(proxy_path), 1)
			.expect("unable to create async stream pool")
			.shared();

	let server = AsyncSocketServer::listen_all(
		enclave_pool,
		&Processor::new(proxy_pool),
	)
	.unwrap();

	match tokio::signal::ctrl_c().await {
		Ok(_) => {
			eprintln!("pivot handling ctrl+c the tokio way");
			server.terminate();
		}
		Err(err) => panic!("{err}"),
	}
}

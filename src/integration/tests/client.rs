use std::time::Duration;

use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	server::SocketServerError,
	server::{RequestProcessor, SocketServer},
};

#[derive(Clone)]
struct EchoProcessor;

impl RequestProcessor for EchoProcessor {
	async fn process(&self, request: &[u8]) -> Vec<u8> {
		request.to_vec()
	}
}

async fn run_echo_server(
	socket_path: &str,
) -> Result<SocketServer, SocketServerError> {
	let pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("unable to create async pool");
	let server = SocketServer::listen_all(pool, EchoProcessor, 128)?;

	Ok(server)
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_connect_works() {
	let socket_path = "/tmp/async_client_test_direct_connect_works.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = Duration::from_millis(500);
	let pool = StreamPool::new(socket, 1)
		.expect("unable to create async pool")
		.shared();

	let client = SocketClient::new(pool, timeout);

	let _server = run_echo_server(socket_path).await.unwrap();

	let r = client.call(&[0]).await;
	assert!(r.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn times_out_properly() {
	let socket_path = "/tmp/async_client_test_times_out_properly.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = Duration::from_millis(500);
	let pool = StreamPool::new(socket, 1)
		.expect("unable to create async pool")
		.shared();
	let client = SocketClient::new(pool, timeout);

	let r = client.call(&[0]).await;
	assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_connect_works() {
	let socket_path = "/tmp/async_client_test_repeat_connect_works.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = Duration::from_millis(500);
	let pool = StreamPool::new(socket, 1)
		.expect("unable to create async pool")
		.shared();
	let client = SocketClient::new(pool, timeout);

	// server not running yet, expect a connection error
	let r = client.call(&[0]).await;
	assert!(r.is_err());

	// start server
	let _server = run_echo_server(socket_path).await.unwrap();

	// server running, expect success
	let r = client.call(&[0]).await;
	assert!(r.is_ok());
}

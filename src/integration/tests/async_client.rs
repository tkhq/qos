use qos_core::{
	async_client::AsyncClient,
	async_server::{AsyncRequestProcessor, AsyncSocketServer},
	io::{AsyncStreamPool, SocketAddress, TimeVal, TimeValLike},
	server::SocketServerError,
};

#[derive(Clone)]
struct EchoProcessor;

impl AsyncRequestProcessor for EchoProcessor {
	async fn process(&self, request: Vec<u8>) -> Vec<u8> {
		request
	}
}

async fn run_echo_server(
	socket_path: &str,
) -> Result<AsyncSocketServer, SocketServerError> {
	let timeout = TimeVal::milliseconds(50);
	let pool =
		AsyncStreamPool::new(SocketAddress::new_unix(socket_path), timeout, 1)
			.expect("unable to create async pool");
	let server = AsyncSocketServer::listen_all(pool, &EchoProcessor)?;

	Ok(server)
}

#[tokio::test]
async fn direct_connect_works() {
	let socket_path = "/tmp/async_client_test_direct_connect_works.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(socket, timeout, 1)
		.expect("unable to create async pool")
		.shared();

	let client = AsyncClient::new(pool);

	let server = run_echo_server(socket_path).await.unwrap();

	let r = client.call(&[0]).await;
	assert!(r.is_ok());

	server.terminate();
}

#[tokio::test]
async fn times_out_properly() {
	let socket_path = "/tmp/async_client_test_times_out_properly.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(socket, timeout, 1)
		.expect("unable to create async pool")
		.shared();
	let client = AsyncClient::new(pool);

	let r = client.call(&[0]).await;
	assert!(r.is_err());
}

#[tokio::test]
async fn repeat_connect_works() {
	let socket_path = "/tmp/async_client_test_repeat_connect_works.sock";
	let socket = SocketAddress::new_unix(socket_path);
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(socket, timeout, 1)
		.expect("unable to create async pool")
		.shared();
	let client = AsyncClient::new(pool);

	// server not running yet, expect a connection error
	let r = client.call(&[0]).await;
	assert!(r.is_err());

	// start server
	let server = run_echo_server(socket_path).await.unwrap();

	// server running, expect success
	let r = client.call(&[0]).await;
	assert!(r.is_ok());

	// cleanup
	server.terminate();
}

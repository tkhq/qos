use qos_core::{
	async_client::AsyncClient,
	async_server::{AsyncRequestProcessor, AsyncSocketServer},
	io::{AsyncStreamPool, SocketAddress, TimeVal, TimeValLike},
	server::SocketServerError,
};
use tokio::task::JoinHandle;

#[derive(Clone)]
struct EchoProcessor;

impl AsyncRequestProcessor for EchoProcessor {
	async fn process(&self, request: Vec<u8>) -> Vec<u8> {
		request
	}
}

async fn run_echo_server(
	socket_path: &str,
) -> Result<Vec<JoinHandle<Result<(), SocketServerError>>>, SocketServerError> {
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(
		std::iter::once(SocketAddress::new_unix(socket_path)),
		timeout,
	);
	let tasks = AsyncSocketServer::listen_all(pool, &EchoProcessor)?;

	Ok(tasks)
}

#[tokio::test]
async fn direct_connect_works() {
	let socket_path = "/tmp/async_client_test_direct_connect_works.sock";
	let sockets = std::iter::once(SocketAddress::new_unix(socket_path));
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(sockets, timeout).shared();

	let client = AsyncClient::new(pool);

	let server_tasks = run_echo_server(socket_path).await.unwrap();

	let r = client.call(&[0]).await;
	assert!(r.is_ok());

	for task in server_tasks {
		task.abort();
	}
}

#[tokio::test]
async fn times_out_properly() {
	let socket_path = "/tmp/async_client_test_times_out_properly.sock";
	let sockets = std::iter::once(SocketAddress::new_unix(socket_path));
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(sockets, timeout).shared();
	let client = AsyncClient::new(pool);

	let r = client.call(&[0]).await;
	assert!(r.is_err());
}

#[tokio::test]
async fn repeat_connect_works() {
	let socket_path = "/tmp/async_client_test_repeat_connect_works.sock";
	let sockets = std::iter::once(SocketAddress::new_unix(socket_path));
	let timeout = TimeVal::milliseconds(50);
	let pool = AsyncStreamPool::new(sockets, timeout).shared();
	let client = AsyncClient::new(pool);

	// server not running yet, expect a connection error
	let r = client.call(&[0]).await;
	assert!(r.is_err());

	// start server
	let server_tasks = run_echo_server(socket_path).await.unwrap();

	// server running, expect success
	let r = client.call(&[0]).await;
	assert!(r.is_ok());

	for task in server_tasks {
		task.abort();
	}
}

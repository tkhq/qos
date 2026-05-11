use std::{
	net::{Ipv4Addr, SocketAddrV4},
	process::Command,
	time::Duration,
};

use integration::{wait_for_tcp_sock, PIVOT_TCP_PATH};
use qos_core::io::{HostBridge, SocketAddress, Stream, StreamPool};
use qos_test_primitives::{find_free_port, ChildWrapper};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
async fn vsock_to_tcp_bridge_works() {
	const APP_USOCK: &str = "/tmp/vsock_to_tcp_bridge_works.usock";
	let port = find_free_port().unwrap();
	let pool = StreamPool::single(SocketAddress::new_unix(APP_USOCK)).unwrap();
	let host_addr: std::net::SocketAddr =
		SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into();

	let mut pivot: ChildWrapper = Command::new(PIVOT_TCP_PATH)
		.arg(format!("{port}"))
		.spawn()
		.unwrap()
		.into();

	// Wait for pivot to bind before probing the bridge. `wait_for_usock`
	// opens a connection, and the bridge immediately forwards accepted
	// streams to the pivot TCP address.
	wait_for_tcp_sock(&format!("127.0.0.1:{port}")).await;

	HostBridge::new(pool, host_addr).vsock_to_tcp();
	wait_for_socket_path(APP_USOCK).await;
	let mut stream = Stream::new(&SocketAddress::new_unix(APP_USOCK));
	let mut stream2 = Stream::new(&SocketAddress::new_unix(APP_USOCK));
	stream.connect().await.unwrap();
	stream2.connect().await.unwrap();

	// send b"hello" and expect it back
	assert_eq!(5, stream.write(b"hello").await.unwrap());

	// Read hello before sending the pivot's exit message. The pivot exits the
	// process after echoing "done", which can otherwise race with this stream.
	let mut buf = [0u8; 5];
	assert_eq!(5, stream.read(&mut buf).await.unwrap());

	// send b"done" and expect it back with pivot exiting
	assert_eq!(4, stream2.write(b"done").await.unwrap());

	// Read done
	let mut buf = [0u8; 4];
	assert_eq!(4, stream2.read(&mut buf).await.unwrap());

	assert!(pivot.wait().unwrap().success());
}

async fn wait_for_socket_path(path: &str) {
	for _ in 0..50 {
		if std::fs::exists(path).unwrap() {
			return;
		}

		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	panic!("unable to find usock at path: {path}");
}

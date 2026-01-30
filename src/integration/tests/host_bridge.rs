use std::{
	net::{Ipv4Addr, SocketAddrV4},
	process::Command,
};

use integration::{wait_for_usock, PIVOT_TCP_PATH};
use qos_core::io::{HostBridge, SocketAddress, Stream, StreamPool};
use qos_test_primitives::{find_free_port, ChildWrapper};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn vsock_to_tcp_bridge_works() {
	const APP_USOCK: &str = "/tmp/vsock_to_tcp_bridge_works.usock";
	let port = find_free_port().unwrap();
	let pool = StreamPool::single(SocketAddress::new_unix(APP_USOCK)).unwrap();
	let host_addr: std::net::SocketAddr =
		SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into();

	HostBridge::new(pool, host_addr).vsock_to_tcp().await;
	let mut pivot: ChildWrapper = Command::new(PIVOT_TCP_PATH)
		.arg(format!("{port}"))
		.spawn()
		.unwrap()
		.into();

	wait_for_usock(APP_USOCK).await;

	let mut stream = Stream::new(&SocketAddress::new_unix(APP_USOCK));
	let mut stream2 = Stream::new(&SocketAddress::new_unix(APP_USOCK));
	stream.connect().await.unwrap();
	stream2.connect().await.unwrap();

	// send b"hello" and expect it back
	assert_eq!(5, stream.write(b"hello").await.unwrap());
	// send b"done" and expect it back with pivot exiting
	assert_eq!(4, stream2.write(b"done").await.unwrap());

	let mut buf = [0u8; 4];
	assert_eq!(4, stream2.read(&mut buf).await.unwrap());

	let mut buf = [0u8; 5];
	assert_eq!(5, stream.read(&mut buf).await.unwrap());

	assert!(pivot.0.wait().unwrap().success());
}

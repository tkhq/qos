use std::{
	fs,
	net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use integration::{
	wait_for_tcp_sock, wait_for_usock, PIVOT_ABORT_PATH, PIVOT_OK_PATH,
	PIVOT_PANIC_PATH, PIVOT_TCP_PATH,
};
use qos_core::{
	handles::Handles,
	io::{HostBridge, SocketAddress, StreamPool},
	protocol::services::boot::{BridgeConfig, ManifestEnvelope},
	reaper::{Reaper, REAPER_EXIT_DELAY},
};
use qos_nsm::mock::MockNsm;
use qos_test_primitives::PathWrapper;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpStream,
};

#[tokio::test]
async fn reaper_works() {
	let secret_path: PathWrapper = "/tmp/reaper_works.secret".into();
	let usock: PathWrapper = "/tmp/reaper_works.sock".into();
	let manifest_path: PathWrapper = "/tmp/reaper_works.manifest".into();
	let msg = "durp-a-durp";

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_OK_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	let mut manifest_envelope = ManifestEnvelope::default();
	manifest_envelope.manifest.pivot.args =
		vec!["--msg".to_string(), msg.to_string()];

	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	assert!(handles.pivot_exists());

	let enclave_socket = SocketAddress::new_unix(&usock);

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(&handles, Box::new(MockNsm), enclave_socket, None)
			.await;
	});

	// Give the enclave server time to bind to the socket
	wait_for_usock(&usock).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Make the sure the reaper executed successfully.
	reaper_handle.await.unwrap();
	let contents = fs::read(integration::PIVOT_OK_SUCCESS_FILE).unwrap();
	assert_eq!(std::str::from_utf8(&contents).unwrap(), msg);
	assert!(fs::remove_file(integration::PIVOT_OK_SUCCESS_FILE).is_ok());
}

#[tokio::test]
async fn reaper_handles_non_zero_exits() {
	let secret_path: PathWrapper =
		"/tmp/reaper_handles_non_zero_exits.secret".into();
	let usock: PathWrapper = "/tmp/reaper_handles_non_zero_exits.sock".into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_non_zero_exits.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_ABORT_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	handles.put_manifest_envelope(&Default::default()).unwrap();
	assert!(handles.pivot_exists());

	let enclave_socket = SocketAddress::new_unix(&usock);

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(&handles, Box::new(MockNsm), enclave_socket, None)
			.await;
	});

	// Give the enclave server time to bind to the socket
	wait_for_usock(&usock).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the reaper has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	tokio::time::sleep(REAPER_EXIT_DELAY * 2).await;

	assert!(reaper_handle.is_finished());
}

#[tokio::test]
async fn reaper_handles_panic() {
	let secret_path: PathWrapper = "/tmp/reaper_handles_panics.secret".into();
	let usock: PathWrapper = "/tmp/reaper_handles_panics.sock".into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_panics.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		secret_path.to_string(),
		manifest_path.to_string(),
		PIVOT_PANIC_PATH.to_string(),
	);

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	handles.put_manifest_envelope(&Default::default()).unwrap();
	assert!(handles.pivot_exists());

	let enclave_socket = SocketAddress::new_unix(&usock);

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(&handles, Box::new(MockNsm), enclave_socket, None)
			.await;
	});

	// Give the enclave server time to bind to the socket
	wait_for_usock(&usock).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// Ensure the reaper has enough time to detect the secret, launch the
	// pivot, and let the pivot exit.
	tokio::time::sleep(REAPER_EXIT_DELAY * 2).await;

	assert!(reaper_handle.is_finished());
}

#[tokio::test]
async fn reaper_handles_bridge() {
	let pivot_port = 4000;
	let host_port = 3000;
	let secret_path: PathWrapper = "/tmp/reaper_handles_bridge.secret".into();
	let usock: PathWrapper = "/tmp/reaper_handles_bridge.sock".into();
	let app_usock: PathWrapper =
		format!("/tmp/reaper_handles_bridge.sock.{pivot_port}.appsock").into();
	let manifest_path: PathWrapper =
		"/tmp/reaper_handles_bridge.manifest".into();

	// For our sanity, ensure the secret does not yet exist
	drop(fs::remove_file(&*secret_path));

	let handles = Handles::new(
		"eph_path".to_string(),
		(*secret_path).to_string(),
		(*manifest_path).to_string(),
		PIVOT_TCP_PATH.to_string(),
	);

	// start the tcp -> vsock bridge on port 3000
	let host_addr: SocketAddr =
		SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_port).into();
	let app_pool =
		StreamPool::single(SocketAddress::new_unix(&app_usock)).unwrap();
	HostBridge::new(app_pool, host_addr).tcp_to_vsock().await;

	// Make sure we have written everything necessary to pivot, except the
	// quorum key
	let mut manifest_envelope = ManifestEnvelope::default();
	manifest_envelope.manifest.pivot.args = vec![format!("{pivot_port}")];
	manifest_envelope.manifest.pivot.bridge_config =
		vec![BridgeConfig::Server {
			port: pivot_port,
			host: "127.0.0.1".into(),
		}];

	handles.put_manifest_envelope(&manifest_envelope).unwrap();
	assert!(handles.pivot_exists());

	let enclave_socket = SocketAddress::new_unix(&usock);

	let reaper_handle = tokio::spawn(async move {
		Reaper::execute(&handles, Box::new(MockNsm), enclave_socket, None)
			.await;
	});

	// wait for enclave to listen
	wait_for_usock(&usock).await;

	// Check that the reaper is still running, presumably waiting for
	// the secret.
	assert!(!reaper_handle.is_finished());

	// Create the file with the secret, which should cause the reaper
	// to start executable.
	fs::write(&*secret_path, b"super dank tank secret tech").unwrap();

	// wait for internal VSOCK -> tcp bridge to listen
	wait_for_usock(&app_usock).await;

	let host_addr = format!("localhost:{host_port}");
	let pivot_addr = format!("localhost:{pivot_port}");

	// ensure pivot is ready and accepting on tcp://localhost:4000
	wait_for_tcp_sock(&pivot_addr).await;
	// ensure bridge is ready and accepting on tcp://localhost:3000
	wait_for_tcp_sock(&host_addr).await;

	let mut stream = TcpStream::connect(&host_addr)
		.await
		.expect("first stream failed to connect");

	// make sure we can handle 2+ connections in parallel
	let mut stream2 = TcpStream::connect(&host_addr)
		.await
		.expect("second stream failed to connect");
	let mut stream3 = TcpStream::connect(&host_addr)
		.await
		.expect("second stream failed to connect");

	// send the msg to the pivot via the bridge, out of order to check for x-streams
	stream3.write_all(b"worlds").await.unwrap();
	// send the msg to the pivot via the bridge
	stream.write_all(b"hello").await.unwrap();

	// read the reply of the "chronologically 2nd" request and ensure it's the same as msg
	let mut reply = [0u8; 5]; // reply buffer
	assert_eq!(stream.read_exact(&mut reply).await.unwrap(), 5);
	assert_eq!(&reply, b"hello");

	// read the reply of the "chronologically 1st" request and ensure it's the same as msg
	let mut reply = [0u8; 6]; // reply buffer
	assert_eq!(stream3.read_exact(&mut reply).await.unwrap(), 6);
	assert_eq!(&reply, b"worlds");

	// send the "finished" msg on the second connection
	stream2.write_all(b"done").await.unwrap();

	let mut done_reply = [0u8; 4]; // reply buffer
	assert_eq!(stream2.read_exact(&mut done_reply).await.unwrap(), 4);
	assert_eq!(&done_reply, b"done");

	// Make the sure the reaper executed successfully.
	reaper_handle.await.unwrap();
	let contents = fs::read(integration::PIVOT_TCP_SUCCESS_FILE).unwrap();
	assert_eq!(&contents, b"worlds"); // expects the chronologically first msg
	assert!(fs::remove_file(integration::PIVOT_TCP_SUCCESS_FILE).is_ok());
}

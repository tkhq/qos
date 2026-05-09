use integration::{wait_for_tcp_sock, wait_for_usock, PIVOT_OK_PATH};
use qos_core::{
	handles::Handles, io::SocketAddress, protocol::msg::ProtocolMsg,
	reaper::Reaper,
};
use qos_host::host::HostServer;
use qos_nsm::mock::MockNsm;
use qos_test_primitives::PathWrapper;
use std::{
	io::{self, Read},
	net::{Ipv4Addr, SocketAddr},
	time::Duration,
};
use tokio::{
	fs::{create_dir_all, remove_dir_all},
	join, select,
};

#[tokio::test(flavor = "multi_thread")]
async fn version_request_returns_version_and_commit() -> Result<(), io::Error> {
	const HOST_PORT: u16 = 3324;
	let test_dir = PathWrapper::from("/tmp/qos_version_test");

	// Pre-clean in case a prior crashed run left files behind.
	remove_dir_all(&test_dir).await.or_else(|err| match err.kind() {
		io::ErrorKind::NotFound => Ok(()),
		_ => Err(err),
	})?;
	create_dir_all(&test_dir).await?;

	let socket = test_dir.join("enclave.sock");
	let secret = test_dir.join("qos.secret");
	let manifest = test_dir.join("qos.manifest");
	let eph = test_dir.join("eph.key");

	let qos_core_handles = Handles::new(
		eph.to_string_lossy().into_owned(),
		secret.to_string_lossy().into_owned(),
		manifest.to_string_lossy().into_owned(),
		PIVOT_OK_PATH.to_string(),
	);

	let qos_core_socket = SocketAddress::new_unix(&socket);
	let mut qos_core_task = tokio::spawn(async move {
		Reaper::execute(
			&qos_core_handles,
			Box::new(MockNsm),
			qos_core_socket,
			None,
		)
		.await;
		panic!("qos_core task ended prematurely");
	});

	let addr = Ipv4Addr::LOCALHOST;

	let qos_host_server = HostServer::new(
		SocketAddress::new_unix(&socket),
		Duration::from_millis(50),
		SocketAddr::new(addr.into(), HOST_PORT),
		None,
	);
	let mut qos_host_task = tokio::spawn(async move {
		qos_host_server.serve().await;
		panic!("qos_host task ended prematurely");
	});

	let wait_for_sockets_future = async move {
		let addr = &(addr, HOST_PORT);
		join!(
			wait_for_tcp_sock(&addr),
			wait_for_usock(socket.to_str().unwrap())
		)
	};

	select! {
		res = &mut qos_host_task => match res {
			Err(join_err) => {
				return Err(io::Error::other(format!("qos_host task did not run to completion: {join_err}")))
			},
			Ok(()) => unreachable!("tokio tasks should explicitly panic if it exits early"),
		},
		res = &mut qos_core_task => match res {
			Err(join_err) => {
				return Err(io::Error::other(format!("qos_core task did not run to completion: {join_err}")))

			},
			Ok(()) => unreachable!("tokio tasks should explicitly panic if it exits early"),
		},
		_ = wait_for_sockets_future => {},
	}

	let url = format!("http://127.0.0.1:{HOST_PORT}/qos/message");
	let req_bytes = ProtocolMsg::VersionRequest.to_canonical_json_vec();
	let response = ureq::post(&url).send_bytes(&req_bytes).unwrap();

	let mut buf = Vec::new();
	response.into_reader().read_to_end(&mut buf).unwrap();
	let decoded = ProtocolMsg::from_json_slice(&buf).unwrap();

	match decoded {
		ProtocolMsg::VersionResponse { version, commit } => {
			assert_eq!(version, env!("CARGO_PKG_VERSION"));
			assert!(!commit.is_empty(), "commit should not be empty");
		}
		other => panic!("unexpected response: {other:?}"),
	}

	qos_host_task.abort();
	qos_core_task.abort();

	Ok(())
}

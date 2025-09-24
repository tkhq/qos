use std::process::Command;

use borsh::BorshDeserialize;
use integration::{
	wait_for_usock, PivotSocketStressMsg, PIVOT_SOCKET_STRESS_PATH,
};
use qos_core::{
	client::{ClientError, SocketClient},
	io::{SocketAddress, StreamPool},
	protocol::INITIAL_CLIENT_TIMEOUT,
};
use qos_test_primitives::ChildWrapper;

const SOCKET_STRESS_SOCK: &str = "/tmp/interleaving_socket_stress.sock";

#[tokio::test]
async fn interleaving_socket_stress() {
	let pool_size = 5;
	let _enclave_app: ChildWrapper = Command::new(PIVOT_SOCKET_STRESS_PATH)
		.arg(SOCKET_STRESS_SOCK)
		.arg("--pool-size")
		.arg(pool_size.to_string()) // pool size
		.spawn()
		.unwrap()
		.into();

	wait_for_usock(SOCKET_STRESS_SOCK).await;

	// needs to be long enough for process exit to register and not cause a timeout
	let app_pool =
		StreamPool::new(SocketAddress::new_unix(SOCKET_STRESS_SOCK), pool_size)
			.unwrap();

	let enclave_client =
		SocketClient::new(app_pool.shared(), INITIAL_CLIENT_TIMEOUT);
	let mut tasks = Vec::new();

	// wait long enough for app to be running and listening
	tokio::time::sleep(std::time::Duration::from_millis(200)).await;

	// perform a "Ok" request
	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::OkRequest(1)).unwrap();
	let resp = enclave_client.call(&app_request).await.expect("OkResponse");
	assert_eq!(
		PivotSocketStressMsg::try_from_slice(&resp).expect("OkResponse"),
		PivotSocketStressMsg::OkResponse(1)
	);

	// do a bunch of timing out requests at the same time, this still needs to fit within the pool size
	for _ in 0..3 {
		let ec = enclave_client.clone();
		tasks.push(tokio::spawn(async move {
			// perform a fully timeouting slow request
			let app_request =
				borsh::to_vec(&PivotSocketStressMsg::SlowRequest(5500))
					.unwrap();
			let err = ec.call(&app_request).await.unwrap_err();
			match err {
				ClientError::IOError(qos_core::io::IOError::RecvTimeout) => (),
				e => panic!("slow pivot did not get expected err {e:?}"),
			};
		}));
	}

	let ec = enclave_client.clone();
	tasks.push(tokio::spawn(async move {
		// perform a "fast enough" slow request request and expect a SlowResponse (checks mismatches)
		let app_request =
			borsh::to_vec(&PivotSocketStressMsg::SlowRequest(50)).unwrap();
		let resp = ec.call(&app_request).await.expect("SlowResponse");
		assert_eq!(
			PivotSocketStressMsg::try_from_slice(&resp).expect("SlowResponse"),
			PivotSocketStressMsg::SlowResponse(50),
		);
	}));

	for r in futures::future::join_all(tasks).await {
		r.unwrap();
	}
}

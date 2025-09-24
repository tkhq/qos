use std::process::Command;

use integration::{
	wait_for_usock, PivotSocketStressMsg, PIVOT_SOCKET_STRESS_PATH,
};
use qos_core::{
	client::{ClientError, SocketClient},
	io::{IOError, SocketAddress, StreamPool, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use qos_test_primitives::ChildWrapper;

const SOCKET_STRESS_SOCK: &str = "/tmp/simple_socket_stress.sock";

#[tokio::test]
async fn simple_socket_stress() {
	let _enclave_app: ChildWrapper = Command::new(PIVOT_SOCKET_STRESS_PATH)
		.arg(SOCKET_STRESS_SOCK)
		.spawn()
		.unwrap()
		.into();

	wait_for_usock(SOCKET_STRESS_SOCK).await;

	// needs to be long enough for process exit to register and not cause a timeout
	let timeout = TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS);

	let app_pool =
		StreamPool::new(SocketAddress::new_unix(SOCKET_STRESS_SOCK), 1)
			.unwrap();

	let enclave_client = SocketClient::new(app_pool.shared(), timeout);

	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::SlowRequest(5500)).unwrap();
	let err = enclave_client.call(&app_request).await.unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::RecvTimeout) => (),
		e => panic!("slow pivot did not get expected err {e:?}"),
	};

	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::PanicRequest).unwrap();
	let err = enclave_client.call(&app_request).await.unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::RecvConnectionClosed) => (),
		e => panic!("panicing pivot did not get expected err {e:?}"),
	};

	tokio::time::sleep(std::time::Duration::from_secs(1)).await;

	// The app has panic'ed and exited - so any proceeding request should fail.
	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::OkRequest(1)).unwrap();
	let err = enclave_client.call(&app_request).await.unwrap_err();
	match err {
		ClientError::IOError(IOError::StdIoError(_)) => (), // for usock this is probably "no such file or directoy", vsock would differ
		e => panic!("did not get expected err {e:?}"),
	};
}

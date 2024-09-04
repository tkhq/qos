use std::process::Command;

use integration::{PivotSocketStressMsg, PIVOT_SOCKET_STRESS_PATH};
use qos_core::{
	client::{Client, ClientError},
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use qos_test_primitives::ChildWrapper;

const SOCKET_STRESS_SOCK: &str = "/tmp/simple_socket_stress.sock";

#[test]
fn simple_socket_stress() {
	let _enclave_app: ChildWrapper = Command::new(PIVOT_SOCKET_STRESS_PATH)
		.arg(SOCKET_STRESS_SOCK)
		.spawn()
		.unwrap()
		.into();

	let enclave_client = Client::new(
		SocketAddress::new_unix(SOCKET_STRESS_SOCK),
		// The timeout of `PivotSocketStressMsg::SlowResponse` is relative to
		// `ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS`.
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
	);

	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::SlowRequest).unwrap();
	let err = enclave_client.send(&app_request).unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::RecvTimeout) => (),
		e => panic!("did not get expected err {:?}", e),
	};

	let app_request =
		borsh::to_vec(&PivotSocketStressMsg::PanicRequest).unwrap();
	let err = enclave_client.send(&app_request).unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::RecvConnectionClosed) => (),
		e => panic!("did not get expected err {:?}", e),
	};

	std::thread::sleep(std::time::Duration::from_secs(1));

	// The app has panic'ed and exited - so any proceeding request should fail.
	let app_request = borsh::to_vec(&PivotSocketStressMsg::OkRequest).unwrap();
	let err = enclave_client.send(&app_request).unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::ConnectNixError(
			nix::Error::ENOENT,
		)) => (),
		e => panic!("did not get expected err {:?}", e),
	};
}

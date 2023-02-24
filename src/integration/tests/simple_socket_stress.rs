use std::process::Command;

use borsh::BorshSerialize;
use integration::{PIVOT_SOCKET_STRESS_PATH, PivotSocketStressMsg};
use qos_core::{io::{SocketAddress, TimeVal, TimeValLike}, client::{Client, ClientError}};
use qos_test_primitives::ChildWrapper;

const SOCKET_STRESS_SOCK: &str = "/tmp/simple_socket_stress.sock";

#[test]
fn simple_socket_stress() {
	let _enclave_app: ChildWrapper =
		Command::new(PIVOT_SOCKET_STRESS_PATH)
			.arg(SOCKET_STRESS_SOCK)
			.spawn()
			.unwrap()
			.into();

	let enclave_client = Client::new(
		SocketAddress::new_unix(SOCKET_STRESS_SOCK),
		TimeVal::seconds(5),
	);

	let app_request = PivotSocketStressMsg::PanicRequest.try_to_vec().unwrap();

	let err = enclave_client.send(&app_request).unwrap_err();
	match err {
		ClientError::IOError(qos_core::io::IOError::RecvConnectionClosed) => (),
		e => panic!("did not get expected err {:?}", e),
	};
}
use std::{process::Command, str};

use borsh::BorshSerialize;
use integration::{PivotRemoteHttpMsg, PIVOT_REMOTE_HTTP_PATH};
use qos_core::{
	client::Client,
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use qos_test_primitives::ChildWrapper;

const REMOTE_HTTP_TEST_SOCKET: &str = "/tmp/remote_http_test.sock";

#[test]
fn remote_http() {
	let _enclave_app: ChildWrapper = Command::new(PIVOT_REMOTE_HTTP_PATH)
		.arg(REMOTE_HTTP_TEST_SOCKET)
		.spawn()
		.unwrap()
		.into();

	let enclave_client = Client::new(
		SocketAddress::new_unix(REMOTE_HTTP_TEST_SOCKET),
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
	);

	let app_request = PivotRemoteHttpMsg::RemoteHttpRequest(
		"https://api.turnkey.com/health".to_string(),
	)
	.try_to_vec()
	.unwrap();
	let response = enclave_client.send(&app_request).unwrap();
	let response_text = str::from_utf8(&response).unwrap();
	assert_eq!(response_text, "something");
}

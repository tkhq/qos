use std::{process::Command, str};

use borsh::BorshSerialize;
use integration::{PivotRemoteTlsMsg, PIVOT_REMOTE_TLS_PATH, QOS_NET_PATH};
use qos_core::{
	client::Client,
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};
use qos_test_primitives::ChildWrapper;

const REMOTE_TLS_TEST_NET_PROXY_SOCKET: &str = "/tmp/remote_tls_test.net.sock";
const REMOTE_TLS_TEST_ENCLAVE_SOCKET: &str =
	"/tmp/remote_tls_test.enclave.sock";

#[test]
fn fetch_remote_tls_content() {
	let _net_proxy: ChildWrapper = Command::new(QOS_NET_PATH)
		.arg("--usock")
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.spawn()
		.unwrap()
		.into();

	let _enclave_app: ChildWrapper = Command::new(PIVOT_REMOTE_TLS_PATH)
		.arg(REMOTE_TLS_TEST_ENCLAVE_SOCKET)
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.spawn()
		.unwrap()
		.into();

	let enclave_client = Client::new(
		SocketAddress::new_unix(REMOTE_TLS_TEST_ENCLAVE_SOCKET),
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
	);

	let app_request = PivotRemoteTlsMsg::RemoteTlsRequest {
		host: "api.turnkey.com".to_string(),
		path: "/health".to_string(),
	}
	.try_to_vec()
	.unwrap();

	let response = enclave_client.send(&app_request).unwrap();
	let response_text = str::from_utf8(&response).unwrap();

	assert!(response_text.contains("Content fetched successfully"));
	assert!(response_text.contains("HTTP/1.1 200 OK"));
	assert!(response_text.contains("currentTime"));

	let app_request = PivotRemoteTlsMsg::RemoteTlsRequest {
		host: "www.googleapis.com".to_string(),
		path: "/oauth2/v3/certs".to_string(),
	}
	.try_to_vec()
	.unwrap();

	let response = enclave_client.send(&app_request).unwrap();
	let response_text = str::from_utf8(&response).unwrap();

	assert!(response_text.contains("Content fetched successfully"));
	assert!(response_text.contains("HTTP/1.1 200 OK"));
	assert!(response_text.contains("keys"));
}

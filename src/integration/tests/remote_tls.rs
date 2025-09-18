use std::process::Command;

use borsh::BorshDeserialize;
use integration::{
	wait_for_usock, PivotRemoteTlsMsg, PIVOT_REMOTE_TLS_PATH, QOS_NET_PATH,
};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::INITIAL_CLIENT_TIMEOUT,
};

use qos_test_primitives::ChildWrapper;

const REMOTE_TLS_TEST_NET_PROXY_SOCKET: &str = "/tmp/remote_tls_test.net.sock";
const REMOTE_TLS_TEST_ENCLAVE_SOCKET: &str =
	"/tmp/remote_tls_test.enclave.sock";
const POOL_SIZE: &str = "1";

#[tokio::test]
async fn fetch_async_remote_tls_content() {
	let _net_proxy: ChildWrapper = Command::new(QOS_NET_PATH)
		.arg("--usock")
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.arg("--pool-size")
		.arg(POOL_SIZE)
		.spawn()
		.unwrap()
		.into();

	let _enclave_app: ChildWrapper = Command::new(PIVOT_REMOTE_TLS_PATH)
		.arg(REMOTE_TLS_TEST_ENCLAVE_SOCKET)
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.spawn()
		.unwrap()
		.into();

	wait_for_usock(REMOTE_TLS_TEST_ENCLAVE_SOCKET).await;

	let enclave_pool = StreamPool::new(
		SocketAddress::new_unix(REMOTE_TLS_TEST_ENCLAVE_SOCKET),
		1,
	)
	.expect("unable to create enclave async pool");

	let enclave_client =
		SocketClient::new(enclave_pool.shared(), INITIAL_CLIENT_TIMEOUT);

	let app_request = borsh::to_vec(&PivotRemoteTlsMsg::RemoteTlsRequest {
		host: "api.turnkey.com".to_string(),
		path: "/health".to_string(),
	})
	.unwrap();

	let response = enclave_client.call(&app_request).await.unwrap();
	let response_text =
		match PivotRemoteTlsMsg::try_from_slice(&response).unwrap() {
			PivotRemoteTlsMsg::RemoteTlsResponse(s) => s,
			PivotRemoteTlsMsg::RemoteTlsRequest { host: _, path: _ } => {
				panic!("unexpected RemoteTlsRequest sent as response")
			}
		};

	assert!(response_text.contains("Content fetched successfully"));
	assert!(response_text.contains("HTTP/1.1 200 OK"));
	assert!(response_text.contains("currentTime"));

	let app_request = borsh::to_vec(&PivotRemoteTlsMsg::RemoteTlsRequest {
		host: "www.googleapis.com".to_string(),
		path: "/oauth2/v3/certs".to_string(),
	})
	.unwrap();

	let response = enclave_client.call(&app_request).await.unwrap();
	let response_text =
		match PivotRemoteTlsMsg::try_from_slice(&response).unwrap() {
			PivotRemoteTlsMsg::RemoteTlsResponse(s) => s,
			PivotRemoteTlsMsg::RemoteTlsRequest { host: _, path: _ } => {
				panic!("unexpected RemoteTlsRequest sent as response")
			}
		};

	assert!(response_text.contains("Content fetched successfully"));
	assert!(response_text.contains("HTTP/1.1 200 OK"));
	assert!(response_text.contains("keys"));
}

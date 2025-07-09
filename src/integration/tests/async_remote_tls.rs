use std::{process::Command, time::Duration};

use borsh::BorshDeserialize;
use integration::{
	PivotRemoteTlsMsg, ASYNC_QOS_NET_PATH, PIVOT_ASYNC_REMOTE_TLS_PATH,
};
use qos_core::{
	async_client::AsyncClient,
	io::{AsyncStreamPool, SocketAddress, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};

use qos_test_primitives::ChildWrapper;

const REMOTE_TLS_TEST_NET_PROXY_SOCKET: &str =
	"/tmp/async_remote_tls_test.net.sock";
const REMOTE_TLS_TEST_ENCLAVE_SOCKET: &str =
	"/tmp/async_remote_tls_test.enclave.sock";
const POOL_SIZE: &str = "1";

#[tokio::test]
async fn fetch_async_remote_tls_content() {
	let _net_proxy: ChildWrapper = Command::new(ASYNC_QOS_NET_PATH)
		.arg("--usock")
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.arg("--pool-size")
		.arg(POOL_SIZE)
		.spawn()
		.unwrap()
		.into();

	let _enclave_app: ChildWrapper = Command::new(PIVOT_ASYNC_REMOTE_TLS_PATH)
		.arg(REMOTE_TLS_TEST_ENCLAVE_SOCKET)
		.arg(REMOTE_TLS_TEST_NET_PROXY_SOCKET)
		.spawn()
		.unwrap()
		.into();

	// ensure the enclave socket is created by qos_net before proceeding
	while !std::fs::exists(REMOTE_TLS_TEST_ENCLAVE_SOCKET).unwrap() {
		tokio::time::sleep(Duration::from_millis(50)).await;
	}

	let enclave_pool = AsyncStreamPool::new(
		SocketAddress::new_unix(REMOTE_TLS_TEST_ENCLAVE_SOCKET),
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
		1,
	)
	.expect("unable to create enclave async pool");

	let enclave_client = AsyncClient::new(enclave_pool.shared());

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

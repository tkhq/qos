use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use std::{path::Path, process::Command, str};

use borsh::BorshDeserialize;
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

/// Waits for socket at `path` until it becomes ready.
/// If the socket isn't ready after `timeout`, this function panics.
fn wait_for_socket_ready<P: AsRef<Path>>(path: P, timeout: Duration) {
	let start = Instant::now();
	while start.elapsed() < timeout {
		match UnixStream::connect(&path) {
			Ok(_) => return, // socket is ready
			Err(e) => {
				// Error while connecting. Retry.
				println!(
					"[retrying] error while connecting at {}: {}",
					path.as_ref().display(),
					e
				)
			}
		}
		std::thread::sleep(Duration::from_millis(50));
	}
	panic!(
		"Unable to connect to {}: timing out after retrying for {} seconds.",
		path.as_ref().display(),
		timeout.as_secs()
	);
}

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

	let app_request = borsh::to_vec(&PivotRemoteTlsMsg::RemoteTlsRequest {
		host: "api.turnkey.com".to_string(),
		path: "/health".to_string(),
	})
	.unwrap();

	wait_for_socket_ready(
		REMOTE_TLS_TEST_NET_PROXY_SOCKET,
		Duration::from_secs(2),
	);
	wait_for_socket_ready(
		REMOTE_TLS_TEST_ENCLAVE_SOCKET,
		Duration::from_secs(2),
	);

	let response = enclave_client.send(&app_request).unwrap();
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

	let response = enclave_client.send(&app_request).unwrap();
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

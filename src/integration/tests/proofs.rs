use std::{process::Command, str};

use borsh::BorshDeserialize;
use integration::{wait_for_usock, PivotProofMsg, PIVOT_PROOF_PATH};
use qos_core::{
	client::SocketClient,
	io::{SocketAddress, StreamPool},
	protocol::INITIAL_CLIENT_TIMEOUT,
};

use qos_p256::QosKeySetV0Public;
use qos_test_primitives::ChildWrapper;

const PROOF_TEST_ENCLAVE_SOCKET: &str = "/tmp/proof_test.enclave.sock";

#[tokio::test]
async fn fetch_and_verify_app_proof() {
	let _enclave_app: ChildWrapper = Command::new(PIVOT_PROOF_PATH)
		.arg(PROOF_TEST_ENCLAVE_SOCKET)
		.spawn()
		.unwrap()
		.into();

	wait_for_usock(PROOF_TEST_ENCLAVE_SOCKET).await;

	let enclave_pool =
		StreamPool::single(SocketAddress::new_unix(PROOF_TEST_ENCLAVE_SOCKET))
			.unwrap();

	let enclave_client =
		SocketClient::new(enclave_pool.shared(), INITIAL_CLIENT_TIMEOUT);

	let app_request =
		borsh::to_vec(&PivotProofMsg::AdditionRequest { a: 2, b: 2 }).unwrap();

	let response = enclave_client.call(&app_request).await.unwrap();

	match PivotProofMsg::try_from_slice(&response).unwrap() {
		PivotProofMsg::AdditionResponse { result, proof } => {
			let ephemeral_public_key =
				QosKeySetV0Public::from_bytes(&proof.public_key).unwrap();
			assert!(ephemeral_public_key
				.verify(
					&borsh::to_vec(&proof.payload).unwrap(),
					&proof.signature
				)
				.is_ok());

			assert_eq!(proof.payload.a, 2);
			assert_eq!(proof.payload.b, 2);
			assert_eq!(proof.payload.result, 4);
			assert_eq!(result, 4);
		}
		_ => {
			panic!("unexpected response")
		}
	};
}

use std::{process::Command, str};

use borsh::BorshDeserialize;
use integration::{PivotProofMsg, PIVOT_PROOF_PATH};
use qos_core::{
	client::Client,
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
};

use qos_p256::P256Public;
use qos_test_primitives::ChildWrapper;

const PROOF_TEST_ENCLAVE_SOCKET: &str = "/tmp/proof_test.enclave.sock";

#[test]
fn fetch_and_verify_app_proof() {
	let _enclave_app: ChildWrapper = Command::new(PIVOT_PROOF_PATH)
		.arg(PROOF_TEST_ENCLAVE_SOCKET)
		.spawn()
		.unwrap()
		.into();

	let enclave_client = Client::new(
		SocketAddress::new_unix(PROOF_TEST_ENCLAVE_SOCKET),
		TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS),
	);

	let app_request =
		borsh::to_vec(&PivotProofMsg::AdditionRequest { a: 2, b: 2 }).unwrap();

	let response = enclave_client.send(&app_request).unwrap();

	match PivotProofMsg::try_from_slice(&response).unwrap() {
		PivotProofMsg::AdditionResponse { result, proof } => {
			let ephemeral_public_key =
				P256Public::from_bytes(&proof.public_key).unwrap();
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

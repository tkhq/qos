use core::panic;
use std::sync::Arc;

use borsh::BorshDeserialize;
use integration::{AdditionProof, AdditionProofPayload, PivotProofMsg};
use qos_core::{
	handles::EphemeralKeyHandle,
	io::{SocketAddress, StreamPool},
	server::{RequestProcessor, SocketServer},
};
use tokio::sync::RwLock;

struct Processor {
	ephemeral_key_handle: EphemeralKeyHandle,
}

impl Processor {
	pub fn new(ephemeral_key_handle: EphemeralKeyHandle) -> Arc<RwLock<Self>> {
		Arc::new(RwLock::new(Self { ephemeral_key_handle }))
	}
}

impl RequestProcessor for Processor {
	async fn process(&self, request: &[u8]) -> Vec<u8> {
		let msg = PivotProofMsg::try_from_slice(request)
			.expect("Received invalid message - test is broken!");

		match msg {
			PivotProofMsg::AdditionRequest { a, b } => {
				let result = a + b;
				let proof_payload = AdditionProofPayload { a, b, result };

				let ephemeral_key =
					self.ephemeral_key_handle.get_ephemeral_key().unwrap();

				let signature = ephemeral_key
					.sign(&borsh::to_vec(&proof_payload).unwrap())
					.unwrap();
				let public_key = ephemeral_key.public_key().to_bytes();

				borsh::to_vec(&PivotProofMsg::AdditionResponse {
					result,
					proof: AdditionProof {
						signature,
						public_key,
						payload: AdditionProofPayload { a, b, result },
					},
				})
				.unwrap()
			}

			_ => {
				panic!("Unexpected msg - test is broken")
			}
		}
	}
}

#[tokio::main]
async fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path: &String = &args[1];

	let app_pool = StreamPool::new(SocketAddress::new_unix(socket_path), 1)
		.expect("unable to create app pool");

	let _server = SocketServer::listen_all(
		app_pool,
		&Processor::new(EphemeralKeyHandle::new(
			"./mock/ephemeral_seed.secret.keep".to_string(),
		)),
		1,
	)
	.unwrap();

	tokio::signal::ctrl_c().await.unwrap();
}

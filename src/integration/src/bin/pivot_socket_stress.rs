use core::panic;

use borsh::{BorshDeserialize, BorshSerialize};
use integration::{PivotSocketStressMsg, PIVOT_SOCKET_STRESS_SOCK};
use qos_core::{
	io::SocketAddress,
	protocol::ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
	server::{RequestProcessor, SocketServer},
};

struct Processor;

impl RequestProcessor for Processor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		// Simulate just some baseline lag for all requests
		std::thread::sleep(std::time::Duration::from_secs(
			1,
		));

		let msg = PivotSocketStressMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken");

		match msg {
			PivotSocketStressMsg::OkRequest => PivotSocketStressMsg::OkResponse
				.try_to_vec()
				.expect("OkResponse is valid borsh"),
			PivotSocketStressMsg::PanicRequest => {
				dbg!("pivot about to panic");
				panic!("\"socket stress\" pivot app has received a PanicRequest")
			}
			PivotSocketStressMsg::SlowRequest => {
				std::thread::sleep(std::time::Duration::from_secs(
					ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS as u64 + 1,
				));
				PivotSocketStressMsg::SlowResponse
					.try_to_vec()
					.expect("OkResponse is valid borsh")
			}
			PivotSocketStressMsg::SlowResponse => {
				panic!("Unexpected slow response - test is broken")
			}
			PivotSocketStressMsg::OkResponse => {
				panic!("Unexpected ok response - test is broken")
			}
		}
	}
}
fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path = &args[1];
	SocketServer::listen(
		SocketAddress::new_unix(socket_path),
		Processor,
	)
	.unwrap();
}

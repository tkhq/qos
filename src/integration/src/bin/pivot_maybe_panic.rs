use core::panic;

use borsh::{BorshDeserialize, BorshSerialize};
use integration::{PivotMaybePanicMsg, PIVOT_MAYBE_PANIC_SOCK};
use qos_core::{
	io::SocketAddress,
	server::{RequestProcessor, SocketServer},
};

struct Processor;

impl RequestProcessor for Processor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		let msg = PivotMaybePanicMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken");
		match msg {
			PivotMaybePanicMsg::OkRequest => PivotMaybePanicMsg::OkResponse
				.try_to_vec()
				.expect("OkResponse is valid borsh"),
			PivotMaybePanicMsg::PanicRequest => {
				panic!("PivotMaybePanicMsg has received a panic request")
			}
			PivotMaybePanicMsg::OkResponse => {
				panic!("Unexpected ok response - test is broken")
			}
		}
	}
}
fn main() {
	SocketServer::listen(
		SocketAddress::new_unix(PIVOT_MAYBE_PANIC_SOCK),
		Processor,
	)
	.unwrap();
}

use core::panic;

use borsh::{BorshDeserialize, BorshSerialize};
use integration::PivotRemoteHttpMsg;
use qos_core::{
	io::SocketAddress,
	server::{RequestProcessor, SocketServer},
};

struct Processor;

impl RequestProcessor for Processor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		let msg = PivotRemoteHttpMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken");

		match msg {
			PivotRemoteHttpMsg::RemoteHttpRequest(url) => {
				// TODO:
				// implement Read/Write traits with
				// ProtocolMsg::RemoteReadRequest and
				// ProtocolMsg::RemoteWriteRequest

				PivotRemoteHttpMsg::RemoteHttpResponse(format!(
					"hello! I am a response to {url}"
				))
				.try_to_vec()
				.expect("RemoteHttpResponse is valid borsh")
			}
			PivotRemoteHttpMsg::RemoteHttpResponse(_) => {
				panic!("Unexpected RemoteHttpResponse - test is broken")
			}
		}
	}
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path = &args[1];
	SocketServer::listen(SocketAddress::new_unix(socket_path), Processor)
		.unwrap();
}

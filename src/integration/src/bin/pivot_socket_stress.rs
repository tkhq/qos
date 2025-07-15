use core::panic;

use borsh::BorshDeserialize;
use integration::PivotSocketStressMsg;
use qos_core::{
	async_server::{AsyncRequestProcessor, AsyncSocketServer},
	io::{AsyncStreamPool, SocketAddress},
};

#[derive(Clone)]
struct Processor;

impl AsyncRequestProcessor for Processor {
	async fn process(&self, request: Vec<u8>) -> Vec<u8> {
		// Simulate just some baseline lag for all requests
		std::thread::sleep(std::time::Duration::from_secs(1));

		let msg = PivotSocketStressMsg::try_from_slice(&request)
			.expect("Received invalid message - test is broken");

		match msg {
			PivotSocketStressMsg::OkRequest => {
				borsh::to_vec(&PivotSocketStressMsg::OkResponse)
					.expect("OkResponse is valid borsh")
			}
			PivotSocketStressMsg::PanicRequest => {
				eprintln!("PIVOT: panic request received, panicing");
				// panic is not enough in tokio, we need process exit
				std::process::exit(1)
			}
			PivotSocketStressMsg::SlowRequest(delay) => {
				eprintln!(
					"PIVOT: slow request received, sleeping for {delay}ms"
				);
				tokio::time::sleep(std::time::Duration::from_millis(delay))
					.await;
				borsh::to_vec(&PivotSocketStressMsg::SlowResponse)
					.expect("OkResponse is valid borsh")
			}
			PivotSocketStressMsg::SlowResponse => {
				panic!("Unexpected SlowResponse - test is broken")
			}
			PivotSocketStressMsg::OkResponse => {
				panic!("Unexpected OkResponse - test is broken")
			}
		}
	}
}

#[tokio::main]
async fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path = &args[1];

	let app_pool =
		AsyncStreamPool::new(SocketAddress::new_unix(socket_path), 1)
			.expect("unable to create app pool");

	let server = AsyncSocketServer::listen_all(app_pool, &Processor).unwrap();

	tokio::signal::ctrl_c().await.unwrap();
	server.terminate();
}

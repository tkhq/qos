use core::panic;
use std::sync::Arc;

use borsh::BorshDeserialize;
use integration::PivotSocketStressMsg;
use qos_core::{
	io::{SocketAddress, StreamPool},
	server::{RequestProcessor, SocketServer},
};
use tokio::sync::RwLock;

#[derive(Clone)]
struct Processor;

impl Processor {
	pub fn new() -> Arc<RwLock<Self>> {
		Arc::new(RwLock::new(Self))
	}
}

impl RequestProcessor for Processor {
	async fn process(&self, request: &[u8]) -> Vec<u8> {
		// Simulate just some baseline lag for all requests
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;

		let msg = PivotSocketStressMsg::try_from_slice(request)
			.expect("Received invalid message - test is broken");

		match msg {
			PivotSocketStressMsg::OkRequest(id) => {
				eprintln!(
					"PIVOT: OkRequest({id}) received, responding with OkResponse({id})"
				);
				borsh::to_vec(&PivotSocketStressMsg::OkResponse(id))
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
				borsh::to_vec(&PivotSocketStressMsg::SlowResponse(delay))
					.expect("OkResponse is valid borsh")
			}
			PivotSocketStressMsg::SlowResponse(_) => {
				panic!("Unexpected SlowResponse - test is broken")
			}
			PivotSocketStressMsg::OkResponse(_) => {
				panic!("Unexpected OkResponse - test is broken")
			}
		}
	}
}

#[tokio::main]
async fn main() {
	let args: Vec<String> = std::env::args().collect();
	let socket_path = &args[1];
	// 2nd arg should be "--pool-size" for Reaper compatibility
	let pool_size_str: &str = args.get(3).map(String::as_str).unwrap_or("1");
	let pool_size =
		pool_size_str.parse().expect("Unable to parse pool size argument");

	let app_pool =
		StreamPool::new(SocketAddress::new_unix(socket_path), pool_size)
			.expect("unable to create app pool");

	let _server =
		SocketServer::listen_all(app_pool, &Processor::new()).unwrap();

	tokio::signal::ctrl_c().await.unwrap();
}

use qos_core::{
	server::{Routable, SocketServer},
	io::SocketAddress,
};

#[derive(
	Debug, Clone, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum AppMsg {
	EchoReq(String),
	EchoResp(String),
	/// Ping request.
	PingReq,
	/// Successful ping response.
	PingResp
	Error(String)
}

struct AppProcessor;
impl Routable for AppProcessor {
	fn process(&self, request: Vec<u8>) -> Vec<u8> {
		let request = match AppMsg::try_from_slice(&request) {
			Ok
			Err
		};

		let response = request {
			AppMsg::EchoReq(data) => AppMsg::EchoResp(data),
			AppMsg::PingReq => AppMsg::PingResp,
			x => AppMsg::Error(format!("{x}"))
		}

		match response.try_to_vec() {
			Ok
			Err
		}
	}
}

fn main() {
	// Start server
	let addr = SocketAddress::new_unix("./todo_make_me_configurable.sock");
	SocketServer::listen(addr, executor).unwrap();
}
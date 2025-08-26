//! Enclave to simulate communication patterns with a secure app

use borsh::BorshDeserialize;
use qos_core::{
	client::Client,
	io::SocketAddress,
	protocol::msg::ProtocolMsg,
	server::{RequestProcessor, SocketServer},
};
use qos_host_primitives::enclave_client_timeout;
use qos_nsm::types::NsmResponse;

struct Processor {
	app_client: Client,
}

impl RequestProcessor for Processor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		let msg_req = ProtocolMsg::try_from_slice(&request)
			.expect("enclave_stub: Failed to deserialize request");

		match msg_req {
			ProtocolMsg::ProxyRequest { data } => {
				let resp_data =
					self.app_client.send(&data).expect("Client error");

				borsh::to_vec(&ProtocolMsg::ProxyResponse { data: resp_data })
					.expect("enclave_stub: Failed to serialize response")
			}
			ProtocolMsg::LiveAttestationDocRequest => {
				let data_string = borsh::to_vec(&"MOCK_DOCUMENT".to_string())
					.expect("unable to serialize mock document");
				let nsm_response =
					NsmResponse::Attestation { document: data_string };

				borsh::to_vec(&ProtocolMsg::LiveAttestationDocResponse {
					nsm_response,
					manifest_envelope: None,
				})
				.expect("enclave stub: Failed to serialize response")
			}
			other => panic!("enclave_stub: Unexpected request {:?}", other),
		}
	}
}

fn main() {
	let args: Vec<_> = std::env::args().collect();
	let enclave_sock_path = &args[1];
	let enclave_sock_addr = SocketAddress::new_unix(enclave_sock_path);

	let app_sock_path = &args[2];
	let app_sock_addr = SocketAddress::new_unix(app_sock_path);
	let processor = Processor {
		app_client: Client::new(app_sock_addr, enclave_client_timeout()),
	};

	SocketServer::listen(enclave_sock_addr, processor).unwrap();
}

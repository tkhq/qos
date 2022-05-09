use axum::{
	body::{Body, Bytes},
	extract::Host,
	http::StatusCode,
	response::Html,
	response::{IntoResponse, Response},
	routing::{get, post},
	Extension, Router,
};
use qos_core::io::SocketAddress;
use qos_core::protocol::ProtocolRequest;
use qos_core::{client::Client, protocol::Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct HostServer {
	enclave_addr: SocketAddress,
	addr: SocketAddr,
}

#[derive(Debug)]
struct State {
	enclave_client: Client,
}

impl HostServer {
	fn new(enclave_addr: SocketAddress, port: u16) -> Self {
		Self { addr: SocketAddr::from(([127, 0, 0, 1], port)), enclave_addr }
	}

	async fn serve(&self) -> Result<(), String> {
		let state = Arc::new(State {
			enclave_client: Client::new(self.enclave_addr.clone()),
		});

		let app = Router::new()
			.route("/health", get(Self::health))
			.route("/message", post(Self::bytes))
			.layer(Extension(state));

		println!("Listening on {}", self.addr);

		axum::Server::bind(&self.addr)
			.serve(app.into_make_service())
			.await
			.unwrap();

		Ok(())
	}

	async fn health(
		Extension(state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		println!("Health...");
		Html("Ok!")
	}

	// request: https://github.com/tokio-rs/axum/blob/main/axum/src/docs/extract.md
	// response: https://github.com/tokio-rs/axum/blob/main/axum/src/docs/response.md
	// error response: https://github.com/tokio-rs/axum/blob/main/axum/src/docs/error_handling.md
	async fn bytes(
		body: Bytes,
		Extension(state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		let mut body = body.to_vec();
		match ProtocolRequest::deserialize(&mut body) {
			Err(_) => {
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					b"Cannot parse payload...".to_vec(),
				)
			}
			Ok(request) => match state.enclave_client.send(request) {
				Err(_) => {
					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						b"Received error from enclave...".to_vec(),
					)
				}
				Ok(response) => {
					return (StatusCode::OK, response.serialize());
				}
			},
		}
	}
}

#[tokio::main]
async fn main() {
	let addr = SocketAddress::new_unix("./dev.sock");
	let port = 3000;

	let server = HostServer::new(addr, port);
	let _ = server.serve().await.map_err(|e| eprintln!("server: {:?}", e));
}

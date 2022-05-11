//! Enclave host implementation. The host primarily consists of a HTTP server
//! that proxies requests to the enclave by establishing a client connection
//! with the enclave.
//!
//! # IMPLEMENTERS NOTE
//!
//! The host HTTP server is currently implemented using the `axum` framework.
//! This may be swapped out in the the future in favor of a lighter package in
//! order to slim the dependency tree. In the mean time, these resources can
//! help familiarize you with the abstractions:
//!
//! * Request body extractors: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/extract.md/>
//! * Response: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/response.md/>
//! * Responding with error: <https://github.com/tokio-rs/axum/blob/main/axum/src/docs/error_handling.md/>
#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc};

use axum::{
	body::Bytes,
	http::StatusCode,
	response::{Html, IntoResponse},
	routing::{get, post},
	Extension, Router,
};
use qos_core::{
	client::Client,
	io::SocketAddress,
	protocol::{ProtocolMsg, Serialize},
};

/// Resource shared across tasks in the [`HostServer`].
#[derive(Debug)]
struct State {
	enclave_client: Client,
}

/// HTTP server for the host of the enclave; proxies requests to the enclave.
pub struct HostServer {
	enclave_addr: SocketAddress,
	addr: SocketAddr,
}

impl HostServer {
	/// Create a new [`HostServer`].
	pub fn new(enclave_addr: SocketAddress, ip: [u8; 4], port: u16) -> Self {
		Self { addr: SocketAddr::from((ip, port)), enclave_addr }
	}

	/// Start the server, running indefinitely.
	pub async fn serve(&self) -> Result<(), String> {
		let state = Arc::new(State {
			enclave_client: Client::new(self.enclave_addr.clone()),
		});

		let app = Router::new()
			.route("/health", get(Self::health))
			.route("/message", post(Self::message))
			.layer(Extension(state));

		println!("Listening on {}", self.addr);

		axum::Server::bind(&self.addr)
			.serve(app.into_make_service())
			.await
			.unwrap();

		Ok(())
	}

	/// Health route handler.
	async fn health(
		Extension(_state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		println!("Health...");
		Html("Ok!")
	}

	/// Message route handler.
	async fn message(
		body: Bytes,
		Extension(state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		let mut body = body.to_vec();
		match ProtocolMsg::deserialize(&mut body) {
			Err(_) => {
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					b"Cannot parse payload...".to_vec(),
				)
			}
			Ok(request) => match state.enclave_client.send(request) {
				Err(_) => (
					StatusCode::INTERNAL_SERVER_ERROR,
					b"Received error from enclave...".to_vec(),
				),
				Ok(response) => (StatusCode::OK, response.serialize()),
			},
		}
	}
}

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

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

use axum::{
	body::Bytes,
	http::StatusCode,
	response::{Html, IntoResponse},
	routing::{get, post},
	Extension, Router,
};
use qos_core::{client::Client, io::SocketAddress, protocol::ProtocolMsg};

pub mod cli;

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

	pub fn new_with_socket_addr(
		enclave_addr: SocketAddress,
		addr: SocketAddr,
	) -> Self {
		Self { addr, enclave_addr }
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
		if body.len() > MAX_ENCODED_MSG_LEN {
			return (
				StatusCode::BAD_REQUEST,
				serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
					.expect("ProtocolMsg can always serialize. qed."),
			);
		}

		match serde_cbor::from_slice(&body) {
			Err(_) => {
				return (
					StatusCode::BAD_REQUEST,
					serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
						.expect("ProtocolMsg can always serialize. qed."),
				)
			}
			Ok(request) => match state.enclave_client.send(request) {
				Err(_) => (
					StatusCode::INTERNAL_SERVER_ERROR,
					serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
						.expect("ProtocolMsg can always serialize. qed."),
				),
				Ok(response) => (
					StatusCode::OK,
					serde_cbor::to_vec(&response)
						.expect("ProtocolMsg can always serialize. qed."),
				),
			},
		}
	}
}

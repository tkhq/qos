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
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::{net::SocketAddr, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

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
	protocol::{ProtocolError, ProtocolMsg},
};

pub mod cli;
pub use cli::CLI;

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
	/// Create a new [`HostServer`]. See [`Self::serve`] for starting the
	/// server.
	#[must_use]
	pub fn new(enclave_addr: SocketAddress, addr: SocketAddr) -> Self {
		Self { enclave_addr, addr }
	}

	/// Start the server, running indefinitely.
	///
	/// # Panics
	///
	/// Panics if there is an issue starting the server.
	// pub async fn serve(&self) -> Result<(), String> {
	pub async fn serve(&self) {
		let state = Arc::new(State {
			enclave_client: Client::new(self.enclave_addr.clone()),
		});

		let app = Router::new()
			.route("/health", get(Self::health))
			.route("/message", post(Self::message))
			.layer(Extension(state));

		println!("HostServer listening on {}", self.addr);

		axum::Server::bind(&self.addr)
			.serve(app.into_make_service())
			.await
			.unwrap();

		// Ok(())
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
			dbg!("OversizeMsg");
			return (
				StatusCode::BAD_REQUEST,
				ProtocolMsg::ProtocolErrorResponse(ProtocolError::OversizeMsg)
					.try_to_vec()
					.expect("ProtocolMsg can always serialize. qed."),
			);
		}

		let response = match ProtocolMsg::try_from_slice(&body) {
			Err(_) => {
				dbg!("InvalidMsg");
				return (
					StatusCode::BAD_REQUEST,
					ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::InvalidMsg,
					)
					.try_to_vec()
					.expect("ProtocolMsg can always serialize. qed."),
				);
			}
			Ok(request) => state.enclave_client.send(&request),
		};

		match response {
			Err(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::EnclaveClient,
				)
				.try_to_vec()
				.expect("ProtocolMsg can always serialize. qed."),
			),
			Ok(response) => (
				StatusCode::OK,
				response
					.try_to_vec()
					.expect("ProtocolMsg can always serialize. qed."),
			),
		}
	}
}

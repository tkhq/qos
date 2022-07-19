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

use axum::{
	body::Bytes,
	http::StatusCode,
	response::{Html, IntoResponse},
	routing::{get, post},
	Extension, Router,
};
use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	client::Client,
	io::SocketAddress,
	protocol::{msg::ProtocolMsg, ProtocolError, ProtocolPhase},
};

pub mod cli;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 256 * MEGABYTE;

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
			.route("/host-health", get(Self::host_health))
			.route("/enclave-health", get(Self::enclave_health))
			.route("/message", post(Self::message))
			.layer(Extension(state));

		println!("HostServer listening on {}", self.addr);

		axum::Server::bind(&self.addr)
			.serve(app.into_make_service())
			.await
			.unwrap();
	}

	/// Health route handler.
	async fn host_health(
		Extension(_state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		println!("Host health...");
		Html("Ok!")
	}

	/// Health route handler.
	async fn enclave_health(
		Extension(state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		println!("Enclave health...");

		let encoded_request = ProtocolMsg::StatusRequest
			.try_to_vec()
			.expect("ProtocolMsg can always serialize. qed.");
		let encoded_response = state.enclave_client.send(&encoded_request);

		let decoded_response = match encoded_response {
			Ok(encoded_response) => {
				match ProtocolMsg::try_from_slice(&encoded_response) {
					Ok(resp) => resp,
					Err(_) => {
						return (
							StatusCode::INTERNAL_SERVER_ERROR,
							Html(
								"Error decoding response from enclave"
									.to_string(),
							),
						)
					}
				}
			}
			Err(_) => {
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Html("Enclave request failed".to_string()),
				)
			}
		};

		match decoded_response {
			ProtocolMsg::StatusResponse(phase) => {
				let inner = format!("{:?}", phase);
				let status = match phase {
					ProtocolPhase::UnrecoverableError
					| ProtocolPhase::WaitingForBootInstruction
					| ProtocolPhase::WaitingForQuorumShards => StatusCode::SERVICE_UNAVAILABLE,
					ProtocolPhase::QuorumKeyProvisioned => StatusCode::OK,
				};

				(status, Html(inner))
			}
			other => {
				let inner = format!("Unexpected response: {:?}", other);
				(StatusCode::INTERNAL_SERVER_ERROR, Html(inner))
			}
		}
	}

	/// Message route handler.
	async fn message(
		encoded_request: Bytes,
		Extension(state): Extension<Arc<State>>,
	) -> impl IntoResponse {
		if encoded_request.len() > MAX_ENCODED_MSG_LEN {
			return (
				StatusCode::BAD_REQUEST,
				ProtocolMsg::ProtocolErrorResponse(ProtocolError::OversizeMsg)
					.try_to_vec()
					.expect("ProtocolMsg can always serialize. qed."),
			);
		}

		match state.enclave_client.send(&encoded_request) {
			Ok(encoded_response) => (StatusCode::OK, encoded_response),
			Err(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::EnclaveClient,
				)
				.try_to_vec()
				.expect("ProtocolMsg can always serialize. qed."),
			),
		}
	}
}

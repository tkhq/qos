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
	extract::{DefaultBodyLimit, State},
	http::StatusCode,
	response::{Html, IntoResponse},
	routing::{get, post},
	Router,
};
use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	client::Client,
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::{
		msg::ProtocolMsg, ProtocolError, ProtocolPhase,
		ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
	},
};

pub mod cli;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 256 * MEGABYTE;
const QOS_SOCKET_CLIENT_TIMEOUT_SECS: i64 =
	ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS + 2;

/// Resource shared across tasks in the [`HostServer`].
#[derive(Debug)]
struct QosHostState {
	enclave_client: Client,
}

/// HTTP server for the host of the enclave; proxies requests to the enclave.
pub struct HostServer {
	enclave_addr: SocketAddress,
	addr: SocketAddr,
	base_path: Option<String>,
}

const HOST_HEALTH: &str = "/host-health";
const ENCLAVE_HEALTH: &str = "/enclave-health";
const MESSAGE: &str = "/message";

impl HostServer {
	/// Create a new [`HostServer`]. See [`Self::serve`] for starting the
	/// server.
	#[must_use]
	pub fn new(
		enclave_addr: SocketAddress,
		addr: SocketAddr,
		base_path: Option<String>,
	) -> Self {
		Self { enclave_addr, addr, base_path }
	}

	fn path(&self, endpoint: &str) -> String {
		if let Some(path) = self.base_path.as_ref() {
			format!("/{path}{endpoint}")
		} else {
			format!("/qos{endpoint}")
		}
	}

	/// Start the server, running indefinitely.
	///
	/// # Panics
	///
	/// Panics if there is an issue starting the server.
	// pub async fn serve(&self) -> Result<(), String> {
	pub async fn serve(&self) {
		let state = Arc::new(QosHostState {
			enclave_client: Client::new(
				self.enclave_addr.clone(),
				TimeVal::seconds(QOS_SOCKET_CLIENT_TIMEOUT_SECS),
			),
		});

		let app = Router::new()
			.route(&self.path(HOST_HEALTH), get(Self::host_health))
			.route(&self.path(ENCLAVE_HEALTH), get(Self::enclave_health))
			.route(&self.path(MESSAGE), post(Self::message))
			.layer(DefaultBodyLimit::disable())
			.with_state(state);

		println!("HostServer listening on {}", self.addr);

		axum::Server::bind(&self.addr)
			.serve(app.into_make_service())
			.await
			.unwrap();
	}

	/// Health route handler.
	async fn host_health(_: State<Arc<QosHostState>>) -> impl IntoResponse {
		println!("Host health...");
		Html("Ok!")
	}

	/// Health route handler.
	async fn enclave_health(
		State(state): State<Arc<QosHostState>>,
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
				let inner = format!("{phase:?}");
				let status = match phase {
					ProtocolPhase::UnrecoverableError
					| ProtocolPhase::WaitingForBootInstruction
					| ProtocolPhase::WaitingForQuorumShards
					| ProtocolPhase::WaitingForForwardedKey => StatusCode::SERVICE_UNAVAILABLE,
					ProtocolPhase::QuorumKeyProvisioned
					| ProtocolPhase::GenesisBooted => StatusCode::OK,
				};

				(status, Html(inner))
			}
			other => {
				let inner = format!("Unexpected response: {other:?}");
				(StatusCode::INTERNAL_SERVER_ERROR, Html(inner))
			}
		}
	}

	/// Message route handler.
	async fn message(
		State(state): State<Arc<QosHostState>>,
		encoded_request: Bytes,
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

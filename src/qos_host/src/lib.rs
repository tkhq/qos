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
		let encoded_response = match state.enclave_client.send(&encoded_request)
		{
			Ok(encoded_response) => encoded_response,
			Err(e) => {
				let msg = format!("Error while trying to send socket request to enclave: {e:?}");
				eprintln!("{msg}");
				return (StatusCode::INTERNAL_SERVER_ERROR, Html(msg));
			}
		};

		let response = match ProtocolMsg::try_from_slice(&encoded_response) {
			Ok(r) => r,
			Err(e) => {
				let msg = format!("Error deserializing response from enclave, make sure qos_host version match qos_core: {e}");
				eprintln!("{msg}");
				return (StatusCode::INTERNAL_SERVER_ERROR, Html(msg));
			}
		};

		match response {
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
				let msg = format!("Unexpected response: Expected a ProtocolMsg::StatusResponse, but got: {other:?}");
				eprintln!("{msg}");
				(StatusCode::INTERNAL_SERVER_ERROR, Html(msg))
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

		let req = encoded_request.clone().to_vec();
		match ProtocolMsg::deserialize(&mut &req[..]) {
			Ok(m) => println!("[qos host: /message] sending valid protocol msg: {m:?}"),
			Err(e) =>println!("[qos host: /message] sending BAD protocol msg with err: {e}"),

		};
		match state.enclave_client.send(&encoded_request) {
			Ok(encoded_response) => (StatusCode::OK, encoded_response),
			Err(e) => {
				let msg = format!("[qos host: /message] Error while trying to send request over socket to enclave: {e:?}");
				eprintln!("{msg}");

				(
					StatusCode::INTERNAL_SERVER_ERROR,
					ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::EnclaveClient,
					)
					.try_to_vec()
					.expect("ProtocolMsg can always serialize. qed."),
				)
			}
		}
	}
}

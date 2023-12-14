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
	response::{Html, IntoResponse, Response},
	routing::{get, post},
	Json, Router,
};
use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::{
	client::Client,
	io::{SocketAddress, TimeVal, TimeValLike},
	protocol::{
		msg::ProtocolMsg, services::boot::ManifestEnvelope, Hash256,
		ProtocolError, ProtocolPhase, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS,
	},
};

pub mod cli;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 256 * MEGABYTE;
const QOS_SOCKET_CLIENT_TIMEOUT_SECS: i64 =
	ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS + 2;

/// Simple error that implements [`IntoResponse`] so it can
/// be returned from handlers as an http response (and not get silently
/// dropped).
struct Error(String);

impl IntoResponse for Error {
	fn into_response(self) -> Response {
		let body = JsonError { error: self.0 };
		eprintln!("qos_host error: {body:?}");

		// In the future we may want to change `Error` into an enum
		// indicating what status code to use. For now it will always be
		// an internal error since we don't need to express other error types.
		(StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
	}
}

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
const ENCLAVE_INFO: &str = "/enclave-info";

/// Response body to the `/enclave-info` endpoint.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveInfo {
	/// Current phase of the enclave.
	pub phase: ProtocolPhase,
	/// Manifest envelope in the enclave.
	pub manifest_envelope: Option<ManifestEnvelope>,
}

/// Vitals we just use for logging right now to avoid logging the entire
/// manifest.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveVitalStats {
	phase: ProtocolPhase,
	namespace: String,
	nonce: u32,
	#[serde(with = "qos_hex::serde")]
	pivot_hash: Hash256,
	#[serde(with = "qos_hex::serde")]
	pcr0: Vec<u8>,
	pivot_args: Vec<String>,
}

/// Body of a 4xx or 5xx response
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct JsonError {
	/// Error message.
	pub error: String,
}

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
			.route(&self.path(ENCLAVE_INFO), get(Self::enclave_info))
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
					| ProtocolPhase::WaitingForForwardedKey
					| ProtocolPhase::ReshardWaitingForQuorumShards
					| ProtocolPhase::UnrecoverableReshardFailedBadShares => {
						StatusCode::SERVICE_UNAVAILABLE
					}
					ProtocolPhase::QuorumKeyProvisioned
					| ProtocolPhase::GenesisBooted
					| ProtocolPhase::ReshardBooted => StatusCode::OK,
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

	async fn enclave_info(
		State(state): State<Arc<QosHostState>>,
	) -> Result<Json<EnclaveInfo>, Error> {
		println!("Enclave info...");

		let enc_status_req = ProtocolMsg::StatusRequest
			.try_to_vec()
			.expect("ProtocolMsg can always serialize. qed.");
		let enc_status_resp = state.enclave_client.send(&enc_status_req)
			.map_err(|e|
				Error(format!("error deserializing status response from enclave, make sure qos_host version match qos_core: {e:?}"))
			)?;

		let status_resp = match ProtocolMsg::try_from_slice(&enc_status_resp) {
			Ok(status_resp) => status_resp,
			Err(e) => {
				return Err(Error(format!("error deserializing status response from enclave, make sure qos_host version match qos_core: {e:?}")));
			}
		};
		let phase = match status_resp {
			ProtocolMsg::StatusResponse(phase) => phase,
			other => {
				return Err(Error(format!("unexpected response: expected a ProtocolMsg::StatusResponse, but got: {other:?}")));
			}
		};

		let enc_manifest_envelope_req = ProtocolMsg::ManifestEnvelopeRequest
			.try_to_vec()
			.expect("ProtocolMsg can always serialize. qed.");
		let enc_manifest_envelope_resp = state
			.enclave_client
			.send(&enc_manifest_envelope_req)
			.map_err(|e|
				Error(format!("error while trying to send manifest envelope socket request to enclave: {e:?}"))
			)?;

		let manifest_envelope_resp = ProtocolMsg::try_from_slice(
			&enc_manifest_envelope_resp,
		)
		.map_err(|e|
			Error(format!("error deserializing manifest envelope response from enclave, make sure qos_host version match qos_core: {e}"))
		)?;

		let manifest_envelope = match manifest_envelope_resp {
			ProtocolMsg::ManifestEnvelopeResponse { manifest_envelope } => {
				*manifest_envelope
			}
			other => {
				return Err(
					Error(format!("unexpected response: expected a ProtocolMsg::ManifestEnvelopeResponse, but got: {other:?}"))
				);
			}
		};

		let vitals_log = if let Some(m) = manifest_envelope.as_ref() {
			serde_json::to_string(&EnclaveVitalStats {
				phase,
				namespace: m.manifest.namespace.name.clone(),
				nonce: m.manifest.namespace.nonce,
				pivot_hash: m.manifest.pivot.hash,
				pcr0: m.manifest.enclave.pcr0.clone(),
				pivot_args: m.manifest.pivot.args.clone(),
			})
			.expect("always valid json. qed.")
		} else {
			serde_json::to_string(&phase).expect("always valid json. qed.")
		};
		println!("{vitals_log}");

		let info = EnclaveInfo { phase, manifest_envelope };

		Ok(Json(info))
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
			Err(e) => {
				let msg = format!("Error while trying to send request over socket to enclave: {e:?}");
				eprint!("{msg}");

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

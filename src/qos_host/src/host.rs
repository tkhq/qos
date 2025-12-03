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

use std::{
	net::{Ipv4Addr, SocketAddr},
	sync::Arc,
	time::Duration,
};

use axum::{
	body::Bytes,
	extract::{DefaultBodyLimit, State},
	http::StatusCode,
	response::{Html, IntoResponse},
	routing::{get, post},
	Json, Router,
};
use borsh::BorshDeserialize;
use qos_core::{
	client::SocketClient,
	io::{HostBridge, SocketAddress, StreamPool},
	protocol::{msg::ProtocolMsg, ProtocolError, ProtocolPhase},
};
use qos_nsm::types::NsmResponse;

use crate::{
	EnclaveInfo, EnclaveVitalStats, Error, ENCLAVE_HEALTH, ENCLAVE_INFO,
	HOST_HEALTH, MAX_ENCODED_MSG_LEN, MESSAGE,
};

/// Resource shared across tasks in the `HostServer`.
#[derive(Debug)]
struct QosHostState {
	enclave_address: SocketAddress,
	enclave_client: SocketClient,
	enable_host_bridge: bool,
}

/// HTTP server for the host of the enclave; proxies requests to the enclave.
#[allow(clippy::module_name_repetitions)]
pub struct HostServer {
	enclave_address: SocketAddress,
	timeout: Duration,
	addr: SocketAddr,
	base_path: Option<String>,
	enable_host_bridge: bool,
}

impl HostServer {
	/// Create a new `HostServer`. See `Self::serve` for starting the server.
	/// Uses `enclave_pool` to connect to the enclave for commands and `app_socket` to create
	/// a tcp to VSOCK bridge after the pivot is accepted if the `enable_host_bridge` is set to `true`.
	#[must_use]
	pub fn new(
		enclave_address: SocketAddress,
		timeout: Duration,
		addr: SocketAddr,
		base_path: Option<String>,
		enable_host_bridge: bool,
	) -> Self {
		Self { enclave_address, timeout, addr, base_path, enable_host_bridge }
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
	pub async fn serve(self) {
		let state = Arc::new(QosHostState {
			enclave_address: self.enclave_address.clone(),
			enclave_client: SocketClient::single(
				self.enclave_address.clone(),
				self.timeout,
			)
			.expect("unable to create enclave socket client"),
			enable_host_bridge: self.enable_host_bridge,
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
	#[allow(clippy::unused_async)]
	async fn host_health(_: State<Arc<QosHostState>>) -> impl IntoResponse {
		println!("Host health...");
		Html("Ok!")
	}

	/// Health route handler.
	async fn enclave_health(
		State(state): State<Arc<QosHostState>>,
	) -> impl IntoResponse {
		println!("Enclave health...");

		let encoded_request = borsh::to_vec(&ProtocolMsg::StatusRequest)
			.expect("ProtocolMsg can always serialize. qed.");
		let encoded_response = match state
			.enclave_client
			.call(&encoded_request)
			.await
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

	async fn enclave_info(
		State(state): State<Arc<QosHostState>>,
	) -> Result<Json<EnclaveInfo>, Error> {
		println!("Enclave info...");

		let enc_status_req = borsh::to_vec(&ProtocolMsg::StatusRequest)
			.expect("ProtocolMsg can always serialize. qed.");
		let enc_status_resp =
			state.enclave_client.call(&enc_status_req).await.map_err(|e| {
				Error(format!("error sending status request to enclave: {e:?}"))
			})?;

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

		let enc_manifest_envelope_req =
			borsh::to_vec(&ProtocolMsg::ManifestEnvelopeRequest)
				.expect("ProtocolMsg can always serialize. qed.");
		let enc_manifest_envelope_resp = state
			.enclave_client
			.call(&enc_manifest_envelope_req)
			.await
			.map_err(|e| {
				Error(format!(
					"error while trying to send manifest envelope socket request to enclave: {e:?}"
				))
			})?;

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
				borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
					ProtocolError::OversizeMsg,
				))
				.expect("ProtocolMsg can always serialize. qed."),
			);
		}

		match state.enclave_client.call(&encoded_request).await {
			Ok(encoded_response) => {
				if state.enable_host_bridge {
					maybe_start_app_host_bridge(
						&state.enclave_address,
						&encoded_request,
						&encoded_response,
					)
					.await;
				}
				(StatusCode::OK, encoded_response)
			}
			Err(e) => {
				eprintln!("Error while trying to send request over socket to enclave: {e:?}");

				(
					StatusCode::INTERNAL_SERVER_ERROR,
					borsh::to_vec(&ProtocolMsg::ProtocolErrorResponse(
						ProtocolError::EnclaveClient,
					))
					.expect("ProtocolMsg can always serialize. qed."),
				)
			}
		}
	}
}

// Start the tcp -> vsock `HostBridge` in case we have successfully processed the manifest
async fn maybe_start_app_host_bridge(
	enclave_socket: &SocketAddress,
	encoded_request: &Bytes,
	encoded_response: &[u8],
) {
	if let Ok(decoded_msg) = borsh::from_slice::<ProtocolMsg>(encoded_request) {
		// if we got the pivot and it was accepted by the enclave, we should start the tcp -> vsock host bridge
		match decoded_msg {
			ProtocolMsg::BootStandardRequest {
				manifest_envelope,
				pivot: _,
			}
			| ProtocolMsg::BootKeyForwardRequest {
				manifest_envelope,
				pivot: _,
			} => {
				if let Ok(decoded_msg) =
					borsh::from_slice::<ProtocolMsg>(encoded_response)
				{
					// check if we got success
					match decoded_msg {
						ProtocolMsg::BootStandardResponse { nsm_response }
						| ProtocolMsg::BootKeyForwardResponse {
							nsm_response,
						} => {
							if let NsmResponse::Error(_) = nsm_response {
								return; // do not run bridge if we got an error back
							}
						}
						_ => {
							// this really shouldn't happen
							eprintln!("mismatched boot response, tcp to vsock bridge might not start");
							return;
						}
					};
				} else {
					eprintln!("error decoding response msg, tcp to vsock bridge might not start");
					return;
				}

				let pool_size =
					manifest_envelope.manifest.pool_size.unwrap_or(1);
				let host_port = manifest_envelope.manifest.app_host_port;
				let host_addr =
					SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), host_port);

				// derive the app socket, for vsock just use the app host port with same CID as the enclave socket,
				// with usock just add ".appsock" suffix
				let app_socket = match enclave_socket.with_port(host_port) {
					Ok(value) => value,
					Err(err) => {
						eprintln!("unable to derive app socket from enclave socket: {err:?}, tcp to vsock bridge will not start");
						return;
					}
				};

				let app_pool = match StreamPool::new(app_socket, pool_size) {
					Ok(value) => value,
					Err(err) => {
						eprintln!("unable to create new app socket pool: {err:?}, tcp to vsock bridge will not start");
						return;
					}
				};

				let bridge = HostBridge::new(app_pool, host_addr);

				bridge.tcp_to_vsock().await; // NOTE: this doesn't await for completion
			}
			_ => {}
		}
	} else {
		eprintln!(
			"error decoding request msg, tcp to vsock bridge might not start"
		);
	}
}

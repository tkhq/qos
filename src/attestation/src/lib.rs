//! Services for fetching attestation documents from QOS hosts. Intended to be added to secure app
//! hosts.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use borsh::BorshDeserialize;
use generated::services::attestation::v1::attestation_service_server::{
	AttestationService, AttestationServiceServer,
};
use generated::services::attestation::v1::{
	GetAttestationRequest, GetAttestationResponse,
};
use generated::tonic;
use qos_core::{
	client::Client as SocketClient, io::SocketAddress,
	protocol::msg::ProtocolMsg,
};
use qos_host_primitives::enclave_client_timeout;
use qos_nsm::types::NsmResponse;

/// Attestation service for fetching enclave documents via an
/// app host.
pub struct Attestation {
	client: SocketClient,
}

impl Attestation {
	/// Create a new instance of [`Self`], with the given enclave
	/// (`enclave_addr`).
	#[must_use]
	pub fn build_service(
		enclave_addr: SocketAddress,
	) -> AttestationServiceServer<Attestation> {
		let inner = Self {
			client: SocketClient::new(enclave_addr, enclave_client_timeout()),
		};
		AttestationServiceServer::new(inner)
	}
}

/// Something that can fetch an attestation document from an app over a socket client.
pub trait AttestationFetchable: Clone {
	/// Perform a health check on a enclave app.
	fn get_attestation(
		&self,
		_request: tonic::Request<GetAttestationRequest>,
	) -> Result<tonic::Response<GetAttestationResponse>, tonic::Status>;
}

#[tonic::async_trait]
impl AttestationService for Attestation {
	async fn get_attestation(
		&self,
		_request: tonic::Request<GetAttestationRequest>,
	) -> Result<tonic::Response<GetAttestationResponse>, tonic::Status> {
		let encoded_request =
			borsh::to_vec(&ProtocolMsg::LiveAttestationDocRequest)
				.expect("ProtocolMsg can always serialize. qed.");

		let encoded_response = self
			.client
			.send(&encoded_request)
			.map_err(|e| tonic::Status::internal(format!("{e:?}")))?;

		let decoded_response =
			ProtocolMsg::try_from_slice(&encoded_response)
				.map_err(|e| tonic::Status::internal(format!("{e:?}")))?;

		match decoded_response {
			ProtocolMsg::LiveAttestationDocResponse {
				nsm_response, ..
			} => {
				match nsm_response {
					NsmResponse::Attestation { document } => {
						Ok(tonic::Response::new(GetAttestationResponse {
							// parse or destructure nsm_response into NsmResponse
							attestation_document: document,
						}))
					}
					other => Err(tonic::Status::internal(format!(
						"Unexpected nsm response type: {other:?}",
					))),
				}
			}
			other => Err(tonic::Status::internal(format!(
				"Unexpected enclave response: {other:?}",
			))),
		}
	}
}

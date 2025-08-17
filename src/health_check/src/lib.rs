//! Services for health checking QOS hosts. Intended to be adding to secure app
//! hosts.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use borsh::BorshDeserialize;
use generated::grpc::health::v1::{
    HealthCheckRequest as K8HealthCheckRequest, HealthCheckResponse as K8HealthCheckResponse,
    health_check_response::ServingStatus as K8ServingStatus,
    health_server::{Health as K8HealthService, HealthServer as K8HealthServer},
};
use generated::health::health_check_service_server::{
    HealthCheckService, HealthCheckServiceServer,
};
use generated::health::{
    AppHealthRequest, AppHealthResponse, EnclaveHealthRequest, EnclaveHealthResponse,
    HostHealthRequest, HostHealthResponse,
};
use generated::tonic;
use qos_host_primitives::enclave_client_timeout;
use qos_core::{
    client::Client as SocketClient,
    io::SocketAddress,
    protocol::{ProtocolPhase, msg::ProtocolMsg},
};
use std::{pin::Pin, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::Stream;

const WATCH_STREAM_TIMEOUT_SEC: u64 = 3;
const STREAM_MSG_BUFFER_MAX: usize = 16;
/// k8s terminology to check if a service is up, but not necessarily ready to serve traffic.
pub const LIVENESS: &str = "liveness";
/// k8s terminology to check if a service is ready to serve traffic.
pub const READINESS: &str = "readiness";

/// Turnkeys health check service for performing primitive health checks via an
/// app host.
pub struct TkHealthCheck<T> {
    client: SocketClient,
    app_check: T,
}

impl<T> TkHealthCheck<T>
where
    T: AppHealthCheckable + Send + Sync + 'static,
{
    /// Create a new instance of [`Self`], with the given enclave
    /// (`enclave_addr`).
    #[must_use]
    pub fn build_service(
        enclave_addr: SocketAddress,
        app_check: T,
    ) -> HealthCheckServiceServer<TkHealthCheck<T>> {
        let inner = Self {
            client: SocketClient::new(enclave_addr, enclave_client_timeout()),
            app_check,
        };
        HealthCheckServiceServer::new(inner)
    }
}

/// Something that can perform a health check on an app over a socket client.
pub trait AppHealthCheckable: Clone {
    /// Perform a health check on a enclave app.
    fn app_health_check(&self) -> Result<tonic::Response<AppHealthResponse>, tonic::Status>;
}

#[tonic::async_trait]
impl<T> HealthCheckService for TkHealthCheck<T>
where
    T: AppHealthCheckable + Send + Sync + 'static,
{
    async fn host_health(
        &self,
        _request: tonic::Request<HostHealthRequest>,
    ) -> Result<tonic::Response<HostHealthResponse>, tonic::Status> {
        let response = HostHealthResponse { code: 200 };
        Ok(tonic::Response::new(response))
    }

    async fn enclave_health(
        &self,
        _request: tonic::Request<EnclaveHealthRequest>,
    ) -> Result<tonic::Response<EnclaveHealthResponse>, tonic::Status> {
        let encoded_request = borsh::to_vec(&ProtocolMsg::StatusRequest)
            .expect("ProtocolMsg can always serialize. qed.");

        let encoded_response = self
            .client
            .send(&encoded_request)
            .map_err(|e| tonic::Status::internal(format!("{e:?}")))?;

        let decoded_response = ProtocolMsg::try_from_slice(&encoded_response)
            .map_err(|e| tonic::Status::internal(format!("{e:?}")))?;

        match decoded_response {
            ProtocolMsg::StatusResponse(phase) => match phase {
                ProtocolPhase::UnrecoverableError
                | ProtocolPhase::WaitingForBootInstruction
                | ProtocolPhase::WaitingForQuorumShards
                | ProtocolPhase::WaitingForForwardedKey
                | ProtocolPhase::GenesisBooted => Err(tonic::Status::unavailable(format!(
                    "Enclave status {phase:?}"
                ))),
                ProtocolPhase::QuorumKeyProvisioned => {
                    Ok(tonic::Response::new(EnclaveHealthResponse {
                        phase: format!("{phase:?}"),
                    }))
                }
            },
            other => Err(tonic::Status::internal(format!(
                "Unexpected enclave response: {other:?}",
            ))),
        }
    }

    async fn app_health(
        &self,
        _request: tonic::Request<AppHealthRequest>,
    ) -> Result<tonic::Response<AppHealthResponse>, tonic::Status> {
        self.app_check.app_health_check()
    }
}

/// GRPC Health Checking Protocol
/// <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>
#[derive(Clone)]
pub struct K8Health<T> {
    app_check: T,
}

impl<T> K8Health<T>
where
    T: AppHealthCheckable + Send + Sync + 'static,
{
    /// Create a new instance of [`Self`], with the given enclave
    /// (`enclave_addr`).
    #[must_use]
    pub fn build_service(app_check: T) -> K8HealthServer<K8Health<T>> {
        let inner = Self { app_check };
        K8HealthServer::new(inner)
    }

    fn app_status(&self) -> K8ServingStatus {
        match self
            .app_check
            .app_health_check()
            .map(|resp| match resp.into_inner().code {
                200 => K8ServingStatus::Serving,
                _ => K8ServingStatus::NotServing,
            })
            .map_err(|_status| K8ServingStatus::NotServing)
        {
            Ok(s) | Err(s) => s,
        }
    }

    fn k8_request(&self, request: &tonic::Request<K8HealthCheckRequest>) -> K8HealthCheckResponse {
        let status = match request.get_ref().service.as_str() {
            LIVENESS => K8ServingStatus::Serving,
            READINESS => self.app_status(),
            _ => K8ServingStatus::ServiceUnknown,
        };

        K8HealthCheckResponse {
            status: status as i32,
        }
    }
}

type ResponseStream =
    Pin<Box<dyn Stream<Item = Result<K8HealthCheckResponse, tonic::Status>> + Send>>;

#[tonic::async_trait]
impl<T> K8HealthService for K8Health<T>
where
    T: AppHealthCheckable + Send + Sync + 'static,
{
    async fn check(
        &self,
        request: tonic::Request<K8HealthCheckRequest>,
    ) -> std::result::Result<tonic::Response<K8HealthCheckResponse>, tonic::Status> {
        Ok(tonic::Response::new(self.k8_request(&request)))
    }

    type WatchStream = ResponseStream;

    async fn watch(
        &self,
        request: tonic::Request<K8HealthCheckRequest>,
    ) -> std::result::Result<tonic::Response<Self::WatchStream>, tonic::Status> {
        let (tx, rx) = mpsc::channel(STREAM_MSG_BUFFER_MAX);
        let self2 = self.clone();
        tokio::spawn(async move {
            loop {
                let status = self2.k8_request(&request);
                match tx.send(Ok(status)).await {
                    Ok(()) => {
                        // `status` was queued to be sent to the gRPC client
                    }
                    Err(_) => {
                        // `output_stream` was dropped, meaning the gRPC client
                        // connection closed. Since `output_stream` was built with
                        // `rx`, `tx.send` will error once `output_stream` (and
                        // therefore also `rx`) is dropped.
                        break;
                    }
                }

                tokio::time::sleep(Duration::from_secs(WATCH_STREAM_TIMEOUT_SEC)).await;
            }
        });

        let output_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        Ok(tonic::Response::new(
            Box::pin(output_stream) as Self::WatchStream
        ))
    }
}

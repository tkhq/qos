//! Reshard Host.
use generated::health::{AppHealthRequest, AppHealthResponse};
use generated::{
    services::reshard::v1::{
        qos_retrieve_reshard_request, qos_retrieve_reshard_response,
        reshard_service_server, QosRetrieveReshardRequest,
        QosRetrieveReshardResponse, RetrieveReshardRequest,
        RetrieveReshardResponse,
    },
	tonic::{self, Request, Response, Status},
};
use health_check::AppHealthCheckable;
use metrics::request;
use qos_core::{client::Client as SocketClient, io::SocketAddress};
use qos_host_primitives::{enclave_client_timeout, GRPC_MAX_RECV_MSG_SIZE};
use std::{
	sync::mpsc::{sync_channel, SyncSender},
	thread,
	time::Instant,
};

use tokio::sync::oneshot::{self, Sender};
use tokio::{
	signal::unix::{signal, SignalKind},
	spawn,
};

type SocketMessage = qos_host_primitives::SocketMessage<
	QosRetrieveReshardRequest,
	QosRetrieveReshardResponse,
>;

/// Host `gRPC` server.f
#[derive(Debug)]
pub struct Host {
	response_channel: SyncSender<SocketMessage>,
}

impl Host {
	fn new(response_channel: SyncSender<SocketMessage>) -> Self {
		Self { response_channel }
	}

	/// Start the host server.
	pub async fn listen(
		listen_addr: std::net::SocketAddr,
		enclave_addr: SocketAddress,
	) -> Result<(), tonic::transport::Error> {
		let reflection_service =
			gen::tonic_reflection::server::Builder::configure()
				.register_encoded_file_descriptor_set(gen::FILE_DESCRIPTOR_SET)
				.build()
				.expect("failed to start reflection service");

		let (response_channel, receiver) = sync_channel::<SocketMessage>(
			qos_host_primitives::SOCKET_MESSAGE_QUEUE_BUFFER_SIZE,
		);

		let app_checker =
			ReshardHealth { response_channel: response_channel.clone() };
		let health_check_service = health_check::TkHealthCheck::build_service(
			enclave_addr.clone(),
			app_checker.clone(),
		);
		let k8_health_service =
			health_check::K8Health::build_service(app_checker);
		let attestation_service =
			attestation::TkAttestation::build_service(enclave_addr.clone());

		let host = Host::new(response_channel);

		thread::spawn(move || {
			let client =
				SocketClient::new(enclave_addr, enclave_client_timeout());

			loop {
				let SocketMessage { request, replier } =
					receiver.recv().expect("failed to receiver message");

				let enclave_resp =
					qos_host_primitives::send_proxy_request(request, &client);

				replier.send(enclave_resp).expect("message processor failed");
			}
		});

		println!("HostServer listening on {listen_addr}");

		let (sigterm_sender, sigterm_receiver) = oneshot::channel();
		spawn(Self::wait_for_sigterm(sigterm_sender));

		tonic::transport::Server::builder()
			.add_service(reflection_service)
			.add_service(
				reshard_service_server::ReshardServiceServer::new(host)
					.max_decoding_message_size(GRPC_MAX_RECV_MSG_SIZE),
			)
			.add_service(health_check_service)
			.add_service(attestation_service)
			.add_service(k8_health_service)
			.serve_with_shutdown(listen_addr, async {
				sigterm_receiver.await.ok();
				println!("SIGTERM received");
			})
			.await
	}

	async fn wait_for_sigterm(sender: Sender<()>) {
		let _ = signal(SignalKind::terminate())
			.expect("failed to create SIGTERM signal handler")
			.recv()
			.await;
		println!("SIGTERM signal handled, forwarding to host server");
		let _ = sender.send(());
	}
}

#[tonic::async_trait]
impl reshard_service_server::ReshardService for Host {
	async fn retrieve_reshard(
		&self,
		request: Request<RetrieveReshardRequest>,
	) -> Result<Response<RetrieveReshardResponse>, Status> {
		let now = Instant::now();

		let request = QosRetrieveReshardRequest {
			input: Some(
				qos_retrieve_reshard_request::Input::RetrieveReshardRequest(
					request.into_inner(),
				),
			),
		};

		let request_decode_elapsed = now.elapsed();

		let now_step = Instant::now();

		let output = qos_host_primitives::send_socket_message(
			request,
			&self.response_channel,
		)
		.map_err(|e| {
			Status::internal(format!(
				"Retrieve reshard: unexpected socket failure: {e:?}"
			))
		})?
		.output
		.ok_or_else(|| {
			Status::internal("QosRetrieveReshardResponse::output was None")
		})?;

		let send_message_elapsed = now_step.elapsed();

		let now_step = Instant::now();

		let response = match output {
			qos_retrieve_reshard_response::Output::RetrieveReshardResponse(
				response,
			) => Ok(Response::new(response)),
			qos_retrieve_reshard_response::Output::Status(status) => {
				Err(Status::from(status))
			}
			_ => Err(Status::internal(format!(
				"Unexpected response from enclave: {output:?}",
			))),
		};

		let response_encode_elapsed = now_step.elapsed();

		request::track_enclave_request(
			"retrieve_reshard",
			response.is_ok(),
			now.elapsed(),
		);
		request::track_enclave_details(
			"retrieve_reshard",
			response.is_ok(),
			"request_decode",
			request_decode_elapsed,
		);
		request::track_enclave_details(
			"retrieve_reshard",
			response.is_ok(),
			"send_message",
			send_message_elapsed,
		);
		request::track_enclave_details(
			"retrieve_reshard",
			response.is_ok(),
			"response_encode",
			response_encode_elapsed,
		);

		response
	}
}

#[derive(Clone)]
struct ReshardHealth {
	response_channel: SyncSender<SocketMessage>,
}

impl AppHealthCheckable for ReshardHealth {
	fn app_health_check(
		&self,
	) -> Result<tonic::Response<AppHealthResponse>, Status> {
		let now = Instant::now();

		let request = QosRetrieveReshardRequest {
			input: Some(qos_retrieve_reshard_request::Input::HealthRequest(
				AppHealthRequest {},
			)),
		};

		let output = qos_host_primitives::send_socket_message(
			request,
			&self.response_channel,
		)
		.map_err(|e| {
			Status::internal(format!(
				"App Health: unexpected socket failure: {e:?}"
			))
		})?
		.output
		.ok_or_else(|| {
			Status::internal("QosReshardResponse::output was None")
		})?;

		let response = match output {
			qos_retrieve_reshard_response::Output::HealthResponse(
				health_response,
			) => Ok(tonic::Response::new(health_response)),
			qos_retrieve_reshard_response::Output::Status(status) => {
				Err(Status::from(status))
			}
			_ => Err(Status::internal(format!(
				"unexpected enclave response: {output:?}"
			))),
		};

		request::track_enclave_request(
			"health",
			response.is_ok(),
			now.elapsed(),
		);

		response
	}
}

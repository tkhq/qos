//! Primitives for building Turnkey secure app gRPC host servers.

#![deny(clippy::all, clippy::unwrap_used)]

use borsh::BorshDeserialize;
use prost::Message;
use qos_core::{
	io::{TimeVal, TimeValLike},
	protocol::{msg::ProtocolMsg, ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS},
};
use std::sync::mpsc::{sync_channel, SyncSender};
use tonic::Status;

pub static SOCKET_MESSAGE_QUEUE_BUFFER_SIZE: usize = 64;

/// Maximum gRPC message size. Set to 25MB (25*1024*1024)
pub static GRPC_MAX_RECV_MSG_SIZE: usize = 26_214_400;

#[derive(Clone)]
pub struct SocketMessage<Req, Resp>
where
	Resp: Message + Default,
	Req: Message,
{
	pub replier: SyncSender<Result<Resp, Status>>,
	pub request: Req,
}

/// Send a message to secure app via socket connection.
pub fn send_socket_message<Req, Resp>(
	request: Req,
	response_channel: &SyncSender<SocketMessage<Req, Resp>>,
) -> Result<Resp, tonic::Status>
where
	Resp: Message + Default,
	Req: Message,
{
	let (replier, receiver) = sync_channel::<Result<Resp, tonic::Status>>(
		SOCKET_MESSAGE_QUEUE_BUFFER_SIZE,
	);

	response_channel.send(SocketMessage { request, replier }).map_err(|e| {
		Status::internal(format!(
			"send_socket_message: unexpected socket failure with error: {e:?}"
		))
	})?;

	receiver.recv().map_err(|e| {
		Status::internal(format!(
			"send_socket_message: failed to get receiver with error: {e:?}"
		))
	})?
}

/// Send a message to a secure app via QOS proxy.
pub fn send_proxy_request<Req, Resp>(
	request: Req,
	client: &qos_core::client::Client,
) -> Result<Resp, tonic::Status>
where
	Resp: Message + Default,
	Req: Message,
{
	let encoded_qos_request = {
		let data = request.encode_to_vec();
		let qos_request = ProtocolMsg::ProxyRequest { data };

		borsh::to_vec(&qos_request).map_err(|e| {
			Status::internal(format!(
				"Failed to serialize qos request: {:?}",
				e
			))
		})?
	};

	let encoded_qos_response =
		client.send(&encoded_qos_request).map_err(|e| {
			Status::internal(format!("Failed to query enclave: {:?}", e))
		})?;
	let qos_response = ProtocolMsg::try_from_slice(&encoded_qos_response)
		.map_err(|e| {
			Status::internal(format!(
				"Failed to deserialized enclave response: {:?}",
				e
			))
		})?;

	let encoded_app_response = match qos_response {
		ProtocolMsg::ProxyResponse { data } => data,
		other => {
			return Err(Status::internal(format!(
				"Expected a ProtocolMsg::ProxyResponse but got {:?}",
				other
			)));
		}
	};

	Resp::decode(&*encoded_app_response).map_err(|e| {
		Status::internal(format!(
			"Failed to deserialize enclave response: {:?}",
			e
		))
	})
}

/// A default timeout for hosts to configure their qos protocol socket client with.
pub fn enclave_client_timeout() -> TimeVal {
	TimeVal::seconds(ENCLAVE_APP_SOCKET_CLIENT_TIMEOUT_SECS * 2)
}

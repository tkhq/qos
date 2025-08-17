//! Service
use crate::routes;
use errors::{Status, TurnkeyError};
use gen::services::{
	health_check::v1::AppHealthResponse,
	reshard::v1::{
		qos_retrieve_reshard_request, qos_retrieve_reshard_response,
		QosRetrieveReshardRequest, QosRetrieveReshardResponse,
	},
};
use qos_core::{handles::QuorumKeyHandle, server::RequestProcessor};

pub struct ReshardProcessor {
	handle: QuorumKeyHandle,
	nsm: Box<dyn qos_nsm::NsmProvider>,
}

impl ReshardProcessor {
	pub fn new(
		handle: QuorumKeyHandle,
		nsm: Box<dyn qos_nsm::NsmProvider>,
	) -> Self {
		Self { handle, nsm }
	}
}

impl RequestProcessor for ReshardProcessor {
	#[allow(clippy::too_many_lines)]
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		use gen::prost::Message as _;

		let reshard_request = match QosRetrieveReshardRequest::decode(&*request)
			.map_err(TurnkeyError::from)
			.map_err(Status::from)
			.map_err(qos_retrieve_reshard_response::Output::Status)
			.map_err(|output| QosRetrieveReshardResponse {
				output: Some(output),
			}) {
			Ok(req) => req,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};

		let quorum_key = match self
			.handle
			.get_quorum_key()
			.map_err(|err| {
				TurnkeyError::internal(&format!(
					"unable to get quorum key: {err:?}"
				))
			})
			.map_err(Status::from)
			.map_err(qos_retrieve_reshard_response::Output::Status)
			.map_err(|output| QosRetrieveReshardResponse {
				output: Some(output),
			}) {
			Ok(result) => result,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};

		let input = match reshard_request
			.input
			.ok_or_else(|| TurnkeyError::internal("missing request input"))
			.map_err(Status::from)
			.map_err(qos_retrieve_reshard_response::Output::Status)
			.map_err(|output| QosRetrieveReshardResponse {
				output: Some(output),
			}) {
			Ok(input) => input,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};

		let output = match input {
			qos_retrieve_reshard_request::Input::RetrieveReshardRequest(
				reshard_request,
			) => {
				match routes::retrieve_reshard::retrieve_reshard(&reshard_request, &quorum_key, &*self.nsm)
                    .map(qos_retrieve_reshard_response::Output::RetrieveReshardResponse)
                    .map_err(Status::from)
                    .map_err(qos_retrieve_reshard_response::Output::Status)
                {
                    Ok(o) | Err(o) => o,
                }
			}
			qos_retrieve_reshard_request::Input::HealthRequest(_) => {
				qos_retrieve_reshard_response::Output::HealthResponse(
					AppHealthResponse { code: 200 },
				)
			}
		};

		QosRetrieveReshardResponse { output: Some(output) }.encode_to_vec()
	}
}

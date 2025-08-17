//! Service
use crate::routes;
// use errors::{Status, TurnkeyError};
use generated::{
	google::rpc::{Status, Code}, health::AppHealthResponse, services::reshard::v1::{
		qos_retrieve_reshard_request, qos_retrieve_reshard_response,
		QosRetrieveReshardRequest, QosRetrieveReshardResponse,
	}
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
		use generated::prost::Message as _;

		let reshard_request = match QosRetrieveReshardRequest::decode(&*request)
			.map_err(|e| {
				qos_retrieve_reshard_response::Output::Status(Status {
					code: Code::Internal as i32,
					message: e.to_string(),
					details: vec![],
				})
			})
			.map_err(|o| QosRetrieveReshardResponse { output: Some(o)})
		{
			Ok(reshard_request) => reshard_request,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};
			
		let quorum_key = match self
			.handle
			.get_quorum_key()
			.map_err(|err| {
				qos_retrieve_reshard_response::Output::Status(Status {
					code: Code::Internal as i32,
					message: format!("unable to get quorum key: {err:?}"),
					details: vec![]
				})
			})
			.map_err(|output| QosRetrieveReshardResponse {
				output: Some(output)
			}) {
			Ok(result) => result,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};

		let input = match reshard_request
			.input
			.ok_or({
				qos_retrieve_reshard_response::Output::Status(Status { 
					code: Code::Internal as i32, 
					message: "missing request input".to_string(),
					 details: vec![] })
			})
			.map_err(|o| QosRetrieveReshardResponse { output: Some(o) })
		{
			Ok(input) => input,
			Err(err_resp) => return err_resp.encode_to_vec(),
		};
			
		let output = match input {
			qos_retrieve_reshard_request::Input::RetrieveReshardRequest(
				reshard_request,
			) => {
				match routes::retrieve_reshard::retrieve_reshard(&reshard_request, &quorum_key, &*self.nsm)
                    .map(qos_retrieve_reshard_response::Output::RetrieveReshardResponse)
                    .map_err(|e| {
						qos_retrieve_reshard_response::Output::Status(Status { 
							code: Code::Internal as i32,
                            message: format!("{e:?}"),
                            details: vec![],
						})
					})
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

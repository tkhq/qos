//! Reshard routes

use errors::{Code, TurnkeyError};
use gen::services::reshard::v1::{
	RetrieveReshardRequest, RetrieveReshardResponse,
};
use qos_p256::P256Pair;

// reshards a quorum key
pub fn retrieve_reshard(
	request: &RetrieveReshardRequest,
	quorum_key: &P256Pair,
	nsm: &dyn qos_nsm::NsmProvider,
) -> Result<RetrieveReshardResponse, TurnkeyError> {
	Ok(RetrieveReshardResponse { reshard_bundle: (Vec::new()) })
}

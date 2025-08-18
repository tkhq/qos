//! Reshard routes

use crate::errors::GrpcError;
use crate::service::ReshardBundle;
use generated::services::reshard::v1::{
	RetrieveReshardResponse, 
};

pub fn retrieve_reshard(
    bundle: &ReshardBundle,
) -> Result<RetrieveReshardResponse, GrpcError> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|e| GrpcError::internal(&format!("serialize failed: {e}")))?;

    Ok(RetrieveReshardResponse { reshard_bundle: json })
}

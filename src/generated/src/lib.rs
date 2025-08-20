//! Proto based Rust types.

// We don't wan't to run clippy on generated code.
#![allow(clippy::all)]
// Allow unused imports as they may be used by generated code -- currently it is required for post::Message and google::rpc::Status to work
#![allow(unused_imports)]

// Re-export prost to ensure crate users don't have to have the burden of keeping
// their own prost dep in sync with this crate.
pub use prost;
pub use prost_types;
pub use qos_hex;

use google::rpc::Status;
use prost::Message;

// Tonic version needs to be in sync with prost, so we re-export it here as well.
#[cfg(feature = "tonic_types")]
pub use tonic;
#[cfg(feature = "tonic_types")]
pub use tonic_reflection;

include!("generated/_include.rs");

// Necessary to enable reflection on gRPC server
#[cfg(feature = "tonic_types")]
pub const FILE_DESCRIPTOR_SET: &[u8] =
	include_bytes!("generated/descriptor.bin");

#[cfg(feature = "tonic_types")]
impl From<Status> for tonic::Status {
	fn from(status: Status) -> Self {
		Self::with_details(
			tonic::Code::from_i32(status.code),
			status.message.clone(),
			status.encode_to_vec().into(),
		)
	}
}

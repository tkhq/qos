//! standardized errors for enclaves. We use gRPC in and out of enclaves, so we model a gRPC error here.
use generated::google::rpc::Code;

/// GRPC error type to use in enclave applications
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GrpcError {
    /// the gRPC code
    pub code: Code,
    /// the gRPC message
    pub message: String,
}

impl GrpcError {
    /// creates a new gRPC error to be returned to the caller
    #[must_use]
    pub fn new(code: Code, message: &str) -> Self {
        GrpcError {
            code,
            message: message.to_string(),
        }
    }

    /// creates a new internal error
    #[must_use]
    pub fn internal(message: &str) -> Self {
        Self::new(Code::Internal, message)
    }
}

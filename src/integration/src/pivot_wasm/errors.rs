//! Error types for the WASM meta-pivot demo.

use std::fmt;

use super::protocol::PivotWasmMsg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PivotWasmError {
	Approval(String),
	NotFound(String),
	PolicyDenied(String),
	Runtime(String),
}

impl PivotWasmError {
	pub fn runtime(message: impl Into<String>) -> Self {
		Self::Runtime(message.into())
	}
}

impl fmt::Display for PivotWasmError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Approval(message)
			| Self::NotFound(message)
			| Self::PolicyDenied(message)
			| Self::Runtime(message) => write!(f, "{message}"),
		}
	}
}

impl From<PivotWasmError> for PivotWasmMsg {
	fn from(error: PivotWasmError) -> Self {
		match error {
			PivotWasmError::Approval(message) => {
				PivotWasmMsg::InvalidApproval { message }
			}
			PivotWasmError::PolicyDenied(reason) => {
				PivotWasmMsg::PolicyDenied { reason }
			}
			PivotWasmError::NotFound(message)
			| PivotWasmError::Runtime(message) => PivotWasmMsg::RuntimeError { message },
		}
	}
}

//! Remote protocol error
use std::net::AddrParseError;

use borsh::{BorshDeserialize, BorshSerialize};
use hickory_resolver::error::ResolveError;

/// Errors during protocol execution.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProtocolError {
	/// Error variant encapsulating OS IO errors
	IOError,
	/// Hash of the Pivot binary does not match the pivot configuration in the
	/// manifest.
	InvalidPivotHash,
	/// The message is too large.
	OversizeMsg,
	/// Payload is too big. See `MAX_ENCODED_MSG_LEN` for the upper bound on
	/// message size.
	OversizedPayload,
	/// Message could not be deserialized
	InvalidMsg,
	/// Parsing error with a protocol message component
	ParseError(String),
	/// DNS Resolution error
	DNSResolutionError(String),
	/// Attempt to save a connection with a duplicate ID
	DuplicateConnectionId(u32),
	/// Attempt to send a message to a remote connection, but ID isn't found
	RemoteConnectionIdNotFound(u32),
	/// Attempting to read on a closed remote connection (`.read` returned 0
	/// bytes)
	RemoteConnectionClosed,
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<AddrParseError> for ProtocolError {
	fn from(err: AddrParseError) -> Self {
		let msg = format!("{err:?}");
		Self::ParseError(msg)
	}
}

impl From<ResolveError> for ProtocolError {
	fn from(err: ResolveError) -> Self {
		let msg = format!("{err:?}");
		Self::ParseError(msg)
	}
}

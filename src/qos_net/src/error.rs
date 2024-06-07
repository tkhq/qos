//! Remote protocol error
use std::net::AddrParseError;

use borsh::{BorshDeserialize, BorshSerialize};
use hickory_resolver::error::ResolveError;

/// Errors during protocol execution.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProtocolError {
	/// Error variant encapsulating OS IO errors
	IOError,
	/// Error variant encapsulating OS IO errors
	QOSIOError,
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
	/// Happens if a RemoteRead response has empty data
	RemoteReadEmpty,
	/// Happens if a RemoteRead returns too much data for the provided buffer and the data doesn't fit.
	/// The first `usize` is the size of the received data, the second `usize` is the size of the buffer.
	RemoteReadOverflow(usize, usize),
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<qos_core::io::IOError> for ProtocolError {
	fn from(_err: qos_core::io::IOError) -> Self {
		Self::QOSIOError
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

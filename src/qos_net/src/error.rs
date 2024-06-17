//! qos_net errors related to creating and using proxy connections.
use std::net::AddrParseError;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "proxy")]
use hickory_resolver::error::ResolveError;

/// Errors related to creating and using proxy connections
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum QosNetError {
	/// Error variant encapsulating OS IO errors
	IOError(String),
	/// Error variant encapsulating OS IO errors
	QOSIOError(String),
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
	ConnectionIdNotFound(u32),
	/// Attempting to read on a closed remote connection (`.read` returned 0
	/// bytes)
	ConnectionClosed,
	/// Happens when a socket `read` results in no data
	EmptyRead,
	/// Happens when a socket `read` returns too much data for the provided
	/// buffer and the data doesn't fit. The first `usize` is the size of the
	/// received data, the second `usize` is the size of the buffer.
	ReadOverflow(usize, usize),
	/// Happens when too many connections are opened in the proxy
	TooManyConnections(usize),
}

impl From<std::io::Error> for QosNetError {
	fn from(err: std::io::Error) -> Self {
		let msg = format!("{err:?}");
		Self::IOError(msg)
	}
}

impl From<qos_core::io::IOError> for QosNetError {
	fn from(err: qos_core::io::IOError) -> Self {
		let msg = format!("{err:?}");
		Self::QOSIOError(msg)
	}
}

impl From<AddrParseError> for QosNetError {
	fn from(err: AddrParseError) -> Self {
		let msg = format!("{err:?}");
		Self::ParseError(msg)
	}
}

#[cfg(feature = "proxy")]
impl From<ResolveError> for QosNetError {
	fn from(err: ResolveError) -> Self {
		let msg = format!("{err:?}");
		Self::ParseError(msg)
	}
}

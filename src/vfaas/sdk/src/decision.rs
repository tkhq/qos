//! Policy decision type, mirrored from the host wire protocol.
//!
//! Kept in sync with `integration::Decision` by Borsh layout (same enum order,
//! same variants). The host deserializes the policy's return value as
//! `integration::Decision`.

use borsh::{BorshDeserialize, BorshSerialize};

/// Policy decision returned by an `#[policy]` function.
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Eq, Clone)]
pub enum Decision {
	/// Permit program execution.
	Allow,
	/// Deny program execution with a human-readable reason.
	Deny(String),
}

//! A compliance-shaped vfaas program: screen an address against a
//! sanctions denylist.
//!
//! The denylist is compiled into the WASM, so the artifact's content hash
//! IS the list version: the attestation on every verdict proves exactly
//! which list screened the address. Shipping a list update means building
//! with the `list-v2` feature and registering the new artifact — a fresh
//! quorum approval, no redeployment, and the old list stays registered and
//! auditable under its own hash.

use borsh::{BorshDeserialize, BorshSerialize};
use vfaas_sdk::{Context, program};

/// A request to screen one address.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct Screen {
	/// The address to screen, `0x`-prefixed hex.
	pub address: String,
}

/// Screening result.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum Status {
	/// Not on the denylist.
	Clear,
	/// On the denylist.
	Flagged,
}

/// The verdict on a screened address.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct Verdict {
	/// Echo of the compiled-in list version, for humans. The wasm hash in
	/// the attestation is the proof.
	pub list_version: u32,
	/// Clear or flagged.
	pub status: Status,
}

/// Version of the compiled-in denylist.
#[cfg(not(feature = "list-v2"))]
pub const LIST_VERSION: u32 = 1;
/// Version of the compiled-in denylist.
#[cfg(feature = "list-v2")]
pub const LIST_VERSION: u32 = 2;

#[cfg(not(feature = "list-v2"))]
const DENYLIST: &[&str] = &[
	"0x1111111111111111111111111111111111111111",
	"0x2222222222222222222222222222222222222222",
];

#[cfg(feature = "list-v2")]
const DENYLIST: &[&str] = &[
	"0x1111111111111111111111111111111111111111",
	"0x2222222222222222222222222222222222222222",
	"0x3333333333333333333333333333333333333333",
];

/// Screen an address against the compiled-in denylist,
/// case-insensitively.
#[program]
pub fn screen(_ctx: &Context, request: Screen) -> Verdict {
	let needle = request.address.to_ascii_lowercase();
	let status = if DENYLIST.contains(&needle.as_str()) {
		Status::Flagged
	} else {
		Status::Clear
	};
	Verdict { list_version: LIST_VERSION, status }
}

#[cfg(test)]
mod tests {
	use super::*;
	use vfaas_sdk::testing::mock_context;

	fn verdict(address: &str) -> Verdict {
		screen(&mock_context(), Screen { address: address.to_string() })
	}

	#[test]
	fn clean_address_is_clear() {
		let v = verdict("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
		assert_eq!(v.status, Status::Clear);
	}

	#[test]
	fn listed_address_is_flagged() {
		let v = verdict("0x1111111111111111111111111111111111111111");
		assert_eq!(v.status, Status::Flagged);
	}

	#[test]
	fn matching_is_case_insensitive() {
		let v = verdict(
			"0x2222222222222222222222222222222222222222"
				.to_uppercase()
				.as_str(),
		);
		assert_eq!(v.status, Status::Flagged);
	}

	#[test]
	fn verdict_carries_the_list_version() {
		assert_eq!(verdict("0x0").list_version, LIST_VERSION);
	}

	/// The upgrade-demo beat: `0x3333…` is clear under list v1 and flagged
	/// under list v2.
	#[test]
	fn newly_listed_address_flips_with_list_v2() {
		let v = verdict("0x3333333333333333333333333333333333333333");

		#[cfg(not(feature = "list-v2"))]
		assert_eq!((v.list_version, v.status), (1, Status::Clear));
		#[cfg(feature = "list-v2")]
		assert_eq!((v.list_version, v.status), (2, Status::Flagged));
	}

	#[test]
	fn round_trips_through_borsh() {
		let request = Screen {
			address: "0x1111111111111111111111111111111111111111".into(),
		};
		let bytes = borsh::to_vec(&request).unwrap();
		let back = Screen::try_from_slice(&bytes).unwrap();
		assert_eq!(back, request);
	}
}

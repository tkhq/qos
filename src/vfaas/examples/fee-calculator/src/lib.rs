//! A business-shaped vfaas program: quote the fee for a transaction.
//!
//! This is the kind of logic a customer would actually ship to an enclave:
//! typed input, typed output, a handful of business rules, and ordinary
//! `cargo test` coverage — no unsafe, no FFI, no enclave knowledge.
//!
//! The input/output types are exported so clients (e.g. the demo xtask) can
//! import this crate and Borsh-encode requests against the exact same
//! definitions the enclave runs.

use borsh::{BorshDeserialize, BorshSerialize};
use vfaas_sdk::{Context, program};

/// Pricing tier the customer account is on.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum Tier {
	/// Pay-as-you-go: 50 bps.
	Basic,
	/// Committed volume: 30 bps.
	Pro,
	/// Custom contract: 10 bps.
	Enterprise,
}

/// A request to quote the fee on a transaction amount.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct FeeRequest {
	/// Transaction amount in cents.
	pub amount_cents: u64,
	/// The account's pricing tier.
	pub tier: Tier,
}

/// A fee quote.
#[derive(
	BorshDeserialize, BorshSerialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct FeeQuote {
	/// The fee in cents.
	pub fee_cents: u64,
	/// The basis points rate that was applied (before floor/cap).
	pub applied_bps: u32,
}

/// Minimum fee charged on any transaction, in cents.
pub const MIN_FEE_CENTS: u64 = 25;
/// Maximum fee charged on any transaction, in cents.
pub const MAX_FEE_CENTS: u64 = 25_000;

/// Quote the fee for a transaction: tiered bps rate, floored at
/// [`MIN_FEE_CENTS`] and capped at [`MAX_FEE_CENTS`].
#[program]
pub fn quote_fee(_ctx: &Context, request: FeeRequest) -> FeeQuote {
	let applied_bps: u32 = match request.tier {
		Tier::Basic => 50,
		Tier::Pro => 30,
		Tier::Enterprise => 10,
	};
	let raw =
		request.amount_cents.saturating_mul(u64::from(applied_bps)) / 10_000;
	FeeQuote { fee_cents: raw.clamp(MIN_FEE_CENTS, MAX_FEE_CENTS), applied_bps }
}

#[cfg(test)]
mod tests {
	use super::*;
	use vfaas_sdk::testing::mock_context;

	fn quote(amount_cents: u64, tier: Tier) -> FeeQuote {
		quote_fee(&mock_context(), FeeRequest { amount_cents, tier })
	}

	#[test]
	fn basic_tier_is_50_bps() {
		// $1,000.00 at 50 bps = $5.00
		let q = quote(100_000, Tier::Basic);
		assert_eq!(q.fee_cents, 500);
		assert_eq!(q.applied_bps, 50);
	}

	#[test]
	fn pro_tier_is_30_bps() {
		// $1,000.00 at 30 bps = $3.00
		assert_eq!(quote(100_000, Tier::Pro).fee_cents, 300);
	}

	#[test]
	fn enterprise_tier_is_10_bps() {
		// $10,000.00 at 10 bps = $10.00
		assert_eq!(quote(1_000_000, Tier::Enterprise).fee_cents, 1_000);
	}

	#[test]
	fn small_amounts_hit_the_minimum_fee() {
		// $10.00 at 50 bps would be 5 cents; floor applies.
		assert_eq!(quote(1_000, Tier::Basic).fee_cents, MIN_FEE_CENTS);
	}

	#[test]
	fn zero_amount_still_charges_the_minimum() {
		assert_eq!(quote(0, Tier::Enterprise).fee_cents, MIN_FEE_CENTS);
	}

	#[test]
	fn exactly_at_the_minimum_boundary() {
		// 50 bps of $50.00 (5_000 cents) = exactly 25 cents.
		assert_eq!(quote(5_000, Tier::Basic).fee_cents, MIN_FEE_CENTS);
	}

	#[test]
	fn huge_amounts_hit_the_cap() {
		// $10,000,000.00 at 50 bps = $50,000.00; cap applies.
		assert_eq!(quote(1_000_000_000, Tier::Basic).fee_cents, MAX_FEE_CENTS);
	}

	#[test]
	fn exactly_at_the_cap_boundary() {
		// 50 bps of $50,000.00 (5_000_000 cents) = exactly $250.00.
		assert_eq!(quote(5_000_000, Tier::Basic).fee_cents, MAX_FEE_CENTS);
	}

	#[test]
	fn overflow_saturates_instead_of_wrapping() {
		// u64::MAX * 50 would overflow; saturating math caps the quote.
		assert_eq!(quote(u64::MAX, Tier::Basic).fee_cents, MAX_FEE_CENTS);
	}

	#[test]
	fn round_trips_through_borsh() {
		let request = FeeRequest { amount_cents: 123_456, tier: Tier::Pro };
		let bytes = borsh::to_vec(&request).unwrap();
		let back = FeeRequest::try_from_slice(&bytes).unwrap();
		assert_eq!(back, request);
	}
}

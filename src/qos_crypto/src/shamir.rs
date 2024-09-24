//! Shamir's Secret Sharing implementation
// The original self-contained SSS Gf256 implementation is adopted from
// https://github.com/veracruz-project/veracruz/blob/398e4d3ab3023492a64ea91740528e58776e1827/sdk/data-generators/shamir-secret-sharing/src/main.rs
// The original code is under MIT license, see
// https://github.com/veracruz-project/veracruz/blob/398e4d3ab3023492a64ea91740528e58776e1827/LICENSE_MIT.markdown

use vsss_rs::Gf256;

use crate::QosCryptoError;

/// Generate `share_count` shares requiring `threshold` shares to reconstruct.
///
/// Known limitations:
/// threshold >= 2
/// `share_count` <= 255
pub fn shares_generate(
	secret: &[u8],
	share_count: usize,
	threshold: usize,
) -> Result<Vec<Vec<u8>>, QosCryptoError> {
	use rand_core::OsRng;

	Gf256::split_array(threshold, share_count, secret, OsRng)
		.map_err(QosCryptoError::Vsss)
}

/// Reconstruct our secret from the given `shares`.
pub fn shares_reconstruct<B: AsRef<[Vec<u8>]>>(
	shares: B,
) -> Result<Vec<u8>, QosCryptoError> {
	Gf256::combine_array(shares).map_err(QosCryptoError::Vsss)
}

#[cfg(test)]
mod test {
	use rand::prelude::SliceRandom;

	use super::*;
	#[test]
	fn make_and_reconstruct_shares() {
		let secret = b"this is a crazy secret";
		let n = 6;
		let k = 3;
		let all_shares = shares_generate(secret, n, k).unwrap();

		// Reconstruct with all the shares
		let shares = all_shares.clone();
		let reconstructed = shares_reconstruct(shares).unwrap();
		assert_eq!(secret.to_vec(), reconstructed);

		// Reconstruct with enough shares
		let shares = &all_shares[..k];
		let reconstructed = shares_reconstruct(shares).unwrap();
		assert_eq!(secret.to_vec(), reconstructed);

		// Reconstruct with not enough shares
		let shares = &all_shares[..(k - 1)];
		let reconstructed = shares_reconstruct(shares).unwrap();
		let old_reconstructed = shares_reconstruct(shares).unwrap();
		assert!(secret.to_vec() != reconstructed);
		assert!(secret.to_vec() != old_reconstructed);

		// Reconstruct with enough shuffled shares
		let mut shares = all_shares.clone()[..k].to_vec();
		shares.shuffle(&mut rand::thread_rng());
		let reconstructed = shares_reconstruct(&shares).unwrap();
		assert_eq!(secret.to_vec(), reconstructed);

		for combo in crate::n_choose_k::combinations(&all_shares, k) {
			let reconstructed = shares_reconstruct(&combo).unwrap();
			assert_eq!(secret.to_vec(), reconstructed);
		}
	}
}

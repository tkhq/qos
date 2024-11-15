//! Shamir Secret Sharing module. We use the [`vsss-rs`](https://crates.io/crates/vsss-rs)
use rand_core::OsRng;
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

	#[test]
	fn can_reconstruct_from_old_shares() {
		// This test if fundamental to ensure updates to the Shamir Secret
		// Sharing logic can be made safely. Here we hardcode shares that were
		// created with the oldest version of this logic, and ensure that we can
		// reconstruct. If this test starts failing please do _not_ ignore it,
		// it's telling you the current quorum key shares will become invalid
		// when combined!
		// --------
		// These shares were generated with the following QOS commit:
		// `31ad6ac8458781f592a442b7dc0e0e019e03f2f4` (2022-05-12)
		// with the following test code:
		//  #[test]
		//  fn make_shares() {
		//      let secret = b"my cute little secret";
		//      let n = 3;
		//      let k = 2;
		//
		//      let all_shares = shares_generate(secret, n, k);
		//      for share in all_shares {
		//          println!("share: {}", hex::encode(share));
		//      }
		//  }
		let shares = [
			qos_hex::decode("01661fc0cc265daa4e7bde354c281dcc23a80c590249")
				.unwrap(),
			qos_hex::decode("027bb5fb26d326e0fc421cf604e495e3d3e4bd24ab0e")
				.unwrap(),
			qos_hex::decode("0370d31b89800f2f9255abb73ca0ed0f8329d20fcc33")
				.unwrap(),
		];

		// Setting is 2-out-of-3. Let's try 3 ways.
		let reconstructed1 =
			shares_reconstruct(vec![shares[0].clone(), shares[1].clone()])
				.unwrap();
		let reconstructed2 =
			shares_reconstruct(vec![shares[1].clone(), shares[2].clone()])
				.unwrap();
		let reconstructed3 =
			shares_reconstruct(vec![shares[0].clone(), shares[2].clone()])
				.unwrap();

		// Regardless of the combination we should get the same secret
		let expected_secret = b"my cute little secret";
		assert_eq!(reconstructed1, expected_secret);
		assert_eq!(reconstructed2, expected_secret);
		assert_eq!(reconstructed3, expected_secret);
	}
}

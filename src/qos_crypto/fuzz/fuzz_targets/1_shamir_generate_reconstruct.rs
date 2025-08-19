#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_crypto::shamir::*;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzShamirStruct {
	pub n: usize,
	pub k: usize,
	secret: Box<[u8]>,
}

// let the fuzzer control the number of shares, share threshold number, and secret
fuzz_target!(|fuzzerdata: FuzzShamirStruct| {
	let n = fuzzerdata.n;
	let k = fuzzerdata.k;
	let secret = fuzzerdata.secret;

	// FUZZER NOTE the effort to reconstruct shares is O(n²) so inputs with a large n
	// are particularly slow

	// FUZZER TODO artificial limit n to avoid slow inputs, reconsider
	if n > 64 {
		return;
	}

	// FUZZER NOTE the shares_generate() function uses RNG internally and is
	// therefore non-deterministic, which may limit the reproducibility and effectiveness of this harness
	let all_shares_res = shares_generate(&secret, n, k);

	match all_shares_res {
		Err(_) => {}
		Ok(all_shares) => {
			// Reconstruct with all the shares
			let shares = all_shares.clone();
			let reconstructed =
				shares_reconstruct(&shares).expect("should succeed");
			// expect the reconstruction to work
			assert_eq!(secret.to_vec(), reconstructed);

			// Reconstruct with enough shares
			let shares = &all_shares[..k];
			let reconstructed =
				shares_reconstruct(shares).expect("should succeed");

			// expect the reconstruction to work
			assert_eq!(secret.to_vec(), reconstructed);

			// Reconstruct with not enough shares
			let shares = &all_shares[..(k - 1)];

			// although this function returns a Result<>, it does not automatically detect that is has received
			// an insufficent number of shares and Err() out - instead, it returns Ok() with an incorrect result
			let reconstructed_res = shares_reconstruct(shares);

			match reconstructed_res {
				// error case is not interesting
				Err(_) => {}
				// OK case is common
				Ok(reconstructed) => {
					// if we managed to reconstruct the secret with less than the minimum number of shares
					// the something is wrong, or we have a random collision
					if reconstructed == secret.to_vec() {
						panic!("reconstructed the secret with less than k shares, this should not happen")
					}
				}
			}
		}
	}
});

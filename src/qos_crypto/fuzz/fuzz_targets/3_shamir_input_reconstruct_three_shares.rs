#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_crypto::shamir::*;

/// let the fuzzer come up with three different shares of arbitrary length
#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzShareReconstruct {
	share_one: Box<[u8]>,
	share_two: Box<[u8]>,
	share_three: Box<[u8]>,
}

// let the fuzzer control the share data in a three share reconstruction scenario
fuzz_target!(|fuzzerdata: FuzzShareReconstruct| {
	let mut shares: Vec<Vec<u8>> = Vec::new();

	// note that the effort to reconstruct shares is O(n²) so inputs with a large n
	// are particularly slow
	// here we have n == 3, so this is not a problem

	// this construction with three shares covers more edge cases than the two share variant
	let mut share_one: Vec<u8> = Vec::new();
	let mut share_two: Vec<u8> = Vec::new();
	let mut share_three: Vec<u8> = Vec::new();

	share_one.extend_from_slice(&fuzzerdata.share_one);
	share_two.extend_from_slice(&fuzzerdata.share_two);
	share_three.extend_from_slice(&fuzzerdata.share_three);

	// Fuzz workaround for issue in vsss-rs <= 4.3.5
	// the bug is fixed in vsss-rs 4.3.6
	// if(share_one.len() != share_two.len() ) || (share_one.len() != share_three.len() )  {
	//     return;
	// }

	shares.push(share_one);
	shares.push(share_two);
	shares.push(share_three);

	// Reconstruct with the shares, we expect this to error out often
	let reconstructed_res = shares_reconstruct(&shares);
	if !reconstructed_res.is_err() {
		// let _reconstructed = reconstructed_res.unwrap();

		// debug print is useful for manual evaluation
		// println!("reconstructed {:?}", _reconstructed);
		// println!("from shares: {:?}", shares);
		// println!("");
	}
});

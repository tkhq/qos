//! Shamir Secret Sharing implementation.
// Grabbed from here:
// https://github.com/veracruz-project/veracruz/blob/main/sdk/data-generators/shamir-secret-sharing/src/main.rs

use std::{convert::TryFrom, iter};

use rand::{rngs::OsRng, Rng};
use vsss_rs::Gf256;

// lookup tables for log and exp of polynomials in GF(256),
#[rustfmt::skip]
const GF256_LOG: [u8; 256] = [
    0xff, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
    0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
    0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
    0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
    0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
    0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
    0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
    0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
    0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
    0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
    0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
    0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
    0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
    0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
    0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
    0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
    0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
    0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
    0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
    0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
    0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
    0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
    0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
    0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
    0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
    0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
    0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
    0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
    0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
    0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
];

#[rustfmt::skip]
const GF256_EXP: [u8; 2*255] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
    0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
    0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
    0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
    0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
    0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
    0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
    0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
    0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
    0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
    0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
    0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
    0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
    0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
    0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
    0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
    0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6,

    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
    0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
    0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
    0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
    0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
    0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
    0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
    0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
    0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
    0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
    0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
    0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
    0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
    0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
    0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
    0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
    0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6,
];

/// Multiply in GF(256).
fn gf256_mul(a: u8, b: u8) -> u8 {
	if a == 0 || b == 0 {
		0
	} else {
		GF256_EXP[usize::from(GF256_LOG[usize::from(a)])
			+ usize::from(GF256_LOG[usize::from(b)])]
	}
}

/// Divide in GF(256)/
fn gf256_div(a: u8, b: u8) -> u8 {
	// multiply a against inverse b
	gf256_mul(a, GF256_EXP[usize::from(255 - GF256_LOG[usize::from(b)])])
}

/// Evaluate a polynomial at x over GF(256) using Horner's method.
fn gf256_eval(f: &[u8], x: u8) -> u8 {
	f.iter().rev().fold(0, |acc, c| gf256_mul(acc, x) ^ c)
}

/// Generate a random polynomial of given degree, fixing f(0) = secret.
fn gf256_generate(secret: u8, degree: usize) -> Vec<u8> {
	let mut rng = rand::thread_rng();
	iter::once(secret)
		.chain(iter::repeat_with(|| rng.gen_range(1..=255)).take(degree))
		.collect()
}

/// Find f(0) using Lagrange interpolation.
fn gf256_interpolate(xs: &[u8], ys: &[u8]) -> u8 {
	assert!(xs.len() == ys.len());
	let mut y = 0u8;
	for (i, (x0, y0)) in xs.iter().zip(ys).enumerate() {
		let mut li = 1u8;
		for (j, (x1, _y1)) in xs.iter().zip(ys).enumerate() {
			if i != j {
				li = gf256_mul(li, gf256_div(*x1, *x0 ^ *x1));
			}
		}

		y ^= gf256_mul(li, *y0);
	}

	y
}

/// Generate n shares requiring k shares to reconstruct.
#[must_use]
pub fn shares_generate(secret: &[u8], n: usize, k: usize) -> Vec<Vec<u8>> {
	let mut shares = vec![vec![]; n];

	// we need to store x for each point somewhere, so just prepend
	// each array with it
	for (i, share) in shares.iter_mut().enumerate().take(n) {
		share.push(u8::try_from(i + 1).expect("exceeded 255 shares"));
	}

	for x in secret {
		// generate random polynomial for each byte
		let f = gf256_generate(*x, k - 1);

		// assign each share a point at f(i)
		for (i, share) in shares.iter_mut().enumerate().take(n) {
			share.push(gf256_eval(
				&f,
				u8::try_from(i + 1).expect("exceeeded 255 shares"),
			));
		}
	}

	shares
}

/// Reconstruct our secret from the given `shares`.
pub fn shares_reconstruct<S: AsRef<[u8]>>(shares: &[S]) -> Vec<u8> {
	let len = shares.iter().map(|s| s.as_ref().len()).min().unwrap_or(0);
	// rather than erroring, return empty secrets if input is malformed.
	// This matches the behavior of bad shares (random output) and simplifies
	// consumers.
	if len == 0 {
		return vec![];
	}

	let mut secret = vec![];

	// x is prepended to each share
	let xs: Vec<u8> = shares.iter().map(|v| v.as_ref()[0]).collect();
	for i in 1..len {
		let ys: Vec<u8> = shares.iter().map(|v| v.as_ref()[i]).collect();
		secret.push(gf256_interpolate(&xs, &ys));
	}

	secret
}

/// Generate n shares requiring k shares to reconstruct.
/// Experimental replacement of shares_generate()
/// TODO error behavior
pub fn shares_generate2(secret: &[u8], n: usize, k: usize) -> Vec<Vec<u8>> {

    let mut osrng = OsRng::default();

    // known differences
    // n=1 k=1 should be valid but triggers SharingMinThreshold
    // n=2 k=1 should be valid triggers SharingMinThreshold

    // TODO error behavior
    let shares = Gf256::split_array(k, n, secret, &mut osrng).unwrap();

	shares
}

/// Reconstruct our secret from the given `shares`.
/// Experimental replacement of shares_reconstruct()
/// TODO error case behavior
pub fn shares_reconstruct2<S: AsRef<[Vec<u8>]>>(shares: S) -> Vec<u8> {

    // TODO error handling
    // example:
    // `Result::unwrap()` on an `Err` value: SharingMinThreshold
    Gf256::combine_array(shares).unwrap()
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
        // let all_shares = shares_generate(secret, n, k);
        let all_shares = shares_generate2(secret, n, k);
        // the two share generation mechanisms use separate, nondeterministic RNGs
        // therefore their results can't be expected to be identical

        // println!("shamir.rs");
        // for share in all_shares.clone() {
        //     println!("{:?}", share);
        //     println!("{}", share.len());
        // }

        // Reconstruct with all the shares
        let shares = all_shares.clone();
        let reconstructed = shares_reconstruct(&shares);
        assert_eq!(secret.to_vec(), reconstructed);
        assert_eq!(shares.len(), n);
        println!("reconstructed shamir.rs: {:?}", reconstructed);

        let vsss_reconstructed: Vec<u8> = Gf256::combine_array(all_shares.clone()).unwrap();
        assert_eq!(reconstructed, vsss_reconstructed);
        println!("reconstructed vsss-rs: {:?}", vsss_reconstructed);

        let vsss_reconstructed2: Vec<u8> = shares_reconstruct2(&shares);
        assert_eq!(reconstructed, vsss_reconstructed2);
        println!("reconstructed vsss-rs2: {:?}", vsss_reconstructed2);


        // Reconstruct with enough shares
        let shares = &all_shares[..k];
        let reconstructed = shares_reconstruct(shares);
        assert_eq!(secret.to_vec(), reconstructed);
        let vsss_reconstructed = Gf256::combine_array(shares).unwrap();
        assert_eq!(reconstructed, vsss_reconstructed);
        let vsss_reconstructed2 = shares_reconstruct2(shares);
        assert_eq!(secret.to_vec(), vsss_reconstructed2);

        // Reconstruct with not enough shares
        let shares = &all_shares[..(k - 1)];
        let reconstructed = shares_reconstruct(shares);
        assert!(secret.to_vec() != reconstructed);
        let vsss_reconstructed_res = Gf256::combine_array(shares);
        if vsss_reconstructed_res.is_ok() {
            let vsss_reconstructed = vsss_reconstructed_res.unwrap();
            assert_eq!(reconstructed, vsss_reconstructed);
            assert!(secret.to_vec() != vsss_reconstructed);
        }
        // let vsss_reconstructed2 = shares_reconstruct2(shares);
        // assert!(secret.to_vec() != vsss_reconstructed2);
        // assert_eq!(reconstructed, vsss_reconstructed2);

        // Reconstruct with enough shuffled shares
        let mut shares = all_shares.clone()[..k].to_vec();
        shares.shuffle(&mut rand::thread_rng());
        let reconstructed = shares_reconstruct(&shares);
        assert_eq!(secret.to_vec(), reconstructed);
        let vsss_reconstructed = Gf256::combine_array(shares).unwrap();
        assert_eq!(reconstructed, vsss_reconstructed);
        assert_eq!(secret.to_vec(), vsss_reconstructed);

        // Reconstruct with no shares
        let shares = vec![];
        let reconstructed = shares_reconstruct(&shares);
        // special return case
        assert_eq!(reconstructed, vec![]);
        // explicit error
        let vsss_reconstructed = Gf256::combine_array(shares);
        assert_eq!(vsss_rs::Error::SharingMinThreshold, vsss_reconstructed.unwrap_err());

	}


}

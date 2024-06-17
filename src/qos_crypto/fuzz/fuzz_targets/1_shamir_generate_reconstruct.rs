#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_crypto::shamir::*;

#[derive(Clone, Debug)]
#[derive(arbitrary::Arbitrary)]
pub struct FuzzShamirStruct {
    pub n: usize,
    pub k: usize,
}

fuzz_target!(|data: FuzzShamirStruct| {
 
    // let the fuzzer control the number of shares and share threshold number
        
    let n = data.n;
    let k = data.k;
    
    // Workaround for problem in the target
    if k > n {
        return;
    }
    
    // Workaround for problem in the target
    if k == 0 {
        return;
    }
    
    // Workaround for problem/known panic behavior in the target
    if n > 255 {
        return;
    }
    
    // fixed plaintext
    let secret = b"this is a crazy secret";

    let all_shares = shares_generate(secret, n, k);
    
    // Reconstruct with all the shares
    let shares = all_shares.clone();
    let reconstructed = shares_reconstruct(&shares);
    assert_eq!(secret.to_vec(), reconstructed);
    
    // Reconstruct with enough shares
    let shares = &all_shares[..k];
    let reconstructed = shares_reconstruct(shares);
    assert_eq!(secret.to_vec(), reconstructed);
    
    // Reconstruct with not enough shares
    let shares = &all_shares[..(k - 1)];
    let reconstructed = shares_reconstruct(shares);
    
    // Workaround for secret length 0, where the error behavior of the target
    // happens to match the input
    if secret.len() > 0 {
        assert!(secret.to_vec() != reconstructed);
    }
});

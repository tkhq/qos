//! vfaas policy: allow only programs whose hash is on a pinned allowlist.
//!
//! The host precomputes `program_hash` and passes it in the
//! `PolicyRequest`, so this policy costs a 32-byte comparison — it never
//! hashes the (potentially multi-megabyte) program inside the guest's fuel
//! budget.
//!
//! The pinned list here is a placeholder digest so the policy is
//! demonstrably deny-by-default; a real deployment pins the hashes of the
//! programs it governs.

use vfaas_sdk::{Context, Decision, PolicyRequest, ProgramHash, policy};

/// Program hashes this policy permits.
pub const ALLOWED_PROGRAM_HASHES: [[u8; 32]; 1] = [[42u8; 32]];

/// Allow execution iff the program's hash is pinned in
/// [`ALLOWED_PROGRAM_HASHES`].
#[policy]
pub fn evaluate(_ctx: &Context, request: PolicyRequest) -> Decision {
    let allowed = ALLOWED_PROGRAM_HASHES
        .iter()
        .any(|digest| ProgramHash::new(*digest) == request.program_hash);
    if allowed {
        Decision::Allow
    } else {
        Decision::Deny(format!(
            "program {} is not on this policy's allowlist",
            request.program_hash
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfaas_sdk::testing::mock_context;

    fn request(program_hash: [u8; 32]) -> PolicyRequest {
        PolicyRequest {
            program_hash: ProgramHash::new(program_hash),
            input_hash: [1u8; 32],
            input: b"hello".to_vec(),
            program: Some(b"\0asm-placeholder".to_vec()),
        }
    }

    #[test]
    fn allows_pinned_hash() {
        let d = evaluate(&mock_context(), request([42u8; 32]));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn denies_unknown_hash() {
        let d = evaluate(&mock_context(), request([9u8; 32]));
        match d {
            Decision::Deny(reason) => {
                assert!(reason.contains("allowlist"));
                // Reason names the offending hash in hex.
                assert!(reason.contains(&"09".repeat(32)));
            }
            Decision::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn decision_does_not_depend_on_program_bytes() {
        // The policy must key off the precomputed hash, not the blob.
        let mut req = request([42u8; 32]);
        req.program = None;
        assert!(matches!(evaluate(&mock_context(), req), Decision::Allow));
    }
}

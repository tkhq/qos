//! vfaas policy: allow execution only for inputs up to a size limit.

use vfaas_sdk::{Context, Decision, PolicyRequest, policy};

/// Largest input, in bytes, this policy permits.
pub const MAX_INPUT_BYTES: usize = 1024;

/// Allow execution iff the input is at most [`MAX_INPUT_BYTES`] long.
#[policy]
pub fn evaluate(_ctx: &Context, request: PolicyRequest) -> Decision {
    if request.input.len() > MAX_INPUT_BYTES {
        Decision::Deny(format!(
            "input too large: {} bytes > {} byte limit",
            request.input.len(),
            MAX_INPUT_BYTES,
        ))
    } else {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfaas_sdk::{ProgramHash, testing::mock_context};

    fn request(input: Vec<u8>) -> PolicyRequest {
        PolicyRequest {
            program_hash: ProgramHash::new([0u8; 32]),
            input_hash: [0u8; 32],
            input,
            program: None,
        }
    }

    #[test]
    fn allows_small_input() {
        let d = evaluate(&mock_context(), request(b"hello".to_vec()));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn allows_empty_input() {
        let d = evaluate(&mock_context(), request(vec![]));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn allows_exactly_at_limit() {
        let d = evaluate(&mock_context(), request(vec![0u8; MAX_INPUT_BYTES]));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn denies_one_past_limit() {
        let d =
            evaluate(&mock_context(), request(vec![0u8; MAX_INPUT_BYTES + 1]));
        match d {
            Decision::Deny(reason) => assert!(reason.contains("too large")),
            Decision::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn deny_reason_carries_byte_counts() {
        let d = evaluate(&mock_context(), request(vec![0u8; 2048]));
        match d {
            Decision::Deny(reason) => {
                assert!(reason.contains("2048"));
                assert!(reason.contains("1024"));
            }
            Decision::Allow => panic!("expected Deny"),
        }
    }
}

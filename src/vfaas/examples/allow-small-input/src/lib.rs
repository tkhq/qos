use vfaas_sdk::{Context, Decision, PolicyRequest, policy};

#[policy]
pub fn evaluate(_ctx: &Context, request: PolicyRequest) -> Decision {
    const MAX_INPUT_BYTES: usize = 1024;
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
    use vfaas_sdk::testing::mock_context;

    fn req(input: Vec<u8>) -> PolicyRequest {
        PolicyRequest { program: vec![], input }
    }

    #[test]
    fn allows_small_input() {
        let d = evaluate(&mock_context(), req(b"hello".to_vec()));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn allows_empty_input() {
        let d = evaluate(&mock_context(), req(vec![]));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn allows_exactly_at_limit() {
        let d = evaluate(&mock_context(), req(vec![0u8; 1024]));
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn denies_oversized_input() {
        let d = evaluate(&mock_context(), req(vec![0u8; 1025]));
        match d {
            Decision::Deny(reason) => assert!(reason.contains("too large")),
            Decision::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn deny_reason_carries_byte_count() {
        let d = evaluate(&mock_context(), req(vec![0u8; 2048]));
        match d {
            Decision::Deny(reason) => {
                assert!(reason.contains("2048"));
                assert!(reason.contains("1024"));
            }
            Decision::Allow => panic!("expected Deny"),
        }
    }
}

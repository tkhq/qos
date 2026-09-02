//! vfaas policy: allow screening only for a well-formed single address.
//!
//! The Turnkey policy engine writes conditions like
//! `eth.tx.to == '<ADDRESS>'`; this is the same idea as one plain Rust
//! function — the deny reason even reads like a condition.

use borsh::{BorshDeserialize, BorshSerialize};
use vfaas_sdk::{Context, Decision, PolicyRequest, policy};

/// Layout mirror of `vfaas_sanctions_screening::Screen`. Field order is
/// the Borsh contract; the policy deliberately does not depend on the
/// program crate (that would link the program's entrypoint into this
/// policy's cdylib exports).
#[derive(BorshDeserialize, BorshSerialize, Debug)]
struct Screen {
    address: String,
}

/// Allow iff the input decodes to a screening request for one well-formed
/// `0x`-prefixed 20-byte hex address.
#[policy]
pub fn evaluate(_ctx: &Context, request: PolicyRequest) -> Decision {
    let Ok(screen) = Screen::try_from_slice(&request.input) else {
        return Decision::Deny("input !~ Screen { address }".to_string());
    };

    match screen.address.strip_prefix("0x") {
        Some(hex)
            if hex.len() == 40
                && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Decision::Allow
        }
        _ => Decision::Deny(format!(
            "screen.address {:?} !~ ^0x[0-9a-fA-F]{{40}}$",
            screen.address
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfaas_sdk::{ProgramHash, testing::mock_context};

    fn decide(address: &str) -> Decision {
        let input = borsh::to_vec(&Screen { address: address.to_string() })
            .unwrap();
        evaluate(
            &mock_context(),
            PolicyRequest {
                program_hash: ProgramHash::new([0u8; 32]),
                input_hash: [0u8; 32],
                input,
                program: None,
            },
        )
    }

    #[test]
    fn well_formed_address_is_allowed() {
        let d = decide("0xabcDEF1234567890abcdef1234567890ABCDEF12");
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn missing_prefix_is_denied() {
        let d = decide("abcdef1234567890abcdef1234567890abcdef12");
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn short_address_is_denied() {
        let d = decide("0xabcdef");
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn non_hex_characters_are_denied() {
        let d = decide("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn deny_reason_reads_like_a_condition() {
        match decide("0xnope") {
            Decision::Deny(reason) => {
                assert!(reason.contains("screen.address"));
                assert!(reason.contains("^0x[0-9a-fA-F]{40}$"));
            }
            Decision::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn undecodable_input_is_denied() {
        let d = evaluate(
            &mock_context(),
            PolicyRequest {
                program_hash: ProgramHash::new([0u8; 32]),
                input_hash: [0u8; 32],
                input: vec![0xff, 0xff, 0xff],
                program: None,
            },
        );
        match d {
            Decision::Deny(reason) => {
                assert!(reason.contains("Screen { address }"));
            }
            Decision::Allow => panic!("expected Deny"),
        }
    }
}

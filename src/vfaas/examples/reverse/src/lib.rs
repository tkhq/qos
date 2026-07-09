use vfaas_sdk::{Context, program};

#[program]
pub fn execute(_ctx: &Context, input: Vec<u8>) -> Vec<u8> {
    input.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfaas_sdk::testing::mock_context;

    #[test]
    fn reverses_ascii() {
        assert_eq!(
            execute(&mock_context(), b"hello world".to_vec()),
            b"dlrow olleh"
        );
    }

    #[test]
    fn empty_stays_empty() {
        assert_eq!(execute(&mock_context(), vec![]), Vec::<u8>::new());
    }

    #[test]
    fn palindrome_is_stable() {
        let bytes = b"racecar".to_vec();
        assert_eq!(execute(&mock_context(), bytes.clone()), bytes);
    }

    #[test]
    fn reverses_arbitrary_bytes() {
        let input: Vec<u8> = (0u8..=255).collect();
        let output = execute(&mock_context(), input);
        assert_eq!(output[0], 255);
        assert_eq!(output[255], 0);
    }
}

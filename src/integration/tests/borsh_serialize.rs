use borsh::BorshSerialize;

#[derive(BorshSerialize, Debug, PartialEq)]
struct TestSerializable {
    a: u32,
    b: String,
    c: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable_to_vec() {
        let test_instance = TestSerializable {
            a: 42,
            b: "Hello, world!".to_string(),
            c: vec![1, 2, 3, 4, 5],
        };

        // Expected serialized output
        let expected: Vec<u8> = vec![
            42, 0, 0, 0,               // a: u32 (little-endian)
            13, 0, 0, 0,               // Length of the string b (13)
            72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, // "Hello, world!" as bytes
            5, 0, 0, 0,                // Length of the vector c (5)
            1, 2, 3, 4, 5              // c: Vec<u8>
        ];

        // Serialize the instance
        let serialized = borsh::to_vec(&test_instance).expect("Serialization failed");

        // Assert that the serialized output matches the expected value
        assert_eq!(serialized, expected, "Serialized bytes differ from the expected value");
    }
}

#[cfg(test)]
mod tests {
    use borsh::{BorshSerialize, BorshDeserialize};

    #[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq)]
    struct TestSerializable {
        a: u32,
        b: String,
        c: Vec<u8>,
    }

    #[test]
    fn test_serializable_to_vec() {
        let inst = TestSerializable {
            a: 42,
            b: "Hello, world!".to_string(),
            c: vec![1, 2, 3, 4, 5],
        };

        // Expected serialized output
        let expected_serialized: Vec<u8> = vec![
            42, 0, 0, 0,               // a: u32 (little-endian)
            13, 0, 0, 0,               // Length of the string b (13)
            72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, // "Hello, world!" as bytes
            5, 0, 0, 0,                // Length of the vector c (5)
            1, 2, 3, 4, 5              // c: Vec<u8>
        ];

        // Serialize the instance
        let serialized = borsh::to_vec(&inst).expect("Serialization failed");

        // Assert that the serialized output matches the expected value
        assert_eq!(serialized, expected_serialized, "Serialized bytes differ from the expected value");

        // Deserialize the serialized data back to a new instance
        let deserialized_inst: TestSerializable = borsh::BorshDeserialize::try_from_slice(&serialized)
            .expect("Deserialization failed");

        // Assert that the deserialized instance matches the original instance
        assert_eq!(deserialized_inst, inst, "Deserialized instance differs from the original");
    }
}

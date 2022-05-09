#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

const su32: usize = std::mem::size_of::<u32>();

#[derive(Debug, PartialEq)]
pub enum ProtocolError {
	UnknownError,
	DeserializationError,
}

pub trait Serialize<T> {
	fn serialize(&self) -> Vec<u8>;
	fn deserialize(data: &mut Vec<u8>) -> Result<T, ProtocolError>;
}

impl Serialize<Vec<u8>> for Vec<u8> {
	fn serialize(&self) -> Vec<u8> {
		let mut vec: Vec<u8> = Vec::with_capacity(self.len() + su32);
		let len = self.len() as u32;
		vec.extend(len.to_le_bytes().iter());
		vec.extend(self.iter());
		vec
	}

	fn deserialize(data: &mut Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
		if data.len() < su32 {
			// Payload size cannot be determined
			return Err(ProtocolError::DeserializationError);
		}
		let len_bytes: [u8; su32] = data
			.drain(0..su32)
			.collect::<Vec<u8>>() // create Vec<u8>
			.try_into() // convert to [u8; 4]
			.map_err(|_| ProtocolError::DeserializationError)?;
		let len_bytes = u32::from_le_bytes(len_bytes) as usize;

		if data.len() < len_bytes {
			// Payload size is incorrect
			return Err(ProtocolError::DeserializationError);
		}
		let result: Vec<u8> = data.drain(0..len_bytes).collect();

		Ok(result)
	}
}

#[derive(Debug, PartialEq)]
pub enum ProtocolRequest {
	Empty,
	Echo(EchoRequest),
}

const PROTOCOL_REQUEST_EMPTY: u8 = 0;
const PROTOCOL_REQUEST_ECHO: u8 = 1;

impl ProtocolRequest {
	fn index(&self) -> u8 {
		match self {
			Self::Empty => PROTOCOL_REQUEST_EMPTY,
			Self::Echo(_) => PROTOCOL_REQUEST_ECHO,
		}
	}
}

impl Serialize<Self> for ProtocolRequest {
	fn serialize(&self) -> Vec<u8> {
		let mut result = vec![self.index()];
		match self {
			Self::Empty => {}
			Self::Echo(req) => {
				result.extend(req.serialize().iter());
			}
		}
		result
	}

	fn deserialize(
		data: &mut Vec<u8>,
	) -> Result<ProtocolRequest, ProtocolError> {
		let index = data.get(0).ok_or(ProtocolError::DeserializationError)?;
		let req = match *index {
			PROTOCOL_REQUEST_EMPTY => ProtocolRequest::Empty,
			PROTOCOL_REQUEST_ECHO => {
				let req = EchoRequest::deserialize(&mut data[1..].to_vec())?;
				ProtocolRequest::Echo(req)
			}
			_ => return Err(ProtocolError::DeserializationError),
		};

		Ok(req)
	}
}

#[derive(PartialEq, Debug)]
pub struct EchoRequest {
	pub data: Vec<u8>,
}

impl Serialize<Self> for EchoRequest {
	fn serialize(&self) -> Vec<u8> {
		self.data.serialize()
	}

	fn deserialize(payload: &mut Vec<u8>) -> Result<Self, ProtocolError> {
		let data = Vec::<u8>::deserialize(payload)?;
		Ok(EchoRequest { data })
	}
}

#[derive(Debug, PartialEq)]
struct NestedRequest {
	nested_struct: EchoRequest,
	data2: Vec<u8>,
}

impl Serialize<Self> for NestedRequest {
	fn serialize(&self) -> Vec<u8> {
		let serialized_nested_struct = self.nested_struct.serialize();
		let serialized_data2 = self.data2.serialize();

		let mut result = Vec::with_capacity(
			serialized_nested_struct.len() + serialized_data2.len(),
		);
		result.extend(serialized_nested_struct.iter());
		result.extend(serialized_data2.iter());

		result
	}

	fn deserialize(payload: &mut Vec<u8>) -> Result<Self, ProtocolError> {
		Ok(Self {
			nested_struct: EchoRequest::deserialize(payload)?,
			data2: Vec::<u8>::deserialize(payload)?,
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn serialize_vecu8() {
		let data = vec![1, 2, 3, 4];
		let expected = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let serialized = data.serialize();
		assert_eq!(serialized, expected);
	}

	#[test]
	fn deserialize_vecu8() {
		let mut data = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let expected = vec![1, 2, 3, 4];
		let deserialized = Vec::<u8>::deserialize(&mut data).unwrap();
		assert_eq!(deserialized, expected);
	}

	#[test]
	fn serialize_integration_vecu8() {
		let data = vec![1, 2, 3, 4, 5, 6];
		let mut serialized = data.serialize();
		let deserialized = Vec::<u8>::deserialize(&mut serialized).unwrap();
		assert_eq!(data, deserialized);
	}

	#[test]
	fn serialize_empty() {
		let expected = vec![ProtocolRequest::Empty.index()];
		let request = ProtocolRequest::Empty;
		let serialized = request.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn serialize_echo_request() {
		let expected = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let req = EchoRequest { data: vec![1, 2, 3, 4] };
		let serialized = req.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn deserialize_echo_request() {
		let expected = EchoRequest { data: vec![1, 2, 3, 4] };
		let mut data = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let deserialized = EchoRequest::deserialize(&mut data).unwrap();
		assert_eq!(expected, deserialized);
	}

	#[test]
	fn serialize_integration_echo_request() {
		let req = EchoRequest { data: vec![1, 2, 3, 4] };
		let mut serialized = req.serialize();
		let deserialized = EchoRequest::deserialize(&mut serialized).unwrap();
		assert_eq!(req, deserialized);
	}

	#[test]
	fn serialize_protocol_request() {
		let expected = vec![1, 4, 0, 0, 0, 1, 2, 3, 4];
		let req = EchoRequest { data: vec![1, 2, 3, 4] };
		let pr = ProtocolRequest::Echo(req);
		let serialized = pr.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn deserialize_protocol_request() {
		let req = EchoRequest { data: vec![1, 2, 3, 4] };
		let pr = ProtocolRequest::Echo(req);
		let mut data = vec![1, 4, 0, 0, 0, 1, 2, 3, 4];
		let deserialized = ProtocolRequest::deserialize(&mut data).unwrap();
		assert_eq!(pr, deserialized);
	}

	#[test]
	fn serialize_nested_request() {
		let echo_request = EchoRequest { data: vec![1, 2, 3, 4] };
		let nested_request = NestedRequest {
			nested_struct: echo_request,
			data2: vec![50, 60, 70, 80],
		};
		let serialized = nested_request.serialize();

		let expected = vec![
			4, 0, 0, 0, // nested_request length
			1, 2, 3, 4, // nested request
			4, 0, 0, 0, // data2 length
			50, 60, 70, 80, // data2
		];
		assert_eq!(expected, serialized);
	}

	#[test]
	fn deserialize_nested_request() {
		let mut data = vec![
			4, 0, 0, 0, // nested_request length
			1, 2, 3, 4, // nested request
			4, 0, 0, 0, // data2 length
			5, 6, 7, 8, // data2
		];
		let expected = NestedRequest {
			nested_struct: EchoRequest { data: vec![1, 2, 3, 4] },
			data2: vec![5, 6, 7, 8],
		};
		let deserialized = NestedRequest::deserialize(&mut data).unwrap();
		assert_eq!(expected, deserialized);
	}

	#[test]
	fn deserialization_input_too_short() {
		let mut data = vec![1];
		let deserialized = Vec::<u8>::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![1, 0, 0, 0];
		let deserialized = Vec::<u8>::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![3, 0, 0, 0, 1, 1];
		let deserialized = Vec::<u8>::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![1];
		let deserialized = EchoRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![1, 0, 0, 0];
		let deserialized = EchoRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![3, 0, 0, 0, 1, 1];
		let deserialized = EchoRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![];
		let deserialized = ProtocolRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![1, 2, 0, 0, 0, 1];
		let deserialized = ProtocolRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![99, 2, 0, 0, 0, 1];
		let deserialized = ProtocolRequest::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));
	}

	// CAUTION: This test takes a really long time...
	// #[test]
	// fn deserialization_payload_too_large() {
	//   let req = EchoRequest{ data: (0..(u32::MAX)).map(|_| u8::MAX).collect()
	// };   let mut serialized = req.serialize();
	//   let deserialized = EchoRequest::deserialize(&mut serialized).unwrap();
	//   assert_eq!(deserialized, req);
	// }
}

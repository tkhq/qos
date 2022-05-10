//! Enclave I/O message format and serialization.

const SU32: usize = std::mem::size_of::<u32>();

#[derive(Debug, PartialEq)]
pub enum ProtocolError {
	DeserializationError,
	InvalidShare,
	ReconstructionError,
}

pub trait Serialize<T> {
	fn serialize(&self) -> Vec<u8>;
	fn deserialize(data: &mut Vec<u8>) -> Result<T, ProtocolError>;
}

impl Serialize<Vec<u8>> for Vec<u8> {
	fn serialize(&self) -> Vec<u8> {
		let mut vec: Vec<u8> = Vec::with_capacity(self.len() + SU32);
		let len = self.len() as u32;
		vec.extend(len.to_le_bytes().iter());
		vec.extend(self.iter());
		vec
	}

	fn deserialize(data: &mut Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
		if data.len() < SU32 {
			// Payload size cannot be determined
			return Err(ProtocolError::DeserializationError);
		}
		let len_bytes: [u8; SU32] = data
			.drain(0..SU32)
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
pub enum ProtocolMsg {
	SuccessResponse,
	// TODO: Error response should hold a protocol error
	ErrorResponse,
	EmptyRequest,
	EmptyResponse,
	EchoRequest(Echo),
	EchoResponse(Echo),
	ProvisionRequest(ProvisionRequest),
	ReconstructRequest,
	NsmRequest(NsmRequest),
}

const PROTOCOL_MSG_SUCCESS_RESPONSE: u8 = 0;
const PROTOCOL_MSG_ERROR_RESPONSE: u8 = 1;
const PROTOCOL_MSG_EMPTY_REQUEST: u8 = 2;
const PROTOCOL_MSG_EMPTY_RESPONSE: u8 = 3;
const PROTOCOL_MSG_ECHO_REQUEST: u8 = 4;
const PROTOCOL_MSG_ECHO_RESPONSE: u8 = 5;
const PROTOCOL_MSG_PROVISION_REQUEST: u8 = 6;
const PROTOCOL_MSG_RECONSTRUCT_REQUEST: u8 = 7;
const PROTOCOL_MSG_NSM_REQUEST: u8 = 8;

// TODO: declaritive macro to create index
impl ProtocolMsg {
	fn index(&self) -> u8 {
		match self {
			Self::SuccessResponse => PROTOCOL_MSG_SUCCESS_RESPONSE,
			Self::ErrorResponse => PROTOCOL_MSG_ERROR_RESPONSE,
			Self::EmptyRequest => PROTOCOL_MSG_EMPTY_REQUEST,
			Self::EmptyResponse => PROTOCOL_MSG_EMPTY_RESPONSE,
			Self::EchoRequest(_) => PROTOCOL_MSG_ECHO_REQUEST,
			Self::EchoResponse(_) => PROTOCOL_MSG_ECHO_RESPONSE,
			Self::ProvisionRequest(_) => PROTOCOL_MSG_PROVISION_REQUEST,
			Self::ReconstructRequest => PROTOCOL_MSG_RECONSTRUCT_REQUEST,
			Self::NsmRequest(_) => PROTOCOL_MSG_NSM_REQUEST,
		}
	}
}

impl Serialize<Self> for ProtocolMsg {
	fn serialize(&self) -> Vec<u8> {
		let mut result = vec![self.index()];
		match self {
			Self::SuccessResponse
			| Self::ErrorResponse
			| Self::ReconstructRequest
			| Self::EmptyResponse
			| Self::EmptyRequest => {}
			Self::EchoRequest(req) | Self::EchoResponse(req) => {
				result.extend(req.serialize().iter());
			}
			Self::ProvisionRequest(req) => {
				result.extend(req.serialize().iter());
			}
			Self::NsmRequest(req) => {
				result.extend(req.serialize().iter());
			}
		}
		result
	}

	fn deserialize(data: &mut Vec<u8>) -> Result<ProtocolMsg, ProtocolError> {
		let index = data.get(0).ok_or(ProtocolError::DeserializationError)?;
		let req = match *index {
			PROTOCOL_MSG_SUCCESS_RESPONSE => ProtocolMsg::SuccessResponse,
			PROTOCOL_MSG_ERROR_RESPONSE => ProtocolMsg::ErrorResponse,
			PROTOCOL_MSG_EMPTY_REQUEST => ProtocolMsg::EmptyRequest,
			PROTOCOL_MSG_EMPTY_RESPONSE => ProtocolMsg::EmptyResponse,
			PROTOCOL_MSG_ECHO_REQUEST => {
				let req = Echo::deserialize(&mut data[1..].to_vec())?;
				ProtocolMsg::EchoRequest(req)
			}
			PROTOCOL_MSG_ECHO_RESPONSE => {
				let req = Echo::deserialize(&mut data[1..].to_vec())?;
				ProtocolMsg::EchoResponse(req)
			}
			PROTOCOL_MSG_PROVISION_REQUEST => {
				let req =
					ProvisionRequest::deserialize(&mut data[1..].to_vec())?;
				ProtocolMsg::ProvisionRequest(req)
			}
			PROTOCOL_MSG_RECONSTRUCT_REQUEST => ProtocolMsg::ReconstructRequest,
			_ => return Err(ProtocolError::DeserializationError),
		};

		Ok(req)
	}
}

#[derive(PartialEq, Debug)]
pub struct Echo {
	pub data: Vec<u8>,
}

impl Serialize<Self> for Echo {
	fn serialize(&self) -> Vec<u8> {
		self.data.serialize()
	}

	fn deserialize(payload: &mut Vec<u8>) -> Result<Self, ProtocolError> {
		let data = Vec::<u8>::deserialize(payload)?;
		Ok(Self { data })
	}
}

#[derive(PartialEq, Debug)]
pub struct ProvisionRequest {
	pub share: Vec<u8>,
}

impl Serialize<Self> for ProvisionRequest {
	fn serialize(&self) -> Vec<u8> {
		self.share.serialize()
	}

	fn deserialize(data: &mut Vec<u8>) -> Result<Self, ProtocolError> {
		Ok(Self { share: Vec::<u8>::deserialize(data)? })
	}
}

#[derive(PartialEq, Debug)]
pub struct ProvisionResponse {}

#[derive(Debug, PartialEq)]
pub struct NsmRequest {
	pub data: Vec<u8>,
}

impl Serialize<Self> for NsmRequest {
	fn serialize(&self) -> Vec<u8> {
		self.data.serialize()
	}

	fn deserialize(payload: &mut Vec<u8>) -> Result<Self, ProtocolError> {
		let data = Vec::<u8>::deserialize(payload)?;
		Ok(Self { data })
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
		let expected = vec![ProtocolMsg::EmptyRequest.index()];
		let request = ProtocolMsg::EmptyRequest;
		let serialized = request.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn serialize_echo_request() {
		let expected = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let req = Echo { data: vec![1, 2, 3, 4] };
		let serialized = req.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn deserialize_echo_request() {
		let expected = Echo { data: vec![1, 2, 3, 4] };
		let mut data = vec![4, 0, 0, 0, 1, 2, 3, 4];
		let deserialized = Echo::deserialize(&mut data).unwrap();
		assert_eq!(expected, deserialized);
	}

	#[test]
	fn serialize_integration_echo_request() {
		let req = Echo { data: vec![1, 2, 3, 4] };
		let mut serialized = req.serialize();
		let deserialized = Echo::deserialize(&mut serialized).unwrap();
		assert_eq!(req, deserialized);
	}

	#[test]
	fn serialize_protocol_request() {
		let expected = vec![4, 4, 0, 0, 0, 1, 2, 3, 4];
		let req = Echo { data: vec![1, 2, 3, 4] };
		let pr = ProtocolMsg::EchoRequest(req);
		let serialized = pr.serialize();
		assert_eq!(expected, serialized);
	}

	#[test]
	fn deserialize_protocol_request() {
		let req = Echo { data: vec![1, 2, 3, 4] };
		let pr = ProtocolMsg::EchoRequest(req);
		let mut data = vec![4, 4, 0, 0, 0, 1, 2, 3, 4];
		let deserialized = ProtocolMsg::deserialize(&mut data).unwrap();
		assert_eq!(pr, deserialized);
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
		let deserialized = Echo::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![1, 0, 0, 0];
		let deserialized = Echo::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![3, 0, 0, 0, 1, 1];
		let deserialized = Echo::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![];
		let deserialized = ProtocolMsg::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![4, 2, 0, 0, 0, 1];
		let deserialized = ProtocolMsg::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));

		let mut data = vec![99, 2, 0, 0, 0, 1];
		let deserialized = ProtocolMsg::deserialize(&mut data);
		assert_eq!(deserialized, Err(ProtocolError::DeserializationError));
	}

	// CAUTION: This test takes a really long time...
	// #[test]
	// fn deserialization_payload_too_large() {
	//   let req = Echo{ data: (0..(u32::MAX)).map(|_| u8::MAX).collect()
	// };   let mut serialized = req.serialize();
	//   let deserialized = Echo::deserialize(&mut serialized).unwrap();
	//   assert_eq!(deserialized, req);
	// }
}

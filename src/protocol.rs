#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(warnings)]

const SLASH: u8 = b"/"[0];

#[derive(Debug)]
pub enum ProtocolError {
  UnknownError,
  DeserializationError
}

pub enum ProtocolRequest {
  Empty,
  Echo(EchoRequest)
}

impl ProtocolRequest {
	fn index(&self) -> u8 {
		match self {
			Self::Empty => 0,
			Self::Echo(_) => 1,
		}
	}
}

pub struct EchoRequest {
  data: Vec<u8>
}

impl EchoRequest {
	fn serialize(&self) -> Vec<u8> {
		let mut result = b"data/".to_vec();
		result.extend(self.data.iter());
		result
	}

  fn deserialize(payload: Vec<u8>) -> Result<Self, ProtocolError> {
    let data_field_id = b"data/".to_vec();
    if data_field_id != payload[0.. data_field_id.len()] {
        return Err(ProtocolError::DeserializationError)
    }

    let payload_sliced = &payload[data_field_id.len()..].iter();

    let data_vec = Vec::new();
    while let Some(byte) = payload_sliced.next(){
      if *byte == SLASH {
        break;
      } else {
        data_vec.push(*byte)
      }
    }

    Ok(EchoRequest { data: data_vec })
  }
}

/// "1/data/0x57843762"
/// let req = ProtocolRequest::Echo(EchoRequest { data: b"Hello World".to_vec() });
// req.serialize()?:

impl ProtocolRequest {
  pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
    let mut serialized = Vec::new();
    serialized.push(self.index());
    Ok(serialized)
  }

  pub fn deserialize() -> Result<ProtocolRequest, ProtocolError> {
    Ok(ProtocolRequest::Empty)
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn serialize_empty() {
    let expected = vec![ProtocolRequest::Empty.index()];
    let request = ProtocolRequest::Empty;
    let serialized = request.serialize().unwrap();
    assert_eq!(expected, serialized);
  }

  #[test]
  fn serialize_echo() {
    let 
    let expected = vec![ProtocolRequest::Echo.index(), ];
  }
}
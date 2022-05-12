//! Enclave I/O message format and serialization.
use std::collections::BTreeSet;

use aws_nitro_enclaves_nsm_api as nsm;
use serde_cbor;

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
			return Err(ProtocolError::DeserializationError)
		}
		let len_bytes: [u8; SU32] = data
			.drain(0..SU32)
			.collect::<Vec<u8>>() // create Vec<u8>
			.try_into() // convert to [u8; 4]
			.map_err(|_| ProtocolError::DeserializationError)?;
		let len_bytes = u32::from_le_bytes(len_bytes) as usize;

		if data.len() < len_bytes {
			// Payload size is incorrect
			return Err(ProtocolError::DeserializationError)
		}
		let result: Vec<u8> = data.drain(0..len_bytes).collect();

		Ok(result)
	}
}

// #[derive(Debug, PartialEq)]
#[derive(Debug)]
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
	NsmRequest(nsm::api::Request),
	NsmResponse(nsm::api::Response),
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
const PROTOCOL_MSG_NSM_RESPONSE: u8 = 9;

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
			Self::NsmResponse(_) => PROTOCOL_MSG_NSM_RESPONSE,
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
				let buff = serde_cbor::to_vec(req).unwrap();
				result.extend(buff.iter());
			}
			Self::NsmResponse(res) => {
				let buff = serde_cbor::to_vec(res).unwrap();
				result.extend(buff.iter());
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
			PROTOCOL_MSG_NSM_REQUEST => {
				let req = serde_cbor::from_slice(&data[1..])
					.map_err(|_| ProtocolError::DeserializationError)?;
				ProtocolMsg::NsmRequest(req)
			}
			PROTOCOL_MSG_NSM_RESPONSE => {
				let req = serde_cbor::from_slice(&data[1..])
					.map_err(|_| ProtocolError::DeserializationError)?;
				ProtocolMsg::NsmResponse(req)
			}
			_ => return Err(ProtocolError::DeserializationError),
		};

		Ok(req)
	}
}

impl PartialEq for ProtocolMsg {
	fn eq(&self, other: &Self) -> bool {
		self.serialize() == other.serialize()
	}
	fn ne(&self, other: &Self) -> bool {
		self.serialize() != other.serialize()
	}
}

#[derive(PartialEq, Debug, Clone)]
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

#[derive(PartialEq, Debug, Clone)]
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

#[derive(PartialEq, Debug, Clone)]
pub struct ProvisionResponse {}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum NsmErrorCode {
	/// No errors
	Success,
	/// Input argument(s) invalid
	InvalidArgument,
	/// PlatformConfigurationRegister index out of bounds
	InvalidIndex,
	/// The received response does not correspond to the earlier request
	InvalidResponse,
	/// PlatformConfigurationRegister is in read-only mode and the operation
	/// attempted to modify it
	ReadOnlyIndex,
	/// Given request cannot be fulfilled due to missing capabilities
	InvalidOperation,
	/// Operation succeeded but provided output buffer is too small
	BufferTooSmall,
	/// The user-provided input is too large
	InputTooLarge,
	/// NitroSecureModule cannot fulfill request due to internal errors
	InternalError,
}

impl From<nsm::api::ErrorCode> for NsmErrorCode {
	fn from(e: nsm::api::ErrorCode) -> Self {
		use nsm::api::ErrorCode as E;
		match e {
			E::Success => Self::Success,
			E::InvalidArgument => Self::InvalidArgument,
			E::InvalidIndex => Self::InvalidIndex,
			E::InvalidResponse => Self::InvalidResponse,
			E::ReadOnlyIndex => Self::ReadOnlyIndex,
			E::InvalidOperation => Self::InvalidOperation,
			E::BufferTooSmall => Self::BufferTooSmall,
			E::InputTooLarge => Self::InputTooLarge,
			E::InternalError => Self::InternalError,
		}
	}
}

#[derive(
	Debug, serde::Serialize, serde::Deserialize, Copy, Clone, PartialEq,
)]
pub enum NsmDigest {
	/// SHA256
	SHA256,
	/// SHA384
	SHA384,
	/// SHA512
	SHA512,
}

impl From<nsm::api::Digest> for NsmDigest {
	fn from(d: nsm::api::Digest) -> Self {
		use nsm::api::Digest as D;
		match d {
			D::SHA256 => Self::SHA256,
			D::SHA384 => Self::SHA384,
			D::SHA512 => Self::SHA512,
		}
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum NsmRequest {
	/// Read data from PlatformConfigurationRegister at `index`
	DescribePCR {
		/// index of the PCR to describe
		index: u16,
	},
	/// Extend PlatformConfigurationRegister at `index` with `data`
	ExtendPCR {
		/// index the PCR to extend
		index: u16,
		/// data to extend it with
		data: Vec<u8>,
	},
	/// Lock PlatformConfigurationRegister at `index` from further
	/// modifications
	LockPCR {
		/// index to lock
		index: u16,
	},
	/// Lock PlatformConfigurationRegisters at indexes `[0, range)` from
	/// further modifications
	LockPCRs {
		/// number of PCRs to lock, starting from index 0
		range: u16,
	},
	/// Return capabilities and version of the connected NitroSecureModule.
	/// Clients are recommended to decode major_version and minor_version
	/// first, and use an appropriate structure to hold this data, or fail
	/// if the version is not supported.
	DescribeNSM,
	/// Requests the NSM to create an AttestationDoc and sign it with it's
	/// private key to ensure authenticity.
	Attestation {
		/// Includes additional user data in the AttestationDoc.
		user_data: Option<Vec<u8>>,
		/// Includes an additional nonce in the AttestationDoc.
		nonce: Option<Vec<u8>>,
		/// Includes a user provided public key in the AttestationDoc.
		public_key: Option<Vec<u8>>,
	},
	/// Requests entropy from the NSM side.
	GetRandom,
}

impl From<nsm::api::Request> for NsmRequest {
	fn from(req: nsm::api::Request) -> Self {
		use nsm::api::Request as R;
		match req {
			R::DescribePCR { index } => Self::DescribePCR { index },
			R::ExtendPCR { index, data } => Self::ExtendPCR { index, data },
			R::LockPCR { index } => Self::LockPCR { index },
			R::DescribeNSM => Self::DescribeNSM,
			R::Attestation { user_data, nonce, public_key } => {
				Self::Attestation {
					user_data: user_data.map(|u| u.to_vec()),
					nonce: nonce.map(|n| n.to_vec()),
					public_key: public_key.map(|p| p.to_vec()),
				}
			}
			R::GetRandom => Self::GetRandom,
			_ => panic!("Not recognized nsm::api::Request"),
		}
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
enum NsmResponse {
	/// returns the current PlatformConfigurationRegister state
	DescribePCR {
		/// true if the PCR is read-only, false otherwise
		lock: bool,
		/// the current value of the PCR
		data: Vec<u8>,
	},
	/// returned if PlatformConfigurationRegister has been successfully
	/// extended
	ExtendPCR {
		/// The new value of the PCR after extending the data into the
		/// register.
		data: Vec<u8>,
	},
	/// returned if PlatformConfigurationRegister has been successfully locked
	LockPCR,
	/// returned if PlatformConfigurationRegisters have been successfully
	/// locked
	LockPCRs,
	/// returns the runtime configuration of the NitroSecureModule
	DescribeNSM {
		/// Breaking API changes are denoted by `major_version`
		version_major: u16,
		/// Minor API changes are denoted by `minor_version`. Minor versions
		/// should be backwards compatible.
		version_minor: u16,
		/// Patch version. These are security and stability updates and do not
		/// affect API.
		version_patch: u16,
		/// `module_id` is an identifier for a singular NitroSecureModule
		module_id: String,
		/// The maximum number of PCRs exposed by the NitroSecureModule.
		max_pcrs: u16,
		/// The PCRs that are read-only.
		locked_pcrs: BTreeSet<u16>,
		/// The digest of the PCR Bank
		digest: NsmDigest,
	},
	/// A response to an Attestation Request containing the CBOR-encoded
	/// AttestationDoc and the signature generated from the doc by the
	/// NitroSecureModule
	Attestation {
		/// A signed COSE structure containing a CBOR-encoded
		/// AttestationDocument as the payload.
		document: Vec<u8>,
	},
	/// A response containing a number of bytes of entropy.
	GetRandom {
		/// The random bytes.
		random: Vec<u8>,
	},
	/// An error has occured, and the NitroSecureModule could not successfully
	/// complete the operation
	Error(NsmErrorCode),
}

impl From<nsm::api::Response> for NsmResponse {
	fn from(req: nsm::api::Response) -> Self {
		use nsm::api::Response as R;
		match req {
			R::DescribePCR { lock, data } => Self::DescribePCR { lock, data },
			R::ExtendPCR { data } => Self::ExtendPCR { data },
			R::LockPCR => Self::LockPCR,
			R::DescribeNSM {
				version_major,
				version_minor,
				version_patch,
				module_id,
				max_pcrs,
				locked_pcrs,
				digest,
			} => Self::DescribeNSM {
				version_major,
				version_minor,
				version_patch,
				module_id,
				max_pcrs,
				locked_pcrs,
				digest: digest.into(),
			},
			R::Attestation { document } => Self::Attestation { document },
			R::GetRandom { random } => Self::GetRandom { random },
			R::Error(e) => Self::Error(e.into()),
			_ => Self::Error(NsmErrorCode::InternalError),
		}
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

	// TODO: Re-implement these tests!
	#[test]
	fn deserialize_protocol_request() {
		// let req = Echo { data: vec![1, 2, 3, 4] };
		// let pr = ProtocolMsg::EchoRequest(req);
		// let mut data = vec![4, 4, 0, 0, 0, 1, 2, 3, 4];
		// let deserialized = ProtocolMsg::deserialize(&mut data).unwrap();
		// assert_eq!(pr, deserialized);
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

		// TODO: Re-implement these tests!

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

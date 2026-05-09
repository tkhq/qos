//! Types specific to AWS nitro enclave protocol implementation. We have types
//! that map 1 to 1 with the types we use from `ws_nitro_enclaves_nsm_api::api`
//! so we can derive borsh, among other things.

use std::collections::BTreeSet;

use aws_nitro_enclaves_nsm_api as nsm;
use nsm::api::{Digest, ErrorCode, Request, Response};

/// Possible error codes from the Nitro Secure Module API.
#[derive(
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
	PartialEq,
	Eq,
	Clone,
)]
pub enum NsmErrorCode {
	/// No errors
	Success,
	/// Input argument(s) invalid
	InvalidArgument,
	/// `PlatformConfigurationRegister` index out of bounds
	InvalidIndex,
	/// The received response does not correspond to the earlier request
	InvalidResponse,
	/// `PlatformConfigurationRegister` is in read-only mode and the operation
	/// attempted to modify it
	ReadOnlyIndex,
	/// Given request cannot be fulfilled due to missing capabilities
	InvalidOperation,
	/// Operation succeeded but provided output buffer is too small
	BufferTooSmall,
	/// The user-provided input is too large
	InputTooLarge,
	/// `NitroSecureModule` cannot fulfill request due to internal errors
	InternalError,
}

impl From<ErrorCode> for NsmErrorCode {
	fn from(e: ErrorCode) -> Self {
		use ErrorCode as E;
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

impl From<NsmErrorCode> for ErrorCode {
	fn from(e: NsmErrorCode) -> Self {
		use NsmErrorCode as E;
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

/// Possible hash digest for the Nitro Secure Module API.
#[derive(
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
	Copy,
	Clone,
	PartialEq,
	Eq,
)]
pub enum NsmDigest {
	/// SHA256
	SHA256,
	/// SHA384
	SHA384,
	/// SHA512
	SHA512,
}

impl From<Digest> for NsmDigest {
	fn from(d: Digest) -> Self {
		use Digest as D;
		match d {
			D::SHA256 => Self::SHA256,
			D::SHA384 => Self::SHA384,
			D::SHA512 => Self::SHA512,
		}
	}
}

impl From<NsmDigest> for Digest {
	fn from(d: NsmDigest) -> Self {
		use NsmDigest as D;
		match d {
			D::SHA256 => Self::SHA256,
			D::SHA384 => Self::SHA384,
			D::SHA512 => Self::SHA512,
		}
	}
}

/// Request type for the Nitro Secure Module API.
#[derive(
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
	PartialEq,
	Eq,
	Clone,
)]
pub enum NsmRequest {
	/// Read data from `PlatformConfigurationRegister` at `index`
	DescribePCR {
		/// index of the PCR to describe
		index: u16,
	},
	/// Extend `PlatformConfigurationRegister` at `index` with `data`
	ExtendPCR {
		/// index the PCR to extend
		index: u16,
		/// data to extend it with
		#[serde(with = "qos_hex::serde")]
		data: Vec<u8>,
	},
	/// Lock `PlatformConfigurationRegister` at `index` from further
	/// modifications
	LockPCR {
		/// index to lock
		index: u16,
	},
	/// Lock `PlatformConfigurationRegisters` at indexes `[0, range)` from
	/// further modifications
	LockPCRs {
		/// number of PCRs to lock, starting from index 0
		range: u16,
	},
	/// Return capabilities and version of the connected `NitroSecureModule`.
	/// Clients are recommended to decode `major_version` and `minor_version`
	/// first, and use an appropriate structure to hold this data, or fail
	/// if the version is not supported.
	DescribeNSM,
	/// Requests the NSM to create an `AttestationDoc` and sign it with it's
	/// private key to ensure authenticity.
	Attestation {
		/// Includes additional user data in the `AttestationDoc`.
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "qos_hex::serde::option"
		)]
		user_data: Option<Vec<u8>>,
		/// Includes an additional nonce in the `AttestationDoc`.
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "qos_hex::serde::option"
		)]
		nonce: Option<Vec<u8>>,
		/// Includes a user provided public key in the `AttestationDoc`.
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "qos_hex::serde::option"
		)]
		public_key: Option<Vec<u8>>,
	},
	/// Requests entropy from the NSM side.
	GetRandom,
}

impl From<Request> for NsmRequest {
	fn from(req: Request) -> Self {
		use Request as R;
		match req {
			R::DescribePCR { index } => Self::DescribePCR { index },
			R::ExtendPCR { index, data } => Self::ExtendPCR { index, data },
			R::LockPCR { index } => Self::LockPCR { index },
			R::LockPCRs { range } => Self::LockPCRs { range },
			R::DescribeNSM => Self::DescribeNSM,
			R::Attestation { user_data, nonce, public_key } => {
				Self::Attestation {
					user_data: user_data.map(|u| u.to_vec()),
					nonce: nonce.map(|n| n.to_vec()),
					public_key: public_key.map(|p| p.to_vec()),
				}
			}
			R::GetRandom => Self::GetRandom,
			_ => panic!("Un-recognized aws-nsm Request"),
		}
	}
}

impl From<NsmRequest> for Request {
	fn from(req: NsmRequest) -> Self {
		use serde_bytes::ByteBuf;
		use NsmRequest as R;
		match req {
			R::DescribePCR { index } => Self::DescribePCR { index },
			R::ExtendPCR { index, data } => Self::ExtendPCR { index, data },
			R::LockPCR { index } => Self::LockPCR { index },
			R::LockPCRs { range } => Self::LockPCRs { range },
			R::DescribeNSM => Self::DescribeNSM,
			R::Attestation { user_data, nonce, public_key } => {
				Self::Attestation {
					user_data: user_data.map(ByteBuf::from),
					nonce: nonce.map(ByteBuf::from),
					public_key: public_key.map(ByteBuf::from),
				}
			}
			R::GetRandom => Self::GetRandom,
		}
	}
}

/// Response type for the Nitro Secure Module API.
#[derive(
	Debug,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
	PartialEq,
	Eq,
	Clone,
)]
pub enum NsmResponse {
	/// returns the current `PlatformConfigurationRegister` state
	#[serde(alias = "describePCR", alias = "describepcr")]
	DescribePCR {
		/// true if the PCR is read-only, false otherwise
		lock: bool,
		/// the current value of the PCR
		#[serde(with = "qos_hex::serde")]
		data: Vec<u8>,
	},
	/// returned if `PlatformConfigurationRegister` has been successfully
	/// extended
	#[serde(alias = "extendPCR", alias = "extendpcr")]
	ExtendPCR {
		/// The new value of the PCR after extending the data into the
		/// register.
		#[serde(with = "qos_hex::serde")]
		data: Vec<u8>,
	},
	/// returned if `PlatformConfigurationRegister` has been successfully locked
	#[serde(alias = "lockPCR", alias = "lockpcr")]
	LockPCR,
	/// returned if `PlatformConfigurationRegisters` have been successfully
	/// locked
	#[serde(alias = "lockPCRs", alias = "lockpcrs")]
	LockPCRs,
	/// returns the runtime configuration of the `NitroSecureModule`
	#[serde(alias = "describeNSM", alias = "describensm")]
	DescribeNSM {
		/// Breaking API changes are denoted by `major_version`
		#[serde(with = "qos_json::string_or_numeric")]
		version_major: u16,
		/// Minor API changes are denoted by `minor_version`. Minor versions
		/// should be backwards compatible.
		#[serde(with = "qos_json::string_or_numeric")]
		version_minor: u16,
		/// Patch version. These are security and stability updates and do not
		/// affect API.
		#[serde(with = "qos_json::string_or_numeric")]
		version_patch: u16,
		/// `module_id` is an identifier for a singular `NitroSecureModule`
		module_id: String,
		/// The maximum number of PCRs exposed by the `NitroSecureModule`.
		#[serde(with = "qos_json::string_or_numeric")]
		max_pcrs: u16,
		/// The PCRs that are read-only.
		#[serde(with = "qos_json::string_or_numeric")]
		locked_pcrs: BTreeSet<u16>,
		/// The digest of the PCR Bank
		digest: NsmDigest,
	},
	/// A response to an Attestation Request containing the CBOR-encoded
	/// `AttestationDoc` and the signature generated from the doc by the
	/// `NitroSecureModule`
	#[serde(alias = "attestation")]
	Attestation {
		/// A signed COSE structure containing a CBOR-encoded
		/// `AttestationDocument` as the payload.
		#[serde(with = "qos_hex::serde")]
		document: Vec<u8>,
	},
	/// A response containing a number of bytes of entropy.
	#[serde(alias = "getRandom", alias = "getrandom")]
	GetRandom {
		/// The random bytes.
		#[serde(with = "qos_hex::serde")]
		random: Vec<u8>,
	},
	/// An error has occured, and the `NitroSecureModule` could not successfully
	/// complete the operation
	#[serde(alias = "error")]
	Error(NsmErrorCode),
}

impl From<Response> for NsmResponse {
	fn from(req: Response) -> Self {
		use Response as R;
		match req {
			R::DescribePCR { lock, data } => Self::DescribePCR { lock, data },
			R::ExtendPCR { data } => Self::ExtendPCR { data },
			R::LockPCR => Self::LockPCR,
			R::LockPCRs => Self::LockPCRs,
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
			_ => Self::Error(ErrorCode::InternalError.into()),
		}
	}
}

impl From<NsmResponse> for nsm::api::Response {
	fn from(req: NsmResponse) -> Self {
		use NsmResponse as R;
		match req {
			R::DescribePCR { lock, data } => Self::DescribePCR { lock, data },
			R::ExtendPCR { data } => Self::ExtendPCR { data },
			R::LockPCR => Self::LockPCR,
			R::LockPCRs => Self::LockPCRs,
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
		}
	}
}

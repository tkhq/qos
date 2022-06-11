//! Enclave I/O message format and serialization.

use std::{io::Write, ops::Deref};

pub use aws_nitro_enclaves_nsm_api::api::{
	Digest as NsmDigest, Request as NsmRequest, Response as NsmResponse,
};
use borsh::BorshSerialize;

use super::{
	boot::ManifestEnvelope,
	genesis::{GenesisOutput, GenesisSet},
	ProtocolError,
};

// NsmResponse is from `aws-nitro-enclaves-nsm-api` and serializes with
// serde_cbor Here, we implement BorshSerialize for NsmResponse by serializing
// with serde_cbor This (likely) breaks one of the native assumptions about
// borsh -- deterministic serialization However, we'll never actually need
// determinism over the NsmResponse so this is OK
#[derive(Debug)]
pub struct NsmResponseWrapper(pub NsmResponse);
impl Deref for NsmResponseWrapper {
	type Target = NsmResponse;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl borsh::BorshSerialize for NsmResponseWrapper {
	fn serialize<W: Write>(
		&self,
		writer: &mut W,
	) -> borsh::maybestd::io::Result<()> {
		let temp_vec = serde_cbor::to_vec(&self.0).map_err(|_| {
			borsh::maybestd::io::Error::from(
				borsh::maybestd::io::ErrorKind::Other,
			)
		})?;

		writer.write(&temp_vec)?;
		Ok(())
	}
}

impl borsh::BorshDeserialize for NsmResponseWrapper {
	fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
		let inner = serde_cbor::from_slice(buf).map_err(|_| {
			borsh::maybestd::io::Error::from(
				borsh::maybestd::io::ErrorKind::Other,
			)
		})?;

		Ok(Self(inner))
	}
}

#[derive(Debug)]
pub struct NsmRequestWrapper(pub NsmRequest);
impl Deref for NsmRequestWrapper {
	type Target = NsmRequest;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl borsh::BorshSerialize for NsmRequestWrapper {
	fn serialize<W: Write>(
		&self,
		writer: &mut W,
	) -> borsh::maybestd::io::Result<()> {
		let temp_vec = serde_cbor::to_vec(&self.0).map_err(|_| {
			borsh::maybestd::io::Error::from(
				borsh::maybestd::io::ErrorKind::Other,
			)
		})?;

		writer.write(&temp_vec)?;
		Ok(())
	}
}

impl borsh::BorshDeserialize for NsmRequestWrapper {
	fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
		let inner = serde_cbor::from_slice(buf).map_err(|_| {
			borsh::maybestd::io::Error::from(
				borsh::maybestd::io::ErrorKind::Other,
			)
		})?;

		Ok(Self(inner))
	}
}

#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProtocolMsg {
	SuccessResponse,
	// TODO: Error response should hold a protocol error
	ErrorResponse,
	UnrecoverableErrorResponse,
	InUnrecoverablePhaseResponse,
	EmptyRequest,
	EmptyResponse,
	EchoRequest(Echo),
	EchoResponse(Echo),
	ProvisionRequest(Provision),
	ReconstructRequest,
	NsmRequest(NsmRequestWrapper),
	NsmResponse(NsmResponseWrapper),
	LoadRequest(Load),

	StatusRequest,
	StatusResponse(super::ProtocolPhase),

	BootRequest(BootInstruction),
	BootStandardResponse(NsmResponseWrapper),
	BootGenesisResponse {
		/// COSE SIGN1 structure with Attestation Doc
		attestation_doc: NsmResponseWrapper,
		/// Output from the Genesis flow.
		genesis_output: GenesisOutput,
	},

	ProtocolErrorResponse(ProtocolError),
}

impl PartialEq for ProtocolMsg {
	fn eq(&self, other: &Self) -> bool {
		self.try_to_vec().expect("ProtocolMsg serializes. qed.")
			== other.try_to_vec().expect("ProtocolMsg serializes. qed.")
	}
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Echo {
	pub data: Vec<u8>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Provision {
	pub share: Vec<u8>,
}

#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SignatureWithPubKey {
	/// Signature
	pub signature: Vec<u8>,
	/// Path to the file containing the public key associated with this
	/// signature.
	pub path: String,
}

#[derive(
	Debug, PartialEq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Load {
	/// The executable to pivot to
	pub executable: Vec<u8>,
	//// Signatures of the data
	pub signatures: Vec<SignatureWithPubKey>,
}

#[derive(
	PartialEq, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum BootInstruction {
	Standard { manifest_envelope: Box<ManifestEnvelope>, pivot: Vec<u8> },
	Genesis { set: GenesisSet },
}

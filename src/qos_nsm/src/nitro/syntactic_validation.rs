//! Basic validation for fields of the Nitro Secure Module Attestation Document.

use std::collections::BTreeMap;

use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};

use super::{AttestError, ByteBuf};

const MIN_PCR_COUNT: usize = 1;
const MAX_PRC_COUNT: usize = 32;
const MAX_PCR_INDEX: usize = 32;
const VALID_PCR_LENS: [usize; 3] = [32, 48, 64];

const MIN_PUB_KEY_LEN: usize = 1;
const MIN_CERT_CHAIN_LEN: usize = 1;
const MAX_PUB_KEY_LEN: usize = 1024;

const MIN_CERT_LEN: usize = 1;
const MAX_CERT_LEN: usize = 1024;

pub(super) fn validate_attestation_doc(
	attestation_doc: &AttestationDoc,
) -> Result<(), AttestError> {
	let AttestationDoc {
		certificate: _, // validated in a separate step
		module_id,
		digest,
		pcrs,
		cabundle,
		timestamp,
		public_key,
		user_data,
		nonce,
	} = attestation_doc;

	validate_module_id(module_id)?;
	validate_digest(*digest)?;
	validate_pcrs(pcrs)?;
	validate_cabundle(cabundle)?;
	validate_timestamp(*timestamp)?;
	validate_public_key(public_key.as_ref())?;
	validate_bytes_512(user_data.as_ref())?;
	validate_bytes_512(nonce.as_ref())?;

	Ok(())
}

/// Mandatory field
fn validate_module_id(id: &str) -> Result<(), AttestError> {
	if id.is_empty() {
		Err(AttestError::InvalidModuleId)
	} else {
		Ok(())
	}
}
/// Mandatory field
fn validate_pcrs(pcrs: &BTreeMap<usize, ByteBuf>) -> Result<(), AttestError> {
	let is_valid_pcr_count =
		pcrs.len() >= MIN_PCR_COUNT && pcrs.len() <= MAX_PRC_COUNT;

	let is_valid_index_and_len = pcrs.iter().all(|(idx, pcr)| {
		let is_valid_idx = *idx <= MAX_PCR_INDEX;
		let is_valid_pcr_len = VALID_PCR_LENS.contains(&pcr.len());
		is_valid_idx && is_valid_pcr_len
	});

	if !is_valid_index_and_len || !is_valid_pcr_count {
		Err(AttestError::InvalidPcr)
	} else {
		Ok(())
	}
}
/// Mandatory field
fn validate_cabundle(cabundle: &[ByteBuf]) -> Result<(), AttestError> {
	let is_valid_len = cabundle.len() >= MIN_CERT_CHAIN_LEN;
	let is_valid_entries = cabundle
		.iter()
		.all(|cert| cert.len() >= MIN_CERT_LEN && cert.len() <= MAX_CERT_LEN);

	if !is_valid_len || !is_valid_entries {
		Err(AttestError::InvalidCABundle)
	} else {
		Ok(())
	}
}
/// Mandatory field
fn validate_digest(d: Digest) -> Result<(), AttestError> {
	if d == Digest::SHA384 {
		Ok(())
	} else {
		Err(AttestError::InvalidDigest)
	}
}
/// Mandatory field
fn validate_timestamp(t: u64) -> Result<(), AttestError> {
	if t == 0 {
		Err(AttestError::InvalidTimeStamp)
	} else {
		Ok(())
	}
}
/// Optional field
fn validate_public_key(pub_key: Option<&ByteBuf>) -> Result<(), AttestError> {
	if let Some(key) = pub_key {
		(key.len() >= MIN_PUB_KEY_LEN && key.len() <= MAX_PUB_KEY_LEN)
			.then_some(())
			.ok_or(AttestError::InvalidPubKey)?;
	}

	Ok(())
}

fn validate_bytes_512(val: Option<&ByteBuf>) -> Result<(), AttestError> {
	if let Some(val) = val {
		if val.len() > 512 {
			return Err(AttestError::InvalidBytes);
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::array;

	use super::*;

	#[test]
	fn valid_attestation_do_passes_validation() {
		let attestation_doc = valid_attestation_doc();
		assert!(validate_attestation_doc(&attestation_doc).is_ok());
	}

	#[test]
	fn bytes_512_works() {
		assert!(validate_bytes_512(None).is_ok());
		assert!(validate_bytes_512(Some(ByteBuf::new()).as_ref()).is_ok());
		assert!(validate_bytes_512(
			Some(ByteBuf::from((0..513).map(|_| 42u8).collect::<Vec<_>>()))
				.as_ref()
		)
		.is_err());
	}

	#[test]
	fn no_pubkey_is_valid() {
		let attestation_doc =
			AttestationDoc { public_key: None, ..valid_attestation_doc() };
		assert!(validate_attestation_doc(&attestation_doc).is_ok());
	}

	#[test]
	fn empty_pubkey_is_invalid() {
		let attestation_doc = AttestationDoc {
			public_key: ByteBuf::new().into(),
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidPubKey)
		));
	}

	#[test]
	fn long_pubkey_is_invalid() {
		let attestation_doc = AttestationDoc {
			public_key: ByteBuf::from(vec![42; 1025]).into(),
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidPubKey)
		));
	}

	#[test]
	fn invalid_timestamp() {
		let attestation_doc =
			AttestationDoc { timestamp: 0, ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidTimeStamp)
		));
	}

	#[test]
	fn invalid_digest() {
		let attestation_doc = AttestationDoc {
			digest: Digest::SHA256,
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidDigest)
		));
	}

	#[test]
	fn empty_ca_bundle() {
		let attestation_doc =
			AttestationDoc { cabundle: Vec::new(), ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidCABundle)
		));
	}

	#[test]
	fn short_cert_in_bundle() {
		let short_cert = vec![ByteBuf::new()];
		let attestation_doc =
			AttestationDoc { cabundle: short_cert, ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidCABundle)
		));
	}

	#[test]
	fn long_cert_in_bundle() {
		let long_ca_in_bundle = vec![ByteBuf::from(vec![3; 1025])];
		let attestation_doc = AttestationDoc {
			cabundle: long_ca_in_bundle,
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidCABundle)
		));
	}

	#[test]
	fn too_many_pcrs() {
		let inner = array::from_fn::<_, 33, _>(|i| (i, pcr::<32>()));

		let too_many_pcrs = BTreeMap::from(inner);

		let attestation_doc =
			AttestationDoc { pcrs: too_many_pcrs, ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidPcr)
		));
	}

	#[test]
	fn not_enough_pcrs() {
		let attestation_doc =
			AttestationDoc { pcrs: BTreeMap::new(), ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidPcr)
		));
	}

	#[test]
	fn invalid_index() {
		let attestation_doc = AttestationDoc {
			pcrs: BTreeMap::from([(33, pcr::<32>())]),
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidPcr)
		));
	}

	#[test]
	fn invalid_pcr_length() {
		let invalid_pcr = pcr::<31>();
		let pcrs = BTreeMap::from([(5, invalid_pcr)]);
		let attestion_doc = AttestationDoc { pcrs, ..valid_attestation_doc() };

		assert!(matches!(
			validate_attestation_doc(&attestion_doc),
			Err(AttestError::InvalidPcr)
		));
	}

	#[test]
	fn validate_module_id_works() {
		let attestation_doc = AttestationDoc {
			module_id: String::new(),
			..valid_attestation_doc()
		};

		assert!(matches!(
			validate_attestation_doc(&attestation_doc),
			Err(AttestError::InvalidModuleId)
		));
	}

	fn valid_attestation_doc() -> AttestationDoc {
		AttestationDoc {
			module_id: "1".into(),
			digest: Digest::SHA384,
			timestamp: 1,
			pcrs: valid_pcrs(),
			certificate: ByteBuf::new(), // not tested here
			cabundle: vec![ByteBuf::from(vec![42])],
			public_key: Some(ByteBuf::from(vec![1u8])),
			user_data: valid_bytes_512().into(),
			nonce: valid_bytes_512().into(),
		}
	}

	fn valid_pcrs() -> BTreeMap<usize, ByteBuf> {
		BTreeMap::from([(0, pcr::<48>()), (32, pcr::<32>()), (5, pcr::<64>())])
	}

	fn pcr<const N: usize>() -> ByteBuf {
		ByteBuf::from(vec![3; N])
	}

	fn valid_bytes_512() -> ByteBuf {
		ByteBuf::from(vec![42; 512])
	}
}

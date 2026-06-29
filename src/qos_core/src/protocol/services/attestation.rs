use std::collections::BTreeSet;

use qos_nsm::{
	NsmProvider, nitro,
	types::{NsmDigest, NsmRequest, NsmResponse},
};

use crate::protocol::{ProtocolError, ProtocolState};

pub(in crate::protocol) fn live_attestation_doc(
	state: &mut ProtocolState,
) -> Result<NsmResponse, ProtocolError> {
	let ephemeral_public_key =
		state.handles.get_ephemeral_key()?.public_key().to_bytes();
	let manifest_hash =
		state.handles.get_manifest_envelope()?.manifest_hash().to_vec();

	Ok(get_post_boot_attestation_doc(
		&*state.attestor,
		ephemeral_public_key,
		manifest_hash,
	))
}

pub(super) fn get_post_boot_attestation_doc(
	attestor: &dyn NsmProvider,
	ephemeral_public_key: Vec<u8>,
	manifest_hash: Vec<u8>,
) -> NsmResponse {
	let request = NsmRequest::Attestation {
		user_data: Some(manifest_hash),
		nonce: None,
		public_key: Some(ephemeral_public_key),
	};

	attestor.nsm_process_request(request)
}

pub(in crate::protocol::services) fn lock_manifest_commitment_pcr_bank(
	attestor: &dyn NsmProvider,
	manifest_hash: &[u8],
	setup_ephemeral_public_key: &[u8],
	live_ephemeral_public_key: &[u8],
) -> Result<(), ProtocolError> {
	let (max_pcrs, locked_pcrs, digest) = describe_nsm(attestor)?;
	if digest != NsmDigest::SHA384 {
		return Err(attest_error(format!(
			"expected NSM PCR digest SHA384, got {digest:?}"
		)));
	}
	if max_pcrs < nitro::ATTESTABLE_PCR_COUNT {
		return Err(attest_error(format!(
			"NSM max_pcrs {max_pcrs} does not cover attestable PCR range 0..{}",
			nitro::ATTESTABLE_PCR_COUNT
		)));
	}

	let expected_setup_pcr = extend_manifest_commitment_pcr(
		attestor,
		nitro::ManifestCommitmentKind::Setup,
		max_pcrs,
		&locked_pcrs,
		manifest_hash,
		setup_ephemeral_public_key,
	)?;
	let expected_live_pcr = extend_manifest_commitment_pcr(
		attestor,
		nitro::ManifestCommitmentKind::Live,
		max_pcrs,
		&locked_pcrs,
		manifest_hash,
		live_ephemeral_public_key,
	)?;

	match attestor.nsm_process_request(NsmRequest::LockPCRs { range: max_pcrs })
	{
		NsmResponse::LockPCRs => {}
		response => return Err(unexpected_nsm_response(&response)),
	}

	let (post_lock_max_pcrs, post_lock_locked_pcrs, _) =
		describe_nsm(attestor)?;
	if post_lock_max_pcrs != max_pcrs {
		return Err(attest_error(format!(
			"NSM max_pcrs changed from {max_pcrs} to {post_lock_max_pcrs}"
		)));
	}
	require_all_pcrs_locked(max_pcrs, &post_lock_locked_pcrs)?;

	verify_locked_manifest_commitment_pcr(
		attestor,
		nitro::ManifestCommitmentKind::Setup,
		&expected_setup_pcr,
	)?;
	verify_locked_manifest_commitment_pcr(
		attestor,
		nitro::ManifestCommitmentKind::Live,
		&expected_live_pcr,
	)?;

	Ok(())
}

fn extend_manifest_commitment_pcr(
	attestor: &dyn NsmProvider,
	kind: nitro::ManifestCommitmentKind,
	max_pcrs: u16,
	locked_pcrs: &BTreeSet<u16>,
	manifest_hash: &[u8],
	ephemeral_public_key: &[u8],
) -> Result<[u8; nitro::PCR_SHA384_LEN], ProtocolError> {
	let pcr_index = kind.pcr_index();
	if pcr_index >= max_pcrs {
		return Err(attest_error(format!(
			"PCR{pcr_index} is not supported by NSM max_pcrs {max_pcrs}"
		)));
	}
	if locked_pcrs.contains(&pcr_index) {
		return Err(attest_error(format!("PCR{pcr_index} is already locked")));
	}

	let (pcr_locked, initial_pcr) = describe_pcr(attestor, pcr_index)?;
	if pcr_locked {
		return Err(attest_error(format!(
			"PCR{pcr_index} is read-only before QOS extends it"
		)));
	}
	if initial_pcr.as_slice() != nitro::MANIFEST_COMMITMENT_INITIAL_PCR {
		return Err(attest_error(format!(
			"PCR{pcr_index} initial value mismatch: expected {}, got {}",
			qos_hex::encode(&nitro::MANIFEST_COMMITMENT_INITIAL_PCR),
			qos_hex::encode(&initial_pcr)
		)));
	}

	let commitment = nitro::manifest_pcr_commitment(
		kind,
		manifest_hash,
		ephemeral_public_key,
	);
	let expected_pcr = nitro::pcr_extend_sha384(&initial_pcr, &commitment)?;
	match attestor.nsm_process_request(NsmRequest::ExtendPCR {
		index: pcr_index,
		data: commitment.to_vec(),
	}) {
		NsmResponse::ExtendPCR { data }
			if data.as_slice() == expected_pcr.as_slice() => {}
		NsmResponse::ExtendPCR { data } => {
			return Err(attest_error(format!(
				"PCR{pcr_index} ExtendPCR returned unexpected value: expected {}, got {}",
				qos_hex::encode(&expected_pcr),
				qos_hex::encode(&data)
			)));
		}
		response => return Err(unexpected_nsm_response(&response)),
	}

	Ok(expected_pcr)
}

fn verify_locked_manifest_commitment_pcr(
	attestor: &dyn NsmProvider,
	kind: nitro::ManifestCommitmentKind,
	expected_pcr: &[u8],
) -> Result<(), ProtocolError> {
	let pcr_index = kind.pcr_index();
	let (post_lock, post_lock_pcr) = describe_pcr(attestor, pcr_index)?;
	if !post_lock {
		return Err(attest_error(format!(
			"PCR{pcr_index} is not read-only after LockPCRs"
		)));
	}
	if post_lock_pcr.as_slice() != expected_pcr {
		return Err(attest_error(format!(
			"PCR{pcr_index} post-lock value mismatch: expected {}, got {}",
			qos_hex::encode(expected_pcr),
			qos_hex::encode(&post_lock_pcr)
		)));
	}

	Ok(())
}

fn describe_nsm(
	attestor: &dyn NsmProvider,
) -> Result<(u16, BTreeSet<u16>, NsmDigest), ProtocolError> {
	match attestor.nsm_process_request(NsmRequest::DescribeNSM) {
		NsmResponse::DescribeNSM { max_pcrs, locked_pcrs, digest, .. } => {
			Ok((max_pcrs, locked_pcrs, digest))
		}
		response => Err(unexpected_nsm_response(&response)),
	}
}

fn describe_pcr(
	attestor: &dyn NsmProvider,
	index: u16,
) -> Result<(bool, Vec<u8>), ProtocolError> {
	match attestor.nsm_process_request(NsmRequest::DescribePCR { index }) {
		NsmResponse::DescribePCR { lock, data } => Ok((lock, data)),
		response => Err(unexpected_nsm_response(&response)),
	}
}

fn require_all_pcrs_locked(
	max_pcrs: u16,
	locked_pcrs: &BTreeSet<u16>,
) -> Result<(), ProtocolError> {
	for idx in 0..max_pcrs {
		if !locked_pcrs.contains(&idx) {
			return Err(attest_error(format!(
				"PCR{idx} is not locked after LockPCRs"
			)));
		}
	}
	Ok(())
}

fn unexpected_nsm_response(response: &NsmResponse) -> ProtocolError {
	attest_error(format!("unexpected NSM response: {response:?}"))
}

fn attest_error(message: String) -> ProtocolError {
	ProtocolError::QosAttestError(message)
}

#[cfg(test)]
mod tests {
	use qos_nsm::{
		NsmProvider,
		mock::MockNsm,
		nitro::{
			self, LIVE_MANIFEST_COMMITMENT_PCR_INDEX,
			SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
		},
		types::{NsmRequest, NsmResponse},
	};

	use super::lock_manifest_commitment_pcr_bank;

	#[test]
	fn lock_manifest_commitment_pcr_bank_locks_all_mock_pcrs() {
		let attestor = MockNsm::new();
		let manifest_hash = [1u8; 32];
		let setup_ephemeral_public_key = [2u8; 65];
		let live_ephemeral_public_key = [3u8; 65];

		lock_manifest_commitment_pcr_bank(
			&attestor,
			&manifest_hash,
			&setup_ephemeral_public_key,
			&live_ephemeral_public_key,
		)
		.unwrap();

		let NsmResponse::DescribeNSM { max_pcrs, locked_pcrs, .. } =
			attestor.nsm_process_request(NsmRequest::DescribeNSM)
		else {
			panic!("unexpected DescribeNSM response");
		};
		assert!((0..max_pcrs).all(|idx| locked_pcrs.contains(&idx)));

		let NsmResponse::DescribePCR { lock, data } = attestor
			.nsm_process_request(NsmRequest::DescribePCR {
				index: SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
			})
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(lock);

		let expected = nitro::expected_manifest_commitment_pcr(
			nitro::ManifestCommitmentKind::Setup,
			&manifest_hash,
			&setup_ephemeral_public_key,
		)
		.unwrap();
		assert_eq!(data.as_slice(), expected.as_slice());

		let NsmResponse::DescribePCR { lock, data } = attestor
			.nsm_process_request(NsmRequest::DescribePCR {
				index: LIVE_MANIFEST_COMMITMENT_PCR_INDEX,
			})
		else {
			panic!("unexpected DescribePCR response");
		};
		assert!(lock);

		let expected = nitro::expected_manifest_commitment_pcr(
			nitro::ManifestCommitmentKind::Live,
			&manifest_hash,
			&live_ephemeral_public_key,
		)
		.unwrap();
		assert_eq!(data.as_slice(), expected.as_slice());
	}
}

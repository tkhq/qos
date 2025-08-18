//! Service
use borsh::{to_vec as borsh_to_vec, BorshDeserialize, BorshSerialize};
use generated::prost::Message;
use generated::{
	google::rpc::{Code, Status},
	health::AppHealthResponse,
	services::reshard::v1::{
		qos_retrieve_reshard_request, qos_retrieve_reshard_response,
		QosRetrieveReshardRequest, QosRetrieveReshardResponse,
	},
};
use qos_core::{
	handles::{self},
	protocol::{
		services::{
			boot::{Approval, Manifest, ManifestEnvelope, ShareSet},
			genesis::GenesisMemberOutput,
		},
		QosHash,
	},
	server::RequestProcessor,
};
use qos_crypto::sha_512;
use qos_nsm::types::{NsmRequest, NsmResponse};
use qos_p256::{P256Pair, P256Public};

#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	BorshSerialize,
	BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct ReshardBundle {
	// Public key of the quorum key that was resharded (hex in JSON thanks to qos_hex in types below).
	#[serde(with = "qos_hex::serde")]
	quorum_public_key: Vec<u8>,

	// Live attestation document bytes / contains the eph key used to sign per member outputs
	#[serde(with = "qos_hex::serde")]
	attestation_doc: Vec<u8>,

	// Contains manaifest, manifest_set_approvals, share_set_approvals
	manifest_envelope: ManifestEnvelope,

	// Encapsulated manifest.
	manifest: Manifest,

	// Approvals from the manifest set.
	manifest_set_approvals: Vec<Approval>,

	// Approvals from the share set. This is used to audit what share holders provisioned the quorum key.
	share_set_approvals: Vec<Approval>,

	// Vector of {share_set_member (pub key), encrypted_quorum_key_share, share_hash (to verify correctly decrypted share)}
	member_outputs: Vec<GenesisMemberOutput>,

	// Signature over sha512(member_outputs borsh) with ephemeral key.
	#[serde(with = "qos_hex::serde")]
	signature: Vec<u8>,
}

pub struct ReshardProcessor {
	cached_reshard_bundle: ReshardBundle,
}

impl ReshardProcessor {
	pub fn new(
		handles: handles::Handles,
		new_share_set: ShareSet,
		nsm: Box<dyn qos_nsm::NsmProvider>,
	) -> Result<Self, String> {
		// load keys
		let quorum_pair: P256Pair = handles
			.get_quorum_key()
			.map_err(|e| format!("unable to get quorum key: {e:?}"))?;
		let eph_pair: P256Pair = handles
			.get_ephemeral_key()
			.map_err(|e| format!("unable to get ephemeral key: {e:?}"))?;

		let quorum_pub = quorum_pair.public_key().to_bytes();
		let master_seed = quorum_pair.to_master_seed();

		// Get attestation doc, which ties the running of this specific instance with:
		// 1. the creation of eph key
		// 2. the manifest and approvals
		let attestation_doc =
			match nsm.nsm_process_request(NsmRequest::Attestation {
				user_data: Some(
					handles.get_manifest_envelope().qos_hash().to_vec(),
				),
				nonce: None,
				public_key: Some(eph_pair.public_key().to_bytes()),
			}) {
				NsmResponse::Attestation { document } => document,
				other => {
					return Err(format!("unexpected NSM response: {other:?}"))
				}
			};

		// Split the master seed
		let n = new_share_set.members.len();
		let k = new_share_set.threshold as usize;
		// shares_generate -> Result<Vec<Vec<u8>>, _>;
		let shares: Vec<Vec<u8>> = qos_crypto::shamir::shares_generate(
			&master_seed[..],
			n,
			k,
		)
		.map_err(|e| format!("shares_generate failed: {e:?}"))?;

		// Encrypt per member of the new share set
		let mut member_outputs = Vec::with_capacity(n);
		for (share, member) in
			shares.into_iter().zip(new_share_set.members.clone())
		{
			let personal_pub = P256Public::from_bytes(&member.pub_key)
				.map_err(|e| {
					format!("bad member pubkey for '{}': {e:?}", member.alias)
				})?;
			let encrypted = personal_pub.encrypt(&share).map_err(|e| {
				format!("encryption of share to pub key failed: {e:?}")
			})?;
			let hash = qos_crypto::sha_512(&share);

			member_outputs.push(GenesisMemberOutput {
				share_set_member: member,
				encrypted_quorum_key_share: encrypted,
				share_hash: hash,
			});
		}

		// borsh serialize the member outputs vector, and sign it with the ephemeral key to tie the running of this specific instance
		// with the creation of these new encrypted shares
		let mo_bytes = borsh_to_vec(&member_outputs)
			.map_err(|e| format!("borsh member_outputs: {e}"))?;
		let digest = sha_512(&mo_bytes);
		let signature = eph_pair
			.sign(&digest)
			.map_err(|e| format!("ephemeral sign failed: {e:?}"))?;

		let manifest_envelope = handles
			.get_manifest_envelope()
			.map_err(|_| format!("get_manifest_envelope failed"))?;

		let manifest = manifest_envelope.manifest.clone();
		let manifest_set_approvals =
			manifest_envelope.manifest_set_approvals.clone();
		let share_set_approvals = manifest_envelope.share_set_approvals.clone();

		// assemble all outputs together
		let reshard_bundle = ReshardBundle {
			quorum_public_key: quorum_pub,
			attestation_doc,
			manifest_envelope,
			manifest,
			manifest_set_approvals,
			share_set_approvals,
			member_outputs,
			signature,
		};

		Ok(Self { cached_reshard_bundle: reshard_bundle })
	}
}

fn respond_err(code: Code, msg: impl Into<String>) -> Vec<u8> {
	let status =
		Status { code: code as i32, message: msg.into(), details: vec![] };
	let o = qos_retrieve_reshard_response::Output::Status(status);
	QosRetrieveReshardResponse { output: Some(o) }.encode_to_vec()
}

impl RequestProcessor for ReshardProcessor {
	fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
		use generated::prost::Message as _;

		let req = match QosRetrieveReshardRequest::decode(request.as_slice()) {
			Ok(r) => r,
			Err(e) => {
				return respond_err(
					Code::InvalidArgument,
					format!("bad protobuf: {e}"),
				)
			}
		};

		// With an empty RetrieveReshardRequest, callers can omit the oneof entirely.
		let output = match req.input {
			None
			| Some(
				qos_retrieve_reshard_request::Input::RetrieveReshardRequest(_),
			) => {
                let resp = match crate::routes::retrieve_reshard::retrieve_reshard(&self.cached_reshard_bundle) {
                    Ok(r) => r,
                    Err(e) => return respond_err(e.code, e.message),
                 };

                qos_retrieve_reshard_response::Output::RetrieveReshardResponse(resp)
			}

			Some(qos_retrieve_reshard_request::Input::HealthRequest(_)) => {
				qos_retrieve_reshard_response::Output::HealthResponse(
					AppHealthResponse { code: 200 },
				)
			}
		};

		QosRetrieveReshardResponse { output: Some(output) }.encode_to_vec()
	}
}

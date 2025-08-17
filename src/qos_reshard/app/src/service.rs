//! Service
use borsh::{BorshDeserialize, BorshSerialize};
use core::iter::zip;
use generated::{
	google::rpc::{Code, Status}, health::AppHealthResponse, services::reshard::v1::{
		qos_retrieve_reshard_request, qos_retrieve_reshard_response,
		QosRetrieveReshardRequest, QosRetrieveReshardResponse, RetrieveReshardResponse,
	}
};
use qos_core::{handles::{EphemeralKeyHandle, QuorumKeyHandle},
    server::RequestProcessor,
    protocol::{
        services::{
            boot::{
                Manifest, ManifestEnvelope, ShareSet, 
            },
            genesis::GenesisMemberOutput,
        },
        ProtocolError
    }
};
use qos_p256::{P256Pair, P256Public};
use qos_crypto::sha_512;
use generated::prost::Message;

#[derive(
    Debug, Clone, PartialEq, Eq,
    BorshSerialize, BorshDeserialize,
    serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ReshardBundle {
	// Public key of the quorum key that was resharded (hex in JSON thanks to qos_hex in types below).
    #[serde(with = "qos_hex::serde")]
    quorum_public_key: Vec<u8>,
	
	// Live attestation document bytes / contains the eph key used to sign per member outputs
    #[serde(with = "qos_hex::serde")]
    attestation_doc: Vec<u8>,

	// Manifest that was used
	manifest: Manifest,

	// Manifest envelope
	manifest_envelope: ManifestEnvelope,
	
	// Per new share set member outputs
    member_outputs: Vec<GenesisMemberOutput>,
	
	// Signature over sha512(member_outputs borsh) with ephemeral key.
    #[serde(with = "qos_hex::serde")]
    signature: Vec<u8>,


}

pub struct ReshardProcessor {
	cached_reshard_bundle: Vec<u8>,
}


impl ReshardProcessor {
	pub fn new(
		quorum_key_handle: QuorumKeyHandle,
		ephemeral_key_handle: EphemeralKeyHandle,
		new_share_set: ShareSet,
		nsm: Box<dyn qos_nsm::NsmProvider>,
	) -> Result<Self, String> {

		new_share_set.members.sort();

		// load keys
		let quorum_pair: P256Pair = quorum_key_handle
            .get_quorum_key()
            .map_err(|e| format!("unable to get quorum key: {e:?}"))?;
        let eph_pair: P256Pair = ephemeral_key_handle
            .get_ephemeral_key()
            .map_err(|e| format!("unable to get ephemeral key: {e:?}"))?;

		let quorum_pub = quorum_pair.public_key().to_bytes();
        let master_seed = quorum_pair.to_master_seed();

		// split the master seed and encrypt per member of the new share set 
		let n = new_share_set.members.len();
        let k = new_share_set.threshold as usize;
        let shares = qos_crypto::shamir::shares_generate(&master_seed[..], n, k);

		let mut member_outputs = Vec::with_capacity(n);
        for (share, member) in shares.iter().zip(new_share_set.members.iter().cloned()) {
            let personal_pub = P256Public::from_bytes(&member.pub_key)
                .map_err(|e| format!("bad member pubkey for '{}': {e:?}", member.alias))?;

            let encrypted_share = personal_pub
                .encrypt(share.as_slice())
                .map_err(|e| format!("encrypt failed for '{}': {e:?}", member.alias))?;

            member_outputs.push(GenesisMemberOutput {
                share_set_member: member,
                encrypted_quorum_key_share: encrypted_share,
                share_hash: qos_crypto::sha_512(share.as_slice()),
            });
	    }
    }
}

fn respond_err(code: Code, msg: impl Into<String>) -> Vec<u8> {
    let status = Status { code: code as i32, message: msg.into(), details: vec![] };
    let o = qos_retrieve_reshard_response::Output::Status(status);
    QosRetrieveReshardResponse { output: Some(o) }.encode_to_vec()
}

impl RequestProcessor for ReshardProcessor {
    fn process(&mut self, request: Vec<u8>) -> Vec<u8> {
        use generated::prost::Message as _;

        let req = match QosRetrieveReshardRequest::decode(request.as_slice()) {
            Ok(r) => r,
            Err(e) => return respond_err(Code::InvalidArgument, format!("bad protobuf: {e}")),
        };

        // With an empty RetrieveReshardRequest, callers can omit the oneof entirely.
        let output = match req.input {
            None
            | Some(qos_retrieve_reshard_request::Input::RetrieveReshardRequest(_)) => {
                let resp = RetrieveReshardResponse {
                    reshard_bundle: self.cached_reshard_bundle.clone(),
                };
                qos_retrieve_reshard_response::Output::RetrieveReshardResponse(resp)
            }
            Some(qos_retrieve_reshard_request::Input::HealthRequest(_)) => {
                qos_retrieve_reshard_response::Output::HealthResponse(AppHealthResponse { code: 200 })
            }
        };

        QosRetrieveReshardResponse { output: Some(output) }.encode_to_vec()
    }
}

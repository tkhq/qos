//! Quorum protocol.

use std::{
	fs::{set_permissions, Permissions},
	os::unix::fs::PermissionsExt,
};

use qos_crypto::RsaPub;

mod attestor;
mod boot;
mod genesis;
mod msg;
mod provisioner;

pub use attestor::{MockNsm, Nsm, NsmProvider, MOCK_NSM_ATTESTATION_DOCUMENT};
use boot::ManifestEnvelope;
pub use msg::*;
use provisioner::*;

use crate::server;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProtocolPhase {
	UnrecoverableError,
	WaitingForBootInstruction,
}

pub struct ProtocolState {
	provisioner: SecretProvisioner,
	attestor: Box<dyn NsmProvider>,
	pivot_file: String,
	ephemeral_key_file: String,
	phase: ProtocolPhase,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
		ephemeral_key_file: String,
	) -> Self {
		let provisioner = SecretProvisioner::new(secret_file);
		Self {
			attestor,
			provisioner,
			pivot_file,
			ephemeral_key_file,
			phase: ProtocolPhase::WaitingForBootInstruction,
		}
	}
}

pub struct Executor {
	state: ProtocolState,
}

impl Executor {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
		ephemeral_key_file: String,
	) -> Self {
		Self {
			state: ProtocolState::new(
				attestor,
				secret_file,
				pivot_file,
				ephemeral_key_file,
			),
		}
	}

	fn routes(&self) -> Vec<Box<ProtocolHandler>> {
		match self.state.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![Box::new(handlers::status)]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				// TODO: should only be `boot_instruction` & status, but don't
				// want to break tests
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm_attestation),
				Box::new(handlers::load),
				Box::new(handlers::status),
				Box::new(handlers::boot_instruction),
			],
		}
	}
}

impl server::Routable for Executor {
	fn process(&mut self, mut req_bytes: Vec<u8>) -> Vec<u8> {
		let err_resp = || {
			serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
				.expect("ProtocolMsg can always be serialized. qed.")
		};

		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return err_resp()
		}

		let msg_req = match serde_cbor::from_slice(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => return err_resp(),
		};

		for handler in self.routes().iter() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => {
					return serde_cbor::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		err_resp()
	}
}

mod handlers {
	use qos_crypto::RsaPair;
	use serde_bytes::ByteBuf;

	use super::*;

	macro_rules! ok {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return Some(ProtocolMsg::ErrorResponse),
			}
		};
	}

	macro_rules! ok_unrecoverable {
		( $e:expr, $state:ident ) => {
			match $e {
				Ok(x) => x,
				Err(_) => {
					// $state.phase = ProtocolPhase::UnrecoverableError;
					return Some(ProtocolMsg::ErrorResponse)
				}
			}
		};
	}

	pub fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::StatusRequest = req {
			Some(ProtocolMsg::StatusResponse(state.phase.clone()))
		} else {
			None
		}
	}

	pub fn empty(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EmptyRequest = req {
			Some(ProtocolMsg::EmptyResponse)
		} else {
			None
		}
	}

	pub fn echo(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::EchoRequest(e) = req {
			Some(ProtocolMsg::EchoResponse(e.clone()))
		} else {
			None
		}
	}

	pub fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ProvisionRequest(pr) = req {
			match state.provisioner.add_share(pr.share.clone()) {
				Ok(_) => Some(ProtocolMsg::SuccessResponse),
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn reconstruct(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::ReconstructRequest = req {
			match state.provisioner.reconstruct() {
				Ok(secret) => {
					state.provisioner.secret = Some(secret);
					Some(ProtocolMsg::SuccessResponse)
				}
				Err(_) => Some(ProtocolMsg::ErrorResponse),
			}
		} else {
			None
		}
	}

	pub fn nsm_attestation(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::NsmRequest(NsmRequest::Attestation { .. }) = req {
			let request = NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(ByteBuf::from(
					RsaPair::generate().unwrap().public_key_to_pem().unwrap(),
				)),
			};
			let fd = state.attestor.nsm_init();
			let response = state.attestor.nsm_process_request(fd, request);
			Some(ProtocolMsg::NsmResponse(response))
		} else {
			None
		}
	}

	pub fn load(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		if let ProtocolMsg::LoadRequest(Load { executable, signatures: _ }) =
			req
		{
			// TODO: this should be fixed when we have the executable load logic
			// figured out
			// for SignatureWithPubKey { signature, path } in signatures {
			// 	let pub_key = match RsaPub::from_pem_file(path) {
			// 		Ok(p) => p,
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	};
			// 	match pub_key.verify_sha256(&signature[..], &data[..]) {
			// 		Ok(_) => {}
			// 		Err(_) => return Some(ProtocolMsg::ErrorResponse),
			// 	}
			// }

			ok!(std::fs::write(&state.pivot_file, executable));
			ok!(set_permissions(
				&state.pivot_file,
				Permissions::from_mode(0o111)
			));

			Some(ProtocolMsg::SuccessResponse)
		} else {
			None
		}
	}

	pub fn boot_instruction(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> Option<ProtocolMsg> {
		macro_rules! ok_u {
			( $e:expr ) => {
				ok_unrecoverable!($e, state);
			};
		}

		match req {
			ProtocolMsg::BootRequest(BootInstruction::Standard {
				manifest_envelope,
				pivot,
			}) => {
				let is_manifest_verified =
					verify_manifest_approvals(manifest_envelope);
				if !is_manifest_verified {
					return Some(ProtocolMsg::ErrorResponse)
				}

				let ephemeral_key = ok_u!(RsaPair::generate());

				// Write the ephemeral key to the filesystem
				ok_u!(std::fs::write(
					state.ephemeral_key_file.clone(),
					ok_u!(ephemeral_key.private_key_to_der()),
				));

				// TODO
				// - Verify pivot hash matches specified hash
				// - Write pivot to disk
				// - Save pivot config to state

				// Get the attestation document from the NSM
				let request = NsmRequest::Attestation {
					user_data: Some(ByteBuf::from(
						manifest_envelope.manifest.hash(),
					)),
					nonce: None,
					public_key: Some(ByteBuf::from(
						ephemeral_key.public_key_to_pem().unwrap(),
					)),
				};
				let fd = state.attestor.nsm_init();
				let sign_cose1_attestation_doc =
					state.attestor.nsm_process_request(fd, request);

				Some(ProtocolMsg::BootStandardResponse(
					sign_cose1_attestation_doc,
				))
			}
			ProtocolMsg::BootRequest(BootInstruction::Genesis { config }) => {
				// Generate the Quorum Key
				// Generate a Quorum Set with the same aliases as the Setup
				// Set Shard the Quorum Key and assign one share to each
				// member of the Quorum Set Encrypt each Quorum Member's
				// share to their public key

				// TODO: Entropy!
				let quorum_key = RsaPair::generate().unwrap();
				let shares = qos_crypto::shares_generate(
					&quorum_key.private_key_to_der().expect("TODO"),
					config.setup_set.members.len(),
					config.setup_set.threshold as usize,
				);

				// TODO: Recovery logic!
				// How many permutations of `threshold` keys should we use
				// to reconstruct the original Quorum Key?

				// TODO: Disaster recovery logic!

				// let members: Vec<GenesisMemberOutput> =
				// config.setup_set.members.iter().enumerate().map(|(i,
				// setup_member)| { 	let personal_key =
				// RsaPair::generate().unwrap(); 	let setup_key =
				// RsaPub::from_der(&setup_member.pub_key).expect("TODO");
				// 	let encrypted_shard =
				// setup_key.envelope_encrypt(&personal_key.
				// private_key_to_der().expect("TODO"));

				// 	let quorum_key_share = shares[i];
				// 	let personal_key: RsaPair = personal_key.into();
				// 	let encrypted_quorum_key_share =
				// personal_key.envelope_encrypt(quorum_key_share);

				// 	// let personal_key = .. generate key;
				// 	// let encrypted_shard = personal_key.encrypt(shard);
				// 	// let encrypted_personal_key =
				// setup_member.pub_key.encrypt(personal_key);

				// 	GenesisMemberOutput { alias: setup_member.alias,
				// encrypted_personal_key: '', encrypted_quorum_key_share:
				// ''} }).collect();

				// Output of a genesis ceremony is:
				//  - Quorum Key has been created
				//  - Quorum Set has been created
				//  - Quorum Key has been sharded to that specific Quorum Set
				//  - NOT: A manifest file
				// Immediately after a genesis ceremony:
				//  - Members of the Quorum Set sign the Quorum Configuration
				//  - This serves as the initial proof-of-access for that Quorum
				//    Set
				// Then, a manifest file is constructed using that Quorum
				// Set
				//  - Threshold members sign this manifest file
				// Later, on some cadence, Quorum Members sign a separate
				// proof-of-access
				//  - This second proof-of-access necessitates using a something
				//    "recent" like a hash of a recent ETH block

				unimplemented!()
			}
			_ => None,
		}
	}

	fn verify_manifest_approvals(manifest_envelope: &ManifestEnvelope) -> bool {
		for approval in manifest_envelope.approvals.iter() {
			let pub_key =
				RsaPub::from_der(&approval.member.pub_key).expect("TODO");
			let verification_result = pub_key.verify_sha256(
				&approval.signature,
				&manifest_envelope.manifest.hash(),
			);

			match verification_result {
				Err(_) => return false,
				Ok(verified) => {
					if !verified {
						return false
					}
				}
			}
		}

		true
	}
}

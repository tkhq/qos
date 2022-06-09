//! Quorum protocol.

use std::{
	fs::{set_permissions, Permissions},
	os::unix::fs::PermissionsExt,
};

mod attestor;
mod msg;
mod provisioner;

pub use attestor::{MockNsm, Nsm, NsmProvider, MOCK_NSM_ATTESTATION_DOCUMENT};
pub use msg::*;
use openssl::rsa::Rsa;
use provisioner::*;
use qos_crypto::{sha_256_hash, RsaPub};

use crate::server;

const MEGABYTE: usize = 1024 * 1024;
const MAX_ENCODED_MSG_LEN: usize = 10 * MEGABYTE;

type ProtocolHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> Option<ProtocolMsg>;

pub struct ProtocolState {
	provisioner: SecretProvisioner,
	attestor: Box<dyn NsmProvider>,
	pivot_file: String,
	ephemeral_key_file: String,
}

impl ProtocolState {
	fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
	) -> Self {
		let provisioner = SecretProvisioner::new(secret_file);
		Self { attestor, provisioner, pivot_file }
	}
}

pub struct Executor {
	routes: Vec<Box<ProtocolHandler>>,
	state: ProtocolState,
}

impl Executor {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		secret_file: String,
		pivot_file: String,
	) -> Self {
		Self {
			routes: vec![
				Box::new(handlers::empty),
				Box::new(handlers::echo),
				Box::new(handlers::provision),
				Box::new(handlers::reconstruct),
				Box::new(handlers::nsm_attestation),
				Box::new(handlers::load),
				Box::new(handlers::boot_instruction),
			],
			state: ProtocolState::new(attestor, secret_file, pivot_file),
		}
	}
}

impl server::Routable for Executor {
	fn process(&mut self, mut req_bytes: Vec<u8>) -> Vec<u8> {
		if req_bytes.len() > MAX_ENCODED_MSG_LEN {
			return serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
				.expect("ProtocolMsg can always be serialized. qed.");
		}

		let msg_req = match serde_cbor::from_slice(&mut req_bytes) {
			Ok(req) => req,
			Err(_) => {
				return serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
					.expect("ProtocolMsg can always be serialized. qed.")
			}
		};

		for handler in self.routes.iter() {
			match handler(&msg_req, &mut self.state) {
				Some(msg_resp) => {
					return serde_cbor::to_vec(&msg_resp)
						.expect("ProtocolMsg can always be serialized. qed.")
				}
				None => continue,
			}
		}

		serde_cbor::to_vec(&ProtocolMsg::ErrorResponse)
			.expect("ProtocolMsg can always be serialized. qed.")
	}
}

mod handlers {
	use std::fs::File;

	use serde_bytes::ByteBuf;

	use super::*;

	macro_rules! ok_or_return {
		( $e:expr ) => {
			match $e {
				Ok(x) => x,
				Err(_) => return Some(ProtocolMsg::ErrorResponse),
			}
		};
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
					Rsa::generate(4096).unwrap().public_key_to_pem().unwrap(),
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

			ok_or_return!(std::fs::write(&state.pivot_file, executable));
			ok_or_return!(set_permissions(
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
		if let ProtocolMsg::BootInstruction(instruction) = req {
			match instruction {
				BootInstruction::Standard { manifest_envelope, pivot } => {
					let is_manifest_verified =
						verify_manifest_approvals(manifest_envelope);
					if !is_manifest_verified {
						return Some(ProtocolMsg::ErrorResponse);
					}

					let ephemeral_key = Rsa::generate(4096).unwrap();
					ok_or_return!(std::fs::write(
						state.ephemeral_key_file,
						ephemeral_key.private_key_to_der().expect("TODO")
					));

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
					let response =
						state.attestor.nsm_process_request(fd, request);
				}
				BootInstruction::Genesis { config } => {
					// Generate the Quorum Key
					// Generate a Quorum Set with the same aliases as the Setup Set
					// Shard the Quorum Key and assign one share to each member of the Quorum Set
					// Encrypt each Quorum Member's share to their public key

					// TODO: Entropy!
					let quorum_key = Rsa::generate(4096).unwrap();
					let shares = qos_crypto::shares_generate(
						&quorum_key.private_key_to_der().expect("TODO"),
						config.setup_set.members.len(),
						config.setup_set.threshold as usize,
					);

					// TODO: Recovery logic!

					let members: Vec<GenesisMemberOutput> = config.setup_set.members.iter().enumerate().map(|(i, setup_member)| {
						let personal_key = Rsa::generate(4096).unwrap();
						let setup_key = RsaPub::from_der(&setup_member.pub_key).expect("TODO");
						let encrypted_shard = setup_key.pub_key.public_encrypt(&shares[i], buf, openssl::rsa::Padding::PKCS1_OAEP);
						
						// let personal_key = .. generate key;
						// let encrypted_shard = personal_key.encrypt(shard);
						// let encrypted_personal_key = setup_member.pub_key.encrypt(personal_key);
						
						GenesisMemberOutput { alias: setup_member.alias, encrypted_personal_key: '', encrypted_quorum_key_share: ''}
					}).collect();



					// Output of a genesis ceremony is:
					//  - Quorum Key has been created
					//  - Quorum Set has been created
					//  - Quorum Key has been sharded to that specific Quorum Set
					//  - NOT: A manifest file
					// Immediately after a genesis ceremony:
					//  - Members of the Quorum Set sign the Quorum Configuration
					//  - This serves as the initial proof-of-access for that Quorum Set
					// Then, a manifest file is constructed using that Quorum Set
					//  - Threshold members sign this manifest file
					// Later, on some cadence, Quorum Members sign a separate proof-of-access
					//  - This second proof-of-access necessitates using a something "recent" like a hash of a recent ETH block
				}
			}

			// If instruction is standard
			// Else if instruction is genesis
			Some(ProtocolMsg::SuccessResponse)
		} else {
			None
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
						return false;
					}
				}
			}
		}

		true
	}
}

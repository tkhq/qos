//! Helper script to generate a mock attestation document that works for the
//! boot_e2e.

use std::{fs, path::Path};

use qos_client::request;
use qos_core::{
	hex,
	protocol::{
		attestor::types::{NsmRequest, NsmResponse},
		msg::ProtocolMsg,
	},
};
use qos_crypto::RsaPair;

const MANIFEST_HASH: &str =
	"7d2fb72c3e819375ac2d330987d825431e2abdcebd0429e80d33c621ce995aaf";

#[tokio::main]
async fn main() {
	// Get hash of manifest used for boot e2e

	let uri = "http://127.0.0.1:3000/message";

	let eph_path = Path::new(
		"./qos-core/src/protocol/attestor/static/boot_e2e_mock_eph.secret",
	);
	// Create / read in mock ephemeral key
	let eph_pair = if eph_path.exists() {
		RsaPair::from_pem_file(&eph_path).unwrap()
	} else {
		let pair = RsaPair::generate().unwrap();
		fs::write(&eph_path, pair.private_key_to_pem().unwrap()).unwrap();

		pair
	};

	// Create an nsm attestation request
	let manifest_hash = hex::decode(MANIFEST_HASH).unwrap();
	let nsm_request = NsmRequest::Attestation {
		user_data: Some(manifest_hash),
		nonce: None,
		public_key: Some(eph_pair.public_key_to_pem().unwrap()),
	};
	let req = ProtocolMsg::NsmRequest { nsm_request };

	println!("Making request to {uri} ...");
	let cose_sign1 = match request::post(uri, &req).unwrap() {
		ProtocolMsg::NsmResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		r => panic!("Unexpected response: {:?}", r),
	};
	println!("Got a response!");

	let att_path =
		"./qos-core/src/protocol/attestor/static/boot_e2e_mock_attestation_doc.boot";
	fs::write(&att_path, cose_sign1).unwrap();

	println!("DONE");
}

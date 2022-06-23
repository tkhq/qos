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
	"ad2d8c29e61f5541b72eecdb558c69792436128c7ab7bd87c6204816be87a59d";

// {
//   "Measurements": {
//     "HashAlgorithm": "Sha384 { ... }",
//     "PCR0": "5fc7fd14e63c72968105b2632b6c9249b8c50e1e901c11301fc179d7fe9767b796ee30e07f019c09bac2b12bdafff56e",
//     "PCR1": "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//     "PCR2": "9c706b679dffdb49241c40d9c52f6c8e301b8d82de53ff41feae7ccaacbb5eb08c51fe3e163a719c311b9c093f91f0da"
//   }
// }

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

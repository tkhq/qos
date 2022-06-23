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
	"e921a73712542adffa99089a16c07c52c49f642ca2cd757597a9a81ae6d6438d";

// {
//   "Measurements": {
//     "HashAlgorithm": "Sha384 { ... }",
//     "PCR0": "c3dbb63a4854b9e9dab9f344e855a17a07ca17137d001235e56ed3524b671151619adde60e9c4a901d87eb5c183dd558",
//     "PCR1": "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//     "PCR2": "d271fb47273a891101621eca216262e661e91d36d0b91a41510ea477e2c499ea3f3d6464919c3ddb5aaba92d8894a75b"
//   }
// }

#[tokio::main]
async fn main() {
	// Get hash of manifest used for boot e2e

	let uri = "http://127.0.0.1:3000/message";

	let eph_path = Path::new(
		"./qos-client/src/attest/nitro/static/boot_e2e_mock_eph.secret",
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
		public_key: Some(eph_pair.public_key_to_der().unwrap()),
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
		"./qos-client/src/attest/nitro/static/boot_e2e_mock_attestation_doc.boot";
	fs::write(&att_path, cose_sign1).unwrap();

	println!("DONE");
}

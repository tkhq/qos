use std::{fs, path::Path};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use borsh::{BorshDeserialize, BorshSerialize};
use qos_core::protocol::{
	attestor::types::NsmResponse,
	msg::ProtocolMsg,
	services::{
		boot::{
			Approval, Manifest, ManifestEnvelope, Namespace, NitroConfig,
			PivotConfig, QuorumMember, QuorumSet, RestartPolicy,
		},
		genesis::{GenesisOutput, GenesisSet, SetupMember},
	},
	Hash256, QosHash,
};
use qos_crypto::{sha_256, RsaPair, RsaPub};

use crate::{
	attest::nitro::{
		attestation_doc_from_der, cert_from_pem, AWS_ROOT_CERT_PEM,
	},
	request,
};

const GENESIS_ATTESTATION_DOC_FILE: &str = "attestation_doc.genesis";
const GENESIS_OUTPUT_FILE: &str = "output.genesis";
const SETUP_PUB_EXT: &str = "setup.pub";
const SETUP_PRIV_EXT: &str = "setup.key";
const SHARE_EXT: &str = "share";
const PERSONAL_KEY_PUB_EXT: &str = "personal.pub";
const PERSONAL_KEY_PRIV_EXT: &str = "personal.key";
const MANIFEST_EXT: &str = "manifest";
const APPROVAL_EXT: &str = "approval";
const EPHEMERAL_KEY_PUB_EXT: &str = "ephemeral.pub";
const STANDARD_ATTESTATION_DOC_FILE: &str = "attestation_doc.boot";

// TODO: <https://github.com/tkhq/qos/issues/59/>

pub(crate) fn generate_setup_key<P: AsRef<Path>>(
	alias: &str,
	namespace: &str,
	key_dir_path: P,
) {
	assert!(
		key_dir_path.as_ref().is_dir(),
		"Provided `--key-dir` does not exist is not valid"
	);

	let setup_key = RsaPair::generate().expect("RSA key generation failed");
	// Write the setup key secret
	// TODO: password encryption
	let private_key_file_path = key_dir_path
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SETUP_PRIV_EXT));
	write_with_msg(
		&private_key_file_path,
		&setup_key
			.private_key_to_pem()
			.expect("Private key PEM conversion failed"),
		"Setup Private Key",
	);
	// Write the setup key public key
	let public_key_file_path = key_dir_path
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SETUP_PUB_EXT));

	write_with_msg(
		&public_key_file_path,
		&setup_key
			.public_key_to_pem()
			.expect("Public key PEM conversion failed"),
		"Setup Public Key",
	);
}

pub(crate) fn boot_genesis<P: AsRef<Path>>(
	uri: &str,
	out_dir: P,
	key_dir: P,
	threshold: u32,
) {
	let genesis_set = create_genesis_set(key_dir, threshold);

	let req = ProtocolMsg::BootGenesisRequest { set: genesis_set.clone() };

	let (nsm_response, genesis_output) = match request::post(uri, &req).unwrap()
	{
		ProtocolMsg::BootGenesisResponse { nsm_response, genesis_output } => {
			(nsm_response, genesis_output)
		}
		_ => panic!("Unexpected response"),
	};
	let cose_sign1_der = match nsm_response {
		NsmResponse::Attestation { document } => document,
		_ => panic!("NSM response was not an attestation document"),
	};

	// Sanity check the genesis output
	assert!(
		genesis_set.members.len() == genesis_output.member_outputs.len(),
		"Output of genesis ceremony does not have same members as Setup Set"
	);
	assert!(
		genesis_output.member_outputs.iter().all(|member_out| genesis_set
			.members
			.contains(&member_out.setup_member)),
		"Output of genesis ceremony does not have same members as Setup Set"
	);

	// Check the attestation document
	drop(extract_attestation_doc(&cose_sign1_der));

	let genesis_output_path = out_dir.as_ref().join(GENESIS_OUTPUT_FILE);
	fs::create_dir_all(out_dir.as_ref()).unwrap();

	// Write the attestation doc
	let attestation_doc_path =
		out_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1_der,
		"COSE Sign1 Attestation Doc",
	);

	// Write the genesis output
	write_with_msg(
		&genesis_output_path,
		&genesis_output.try_to_vec().unwrap(),
		"`GenesisOutput`",
	);
}

fn create_genesis_set<P: AsRef<Path>>(
	key_dir: P,
	threshold: u32,
) -> GenesisSet {
	// Get all the files in the key directory
	let key_files = {
		assert!(
			key_dir.as_ref().is_dir(),
			"Provided path is not a valid directory"
		);
		fs::read_dir(key_dir.as_ref()).expect("Failed to read key directory")
	};

	// Assemble the genesis members from all the public keys in the key
	// directory
	let members: Vec<_> = key_files
		.map(|maybe_key_path| maybe_key_path.unwrap().path())
		.filter_map(|key_path| {
			let file_name = key_path
				.file_name()
				.map(std::ffi::OsStr::to_string_lossy)
				.unwrap();
			let split: Vec<_> = file_name.split('.').collect();

			// TODO: do we want to dissallow having anything in this folder
			// that is not a public key for the quorum set?
			if *split.last().unwrap() != "pub" {
				println!("A non `.pub` file was found in the setup key directory - skipping.");
				return None;
			}

			let public_key = RsaPub::from_pem_file(key_path.clone())
				.expect("Failed to read in rsa pub key.");

			Some(SetupMember {
				alias: (*split.get(0).unwrap()).to_string(),
				pub_key: public_key.public_key_to_der().unwrap(),
			})
		})
		.collect();

	println!("Threshold: {}", threshold);
	println!("N: {}", members.len());
	println!("Members:");
	for member in members.clone() {
		println!("  Alias: {}", member.alias);
	}

	GenesisSet { members, threshold }
}

pub(crate) fn after_genesis<P: AsRef<Path>>(
	genesis_dir: P,
	setup_key_path: P,
	pcr0: &[u8],
	pcr1: &[u8],
	pcr2: &[u8],
) {
	let attestation_doc_path =
		genesis_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	let genesis_set_path = genesis_dir.as_ref().join(GENESIS_OUTPUT_FILE);

	// Read in the setup key
	let setup_pair = RsaPair::from_pem_file(&setup_key_path)
		.expect("Failed to read Setup Key");
	// Get the alias from the setup key file name
	let (alias, namespace) = {
		let split = split_file_name(setup_key_path.as_ref());
		(
			(*split.get(0).unwrap()).to_string(),
			(*split.get(1).unwrap()).to_string(),
		)
	};
	println!("Alias: {}, Namespace: {}", alias, namespace);

	// Read in the attestation doc from the genesis directory
	let cose_sign1 =
		fs::read(attestation_doc_path).expect("Could not read attestation_doc");
	let attestation_doc = extract_attestation_doc(&cose_sign1);

	// Read in the genesis output from the genesis directory
	let genesis_output = GenesisOutput::try_from_slice(
		&fs::read(genesis_set_path).expect("Failed to read genesis set"),
	)
	.expect("Could not deserialize the genesis set");

	// Check the attestation document
	verify_attestation_doc_against_user_input(
		&attestation_doc,
		&genesis_output.qos_hash(),
		pcr0,
		pcr1,
		pcr2,
	);

	// Get the members specific output based on alias & setup key
	let setup_public =
		setup_pair.public_key_to_der().expect("Invalid setup key");
	let member_output = genesis_output
		.member_outputs
		.iter()
		.find(|m| {
			m.setup_member.pub_key == setup_public
				&& m.setup_member.alias == alias
		})
		.expect("Could not find a member output associated with the setup key");

	// Decrypt the Personal Key with the Setup Key
	let personal_pair = {
		let personal_key = setup_pair
			.envelope_decrypt(&member_output.encrypted_personal_key)
			.expect("Failed to decrypt personal key");
		RsaPair::from_der(&personal_key)
			.expect("Failed to create RsaPair from decrypted personal key")
	};
	// Sanity check
	assert_eq!(
		personal_pair.public_key_to_der().unwrap(),
		member_output.public_personal_key
	);

	// Make sure we can decrypt the Share with the Personal Key
	drop(
		personal_pair
			.envelope_decrypt(&member_output.encrypted_quorum_key_share)
			.expect("Share could not be decrypted with personal key"),
	);

	// Store the encrypted share
	let share_path = genesis_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SHARE_EXT));
	write_with_msg(
		share_path.as_path(),
		&member_output.encrypted_quorum_key_share,
		"Encrypted Quorum Share",
	);

	// Store the Personal Key, TODO: password encrypt the private key
	// Public
	let personal_key_pub_path = genesis_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, PERSONAL_KEY_PUB_EXT));
	write_with_msg(
		personal_key_pub_path.as_path(),
		&personal_pair
			.public_key_to_pem()
			.expect("Could not create public key from personal pair"),
		"Personal Public Key",
	);
	// Private
	let personal_key_priv_path = genesis_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, PERSONAL_KEY_PRIV_EXT));
	write_with_msg(
		personal_key_priv_path.as_path(),
		&personal_pair
			.private_key_to_pem()
			.expect("Could not create private key from personal pair"),
		"Personal Private Key",
	);
}

/// Panics if verification fails
fn verify_attestation_doc_against_user_input(
	attestation_doc: &AttestationDoc,
	_user_data: &[u8],
	pcr0: &[u8],
	pcr1: &[u8],
	pcr2: &[u8],
) {
	// TODO: this is a hack - we should instead have more realistic
	// mock attestation docs
	#[cfg(not(feature = "mock"))]
	{
		// user data is hash of genesis output
		assert_eq!(
			_user_data,
			attestation_doc.user_data.as_ref().unwrap().to_vec(),
			"Attestation doc does not have hash of genesis output."
		);
		// public key is none
		// assert_eq!(
		// 	attestation_doc.public_key, None,
		// 	"Attestation doc has a public_key when none was expected."
		// );
	}
	#[cfg(feature = "mock")]
	println!(
		"WARNING: SKIPPING ATTESTATION DOC CHECK. DO NOT USE IN PRODUCTION"
	);

	// nonce is none
	assert_eq!(
		attestation_doc.nonce, None,
		"Attestation doc has a nonce when none was expected."
	);

	// pcr0 matches
	assert_eq!(
		pcr0,
		attestation_doc
			.pcrs
			.get(&0)
			.expect("pcr0 not found")
			.clone()
			.into_vec(),
		"pcr0 does not match attestation doc"
	);

	// pcr1 matches
	assert_eq!(
		pcr1,
		attestation_doc
			.pcrs
			.get(&1)
			.expect("pcr1 not found")
			.clone()
			.into_vec(),
		"pcr1 does not match attestation doc"
	);

	// pcr2 matches
	assert_eq!(
		pcr2,
		attestation_doc
			.pcrs
			.get(&2)
			.expect("pcr2 not found")
			.clone()
			.into_vec(),
		"pcr2 does not match attestation doc"
	);
	// - TODO: how do we want to validate the module id?
}

/// Panics if extraction or validation fails.
fn extract_attestation_doc(cose_sign1_der: &[u8]) -> AttestationDoc {
	#[cfg(feature = "mock")]
	let validation_time = crate::attest::nitro::MOCK_SECONDS_SINCE_EPOCH;
	#[cfg(not(feature = "mock"))]
	// TODO: we should probably insert the validation time into the genesis
	// doc?
	let validation_time = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	attestation_doc_from_der(
		cose_sign1_der,
		&cert_from_pem(AWS_ROOT_CERT_PEM)
			.expect("AWS ROOT CERT is not valid PEM"),
		validation_time,
	)
	.expect("Issue extracting and verifying attestation doc")
}

pub(crate) struct GenerateManifestArgs<P: AsRef<Path>> {
	pub genesis_out_path: P,
	pub nonce: u32,
	pub namespace: String,
	pub pivot_hash: Hash256,
	pub restart_policy: RestartPolicy,
	pub pcr0: Vec<u8>,
	pub pcr1: Vec<u8>,
	pub pcr2: Vec<u8>,
	pub root_cert_path: P,
	pub out_dir: P,
}

pub(crate) fn generate_manifest<P: AsRef<Path>>(args: GenerateManifestArgs<P>) {
	let GenerateManifestArgs {
		genesis_out_path,
		nonce,
		namespace,
		pivot_hash,
		restart_policy,
		pcr0,
		pcr1,
		pcr2,
		root_cert_path,
		out_dir,
	} = args;

	let aws_root_certificate = {
		let pem = fs::read(root_cert_path.as_ref())
			.expect("Failed to read in root cert");
		cert_from_pem(&pem)
			.expect("AWS root cert: failed to convert PEM to DER")
	};

	let genesis_output = {
		let buf = fs::read(genesis_out_path.as_ref())
			.expect("Failed to read genesis output file");
		GenesisOutput::try_from_slice(&buf)
			.expect("Failed to decode genesis output")
	};

	let members: Vec<_> = genesis_output
		.member_outputs
		.iter()
		.map(|m| QuorumMember {
			alias: m.setup_member.alias.clone(),
			pub_key: m.public_personal_key.clone(),
		})
		.collect();

	let manifest = Manifest {
		namespace: Namespace { name: namespace.clone(), nonce },
		pivot: PivotConfig { hash: pivot_hash, restart: restart_policy },
		quorum_key: genesis_output.quorum_key,
		quorum_set: QuorumSet { threshold: genesis_output.threshold, members },
		enclave: NitroConfig { pcr0, pcr1, pcr2, aws_root_certificate },
	};

	let manifest_path = out_dir
		.as_ref()
		.join(format!("{}.{}.{}", namespace, nonce, MANIFEST_EXT));
	write_with_msg(&manifest_path, &manifest.try_to_vec().unwrap(), "Manifest");
}

pub(crate) fn sign_manifest<P: AsRef<Path>>(
	manifest_hash: Hash256,
	personal_key_path: P,
	manifest_path: P,
	out_dir: P,
) {
	let manifest = {
		let buf =
			fs::read(manifest_path.as_ref()).expect("Failed to read manifest");
		Manifest::try_from_slice(&buf).expect("Failed to deserialize manifest")
	};

	assert_eq!(
		manifest.qos_hash(),
		manifest_hash,
		"Manifest hashes do not match"
	);

	let (alias, namespace) = {
		let split = split_file_name(personal_key_path.as_ref());
		(split[0].clone(), split[1].clone())
	};
	println!("Alias: {}, Namespace: {}", alias, namespace);

	assert_eq!(
		manifest.namespace.name, namespace,
		"namespace in file name does not match namespace in manifest"
	);

	let personal_pair = RsaPair::from_pem_file(personal_key_path.as_ref())
		.expect("Failed to read Personal Key");

	let approval = Approval {
		signature: personal_pair
			.sign_sha256(&manifest_hash)
			.expect("Failed to sign"),
		member: QuorumMember {
			pub_key: personal_pair
				.public_key_to_der()
				.expect("Failed to get public key"),
			alias: alias.clone(),
		},
	};

	let approval_file = format!(
		"{}.{}.{}.{}",
		alias, namespace, manifest.namespace.nonce, APPROVAL_EXT
	);
	let approval_path = out_dir.as_ref().join(approval_file);
	write_with_msg(
		&approval_path,
		&approval.try_to_vec().expect("Failed to serialize approval"),
		"Manifest Approval",
	);
}

pub(crate) fn boot_standard<P: AsRef<Path>>(
	uri: &str,
	pivot_path: P,
	boot_dir: P,
) {
	// Read in pivot binary
	let pivot =
		fs::read(pivot_path.as_ref()).expect("Failed to read pivot binary");
	// Read in manifest
	let (manifest, approvals) = find_manifest_and_approvals(&boot_dir);
	let manifest_hash = manifest.qos_hash();
	assert_eq!(
		sha_256(&pivot),
		manifest.pivot.hash,
		"Hash of pivot binary does not match manifest"
	);

	// Create manifest envelope
	let manifest_envelope =
		Box::new(ManifestEnvelope { manifest: manifest.clone(), approvals });

	// Broadcast boot standard instruction and extract the attestation doc from
	// the response.
	let req = ProtocolMsg::BootStandardRequest { manifest_envelope, pivot };
	let cose_sign1_der = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootStandardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		_ => panic!("Unexpected response"),
	};
	let attestation_doc = extract_attestation_doc(&cose_sign1_der);

	// Verify attestation document
	// TODO: anything else to verify here?
	verify_attestation_doc_against_user_input(
		&attestation_doc,
		&manifest_hash,
		&manifest.enclave.pcr0,
		&manifest.enclave.pcr1,
		&manifest.enclave.pcr2,
	);

	let ephemeral_key = attestation_doc
		.public_key
		.expect("No ephemeral key in the attestation doc");

	// TODO - don't write the ephemeral key, always extract it from the attestation document
	// Write the ephemeral key
	let ephemeral_path = boot_dir.as_ref().join(format!(
		"{}.{}.{}",
		manifest.namespace.name,
		manifest.namespace.nonce,
		EPHEMERAL_KEY_PUB_EXT
	));
	write_with_msg(&ephemeral_path, &ephemeral_key, "Ephemeral Public Key");

	// write attestation doc
	let attestation_doc_path =
		boot_dir.as_ref().join(STANDARD_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1_der,
		"COSE Sign1 Attestation Doc",
	);
}

fn find_manifest_and_approvals<P: AsRef<Path>>(
	boot_dir: P,
) -> (Manifest, Vec<Approval>) {
	let files: Vec<_> = {
		assert!(
			boot_dir.as_ref().is_dir(),
			"Provided path is not a valid directory"
		);
		fs::read_dir(boot_dir.as_ref())
			.expect("Failed to read boot directory")
			.map(|p| p.unwrap().path())
			.collect()
	};
	let m: Vec<_> = files
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != MANIFEST_EXT) {
				return None;
			};

			let buf = fs::read(path).expect("Failed to read manifest");
			Some(
				Manifest::try_from_slice(&buf)
					.expect("Failed to deserialize manifest"),
			)
		})
		.collect();
	// Make sure there is exactly one manifest
	assert_eq!(m.len(), 1, "Did not find correct number of manifests");
	let manifest = m.first().expect("No manifest in directory").clone();

	let approvals: Vec<_> = files
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			// Only look at files with the approval extension
			if file_name
				.last()
				.map_or(true, |s| s.as_str() != APPROVAL_EXT)
			{
				return None;
			};

			let approval = Approval::try_from_slice(
				&fs::read(path).expect("Failed to read in approval"),
			)
			.expect("Failed to deserialize approval");

			assert!(
				manifest.quorum_set.members.contains(&approval.member),
				"Found approval from member ({:?}) not included in the Quorum Set", approval.member.alias
			);

			let pub_key = RsaPub::from_der(&approval.member.pub_key)
				.expect("Failed to interpret pub key");
			assert!(
				pub_key
					.verify_sha256(&approval.signature, &manifest.qos_hash())
					.unwrap(),
				"Approval signature could not be verified against manifest"
			);

			Some(approval)
		})
		.collect();
	assert!(approvals.len() > manifest.quorum_set.threshold as usize);

	(manifest, approvals)
}

pub(crate) fn post_share<P: AsRef<Path>>(
	uri: &str,
	personal_dir: P,
	boot_dir: P
	manifest_hash: Hash256,
) {
	// TODO validate the manifest is the expected one

	// read in attestation document
}

// Get the file name from a path and split on `"."`.
fn split_file_name(p: &Path) -> Vec<String> {
	let file_name =
		p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();
	file_name.split('.').map(String::from).collect()
}

fn write_with_msg(path: &Path, buf: &[u8], item_name: &str) {
	let path_str = path.as_os_str().to_string_lossy();
	fs::write(path, buf).unwrap_or_else(|_| {
		panic!("Failed writing {} to file", path_str.clone())
	});
	println!("{} written to: {}", item_name, path_str);
}

#[cfg(test)]
mod test {
	// TODO
}
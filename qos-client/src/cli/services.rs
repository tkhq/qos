use std::{
	fs, mem,
	path::{Path, PathBuf},
};

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
const STANDARD_ATTESTATION_DOC_FILE: &str = "attestation_doc.boot";

// TODO: <https://github.com/tkhq/qos/issues/59/>

pub(crate) fn generate_setup_key<P: AsRef<Path>>(
	alias: &str,
	namespace: &str,
	personal_dir: P,
) {
	fs::create_dir_all(personal_dir.as_ref()).unwrap();

	let setup_key = RsaPair::generate().expect("RSA key generation failed");
	// Write the setup key secret
	// TODO: password encryption
	let private_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SETUP_PRIV_EXT));
	write_with_msg(
		&private_path,
		&setup_key
			.private_key_to_pem()
			.expect("Private key PEM conversion failed"),
		"Setup Private Key",
	);

	// Write the setup key public key
	let public_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SETUP_PUB_EXT));
	write_with_msg(
		&public_path,
		&setup_key
			.public_key_to_pem()
			.expect("Public key PEM conversion failed"),
		"Setup Public Key",
	);
}

pub(crate) fn boot_genesis<P: AsRef<Path>>(
	uri: &str,
	genesis_dir: P,
	threshold: u32,
) {
	let genesis_set = create_genesis_set(&genesis_dir, threshold);

	let req = ProtocolMsg::BootGenesisRequest { set: genesis_set.clone() };
	let (cose_sign1, genesis_output) = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootGenesisResponse {
			nsm_response: NsmResponse::Attestation { document },
			genesis_output,
		} => (document, genesis_output),
		_ => panic!("Unexpected response"),
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
	drop(extract_attestation_doc(&cose_sign1));
	// TODO should we check against expected PCRs here?

	// Write the attestation doc
	let attestation_doc_path =
		genesis_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);

	// Write the genesis output
	let genesis_output_path = genesis_dir.as_ref().join(GENESIS_OUTPUT_FILE);
	write_with_msg(
		&genesis_output_path,
		&genesis_output.try_to_vec().unwrap(),
		"`GenesisOutput`",
	);
}

fn create_genesis_set<P: AsRef<Path>>(
	genesis_dir: P,
	threshold: u32,
) -> GenesisSet {
	// Assemble the genesis members from all the public keys in the key
	// directory
	let members: Vec<_> = find_file_paths(&genesis_dir)
		.iter()
		.filter_map(|path| {
			let n = split_file_name(path);

			// TODO: do we want to dissallow having anything in this folder
			// that is not a public key for the quorum set?
			if n.last().map_or(true, |s| s.as_str() != "pub")
				|| n.get(n.len() - 2).map_or(true, |s| s.as_str() != "setup")
			{
				return None;
			}

			let public_key = RsaPub::from_pem_file(&path)
				.expect("Failed to read in rsa pub key.");
			Some(SetupMember {
				alias: (*n.get(0).unwrap()).to_string(),
				pub_key: public_key.public_key_to_der().unwrap(),
			})
		})
		.collect();

	println!("Threshold: {}", threshold);
	println!("N: {}", members.len());
	println!("Members:");
	for member in &members {
		println!("  Alias: {}", member.alias);
	}

	GenesisSet { members, threshold }
}

pub(crate) fn after_genesis<P: AsRef<Path>>(
	genesis_dir: P,
	personal_dir: P,
	pcr0: &[u8],
	pcr1: &[u8],
	pcr2: &[u8],
) {
	let attestation_doc_path =
		genesis_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	let genesis_set_path = genesis_dir.as_ref().join(GENESIS_OUTPUT_FILE);

	// Read in the setup key
	let (setup_pair, setup_file_name) = find_setup_key(&personal_dir);

	// Get the alias from the setup key file name
	let alias = (*setup_file_name.get(0).unwrap()).to_string();
	let namespace = (*setup_file_name.get(1).unwrap()).to_string();
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
	let share_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SHARE_EXT));
	write_with_msg(
		share_path.as_path(),
		&member_output.encrypted_quorum_key_share,
		"Encrypted Quorum Share",
	);

	// Store the Personal Key, TODO: password encrypt the private key
	// Public
	let personal_key_pub_path = personal_dir
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
	let personal_key_priv_path = personal_dir
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

pub(crate) struct GenerateManifestArgs<P: AsRef<Path>> {
	pub genesis_dir: P,
	pub nonce: u32,
	pub namespace: String,
	pub pivot_hash: Hash256,
	pub restart_policy: RestartPolicy,
	pub pcr0: Vec<u8>,
	pub pcr1: Vec<u8>,
	pub pcr2: Vec<u8>,
	pub root_cert_path: P,
	pub boot_dir: P,
}

pub(crate) fn generate_manifest<P: AsRef<Path>>(args: GenerateManifestArgs<P>) {
	let GenerateManifestArgs {
		genesis_dir,
		nonce,
		namespace,
		pivot_hash,
		restart_policy,
		pcr0,
		pcr1,
		pcr2,
		root_cert_path,
		boot_dir,
	} = args;

	let aws_root_certificate = cert_from_pem(
		&fs::read(root_cert_path.as_ref())
			.expect("Failed to read in root cert"),
	)
	.expect("AWS root cert: failed to convert PEM to DER");

	let genesis_output = find_genesis_output(&genesis_dir);

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

	fs::create_dir_all(&boot_dir).expect("Failed to created boot dir");
	let manifest_path = boot_dir
		.as_ref()
		.join(format!("{}.{}.{}", namespace, nonce, MANIFEST_EXT));
	write_with_msg(&manifest_path, &manifest.try_to_vec().unwrap(), "Manifest");
}

pub(crate) fn sign_manifest<P: AsRef<Path>>(
	manifest_hash: Hash256,
	personal_dir: P,
	boot_dir: P,
) {
	let manifest = find_manifest(&boot_dir);
	let (personal_pair, mut personal_path) = find_personal_key(&personal_dir);
	let alias = mem::take(&mut personal_path[0]);
	let namespace = mem::take(&mut personal_path[1]);

	assert_eq!(
		manifest.qos_hash(),
		manifest_hash,
		"Manifest hashes do not match"
	);
	assert_eq!(
		manifest.namespace.name, namespace,
		"namespace in file name does not match namespace in manifest"
	);

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

	let approval_path = boot_dir.as_ref().join(format!(
		"{}.{}.{}.{}",
		alias, namespace, manifest.namespace.nonce, APPROVAL_EXT
	));
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
	let manifest = find_manifest(&boot_dir);
	let approvals = find_approvals(&boot_dir, &manifest);
	let manifest_hash = manifest.qos_hash();

	assert_eq!(
		sha_256(&pivot),
		manifest.pivot.hash,
		"Hash of pivot binary does not match manifest"
	);

	// Create manifest envelope
	let manifest_envelope =
		Box::new(ManifestEnvelope { manifest: manifest.clone(), approvals });

	let req = ProtocolMsg::BootStandardRequest { manifest_envelope, pivot };
	// Broadcast boot standard instruction and extract the attestation doc from
	// the response.
	let cose_sign1 = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootStandardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		_ => panic!("Unexpected response"),
	};

	let attestation_doc = extract_attestation_doc(&cose_sign1);
	// Verify attestation document
	// TODO: anything else to verify here?
	verify_attestation_doc_against_user_input(
		&attestation_doc,
		&manifest_hash,
		&manifest.enclave.pcr0,
		&manifest.enclave.pcr1,
		&manifest.enclave.pcr2,
	);

	// Make sure the ephemeral key is valid.
	drop(
		RsaPub::from_der(
			&attestation_doc
				.public_key
				.expect("No ephemeral key in the attestation doc"),
		)
		.expect("Ephemeral key not valid public key"),
	);

	// write attestation doc
	let attestation_doc_path =
		boot_dir.as_ref().join(STANDARD_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);
}

pub(crate) fn post_share<P: AsRef<Path>>(
	uri: &str,
	personal_dir: P,
	boot_dir: P,
	manifest_hash: Hash256,
) {
	// Read in manifest, share and personal key
	let manifest = find_manifest(&boot_dir);
	let encrypted_share = find_share(&personal_dir);
	let (personal_pair, _) = find_personal_key(&personal_dir);
	let attestation_doc = find_attestation_doc(&boot_dir);

	// Make sure hash matches the manifest hash
	assert_eq!(
		manifest.qos_hash(),
		manifest_hash,
		"Given hash did not match the hash of the manifest"
	);

	// Validate attestation doc
	verify_attestation_doc_against_user_input(
		&attestation_doc,
		&manifest_hash,
		&manifest.enclave.pcr0,
		&manifest.enclave.pcr1,
		&manifest.enclave.pcr2,
	);

	// Get ephemeral key from attestation doc
	let ephemeral_pub = RsaPub::from_der(
		&attestation_doc
			.public_key
			.expect("No ephemeral key in attestation doc"),
	)
	.expect("Failed to read ephemeral key");

	// Decrypt share and re-encrypt to ephemeral key
	let share = ephemeral_pub
		.envelope_encrypt(
			&personal_pair
				.envelope_decrypt(&encrypted_share)
				.expect("Failed to decrypt share with personal key."),
		)
		.expect("Failed to encrypt share to ephemeral key");

	let req = ProtocolMsg::ProvisionRequest { share };
	let is_reconstructed = match request::post(uri, &req).unwrap() {
		ProtocolMsg::ProvisionResponse { reconstructed } => reconstructed,
		_ => panic!("Unexpected response"),
	};

	if is_reconstructed {
		println!("The quorum key has been reconstructed.");
	} else {
		println!("The quorum key has *not* been reconstructed.");
	}
}

fn find_file_paths<P: AsRef<Path>>(dir: P) -> Vec<PathBuf> {
	assert!(dir.as_ref().is_dir(), "Provided path is not a valid directory");
	fs::read_dir(dir.as_ref())
		.expect("Failed to read directory")
		.map(|p| p.unwrap().path())
		.collect()
}

fn find_setup_key<P: AsRef<Path>>(personal_dir: P) -> (RsaPair, Vec<String>) {
	let mut s: Vec<_> = find_file_paths(&personal_dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != "key")
				|| file_name
					.get(file_name.len() - 2)
					.map_or(true, |s| s.as_str() != "setup")
			{
				return None;
			};

			Some((
				RsaPair::from_pem_file(path)
					.expect("Could not read PEM from setup.key"),
				file_name,
			))
		})
		.collect();
	// Make sure there is exactly one manifest
	assert_eq!(s.len(), 1, "Did not find exactly 1 setup key.");

	s.remove(0)
}

fn find_genesis_output<P: AsRef<Path>>(genesis_dir: P) -> GenesisOutput {
	let mut g: Vec<_> = find_file_paths(&genesis_dir)
		.iter()
		.filter_map(|path| {
			let file_name =
				path.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();
			if file_name != GENESIS_OUTPUT_FILE {
				return None;
			}

			Some(
				GenesisOutput::try_from_slice(
					&fs::read(path)
						.expect("Failed to read genesis output file"),
				)
				.expect("Failed to deserialize genesis output"),
			)
		})
		.collect();
	// Make sure there is exactly one manifest
	assert_eq!(g.len(), 1, "Did not find exactly 1 genesis output");

	g.remove(0)
}

fn find_approvals<P: AsRef<Path>>(
	boot_dir: P,
	manifest: &Manifest,
) -> Vec<Approval> {
	let approvals: Vec<_> =  find_file_paths(&boot_dir)
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

	approvals
}

fn find_manifest<P: AsRef<Path>>(boot_dir: P) -> Manifest {
	let mut m: Vec<_> = find_file_paths(&boot_dir)
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

	m.remove(0)
}

fn find_personal_key<P: AsRef<Path>>(
	personal_dir: P,
) -> (RsaPair, Vec<String>) {
	let mut p: Vec<_> = find_file_paths(&personal_dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			// Only look at files with the personal.key extension
			if file_name.last().map_or(true, |s| s.as_str() != "key")
				|| file_name
					.get(file_name.len() - 2)
					.map_or(true, |s| s.as_str() != "personal")
			{
				return None;
			};

			Some((
				RsaPair::from_pem_file(path)
					.expect("Could not read PEM from personal.key"),
				file_name,
			))
		})
		.collect();
	assert_eq!(
		p.len(),
		1,
		"Did not find exactly 1 personal key in the personal-dir"
	);

	p.remove(0)
}

fn find_share<P: AsRef<Path>>(personal_dir: P) -> Vec<u8> {
	let mut s: Vec<_> = find_file_paths(&personal_dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			// Only look at files with the personal.key extension
			if file_name.last().map_or(true, |s| s.as_str() != "share") {
				return None;
			};

			Some(fs::read(path).expect("Failed to read in share"))
		})
		.collect();
	assert_eq!(s.len(), 1, "Did not find exactly 1 share in the personal-dir");

	s.remove(0)
}

/// Find the standard boot attestation doc in a directory.
fn find_attestation_doc<P: AsRef<Path>>(boot_dir: P) -> AttestationDoc {
	let mut a: Vec<_> = find_file_paths(&boot_dir)
		.iter()
		.filter_map(|path| {
			let file_name =
				path.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();

			if file_name != STANDARD_ATTESTATION_DOC_FILE {
				return None;
			}

			Some(extract_attestation_doc(
				&fs::read(&path)
					.expect("Failed to read standard attestation doc"),
			))
		})
		.collect();
	assert_eq!(
		a.len(),
		1,
		"Did not find exactly 1 attestation doc in the personal-dir"
	);

	a.remove(0)
}

/// Extract the attestation doc from a COSE Sign1 structure. Validates the cert
/// chain and basic semantics.
///
/// # Panics
///
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

/// Verify that `attestation_doc` matches the specified parameters.
///
/// # Panics
///
/// Panics if verification fails.
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

/// Get the file name from a path and split on `"."`.
fn split_file_name(p: &Path) -> Vec<String> {
	let file_name =
		p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap();
	file_name.split('.').map(String::from).collect()
}

/// Write `buf` to the file specified by `path` and write to stdout that
/// `item_name` was written to `path`.
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

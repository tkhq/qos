use std::{
	fs,
	fs::File,
	io::BufRead,
	mem,
	path::{Path, PathBuf},
};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use borsh::{BorshDeserialize, BorshSerialize};
use qos_attest::nitro::{
	attestation_doc_from_der, cert_from_pem, unsafe_attestation_doc_from_der,
	verify_attestation_doc_against_user_input, AWS_ROOT_CERT_PEM,
};
use qos_core::protocol::{
	attestor::types::NsmResponse,
	msg::ProtocolMsg,
	services::{
		boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, Namespace,
			NitroConfig, PivotConfig, QuorumMember, RestartPolicy, ShareSet,
		},
		genesis::{GenesisOutput, GenesisSet},
	},
	Hash256, QosHash,
};
use qos_crypto::{sha_256, sha_384, RsaPair, RsaPub};

use crate::request;

const SECRET_EXT: &str = "secret";
const GENESIS_ATTESTATION_DOC_FILE: &str = "genesis_attestation_doc";
const GENESIS_OUTPUT_FILE: &str = "genesis_output";
const SHARE_EXT: &str = "share";
const SHARE_KEY_PUB_EXT: &str = "share_key.pub";
const SHARE_KEY_PRIV_EXT: &str = "share_key.secret";
const MANIFEST_EXT: &str = "manifest";
const MANIFEST_ENVELOPE: &str = "manifest_envelope";
const APPROVAL_EXT: &str = "approval";
const STANDARD_ATTESTATION_DOC_FILE: &str = "boot_attestation_doc";
const EPH_WRAPPED_SHARE_FILE: &str = "ephemeral_key_wrapped.share";
const ATTESTATION_APPROVAL_FILE: &str = "attestation_approval";
const SHARE_SET_ALIAS: &str = "SHARE_SET_ALIAS";
const QUORUM_THRESHOLD_FILE: &str = "quorum_threshold";
const QUORUM_KEY: &str = "quorum_key";
const PUB_EXT: &str = "pub";

const DANGEROUS_DEV_BOOT_MEMBER: &str = "DANGEROUS_DEV_BOOT_MEMBER";
const DANGEROUS_DEV_BOOT_NAMESPACE: &str =
	"DANGEROUS_DEV_BOOT_MEMBER_NAMESPACE";

pub(crate) fn generate_share_key<P: AsRef<Path>>(
	alias: &str,
	namespace: &str,
	personal_dir: P,
) {
	fs::create_dir_all(personal_dir.as_ref()).unwrap();

	let share_key_pair =
		RsaPair::generate().expect("RSA key generation failed");
	// Write the personal key secret
	// TODO: password encryption
	let private_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SHARE_KEY_PRIV_EXT));
	write_with_msg(
		&private_path,
		&share_key_pair
			.private_key_to_pem()
			.expect("Private key PEM conversion failed"),
		"Share Key Secret",
	);

	// Write the setup key public key
	let public_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SHARE_KEY_PUB_EXT));
	write_with_msg(
		&public_path,
		&share_key_pair
			.public_key_to_pem()
			.expect("Public key PEM conversion failed"),
		"Share Key Public",
	);
}

// TODO: verify PCR3
pub(crate) fn boot_genesis<P: AsRef<Path>>(
	uri: &str,
	genesis_dir: P,
	threshold: u32,
	qos_build_fingerprints_path: P,
	pcr3_preimage_path: P,
	unsafe_skip_attestation: bool,
) {
	let genesis_set = create_genesis_set(&genesis_dir, threshold);

	let req = ProtocolMsg::BootGenesisRequest { set: genesis_set.clone() };
	let (cose_sign1, genesis_output) = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootGenesisResponse {
			nsm_response: NsmResponse::Attestation { document },
			genesis_output,
		} => (document, genesis_output),
		r => panic!("Unexpected response: {:?}", r),
	};
	let attestation_doc =
		extract_attestation_doc(&cose_sign1, unsafe_skip_attestation);

	let qos_build_fingerprints =
		extract_qos_build_fingerprints(qos_build_fingerprints_path);

	// Sanity check the genesis output
	assert!(
		genesis_set.members.len() == genesis_output.member_outputs.len(),
		"Output of genesis ceremony does not have same members as Genesis Set"
	);
	assert!(
		genesis_output.member_outputs.iter().all(|member_out| genesis_set
			.members
			.contains(&member_out.share_set_member)),
		"Output of genesis ceremony does not have same members as Genesis Set"
	);

	// Check the attestation document
	if unsafe_skip_attestation {
		println!("**WARNING:** Skipping attestation document verification.");
	} else {
		let user_data = &genesis_output.qos_hash();
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			user_data,
			&qos_build_fingerprints.pcr0,
			&qos_build_fingerprints.pcr1,
			&qos_build_fingerprints.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		);
	}

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
			let mut n = split_file_name(path);

			if n.last().map_or(true, |s| s.as_str() != PUB_EXT)
				|| n.get(n.len() - 2)
					.map_or(true, |s| s.as_str() != "share_key")
			{
				return None;
			}

			let public_key = RsaPub::from_pem_file(&path)
				.expect("Failed to read in rsa pub key.");
			Some(QuorumMember {
				alias: mem::take(&mut n[0]),
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

/// TODO: verify pcr3
pub(crate) fn after_genesis<P: AsRef<Path>>(
	genesis_dir: P,
	personal_dir: P,
	qos_build_fingerprints_path: P,
	pcr3_preimage_path: P,
	unsafe_skip_attestation: bool,
) {
	let attestation_doc_path =
		genesis_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	let genesis_set_path = genesis_dir.as_ref().join(GENESIS_OUTPUT_FILE);

	// Read in the setup key
	let (share_key_pair, mut share_key_file_name) =
		find_share_key(&personal_dir);

	// Get the PCRs for QOS so we can verify
	let qos_build_fingerprints =
		extract_qos_build_fingerprints(qos_build_fingerprints_path);
	println!(
		"QOS build fingerprints taken from commit: {}",
		qos_build_fingerprints.qos_commit
	);

	// Get the alias from the setup key file name
	let alias = mem::take(&mut share_key_file_name[0]);
	let namespace = mem::take(&mut share_key_file_name[1]);
	drop(share_key_file_name);
	println!("Alias: {}, Namespace: {}", alias, namespace);

	// Read in the attestation doc from the genesis directory
	let cose_sign1 =
		fs::read(attestation_doc_path).expect("Could not read attestation_doc");
	let attestation_doc =
		extract_attestation_doc(&cose_sign1, unsafe_skip_attestation);

	// Read in the genesis output from the genesis directory
	let genesis_output = GenesisOutput::try_from_slice(
		&fs::read(genesis_set_path).expect("Failed to read genesis set"),
	)
	.expect("Could not deserialize the genesis set");

	// Check the attestation document
	if unsafe_skip_attestation {
		println!("**WARNING:** Skipping attestation document verification.");
	} else {
		let user_data = &genesis_output.qos_hash();
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			user_data,
			&qos_build_fingerprints.pcr0,
			&qos_build_fingerprints.pcr1,
			&qos_build_fingerprints.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		);
	}

	// Get the members specific output based on alias & setup key
	let share_key_public =
		share_key_pair.public_key_to_der().expect("Invalid setup key");
	let member_output = genesis_output
		.member_outputs
		.iter()
		.find(|m| {
			m.share_set_member.pub_key == share_key_public
				&& m.share_set_member.alias == alias
		})
		.expect("Could not find a member output associated with the setup key");

	// Make sure we can decrypt the Share with the Personal Key
	let plaintext_share = share_key_pair
		.envelope_decrypt(&member_output.encrypted_quorum_key_share)
		.expect("Share could not be decrypted with personal key");

	assert_eq!(
		sha_256(&plaintext_share),
		member_output.share_hash,
		"Expected share hash do not match the actual share hash"
	);

	drop(plaintext_share);

	// Store the encrypted share
	let share_path = personal_dir
		.as_ref()
		.join(format!("{}.{}.{}", alias, namespace, SHARE_EXT));
	write_with_msg(
		share_path.as_path(),
		&member_output.encrypted_quorum_key_share,
		"Encrypted Quorum Share",
	);
}

pub(crate) struct GenerateManifestArgs<P: AsRef<Path>> {
	pub nonce: u32,
	pub namespace: String,
	pub restart_policy: RestartPolicy,
	pub pivot_build_fingerprints_path: P,
	pub qos_build_fingerprints_path: P,
	pub pcr3_preimage_path: P,
	pub root_cert_path: P,
	pub share_set_dir: P,
	pub manifest_set_dir: P,
	pub namespace_dir: P,
	pub boot_dir: P,
	pub pivot_args: Vec<String>,
}

pub(crate) fn generate_manifest<P: AsRef<Path>>(args: GenerateManifestArgs<P>) {
	let GenerateManifestArgs {
		nonce,
		namespace,
		pivot_build_fingerprints_path,
		restart_policy,
		qos_build_fingerprints_path,
		pcr3_preimage_path,
		root_cert_path,
		manifest_set_dir,
		share_set_dir,
		namespace_dir,
		boot_dir,
		pivot_args,
	} = args;

	let aws_root_certificate = cert_from_pem(
		&fs::read(root_cert_path.as_ref())
			.expect("Failed to read in root cert"),
	)
	.expect("AWS root cert: failed to convert PEM to DER");

	let pcr3 = extract_pcr3(pcr3_preimage_path);
	let QosBuildFingerprints { pcr0, pcr1, pcr2, qos_commit } =
		extract_qos_build_fingerprints(qos_build_fingerprints_path);
	let PivotBuildFingerprints { pivot_hash, pivot_commit } =
		extract_pivot_build_fingerprints(pivot_build_fingerprints_path);

	// Get manifest set keys & threshold
	let mut manifest_set = get_manifest_set(manifest_set_dir);
	// Get share set keys & threshold
	let mut share_set = get_share_set(share_set_dir);
	// Get quorum key from namespaces dir
	let quorum_key: RsaPub = find_quorum_key(namespace_dir);

	// We want to try and build the same manifest regardless of the OS.
	manifest_set.members.sort();
	share_set.members.sort();

	let manifest = Manifest {
		namespace: Namespace { name: namespace.clone(), nonce },
		pivot: PivotConfig {
			commit: pivot_commit,
			hash: pivot_hash.try_into().expect("pivot hash was not 256 bits"),
			restart: restart_policy,
			args: pivot_args,
		},
		quorum_key: quorum_key.public_key_to_der().unwrap(),
		manifest_set,
		share_set,
		enclave: NitroConfig { pcr0, pcr1, pcr2, pcr3, aws_root_certificate },
		qos_commit,
	};

	fs::create_dir_all(&boot_dir).expect("Failed to created boot dir");
	let manifest_path = boot_dir
		.as_ref()
		.join(format!("{}.{}.{}", namespace, nonce, MANIFEST_EXT));
	write_with_msg(&manifest_path, &manifest.try_to_vec().unwrap(), "Manifest");
}

// TODO for verifing the manifest
// - verify PCR3 (enter pre-image as arg)
// - verify that this manifest is in the manifest repo & correct nonce (point to
//   manifest repo)
// - verify the manifest namespace (prompt user)
// - verify the public quorum key (either prompt user or enter as CLI input)
// - verify the CLI args (prompt user)
pub(crate) fn sign_manifest<P: AsRef<Path>>(
	manifest_hash: Hash256,
	personal_dir: P,
	boot_dir: P,
	// TODO
	// qos_build_fingerprints_path: P,
	// pcr3_preimage_path: P,
	// pivot_build_fingerprints_path: P,
) {
	let manifest = find_manifest(&boot_dir);
	let (personal_pair, mut personal_path) = find_share_key(&personal_dir);
	let alias = mem::take(&mut personal_path[0]);
	let namespace = mem::take(&mut personal_path[1]);
	drop(personal_path);

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
	pcr3_preimage_path: P,
	unsafe_skip_attestation: bool,
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
	let manifest_envelope = Box::new(ManifestEnvelope {
		manifest: manifest.clone(),
		manifest_set_approvals: approvals,
		share_set_approvals: vec![],
	});

	let req = ProtocolMsg::BootStandardRequest { manifest_envelope, pivot };
	// Broadcast boot standard instruction and extract the attestation doc from
	// the response.
	let cose_sign1 = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootStandardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		r => panic!("Unexpected response: {:?}", r),
	};

	let attestation_doc =
		extract_attestation_doc(&cose_sign1, unsafe_skip_attestation);

	// Verify attestation document
	if unsafe_skip_attestation {
		println!("**WARNING:** Skipping attestation document verification.");
	} else {
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			&manifest_hash,
			&manifest.enclave.pcr0,
			&manifest.enclave.pcr1,
			&manifest.enclave.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		);
	}

	// Make sure the ephemeral key is valid.
	drop(
		RsaPub::from_pem(
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

pub(crate) fn get_attestation_doc<P: AsRef<Path>>(
	uri: &str,
	attestation_dir: P,
) {
	let (cose_sign1, manifest_envelope) =
		match request::post(uri, &ProtocolMsg::LiveAttestationDocRequest) {
			Ok(ProtocolMsg::LiveAttestationDocResponse {
				nsm_response: NsmResponse::Attestation { document },
				manifest_envelope: Some(manifest_envelope),
			}) => (document, manifest_envelope),
			Ok(ProtocolMsg::LiveAttestationDocResponse {
				nsm_response: _,
				manifest_envelope: None
			}) => panic!("ManifestEnvelope does not exist in enclave - likely waiting for boot instruction"),
			r => panic!("Unexpected response: {:?}", r),
		};

	let attestation_doc_path =
		attestation_dir.as_ref().join(STANDARD_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);

	let manifest_envelope_path =
		attestation_dir.as_ref().join(MANIFEST_ENVELOPE);
	write_with_msg(
		&manifest_envelope_path,
		&manifest_envelope.try_to_vec().expect("borsh works"),
		"ManifestEnvelope",
	);
}

pub(crate) fn proxy_re_encrypt_share<P: AsRef<Path>>(
	attestation_dir: P,
	manifest_hash: Hash256,
	personal_dir: P, // TODO: replace this with just using yubikey to sign
	pcr3_preimage_path: P,
	unsafe_skip_attestation: bool,
	unsafe_eph_path_override: Option<String>,
) {
	let manifest_envelope = find_manifest_envelope(&attestation_dir);
	let attestation_doc =
		find_attestation_doc(&attestation_dir, unsafe_skip_attestation);
	let encrypted_share = find_share(&personal_dir);
	let (personal_pair, _) = find_share_key(&personal_dir);

	// Check manifest signatures
	manifest_envelope
		.check_approvals()
		.expect("Manifest does not correct manifest set approvals");

	// Make sure given hash matches the manifest hash
	assert_eq!(
		manifest_envelope.manifest.qos_hash(),
		manifest_hash,
		"Given hash did not match the hash of the manifest"
	);

	// TODO:
	// - point the keys directory and print the names of those who signed with
	//   manifest keys
	// 	- prompt with name and key of each person who signed
	//  - prompt with the number of people who signed
	// - verify PCR3 (enter pre-image as arg)

	// Verify the attestation doc matches up with the pcrs in the manifest
	if unsafe_skip_attestation {
		println!("**WARNING:** Skipping attestation document verification.");
	} else {
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			&manifest_hash,
			&manifest_envelope.manifest.enclave.pcr0,
			&manifest_envelope.manifest.enclave.pcr1,
			&manifest_envelope.manifest.enclave.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		);
	}

	// Pull out the ephemeral key or use the override
	let eph_pub: RsaPub = if let Some(eph_path) = unsafe_eph_path_override {
		RsaPair::from_pem_file(&eph_path)
			.expect("Could not read ephemeral key override")
			.into()
	} else {
		RsaPub::from_pem(
			&attestation_doc
				.public_key
				.expect("No ephemeral key in the attestation doc"),
		)
		.expect("Ephemeral key not valid public key")
	};

	let share = {
		let plaintext_share = &personal_pair
			.envelope_decrypt(&encrypted_share)
			.expect("Failed to decrypt share with personal key.");
		eph_pub
			.envelope_encrypt(plaintext_share)
			.expect("Envelope encryption error")
	};

	let approval = Approval {
		signature: personal_pair
			.sign_sha256(&manifest_envelope.manifest.qos_hash())
			.expect("Failed to sign"),
		member: QuorumMember {
			pub_key: personal_pair
				.public_key_to_der()
				.expect("Failed to get public key"),
			alias: SHARE_SET_ALIAS.to_string(),
		},
	}
	.try_to_vec()
	.expect("Could not serialize Approval");

	let approval_path =
		attestation_dir.as_ref().join(ATTESTATION_APPROVAL_FILE);
	write_with_msg(&approval_path, &approval, "Share Set Approval");

	let share_path = attestation_dir.as_ref().join(EPH_WRAPPED_SHARE_FILE);
	write_with_msg(&share_path, &share, "Ephemeral key wrapped share");
}

pub(crate) fn post_share<P: AsRef<Path>>(uri: &str, attestation_dir: P) {
	// Get the ephemeral key wrapped share
	let share = find_share(&attestation_dir);
	let approval = find_attestation_approval(&attestation_dir);

	let req = ProtocolMsg::ProvisionRequest { share, approval };
	let is_reconstructed = match request::post(uri, &req).unwrap() {
		ProtocolMsg::ProvisionResponse { reconstructed } => reconstructed,
		r => panic!("Unexpected response: {:?}", r),
	};

	if is_reconstructed {
		println!("The quorum key has been reconstructed.");
	} else {
		println!("The quorum key has *not* been reconstructed.");
	}
}

#[allow(clippy::too_many_lines)]
pub(crate) fn dangerous_dev_boot<P: AsRef<Path>>(
	uri: &str,
	pivot_path: P,
	restart: RestartPolicy,
	args: Vec<String>,
	unsafe_eph_path_override: Option<String>,
) {
	// Generate a quorum key
	let quorum_pair = RsaPair::generate().expect("Failed RSA gen");
	let quorum_public_der = quorum_pair.public_key_to_der().unwrap();
	let member = QuorumMember {
		alias: DANGEROUS_DEV_BOOT_MEMBER.to_string(),
		pub_key: quorum_public_der.clone(),
	};

	// Shard it with N=1, K=1
	let share = {
		let mut shares = qos_crypto::shamir::shares_generate(
			&quorum_pair.private_key_to_der().unwrap(),
			1,
			1,
		);
		assert_eq!(
			shares.len(),
			1,
			"Error generating shares - did not get exactly one share."
		);
		shares.remove(0)
	};

	// Read in the pivot
	let pivot = fs::read(&pivot_path).expect("Failed to ready pivot binary.");

	let mock_pcr = vec![0; 48];
	// Create a manifest with manifest set of 1 - everything hardcoded expect
	// pivot config
	let manifest = Manifest {
		namespace: Namespace {
			name: DANGEROUS_DEV_BOOT_NAMESPACE.to_string(),
			nonce: u32::MAX,
		},
		enclave: NitroConfig {
			pcr0: mock_pcr.clone(),
			pcr1: mock_pcr.clone(),
			pcr2: mock_pcr.clone(),
			pcr3: mock_pcr,
			aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
		},
		pivot: PivotConfig {
			commit: "mock-commit-ref".to_string(),
			hash: sha_256(&pivot),
			restart,
			args,
		},
		quorum_key: quorum_public_der,
		manifest_set: ManifestSet {
			threshold: 1,
			// The only member is the quorum member
			members: vec![member.clone()],
		},
		share_set: ShareSet {
			threshold: 1,
			// The only member is the quorum member
			members: vec![member.clone()],
		},
		qos_commit: "mock-qos-commit-ref".to_string(),
	};

	// Create and post the boot standard instruction
	let manifest_envelope = {
		let signature = quorum_pair
			.sign_sha256(&manifest.qos_hash())
			.expect("Failed to sign");
		Box::new(ManifestEnvelope {
			manifest,
			manifest_set_approvals: vec![Approval { signature, member }],
			share_set_approvals: vec![],
		})
	};

	let req = ProtocolMsg::BootStandardRequest {
		manifest_envelope: manifest_envelope.clone(),
		pivot,
	};
	let attestation_doc = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootStandardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => extract_attestation_doc(&document, true),
		r => panic!("Unexpected response: {:?}", r),
	};

	// Pull out the ephemeral key or use the override
	let eph_pub: RsaPub = if let Some(eph_path) = unsafe_eph_path_override {
		RsaPair::from_pem_file(&eph_path)
			.expect("Could not read ephemeral key override")
			.into()
	} else {
		RsaPub::from_pem(
			&attestation_doc
				.public_key
				.expect("No ephemeral key in the attestation doc"),
		)
		.expect("Ephemeral key not valid public key")
	};

	// Create ShareSet approval
	let approval = Approval {
		signature: quorum_pair
			.sign_sha256(&manifest_envelope.manifest.qos_hash())
			.expect("Failed to sign"),
		member: QuorumMember {
			pub_key: quorum_pair
				.public_key_to_der()
				.expect("Failed to get public key"),
			alias: DANGEROUS_DEV_BOOT_MEMBER.to_string(),
		},
	};

	// Post the share
	let req = ProtocolMsg::ProvisionRequest {
		share: eph_pub
			.envelope_encrypt(&share)
			.expect("Failed to encrypt share to eph key."),
		approval,
	};
	match request::post(uri, &req).unwrap() {
		ProtocolMsg::ProvisionResponse { reconstructed } => {
			assert!(reconstructed, "Quorum Key was not reconstructed");
		}
		r => panic!("Unexpected response: {:?}", r),
	};

	println!("Enclave should be finished booting!");
}

fn find_file_paths<P: AsRef<Path>>(dir: P) -> Vec<PathBuf> {
	assert!(dir.as_ref().is_dir(), "Provided path is not a valid directory");
	fs::read_dir(dir.as_ref())
		.expect("Failed to read directory")
		.map(|p| p.unwrap().path())
		.collect()
}

fn find_share_key<P: AsRef<Path>>(personal_dir: P) -> (RsaPair, Vec<String>) {
	let mut s: Vec<_> = find_file_paths(&personal_dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != SECRET_EXT)
				|| file_name
					.get(file_name.len() - 2)
					.map_or(true, |s| s.as_str() != "share_key")
			{
				return None;
			};

			Some((
				RsaPair::from_pem_file(path)
					.expect("Could not read PEM from share_key.key"),
				file_name,
			))
		})
		.collect();
	// Make sure there is exactly one manifest
	assert_eq!(s.len(), 1, "Did not find exactly 1 setup key.");

	s.remove(0)
}

fn find_quorum_key<P: AsRef<Path>>(dir: P) -> RsaPub {
	let mut s: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT)
				|| file_name.first().map_or(true, |s| s.as_str() != QUORUM_KEY)
			{
				return None;
			};

			Some(
				RsaPub::from_pem_file(path)
					.expect("Could not read PEM from share_key.key"),
			)
		})
		.collect();
	// Make sure there is exactly one manifest
	assert_eq!(s.len(), 1, "Did not find exactly 1 quorum key.");

	s.remove(0)
}

fn find_threshold<P: AsRef<Path>>(dir: P) -> u32 {
	// We expect the threshold file to be named `quorum_threshold` and contain a
	// single line with just the a base 10 number. It should live in the
	// directory containing the keys in the set.

	let mut probably_threshold: Vec<u32> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.len() != 1
				|| file_name
					.first()
					.map_or(true, |s| s.as_str() != QUORUM_THRESHOLD_FILE)
			{
				return None;
			};

			let file =
				File::open(path).expect("failed to open quorum_threshold file");
			// Get the fi
			let threshold: u32 = std::io::BufReader::new(file)
				.lines()
				.next() // First line
				.unwrap()
				.unwrap()
				.trim() // Trim any whitespace just to be sure
				.parse() // Parse into a u32
				.expect("Could not parse threshold into u32");

			Some(threshold)
		})
		.collect();

	assert_eq!(
		probably_threshold.len(),
		1,
		"Did not find exactly 1 threshold."
	);

	probably_threshold.remove(0)
}

fn get_share_set<P: AsRef<Path>>(dir: P) -> ShareSet {
	// Get keys
	let members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let mut file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT)
				|| file_name
					.get(file_name.len() - 2)
					.map_or(true, |s| s.as_str() != "share_key")
			{
				return None;
			};

			let public = RsaPub::from_pem_file(path)
				.expect("Could not read PEM from share_key.pub");
			Some(QuorumMember {
				alias: mem::take(&mut file_name[0]),
				pub_key: public.public_key_to_der().unwrap(),
			})
		})
		.collect();

	ShareSet { members, threshold: find_threshold(dir) }
}

fn get_manifest_set<P: AsRef<Path>>(dir: P) -> ManifestSet {
	let members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let mut file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT)
				|| file_name
					.get(file_name.len() - 2)
					.map_or(true, |s| s.as_str() != "share_key")
			{
				return None;
			};

			let public = RsaPub::from_pem_file(path)
				.expect("Could not read PEM from share_key.pub");
			Some(QuorumMember {
				alias: mem::take(&mut file_name[0]),
				pub_key: public.public_key_to_der().unwrap(),
			})
		})
		.collect();

	ManifestSet { members, threshold: find_threshold(dir) }
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
				manifest.manifest_set.members.contains(&approval.member),
				"Found approval from member ({:?}) not included in the Manifest Set", approval.member.alias
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
	assert!(approvals.len() >= manifest.manifest_set.threshold as usize);

	approvals
}

fn find_manifest<P: AsRef<Path>>(dir: P) -> Manifest {
	let mut m: Vec<_> = find_file_paths(&dir)
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

fn find_attestation_doc<P: AsRef<Path>>(
	dir: P,
	unsafe_skip_attestation: bool,
) -> AttestationDoc {
	let mut a: Vec<_> = find_file_paths(&dir)
		.iter()
		.map(|p| {
			(p, p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap())
		})
		.filter_map(|(path, file)| {
			if file == STANDARD_ATTESTATION_DOC_FILE {
				let cose_sign1_der =
					fs::read(path).expect("Failed to read attestation doc");

				Some(extract_attestation_doc(
					&cose_sign1_der,
					unsafe_skip_attestation,
				))
			} else {
				None
			}
		})
		.collect();

	assert_eq!(a.len(), 1, "Not exactly one attestation doc");

	a.remove(0)
}

fn find_manifest_envelope<P: AsRef<Path>>(dir: P) -> ManifestEnvelope {
	let mut a: Vec<_> = find_file_paths(&dir)
		.iter()
		.map(|p| {
			(p, p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap())
		})
		.filter_map(|(path, file)| {
			if file == MANIFEST_ENVELOPE {
				let manifest_envelope =
					fs::read(path).expect("Failed to read manifest envelope");

				Some(
					ManifestEnvelope::try_from_slice(&manifest_envelope)
						.expect("Could not decode manifest envelope"),
				)
			} else {
				None
			}
		})
		.collect();

	assert_eq!(a.len(), 1, "Not exactly one manifest envelope in directory");

	a.remove(0)
}

fn find_attestation_approval<P: AsRef<Path>>(dir: P) -> Approval {
	let mut a: Vec<_> = find_file_paths(&dir)
		.iter()
		.map(|p| {
			(p, p.file_name().map(std::ffi::OsStr::to_string_lossy).unwrap())
		})
		.filter_map(|(path, file)| {
			if file == ATTESTATION_APPROVAL_FILE {
				let manifest_envelope =
					fs::read(path).expect("Failed to read manifest envelope");

				Some(
					Approval::try_from_slice(&manifest_envelope)
						.expect("Could not decode manifest envelope"),
				)
			} else {
				None
			}
		})
		.collect();

	assert_eq!(a.len(), 1, "Not exactly one manifest envelope in directory");

	a.remove(0)
}

// fn find_personal_key<P: AsRef<Path>>(
// 	personal_dir: P,
// ) -> (RsaPair, Vec<String>) {
// 	let mut p: Vec<_> = find_file_paths(&personal_dir)
// 		.iter()
// 		.filter_map(|path| {
// 			let file_name = split_file_name(path);
// 			// Only look at files with the personal.key extension
// 			if file_name.last().map_or(true, |s| s.as_str() != SECRET_EXT)
// 				|| file_name
// 					.get(file_name.len() - 2)
// 					.map_or(true, |s| s.as_str() != "personal")
// 			{
// 				return None;
// 			};

// 			Some((
// 				RsaPair::from_pem_file(path)
// 					.expect("Could not read PEM from personal.secret"),
// 				file_name,
// 			))
// 		})
// 		.collect();

// 	assert_eq!(
// 		p.len(),
// 		1,
// 		"Did not find exactly 1 personal secret in the personal-dir"
// 	);

// 	p.remove(0)
// }

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
	assert_eq!(s.len(), 1, "Did not find exactly 1 share in the directory");

	s.remove(0)
}

struct QosBuildFingerprints {
	pcr0: Vec<u8>,
	pcr1: Vec<u8>,
	pcr2: Vec<u8>,
	qos_commit: String,
}

fn extract_qos_build_fingerprints<P: AsRef<Path>>(
	file_path: P,
) -> QosBuildFingerprints {
	let file = File::open(file_path)
		.expect("failed to open qos build fingerprints file");
	let mut lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();

	QosBuildFingerprints {
		pcr0: qos_hex::decode(&lines[0]).expect("Invalid hex for pcr0"),
		pcr1: qos_hex::decode(&lines[1]).expect("Invalid hex for pcr1"),
		pcr2: qos_hex::decode(&lines[2]).expect("Invalid hex for pcr2"),
		qos_commit: mem::take(&mut lines[3]),
	}
}

fn extract_pcr3<P: AsRef<Path>>(file_path: P) -> Vec<u8> {
	let file = File::open(file_path)
		.expect("failed to open qos build fingerprints file");
	let mut lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();

	let role_arn = std::mem::take(&mut lines[0]);

	let preimage = {
		// Pad preimage with 48 bytes
		let mut preimage = [0u8; 48].to_vec();
		preimage.extend_from_slice(role_arn.as_bytes());
		preimage
	};

	sha_384(&preimage).to_vec()
}

struct PivotBuildFingerprints {
	pivot_hash: Vec<u8>,
	pivot_commit: String,
}

fn extract_pivot_build_fingerprints<P: AsRef<Path>>(
	file_path: P,
) -> PivotBuildFingerprints {
	let file = File::open(file_path)
		.expect("failed to open qos build fingerprints file");
	let mut lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();

	PivotBuildFingerprints {
		pivot_hash: qos_hex::decode(&lines[0])
			.expect("Invalid hex for pivot hash"),
		pivot_commit: mem::take(&mut lines[1]),
	}
}

/// Extract the attestation doc from a COSE Sign1 structure. Validates the cert
/// chain and basic semantics.
///
/// # Panics
///
/// Panics if extraction or validation fails.
pub(crate) fn extract_attestation_doc(
	cose_sign1_der: &[u8],
	unsafe_skip_attestation: bool,
) -> AttestationDoc {
	if unsafe_skip_attestation {
		unsafe_attestation_doc_from_der(cose_sign1_der)
			.expect("Failed to extract attestation doc")
	} else {
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
		.expect("Failed to extract and verify attestation doc")
	}
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

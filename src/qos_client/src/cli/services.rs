use std::{
	fs,
	fs::File,
	io,
	io::{BufRead, Write},
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
	QosHash,
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
		manifest_set_dir,
		share_set_dir,
		namespace_dir,
		boot_dir,
		pivot_args,
	} = args;

	let nitro_config =
		extract_nitro_config(qos_build_fingerprints_path, pcr3_preimage_path);
	let PivotBuildFingerprints { pivot_hash, pivot_commit } =
		extract_pivot_build_fingerprints(pivot_build_fingerprints_path);

	// Get manifest set keys & threshold
	let manifest_set = get_manifest_set(manifest_set_dir);
	// Get share set keys & threshold
	let share_set = get_share_set(share_set_dir);
	// Get quorum key from namespaces dir
	let quorum_key: RsaPub = find_quorum_key(namespace_dir);

	let manifest = Manifest {
		namespace: Namespace {
			name: namespace.clone(),
			nonce,
			quorum_key: quorum_key.public_key_to_der().unwrap(),
		},
		pivot: PivotConfig {
			commit: pivot_commit,
			hash: pivot_hash.try_into().expect("pivot hash was not 256 bits"),
			restart: restart_policy,
			args: pivot_args,
		},
		manifest_set,
		share_set,
		enclave: nitro_config,
	};

	fs::create_dir_all(&boot_dir).expect("Failed to created boot dir");
	let manifest_path = boot_dir
		.as_ref()
		.join(format!("{}.{}.{}", namespace, nonce, MANIFEST_EXT));
	write_with_msg(&manifest_path, &manifest.try_to_vec().unwrap(), "Manifest");
}

fn extract_nitro_config<P: AsRef<Path>>(
	qos_build_fingerprints_path: P,
	pcr3_preimage_path: P,
) -> NitroConfig {
	let pcr3 = extract_pcr3(pcr3_preimage_path);
	let QosBuildFingerprints { pcr0, pcr1, pcr2, qos_commit } =
		extract_qos_build_fingerprints(qos_build_fingerprints_path);

	NitroConfig {
		pcr0,
		pcr1,
		pcr2,
		pcr3,
		qos_commit,
		aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
	}
}

pub(crate) struct ApproveManifestArgs<P: AsRef<Path>> {
	pub personal_dir: P,
	pub manifest_dir: P,
	pub qos_build_fingerprints_path: P,
	pub pcr3_preimage_path: P,
	pub pivot_build_fingerprints_path: P,
	pub namespace_dir: P,
	pub manifest_set_dir: P,
	pub share_set_dir: P,
	pub alias: String,
}

pub(crate) fn approve_manifest<P: AsRef<Path>>(args: ApproveManifestArgs<P>) {
	let ApproveManifestArgs {
		personal_dir,
		manifest_dir,
		qos_build_fingerprints_path,
		pcr3_preimage_path,
		pivot_build_fingerprints_path,
		namespace_dir,
		manifest_set_dir,
		share_set_dir,
		alias,
	} = args;

	let manifest = find_manifest(&manifest_dir);
	let (personal_pair, _) = find_share_key(&personal_dir);

	if !approve_manifest_programmatic_verifications(
		&manifest,
		&get_manifest_set(manifest_set_dir),
		&get_share_set(share_set_dir),
		&extract_nitro_config(qos_build_fingerprints_path, pcr3_preimage_path),
		&extract_pivot_build_fingerprints(pivot_build_fingerprints_path),
		&find_quorum_key(namespace_dir),
	) {
		eprintln!("Exiting early without approving manifest");
		std::process::exit(1);
	}

	let mut prompter =
		Prompter { reader: io::stdin().lock(), writer: io::stdout() };
	if !approve_manifest_human_verifications(&manifest, &mut prompter) {
		eprintln!("Exiting early without approving manifest");
		std::process::exit(1);
	}
	drop(prompter);

	let approval = Approval {
		signature: personal_pair
			.sign_sha256(&manifest.qos_hash())
			.expect("Failed to sign"),
		member: QuorumMember {
			pub_key: personal_pair
				.public_key_to_der()
				.expect("Failed to get public key"),
			alias: alias.clone(),
		},
	};

	let approval_path = manifest_dir.as_ref().join(format!(
		"{}.{}.{}.{}",
		alias, manifest.namespace.name, manifest.namespace.nonce, APPROVAL_EXT
	));
	write_with_msg(
		&approval_path,
		&approval.try_to_vec().expect("Failed to serialize approval"),
		"Manifest Approval",
	);
}

fn approve_manifest_programmatic_verifications(
	manifest: &Manifest,
	manifest_set: &ManifestSet,
	share_set: &ShareSet,
	nitro_config: &NitroConfig,
	pivot_build_fingerprints: &PivotBuildFingerprints,
	quorum_key: &RsaPub,
) -> bool {
	// Verify manifest set composition
	if manifest.manifest_set != *manifest_set {
		eprintln!("Manifest Set composition does not match");
		return false;
	}

	// Verify share set composition
	if manifest.share_set != *share_set {
		eprintln!("Share Set composition does not match");
		return false;
	}

	// Verify pcrs 0, 1, 2, 3.
	if manifest.enclave != *nitro_config {
		eprintln!("Nitro configuration does not match");
		return false;
	}

	// Verify the pivot could be built deterministically
	if manifest.pivot.hash.to_vec() != *pivot_build_fingerprints.pivot_hash {
		eprintln!("Pivot hash does not match");
		return false;
	}

	// Verify the pivot was built from the intended commit
	if manifest.pivot.commit != pivot_build_fingerprints.pivot_commit {
		eprintln!("Pivot commit does not match");
		return false;
	}

	// Verify the intended Quorum Key is being used
	if manifest.namespace.quorum_key != quorum_key.public_key_to_der().unwrap()
	{
		eprintln!("Pivot commit does not match");
		return false;
	}

	true
}

fn approve_manifest_human_verifications<R, W>(
	manifest: &Manifest,
	prompter: &mut Prompter<R, W>,
) -> bool
where
	R: BufRead,
	W: Write,
{
	// Check the namespace name
	{
		let prompt = format!(
			"Is this the correct namespace name: {}? (yes/no)",
			manifest.namespace.name
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check the namespace nonce
	{
		let prompt = format!(
			"Is this the correct namespace nonce: {}? (yes/no)",
			manifest.namespace.nonce
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check pivot restart policy
	{
		let prompt = format!(
			"Is this the correct pivot restart policy: {:?}? (yes/no)",
			manifest.pivot.restart
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check pivot arguments
	{
		let prompt = format!(
			"Are these the correct pivot args:\n{:?}?\n(yes/no)",
			manifest.pivot.args
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	true
}

pub(crate) fn generate_manifest_envelope<P: AsRef<Path>>(manifest_dir: P) {
	let manifest = find_manifest(&manifest_dir);
	let approvals = find_approvals(&manifest_dir, &manifest);

	// Create manifest envelope
	let manifest_envelope = ManifestEnvelope {
		manifest,
		manifest_set_approvals: approvals,
		share_set_approvals: vec![],
	};

	if let Err(e) = manifest_envelope.check_approvals() {
		eprintln!("Error with approvals: {:?}", e);
		std::process::exit(1);
	}

	let path = manifest_dir.as_ref().join(MANIFEST_ENVELOPE);
	write_with_msg(
		&path,
		&manifest_envelope.try_to_vec().expect("Failed to serialize approval"),
		"Manifest Approval",
	);
}

pub(crate) fn boot_standard<P: AsRef<Path>>(
	uri: &str,
	pivot_path: P,
	manifest_dir: P,
	pcr3_preimage_path: P,
	unsafe_skip_attestation: bool,
) {
	// Read in pivot binary
	let pivot =
		fs::read(pivot_path.as_ref()).expect("Failed to read pivot binary");

	// Create manifest envelope
	let manifest_envelope = find_manifest_envelope(manifest_dir);
	let manifest = manifest_envelope.manifest.clone();

	let req = ProtocolMsg::BootStandardRequest {
		manifest_envelope: Box::new(manifest_envelope),
		pivot,
	};
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
			&manifest.qos_hash(),
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

pub(crate) struct ProxyReEncryptShareArgs<P: AsRef<Path>> {
	pub attestation_dir: P,
	pub personal_dir: P, // TODO: replace this with just using yubikey to sign
	pub pcr3_preimage_path: P,
	pub manifest_set_dir: P,
	pub alias: String,
	pub unsafe_skip_attestation: bool,
	pub unsafe_eph_path_override: Option<String>,
}

// Verifications in this focus around ensuring
// - the intended manifest is being used
// - the manifest set approved the manifest and is the correct set
// - the enclave belongs to the intended organization (and not an attackers
//   organization)
pub(crate) fn proxy_re_encrypt_share<P: AsRef<Path>>(
	ProxyReEncryptShareArgs {
		attestation_dir,
		personal_dir,
		pcr3_preimage_path,
		manifest_set_dir,
		alias,
		unsafe_skip_attestation,
		unsafe_eph_path_override,
	}: ProxyReEncryptShareArgs<P>,
) {
	// TODO:
	// - manifest envelope should come from `namespaces` repo, not what is
	// output by get attestation document.
	// - boot standard should output a manifest envelope or we have another
	// command that generates manifest envelope.
	let manifest_envelope = find_manifest_envelope(&attestation_dir);
	let attestation_doc =
		find_attestation_doc(&attestation_dir, unsafe_skip_attestation);
	let encrypted_share = find_share(&personal_dir);
	let (personal_pair, _) = find_share_key(&personal_dir);

	let pcr3_preimage = find_pcr3(&pcr3_preimage_path);

	// Verify the attestation doc matches up with the pcrs in the manifest
	if unsafe_skip_attestation {
		println!("**WARNING:** Skipping attestation document verification.");
	} else {
		verify_attestation_doc_against_user_input(
			&attestation_doc,
			&manifest_envelope.manifest.qos_hash(),
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

	if !proxy_re_encrypt_share_programmatic_verifications(
		&manifest_envelope,
		&get_manifest_set(manifest_set_dir),
		&QuorumMember {
			alias: alias.clone(),
			pub_key: personal_pair.public_key_to_der().unwrap(),
		},
	) {
		eprintln!("Exiting early without re-encrypting / approving");
		std::process::exit(1);
	}

	let mut prompter =
		Prompter { reader: io::stdin().lock(), writer: io::stdout() };
	if !proxy_re_encrypt_share_human_verifications(
		&manifest_envelope,
		&pcr3_preimage,
		&mut prompter,
	) {
		eprintln!("Exiting early without re-encrypting / approving");
		std::process::exit(1);
	}
	drop(prompter);

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
			alias,
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

// TODO: check that the user is in
fn proxy_re_encrypt_share_programmatic_verifications(
	manifest_envelope: &ManifestEnvelope,
	manifest_set: &ManifestSet,
	member: &QuorumMember,
) -> bool {
	// Check manifest signatures
	if let Err(e) = manifest_envelope.check_approvals() {
		eprintln!("Manifest envelope did not have valid approvals: {:?}", e);
		return false;
	};

	if manifest_envelope.manifest.manifest_set != *manifest_set {
		eprintln!(
			"Manifest's manifest set does not match locally found Manifest Set"
		);
		return false;
	}

	if !manifest_envelope.manifest.share_set.members.contains(member) {
		eprintln!("The provided share set key and alias are not part of the Share Set");
		return false;
	}

	true
}

fn proxy_re_encrypt_share_human_verifications<R, W>(
	manifest_envelope: &ManifestEnvelope,
	pcr3_preimage: &str,
	prompter: &mut Prompter<R, W>,
) -> bool
where
	R: BufRead,
	W: Write,
{
	// Check the namespace name
	{
		let prompt = format!(
			"Is this the correct namespace name: {}? (yes/no)",
			manifest_envelope.manifest.namespace.name
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check the namespace nonce
	{
		let prompt = format!(
			"Is this the correct namespace nonce: {}? (yes/no)",
			manifest_envelope.manifest.namespace.nonce
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check that the IAM role is correct
	{
		let prompt = format!(
			"Does this AWS IAM role belong to the intended organization: {}? (yes/no)",
			pcr3_preimage
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	{
		let mut approvers = manifest_envelope
			.manifest_set_approvals
			.iter()
			.cloned()
			.map(|m| m.member.alias)
			.map(|a| format!("\talias: {a}"))
			.collect::<Vec<_>>();
		approvers.sort();
		let approvers = approvers.join("\n");

		let prompt = format!("The following manifest set members approved:\n{approvers}\nIs this ok? (yes/no)");

		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	true
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
			quorum_key: quorum_public_der,
		},
		enclave: NitroConfig {
			pcr0: mock_pcr.clone(),
			pcr1: mock_pcr.clone(),
			pcr2: mock_pcr.clone(),
			pcr3: mock_pcr,
			qos_commit: "mock-qos-commit-ref".to_string(),
			aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
		},
		pivot: PivotConfig {
			commit: "mock-commit-ref".to_string(),
			hash: sha_256(&pivot),
			restart,
			args,
		},
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
	let mut members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let mut file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT) {
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

	// We want to try and build the same manifest regardless of the OS.
	members.sort();

	ShareSet { members, threshold: find_threshold(dir) }
}

fn get_manifest_set<P: AsRef<Path>>(dir: P) -> ManifestSet {
	let mut members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let mut file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT) {
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

	// We want to try and build the same manifest regardless of the OS.
	members.sort();

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

fn find_pcr3<P: AsRef<Path>>(file_path: P) -> String {
	let file = File::open(file_path).expect("failed to open pcr3 preimage");
	let mut lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();

	lines.remove(0)
}

fn extract_pcr3<P: AsRef<Path>>(file_path: P) -> Vec<u8> {
	let role_arn = find_pcr3(file_path);

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

struct Prompter<R, W> {
	reader: R,
	writer: W,
}

impl<R, W> Prompter<R, W>
where
	R: BufRead,
	W: Write,
{
	fn prompt(&mut self, question: &str) -> String {
		writeln!(&mut self.writer, "{}", question).expect("Unable to write");
		let mut s = String::new();
		let _amt = self.reader.read_line(&mut s).expect("Unable to read");
		s.trim().to_string()
	}

	fn prompt_is_yes(&mut self, question: &str) -> bool {
		self.prompt(question) == "yes"
	}
}

#[cfg(test)]
mod tests {
	use std::vec;

	use qos_attest::nitro::{cert_from_pem, AWS_ROOT_CERT_PEM};
	use qos_core::protocol::{
		services::boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, Namespace,
			NitroConfig, PivotConfig, QuorumMember, RestartPolicy, ShareSet,
		},
		QosHash,
	};
	use qos_crypto::{RsaPair, RsaPub};

	use super::{
		approve_manifest_human_verifications,
		approve_manifest_programmatic_verifications,
		proxy_re_encrypt_share_human_verifications,
		proxy_re_encrypt_share_programmatic_verifications,
		PivotBuildFingerprints, Prompter,
	};

	struct Setup {
		manifest: Manifest,
		manifest_set: ManifestSet,
		share_set: ShareSet,
		nitro_config: NitroConfig,
		pivot_build_fingerprints: PivotBuildFingerprints,
		quorum_key: RsaPub,
		manifest_envelope: ManifestEnvelope,
	}
	fn setup() -> Setup {
		let pairs: Vec<_> =
			(0..3).map(|_| RsaPair::generate().unwrap()).collect();

		let members: Vec<_> = pairs
			.iter()
			.enumerate()
			.map(|(i, pair)| QuorumMember {
				pub_key: pair.public_key_to_der().unwrap(),
				alias: i.to_string(),
			})
			.collect();

		let manifest_set =
			ManifestSet { members: members.clone(), threshold: 2 };
		let share_set = ShareSet { members: members.clone(), threshold: 2 };
		let nitro_config = NitroConfig {
			pcr0: vec![1; 42],
			pcr1: vec![2; 42],
			pcr2: vec![3; 42],
			pcr3: vec![4; 42],
			qos_commit: "good-qos-commit".to_string(),
			aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
		};
		let pivot_build_fingerprints = PivotBuildFingerprints {
			pivot_hash: vec![5; 32],
			pivot_commit: "good-pivot-commit".to_string(),
		};
		let quorum_key: RsaPub = RsaPair::generate().unwrap().into();

		let manifest = Manifest {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 2,
				quorum_key: quorum_key.public_key_to_der().unwrap(),
			},
			pivot: PivotConfig {
				hash: pivot_build_fingerprints
					.pivot_hash
					.clone()
					.try_into()
					.unwrap(),
				commit: pivot_build_fingerprints.pivot_commit.clone(),
				restart: RestartPolicy::Never,
				args: ["--option1", "argument"]
					.into_iter()
					.map(String::from)
					.collect(),
			},
			manifest_set: manifest_set.clone(),
			share_set: share_set.clone(),
			enclave: nitro_config.clone(),
		};

		let manifest_envelope = ManifestEnvelope {
			manifest: manifest.clone(),
			manifest_set_approvals: std::iter::zip(
				pairs[..2].iter(),
				members.iter(),
			)
			.map(|(pair, member)| Approval {
				signature: pair.sign_sha256(&manifest.qos_hash()).unwrap(),
				member: member.clone(),
			})
			.collect(),
			share_set_approvals: vec![],
		};

		Setup {
			manifest,
			manifest_set,
			share_set,
			nitro_config,
			pivot_build_fingerprints,
			quorum_key,
			manifest_envelope,
		}
	}

	mod approve_manifest_programmatic_verifications {
		use super::*;

		#[test]
		fn works() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			assert!(approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatch_manifest_set() {
			let Setup {
				manifest,
				mut manifest_set,
				share_set,
				nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			manifest_set.members.get_mut(0).unwrap().alias =
				"vape2live".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_share_set() {
			let Setup {
				manifest,
				manifest_set,
				mut share_set,
				nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			share_set.members.get_mut(0).unwrap().alias =
				"vape2live".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pcr0() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			nitro_config.pcr0 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pcr1() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			nitro_config.pcr1 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pcr2() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			nitro_config.pcr2 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pcr3() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			nitro_config.pcr3 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_qos_commit() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut nitro_config,
				pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			nitro_config.qos_commit = "bad qos commit".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pivot_hash() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				nitro_config,
				mut pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			pivot_build_fingerprints.pivot_hash = vec![42; 32];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pivot_commit() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				nitro_config,
				mut pivot_build_fingerprints,
				quorum_key,
				..
			} = setup();

			pivot_build_fingerprints.pivot_commit =
				"bad-pivot-commit".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_quorum_key() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				nitro_config,
				pivot_build_fingerprints,
				..
			} = setup();

			let quorum_key: RsaPub = RsaPair::generate().unwrap().into();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&nitro_config,
				&pivot_build_fingerprints,
				&quorum_key,
			));
		}
	}

	mod approve_manifest_human_verifications {
		use super::*;
		#[test]
		fn human_verification_works() {
			let Setup { manifest, .. } = setup();

			let mut vec_out = Vec::<u8>::new();
			let vec_in = "yes\nyes\nyes\nyes\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));
		}

		#[test]
		fn exits_early_with_bad_namespace_name() {
			let Setup { manifest, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "ye\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!super::approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			assert_eq!(
				&output,
				"Is this the correct namespace name: test-namespace? (yes/no)\n"
			);
		}

		#[test]
		fn exits_early_with_bad_namespace_nonce() {
			let Setup { manifest, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nye".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!super::approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.split('\n').collect();

			assert_eq!(
				output[1],
				"Is this the correct namespace nonce: 2? (yes/no)"
			);
		}

		#[test]
		fn exits_early_with_bad_restart_policy() {
			let Setup { manifest, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\ny".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!super::approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.split('\n').collect();

			assert_eq!(
				output[2],
				"Is this the correct pivot restart policy: Never? (yes/no)"
			);
		}

		#[test]
		fn exits_early_with_bad_pivot_args() {
			let Setup { manifest, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\nyes\nno".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!super::approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.split('\n').collect();

			assert_eq!(output[3], "Are these the correct pivot args:");
			assert_eq!(output[4], "[\"--option1\", \"argument\"]?");
			assert_eq!(output[5], "(yes/no)");
		}
	}

	mod proxy_re_encrypt_share_programmatic_verifications {
		use super::*;

		#[test]
		fn accepts_valid() {
			let Setup { manifest_set, share_set, manifest_envelope, .. } =
				setup();

			let member = share_set.members[0].clone();
			assert!(proxy_re_encrypt_share_programmatic_verifications(
				&manifest_envelope,
				&manifest_set,
				&member
			));
		}

		#[test]
		fn rejects_invalid_approval() {
			let Setup {
				manifest_set, share_set, mut manifest_envelope, ..
			} = setup();

			manifest_envelope
				.manifest_set_approvals
				.get_mut(0)
				.unwrap()
				.signature = vec![0; 32];

			let member = share_set.members[0].clone();
			assert!(!proxy_re_encrypt_share_programmatic_verifications(
				&manifest_envelope,
				&manifest_set,
				&member
			));
		}

		#[test]
		fn rejects_approval_from_member_not_part_of_manifest_set() {
			let Setup {
				manifest_set, share_set, mut manifest_envelope, ..
			} = setup();

			manifest_envelope
				.manifest_set_approvals
				.get_mut(0)
				.unwrap()
				.member
				.alias = "yoloswag420blazeit".to_string();

			let member = share_set.members[0].clone();
			assert!(!proxy_re_encrypt_share_programmatic_verifications(
				&manifest_envelope,
				&manifest_set,
				&member
			));
		}

		#[test]
		fn rejects_if_not_enough_approvals() {
			let Setup {
				manifest_set, share_set, mut manifest_envelope, ..
			} = setup();

			manifest_envelope.manifest_set_approvals.pop().unwrap();

			let member = share_set.members[0].clone();
			assert!(!proxy_re_encrypt_share_programmatic_verifications(
				&manifest_envelope,
				&manifest_set,
				&member
			));
		}

		#[test]
		fn rejects_mismatched_manifest_sets() {
			let Setup {
				mut manifest_set, share_set, manifest_envelope, ..
			} = setup();

			manifest_set.members.push(QuorumMember {
				alias: "got what plants need".to_string(),
				pub_key: RsaPair::generate()
					.unwrap()
					.public_key_to_der()
					.unwrap(),
			});

			let member = share_set.members[0].clone();
			assert!(!proxy_re_encrypt_share_programmatic_verifications(
				&manifest_envelope,
				&manifest_set,
				&member
			));
		}
	}

	mod proxy_re_encrypt_share_human_verifications {
		use super::*;
		#[test]
		fn accepts_all_yes_responses() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\nyes\nyes\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));
		}

		#[test]
		fn exits_early_bad_namespace_name() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "no\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			assert_eq!(&output, "Is this the correct namespace name: test-namespace? (yes/no)\n");
		}

		#[test]
		fn exits_early_bad_namespace_nonce() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nno\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.trim().split('\n').collect();
			assert_eq!(
				output.last().unwrap(),
				&"Is this the correct namespace nonce: 2? (yes/no)"
			);
		}

		#[test]
		fn exits_early_bad_iam_role() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\nNO\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.trim().split('\n').collect();
			assert_eq!(output.last().unwrap(), &"Does this AWS IAM role belong to the intended organization: pr3? (yes/no)");
		}

		#[test]
		fn exits_early_bad_manifest_set_members() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\nyes\ny".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.trim().split('\n').collect();

			assert_eq!(
				output[3],
				"The following manifest set members approved:"
			);
			assert_eq!(output[4], "\talias: 0");
			assert_eq!(output[5], "\talias: 1");
			assert_eq!(output[6], "Is this ok? (yes/no)");
			assert_eq!(output.len(), 7);
		}
	}
}

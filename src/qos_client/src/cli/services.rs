use std::{
	fs::{self, File},
	io::{self, BufRead, BufReader, Write},
	mem,
	path::{Path, PathBuf},
};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use borsh::BorshDeserialize;
use qos_core::protocol::{
	msg::ProtocolMsg,
	services::{
		boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, MemberPubKey,
			Namespace, NitroConfig, PatchSet, PivotConfig, QuorumMember,
			RestartPolicy, ShareSet,
		},
		genesis::{GenesisOutput, GenesisSet},
		key::EncryptedQuorumKey,
	},
	QosHash,
};
use qos_crypto::{sha_256, sha_384, sha_512};
use qos_nsm::{
	nitro::{
		attestation_doc_from_der, cert_from_pem,
		unsafe_attestation_doc_from_der,
		verify_attestation_doc_against_user_input, AWS_ROOT_CERT_PEM,
	},
	types::NsmResponse,
};
use qos_p256::{P256Error, P256Pair, P256Public};
use zeroize::Zeroizing;

use super::DisplayType;
use crate::request;

const PUB_EXT: &str = "pub";
const GENESIS_ATTESTATION_DOC_FILE: &str = "genesis_attestation_doc";
const GENESIS_OUTPUT_FILE: &str = "genesis_output";
const MANIFEST_ENVELOPE: &str = "manifest_envelope";
const APPROVAL_EXT: &str = "approval";
const QUORUM_THRESHOLD_FILE: &str = "quorum_threshold";
const DR_WRAPPED_QUORUM_KEY: &str = "dr_wrapped_quorum_key";
const PCRS_PATH: &str = "aws-x86_64.pcrs";
const GENESIS_DR_ARTIFACTS: &str = "genesis_dr_artifacts";

const DANGEROUS_DEV_BOOT_MEMBER: &str = "DANGEROUS_DEV_BOOT_MEMBER";
const DANGEROUS_DEV_BOOT_NAMESPACE: &str =
	"DANGEROUS_DEV_BOOT_MEMBER_NAMESPACE";

#[cfg(not(feature = "smartcard"))]
pub(crate) const SMARTCARD_FEAT_DISABLED_MSG: &str =
	"The \"smartcard\" feature must be enabled to use YubiKey related functionality.";

const ENTER_PIN_PROMPT: &str = "Enter your pin: ";
const TAP_MSG: &str = "Tap your YubiKey";

/// Client errors.
#[derive(Debug)]
pub enum Error {
	/// Failed to open a yubikey. Make sure only 1 yubikey is connected to the
	/// machine. Also try unplugging the yubikey to reset the PCSC session.
	#[cfg(feature = "smartcard")]
	OpenSingleYubiKey(yubikey::Error),
	/// Error'ed while tried to generate a key and cert for the signing slot.
	#[cfg(feature = "smartcard")]
	GenerateSign(crate::yubikey::YubiKeyError),
	/// Error'ed while tried to generate a key and cert for the encryption
	/// slot.
	#[cfg(feature = "smartcard")]
	GenerateEncrypt(crate::yubikey::YubiKeyError),
	/// General wrapper for yubikey error
	#[cfg(feature = "smartcard")]
	YubiKey(crate::yubikey::YubiKeyError),
	/// Error from qos p256.
	P256(qos_p256::P256Error),
	/// The public key read from the yubikey for the pair did not match what
	/// was expected.
	#[cfg(feature = "smartcard")]
	WrongPublicKey,
	/// An error trying to read a pin from the terminal
	#[allow(clippy::enum_variant_names)]
	#[cfg(feature = "smartcard")]
	PinEntryError(std::io::Error),
	/// Failed to read share
	ReadShare(String),
	/// Error while try to read the quorum public key.
	FailedToReadQuorumPublicKey(qos_p256::P256Error),
	/// Error trying to the read a file that is supposed to have a manifest.
	FailedToReadManifestFile(std::io::Error),
	/// Error deserializing manifest.
	FileDidNotHaveValidManifest,
	/// Error trying to read a file that is supposed to have a manifest
	/// envelope.
	FailedToReadManifestEnvelopeFile(std::io::Error),
	/// Error deserializing manifest envelope.
	FileDidNotHaveValidManifestEnvelope,
	/// Error trying to read a file that is supposed to contain attestation
	/// doc.
	FailedToReadAttestationDoc(std::io::Error),
	/// Error trying to the read a file that is supposed to contain attestation
	/// approval.
	FailedToReadAttestationApproval(std::io::Error),
	/// Error deserializing manifest envelope.
	FileDidNotHaveValidAttestationApproval,
	/// Failed to read file that was supposed to contain Ephemeral Key wrapped
	/// share.
	FailedToReadEphWrappedShare(std::io::Error),
	FailedToRead {
		path: String,
		error: String,
	},
	/// Failed to decode some hex
	CouldNotDecodeHex(qos_hex::HexError),
	/// Failed to deserialize something from borsh.
	#[allow(clippy::enum_variant_names)]
	BorshError,
	FailedToReadDrKey(qos_p256::P256Error),
	QosAttest(String),
	/// Pivot file
	FailedToReadPivot(std::io::Error),
	/// Unexpected response from a request to the enclave - likely an error.
	UnexpectedProtocolMsgResponse(String),
	/// Could not read the file that should contain the encrypted quorum key.
	FailedToReadEncryptedQuorumKey,
	/// The contents of the file are not a valid encrypted quorum key struct.
	InvalidEncryptedQuorumKey,
	/// Signature could not be verified.
	InvalidSignature,
	/// Could not deterministically reproduce a signature.
	CouldNotReproduceSignature,
	/// Decryption did not result in the expected palintext.
	BadDecryption,
	/// The seed was read two different ways and the results did not match -
	/// most likely a bug with the code.
	#[allow(clippy::enum_variant_names)]
	ErrorReadingSeed,
	/// Given quorum key seed does not match the hash of the expected quorum
	/// key seed.
	SecretDoesNotMatch,
}

impl From<borsh::io::Error> for Error {
	fn from(_: borsh::io::Error) -> Self {
		Self::BorshError
	}
}

#[cfg(feature = "smartcard")]
impl From<crate::yubikey::YubiKeyError> for Error {
	fn from(err: crate::yubikey::YubiKeyError) -> Self {
		Error::YubiKey(err)
	}
}

impl From<P256Error> for Error {
	fn from(err: P256Error) -> Self {
		Error::P256(err)
	}
}

impl From<qos_hex::HexError> for Error {
	fn from(err: qos_hex::HexError) -> Error {
		Error::CouldNotDecodeHex(err)
	}
}

impl From<qos_nsm::nitro::AttestError> for Error {
	fn from(err: qos_nsm::nitro::AttestError) -> Error {
		let msg = format!("{err:?}");
		Error::QosAttest(msg)
	}
}

/// Use a P256 key pair or Yubikey for signing operations.
pub enum PairOrYubi {
	/// Yubikey
	#[cfg(feature = "smartcard")]
	Yubi((yubikey::YubiKey, Vec<u8>)),
	/// P256 keypair
	Pair(P256Pair),
}

impl PairOrYubi {
	/// Create a P256 key pair or yubikey from the given inputs
	#[allow(clippy::missing_panics_doc)]
	pub fn from_inputs(
		yubikey_flag: bool,
		secret_path: Option<String>,
		maybe_pin_path: Option<String>,
	) -> Result<Self, Error> {
		let result = match (yubikey_flag, secret_path) {
			(true, None) => {
				#[cfg(feature = "smartcard")]
				{
					let yubi = crate::yubikey::open_single()?;

					let pin = if let Some(pin_path) = maybe_pin_path {
						pin_from_path(pin_path)
					} else {
						rpassword::prompt_password(ENTER_PIN_PROMPT)
							.map_err(Error::PinEntryError)?
							.as_bytes()
							.to_vec()
					};

					PairOrYubi::Yubi((yubi, pin))
				}
				#[cfg(not(feature = "smartcard"))]
				{
					panic!("{TAP_MSG}");
				}
			}
			(false, Some(path)) => {
				let pair = P256Pair::from_hex_file(path)?;
				PairOrYubi::Pair(pair)
			}
			(false, None) => panic!("Need either yubikey flag or secret path"),
			(true, Some(_)) => {
				panic!("Cannot have both yubikey flag and secret path")
			}
		};

		Ok(result)
	}

	/// Sign the payload
	pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, ref pin)) => {
				println!("{TAP_MSG}");
				crate::yubikey::sign_data(yubi, data, pin).map_err(Into::into)
			}
			Self::Pair(ref pair) => pair.sign(data).map_err(Into::into),
		}
	}

	/// Decrypt the payload
	pub fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, ref pin)) => {
				println!("{TAP_MSG}");
				let shared_secret =
					crate::yubikey::shared_secret(yubi, payload, pin)?;
				let encrypt_pub = crate::yubikey::key_agree_public_key(yubi)?;
				let public = qos_p256::encrypt::P256EncryptPublic::from_bytes(
					&encrypt_pub,
				)?;

				public
					.decrypt_from_shared_secret(payload, &shared_secret)
					.map_err(Into::into)
			}
			Self::Pair(ref pair) => pair.decrypt(payload).map_err(Into::into),
		}
	}

	/// Get the public key in bytes
	pub fn public_key_bytes(&mut self) -> Result<Vec<u8>, Error> {
		match self {
			#[cfg(feature = "smartcard")]
			Self::Yubi((ref mut yubi, _)) => {
				crate::yubikey::pair_public_key(yubi).map_err(Into::into)
			}
			Self::Pair(ref pair) => Ok(pair.public_key().to_bytes()),
		}
	}
}

pub(crate) fn generate_file_key<P: AsRef<Path>>(
	master_secret_path: P,
	pub_key_path: P,
) {
	let share_key_pair =
		P256Pair::generate().expect("unable to generate P256 keypair");

	// Write the personal key secret
	write_with_msg(
		master_secret_path.as_ref(),
		&share_key_pair.to_master_seed_hex(),
		"Master Seed",
	);

	// Write the setup key public key
	write_with_msg(
		pub_key_path.as_ref(),
		&share_key_pair.public_key().to_hex_bytes(),
		"File Key Public",
	);
}

#[cfg(feature = "smartcard")]
pub(crate) fn provision_yubikey<P: AsRef<Path>>(
	pub_path: P,
) -> Result<(), Error> {
	let mut yubikey =
		yubikey::YubiKey::open().map_err(Error::OpenSingleYubiKey)?;

	let pin = rpassword::prompt_password(ENTER_PIN_PROMPT)
		.map_err(Error::PinEntryError)?
		.as_bytes()
		.to_vec();

	let _sign_public_key_bytes = crate::yubikey::generate_signed_certificate(
		&mut yubikey,
		crate::yubikey::SIGNING_SLOT,
		&pin,
		yubikey::MgmKey::default(),
		yubikey::TouchPolicy::Always,
	)
	.map_err(Error::GenerateSign)?;

	let _encrypt_public_key_bytes =
		crate::yubikey::generate_signed_certificate(
			&mut yubikey,
			crate::yubikey::KEY_AGREEMENT_SLOT,
			&pin,
			yubikey::MgmKey::default(),
			yubikey::TouchPolicy::Always,
		)
		.map_err(Error::GenerateEncrypt)?;

	let public_key_bytes = crate::yubikey::pair_public_key(&mut yubikey)?;
	let public_key_hex = qos_hex::encode(&public_key_bytes);

	// Explicitly drop the yubikey to disconnect the PCSC session.
	drop(yubikey);

	write_with_msg(
		pub_path.as_ref(),
		public_key_hex.as_bytes(),
		"YubiKey encrypt+sign public key",
	);

	Ok(())
}

pub(crate) fn pin_from_path<P: AsRef<Path>>(path: P) -> Vec<u8> {
	let file = File::open(path).expect("Failed to open current pin path");
	BufReader::new(file)
		.lines()
		.next()
		.expect("First line missing from current pin file")
		.expect("Error reading first line")
		.as_bytes()
		.to_vec()
}

#[cfg(feature = "smartcard")]
pub(crate) fn advanced_provision_yubikey<P: AsRef<Path>>(
	master_seed_path: P,
	maybe_pin_path: Option<String>,
) -> Result<(), Error> {
	let mut yubikey =
		yubikey::YubiKey::open().map_err(Error::OpenSingleYubiKey)?;

	let pin = if let Some(pin_path) = maybe_pin_path {
		pin_from_path(pin_path)
	} else {
		rpassword::prompt_password(ENTER_PIN_PROMPT)
			.map_err(Error::PinEntryError)?
			.as_bytes()
			.to_vec()
	};

	let pair = P256Pair::from_hex_file(master_seed_path)?;

	let master_seed = pair.to_master_seed();
	let encrypt_secret = qos_p256::derive_secret(
		master_seed,
		qos_p256::P256_ENCRYPT_DERIVE_PATH,
	)?;
	let sign_secret =
		qos_p256::derive_secret(master_seed, qos_p256::P256_SIGN_DERIVE_PATH)?;

	crate::yubikey::import_key_and_generate_signed_certificate(
		&mut yubikey,
		&sign_secret,
		crate::yubikey::SIGNING_SLOT,
		&pin,
		yubikey::MgmKey::default(),
		yubikey::TouchPolicy::Always,
	)
	.map_err(Error::GenerateSign)?;

	crate::yubikey::import_key_and_generate_signed_certificate(
		&mut yubikey,
		&encrypt_secret,
		crate::yubikey::KEY_AGREEMENT_SLOT,
		&pin,
		yubikey::MgmKey::default(),
		yubikey::TouchPolicy::Always,
	)
	.map_err(Error::GenerateEncrypt)?;

	let public_key_bytes = crate::yubikey::pair_public_key(&mut yubikey)?;
	let other = pair.public_key().to_bytes();

	if public_key_bytes != other {
		return Err(Error::WrongPublicKey);
	}
	// Explicitly drop the yubikey to disconnect the PCSC session.
	drop(yubikey);

	Ok(())
}

pub(crate) struct BootGenesisArgs<'a, P: AsRef<Path>> {
	pub uri: &'a str,
	pub namespace_dir: P,
	pub share_set_dir: P,
	pub qos_release_dir_path: P,
	pub pcr3_preimage_path: P,
	pub unsafe_skip_attestation: bool,
	pub dr_key_path: Option<P>,
}

pub(crate) fn boot_genesis<P: AsRef<Path>>(
	BootGenesisArgs {
		uri,
		namespace_dir,
		share_set_dir,
		qos_release_dir_path,
		pcr3_preimage_path,
		unsafe_skip_attestation,
		dr_key_path,
	}: BootGenesisArgs<P>,
) -> Result<(), Error> {
	let genesis_set = get_genesis_set(&share_set_dir);
	let dr_key = if let Some(p) = dr_key_path {
		let public =
			P256Public::from_hex_file(p).map_err(Error::FailedToReadDrKey)?;
		Some(public.to_bytes())
	} else {
		None
	};

	let req =
		ProtocolMsg::BootGenesisRequest { set: genesis_set.clone(), dr_key };
	let (cose_sign1, genesis_output) = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootGenesisResponse {
			nsm_response: NsmResponse::Attestation { document },
			genesis_output,
		} => (document, genesis_output),
		r => panic!("Unexpected response: {r:?}"),
	};
	let quorum_key =
		P256Public::from_bytes(&genesis_output.quorum_key).unwrap();
	let attestation_doc =
		extract_attestation_doc(&cose_sign1, unsafe_skip_attestation, None);

	let qos_pcrs = extract_qos_pcrs(qos_release_dir_path);

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
			&qos_pcrs.pcr0,
			&qos_pcrs.pcr1,
			&qos_pcrs.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		)?;
	}

	let dr_artifacts = [
		("quorum_key_hash", &genesis_output.quorum_key_hash[..]),
		("test_message_ciphertext", &genesis_output.test_message_ciphertext),
		("test_message_signature", &genesis_output.test_message_signature),
		("test_message", &genesis_output.test_message),
	]
	.map(|(k, v)| format!("{k} {}", qos_hex::encode(v)))
	.join("\n");

	// Write the dr artifacts.
	let dr_artifacts_path = namespace_dir.as_ref().join(GENESIS_DR_ARTIFACTS);
	write_with_msg(
		&dr_artifacts_path,
		dr_artifacts.as_bytes(),
		"Genesis DR Artifacts",
	);

	// Write the attestation doc
	let attestation_doc_path =
		namespace_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	write_with_msg(
		&attestation_doc_path,
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);

	// Write the genesis output
	let genesis_output_path = namespace_dir.as_ref().join(GENESIS_OUTPUT_FILE);
	write_with_msg(
		&genesis_output_path,
		&borsh::to_vec(&*genesis_output).unwrap(),
		"`GenesisOutput`",
	);

	// Write the quorum public key
	let quorum_key_path = namespace_dir.as_ref().join("quorum_key.pub");
	write_with_msg(
		&quorum_key_path,
		&quorum_key.to_hex_bytes(),
		"quorum_key.pub",
	);

	if let Some(dr_wrapped_quorum_key) =
		genesis_output.dr_key_wrapped_quorum_key
	{
		let dr_wrapped_quorum_key_path =
			namespace_dir.as_ref().join(DR_WRAPPED_QUORUM_KEY);
		write_with_msg(
			&dr_wrapped_quorum_key_path,
			&dr_wrapped_quorum_key,
			"DR Wrapped Quorum Key",
		);
	}

	Ok(())
}

pub(crate) fn verify_genesis<P: AsRef<Path>>(
	namespace_dir: P,
	master_seed_path: P,
) -> Result<(), Error> {
	let genesis_output_path = namespace_dir.as_ref().join(GENESIS_OUTPUT_FILE);
	let genesis_output = GenesisOutput::try_from_slice(
		&fs::read(genesis_output_path).expect("Failed to read genesis output file"),
	)
	.expect(
		"Failed to deserialize genesis output - check that qos_client and qos_core version line up",
	);

	let master_seed_hex = fs::read_to_string(&master_seed_path)
		.expect("Failed to read master seed to string");
	let pair = P256Pair::from_hex_file(master_seed_path)
		.expect("Failed to use master seed to create p256 pair: {e:?}");

	// sanity check our logic to read in master seed
	if pair.to_master_seed_hex() != master_seed_hex.as_bytes() {
		return Err(Error::ErrorReadingSeed);
	}

	// check quorum_key_hash
	if sha_512(master_seed_hex.as_bytes()) != genesis_output.quorum_key_hash {
		return Err(Error::SecretDoesNotMatch);
	}
	println!("Quorum key hash is correct");

	// check test_message_signature
	if let Err(_e) = pair.public_key().verify(
		&genesis_output.test_message,
		&genesis_output.test_message_signature,
	) {
		return Err(Error::InvalidSignature);
	}
	println!("Quorum key signature over test message successfully verifies");
	let expected_signature = pair.sign(&genesis_output.test_message)?;
	if expected_signature != genesis_output.test_message_signature {
		return Err(Error::CouldNotReproduceSignature);
	}
	println!("Quorum key signature over test message was deterministically reproduced");

	// check test_message_ciphertext
	let plaintext = pair.decrypt(&genesis_output.test_message_ciphertext)?;
	if plaintext != genesis_output.test_message {
		return Err(Error::BadDecryption);
	}
	println!("Successfully decrypted test message ciphertext");

	println!("verify-genesis successful");

	Ok(())
}

pub(crate) struct AfterGenesisArgs<P: AsRef<Path>> {
	pub pair: PairOrYubi,
	pub share_path: P,
	pub alias: String,
	pub namespace_dir: P,
	pub qos_release_dir_path: P,
	pub pcr3_preimage_path: P,
	pub unsafe_skip_attestation: bool,
	pub validation_time_override: Option<u64>,
}

pub(crate) fn after_genesis<P: AsRef<Path>>(
	AfterGenesisArgs {
		mut pair,
		share_path,
		alias,
		namespace_dir,
		qos_release_dir_path,
		pcr3_preimage_path,
		unsafe_skip_attestation,
		validation_time_override,
	}: AfterGenesisArgs<P>,
) -> Result<(), Error> {
	let attestation_doc_path =
		namespace_dir.as_ref().join(GENESIS_ATTESTATION_DOC_FILE);
	let genesis_set_path = namespace_dir.as_ref().join(GENESIS_OUTPUT_FILE);

	// Get the PCRs for QOS so we can verify
	let qos_pcrs = extract_qos_pcrs(&qos_release_dir_path);

	// Read in the attestation doc from the genesis directory
	let cose_sign1 =
		fs::read(attestation_doc_path).expect("Could not read attestation_doc");
	let attestation_doc = extract_attestation_doc(
		&cose_sign1,
		unsafe_skip_attestation,
		validation_time_override,
	);

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
			&qos_pcrs.pcr0,
			&qos_pcrs.pcr1,
			&qos_pcrs.pcr2,
			&extract_pcr3(pcr3_preimage_path),
		)?;
	}

	// Get the members specific output based on alias & setup key
	let share_key_public = pair.public_key_bytes()?;
	let member_output = genesis_output
		.member_outputs
		.iter()
		.find(|m| {
			m.share_set_member.pub_key == share_key_public
				&& m.share_set_member.alias == alias
		})
		.expect("Could not find a member output associated with the setup key");

	// Make sure we can decrypt the Share with the Personal Key
	let plaintext_share =
		pair.decrypt(&member_output.encrypted_quorum_key_share)?;

	assert_eq!(
		sha_512(&plaintext_share),
		member_output.share_hash,
		"Expected share hash do not match the actual share hash"
	);

	drop(plaintext_share);

	// Store the encrypted share
	write_with_msg(
		share_path.as_ref(),
		&member_output.encrypted_quorum_key_share,
		"Encrypted Quorum Share",
	);

	Ok(())
}

pub(crate) struct GenerateManifestArgs<P: AsRef<Path>> {
	pub nonce: u32,
	pub namespace: String,
	pub restart_policy: RestartPolicy,
	pub pivot_hash_path: P,
	pub qos_release_dir_path: P,
	pub pcr3_preimage_path: P,
	pub share_set_dir: P,
	pub manifest_set_dir: P,
	pub patch_set_dir: P,
	pub quorum_key_path: P,
	pub manifest_path: P,
	pub pivot_args: Vec<String>,
}

pub(crate) fn generate_manifest<P: AsRef<Path>>(
	args: GenerateManifestArgs<P>,
) -> Result<(), Error> {
	let GenerateManifestArgs {
		nonce,
		namespace,
		pivot_hash_path,
		restart_policy,
		qos_release_dir_path,
		pcr3_preimage_path,
		manifest_set_dir,
		share_set_dir,
		patch_set_dir,
		quorum_key_path,
		manifest_path,
		pivot_args,
	} = args;

	let nitro_config =
		extract_nitro_config(qos_release_dir_path, pcr3_preimage_path);
	let pivot_hash = extract_pivot_hash(pivot_hash_path);

	// Get manifest set keys & threshold
	let manifest_set = get_manifest_set(manifest_set_dir);
	// Get share set keys & threshold
	let share_set = get_share_set(share_set_dir);
	let patch_set = get_patch_set(patch_set_dir);
	// Get quorum key from namespaces dir
	let quorum_key = P256Public::from_hex_file(&quorum_key_path)
		.map_err(Error::FailedToReadQuorumPublicKey)?;

	let manifest = Manifest {
		namespace: Namespace {
			name: namespace,
			nonce,
			quorum_key: quorum_key.to_bytes(),
		},
		pivot: PivotConfig {
			hash: pivot_hash.try_into().expect("pivot hash was not 256 bits"),
			restart: restart_policy,
			args: pivot_args,
		},
		manifest_set,
		share_set,
		patch_set,
		enclave: nitro_config,
	};

	write_with_msg(
		manifest_path.as_ref(),
		&borsh::to_vec(&manifest).unwrap(),
		"Manifest",
	);

	Ok(())
}

fn extract_nitro_config<P: AsRef<Path>>(
	qos_release_dir_path: P,
	pcr3_preimage_path: P,
) -> NitroConfig {
	let pcr3 = extract_pcr3(pcr3_preimage_path);
	let QosPcrs { pcr0, pcr1, pcr2 } = extract_qos_pcrs(&qos_release_dir_path);

	NitroConfig {
		pcr0,
		pcr1,
		pcr2,
		pcr3,
		qos_commit: String::new(),
		aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
	}
}

pub(crate) struct ApproveManifestArgs<P: AsRef<Path>> {
	pub pair: PairOrYubi,
	pub manifest_path: P,
	pub manifest_approvals_dir: P,
	pub qos_release_dir_path: P,
	pub pcr3_preimage_path: P,
	pub pivot_hash_path: P,
	pub quorum_key_path: P,
	pub manifest_set_dir: P,
	pub share_set_dir: P,
	pub patch_set_dir: P,
	pub alias: String,
	pub unsafe_auto_confirm: bool,
}

pub(crate) fn approve_manifest<P: AsRef<Path>>(
	args: ApproveManifestArgs<P>,
) -> Result<(), Error> {
	let ApproveManifestArgs {
		mut pair,
		manifest_path,
		manifest_approvals_dir,
		qos_release_dir_path,
		pcr3_preimage_path,
		pivot_hash_path,
		quorum_key_path,
		manifest_set_dir,
		share_set_dir,
		patch_set_dir,
		alias,
		unsafe_auto_confirm,
	} = args;

	let manifest = read_manifest(&manifest_path)?;
	let quorum_key = P256Public::from_hex_file(&quorum_key_path)
		.map_err(Error::FailedToReadQuorumPublicKey)?;

	if !approve_manifest_programmatic_verifications(
		&manifest,
		&get_manifest_set(manifest_set_dir),
		&get_share_set(share_set_dir),
		&get_patch_set(patch_set_dir),
		&extract_nitro_config(qos_release_dir_path, pcr3_preimage_path),
		&extract_pivot_hash(pivot_hash_path),
		&quorum_key,
	) {
		eprintln!("Exiting early without approving manifest");
		std::process::exit(1);
	}

	if !unsafe_auto_confirm {
		let stdin = io::stdin();
		let stdin_locked = stdin.lock();
		let mut prompter =
			Prompter { reader: stdin_locked, writer: io::stdout() };
		if !approve_manifest_human_verifications(&manifest, &mut prompter) {
			eprintln!("Exiting early without approving manifest");
			std::process::exit(1);
		}
		drop(prompter);
	}

	let approval = Approval {
		signature: pair.sign(&manifest.qos_hash())?,
		member: QuorumMember {
			pub_key: pair.public_key_bytes()?,
			alias: alias.clone(),
		},
	};

	let approval_path = manifest_approvals_dir.as_ref().join(format!(
		"{}-{}-{}.{}",
		alias,
		manifest.namespace.name.replace('/', "-"),
		manifest.namespace.nonce,
		APPROVAL_EXT
	));
	write_with_msg(
		&approval_path,
		&borsh::to_vec(&approval).expect("Failed to serialize approval"),
		"Manifest Approval",
	);

	drop(pair);

	Ok(())
}

fn approve_manifest_programmatic_verifications(
	manifest: &Manifest,
	manifest_set: &ManifestSet,
	share_set: &ShareSet,
	patch_set: &PatchSet,
	nitro_config: &NitroConfig,
	pivot_hash: &[u8],
	quorum_key: &P256Public,
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

	// Verify share set composition
	if manifest.patch_set != *patch_set {
		eprintln!("Share Set composition does not match");
		return false;
	}

	// Verify pcrs 0, 1, 2, 3.
	if manifest.enclave != *nitro_config {
		eprintln!("Nitro configuration does not match");
		return false;
	}

	// Verify the pivot could be built deterministically
	if manifest.pivot.hash != pivot_hash {
		eprintln!("Pivot hash does not match");
		return false;
	}

	// Verify the intended Quorum Key is being used
	if manifest.namespace.quorum_key != quorum_key.to_bytes() {
		eprintln!("Quorum public key does not match");
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
			"Is this the correct namespace name: {}? (y/n)",
			manifest.namespace.name
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check the namespace nonce
	{
		let prompt = format!(
			"Is this the correct namespace nonce: {}? (y/n)",
			manifest.namespace.nonce
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check pivot restart policy
	{
		let prompt = format!(
			"Is this the correct pivot restart policy: {:?}? (y/n)",
			manifest.pivot.restart
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check pivot arguments
	{
		let prompt = format!(
			"Are these the correct pivot args:\n{:?}?\n(y/n)",
			manifest.pivot.args
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	true
}

pub(crate) fn generate_manifest_envelope<P: AsRef<Path>>(
	manifest_approvals_dir: P,
	manifest_path: P,
	maybe_manifest_envelope_path: Option<String>,
) -> Result<(), Error> {
	let manifest = read_manifest(&manifest_path)?;
	let approvals = find_approvals(&manifest_approvals_dir, &manifest);

	// Create manifest envelope
	let manifest_envelope = ManifestEnvelope {
		manifest,
		manifest_set_approvals: approvals,
		share_set_approvals: vec![],
	};

	if let Err(e) = manifest_envelope.check_approvals() {
		eprintln!("Error with approvals: {e:?}");
		std::process::exit(1);
	}

	let path = maybe_manifest_envelope_path.map_or_else(
		|| manifest_approvals_dir.as_ref().join(MANIFEST_ENVELOPE),
		PathBuf::from,
	);
	write_with_msg(
		&path,
		&borsh::to_vec(&manifest_envelope)
			.expect("Failed to serialize manifest envelope"),
		"Manifest Envelope",
	);

	Ok(())
}

pub(crate) fn boot_key_fwd<P: AsRef<Path>>(
	uri: &str,
	manifest_envelope_path: P,
	pivot_path: P,
	attestation_doc_path: P,
) -> Result<(), Error> {
	let pivot =
		fs::read(pivot_path.as_ref()).map_err(Error::FailedToReadPivot)?;
	let manifest_envelope = read_manifest_envelope(manifest_envelope_path)?;

	let req = ProtocolMsg::BootKeyForwardRequest {
		manifest_envelope: Box::new(manifest_envelope),
		pivot,
	};
	let cose_sign1 = match request::post(uri, &req).unwrap() {
		ProtocolMsg::BootKeyForwardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		r => {
			return Err(Error::UnexpectedProtocolMsgResponse(format!("{r:?}")))
		}
	};

	write_with_msg(
		attestation_doc_path.as_ref(),
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);

	Ok(())
}

pub(crate) fn export_key<P: AsRef<Path>>(
	uri: &str,
	manifest_envelope_path: P,
	attestation_doc_path: P,
	encrypted_quorum_key_path: P,
) -> Result<(), Error> {
	let manifest_envelope = read_manifest_envelope(manifest_envelope_path)?;
	let cose_sign1_attestation_doc = fs::read(attestation_doc_path.as_ref())
		.map_err(Error::FailedToReadAttestationDoc)?;

	let req = ProtocolMsg::ExportKeyRequest {
		manifest_envelope: Box::new(manifest_envelope),
		cose_sign1_attestation_doc,
	};

	let encrypted_quorum_key = match request::post(uri, &req).unwrap() {
		ProtocolMsg::ExportKeyResponse { encrypted_quorum_key, signature } => {
			EncryptedQuorumKey { encrypted_quorum_key, signature }
		}
		r => {
			return Err(Error::UnexpectedProtocolMsgResponse(format!("{r:?}")))
		}
	};

	write_with_msg(
		encrypted_quorum_key_path.as_ref(),
		&borsh::to_vec(&encrypted_quorum_key).expect("valid borsh. qed."),
		"Encrypted Quorum Key",
	);

	Ok(())
}

pub(crate) fn inject_key<P: AsRef<Path>>(
	uri: &str,
	encrypted_quorum_key_path: P,
) -> Result<(), Error> {
	let encrypted_quorum_key = {
		let bytes = std::fs::read(encrypted_quorum_key_path)
			.map_err(|_| Error::FailedToReadEncryptedQuorumKey)?;
		EncryptedQuorumKey::try_from_slice(&bytes)
			.map_err(|_| Error::InvalidEncryptedQuorumKey)?
	};

	let req = ProtocolMsg::InjectKeyRequest {
		encrypted_quorum_key: encrypted_quorum_key.encrypted_quorum_key,
		signature: encrypted_quorum_key.signature,
	};

	match request::post(uri, &req).unwrap() {
		ProtocolMsg::InjectKeyResponse => println!("Successful key injection!"),
		r => {
			return Err(Error::UnexpectedProtocolMsgResponse(format!("{r:?}")))
		}
	};

	Ok(())
}

pub(crate) struct BootStandardArgs<P: AsRef<Path>> {
	pub uri: String,
	pub pivot_path: P,
	pub manifest_envelope_path: P,
	pub pcr3_preimage_path: P,
	pub unsafe_skip_attestation: bool,
}

pub(crate) fn boot_standard<P: AsRef<Path>>(
	BootStandardArgs {
		uri,
		pivot_path,
		manifest_envelope_path,
		pcr3_preimage_path,
		unsafe_skip_attestation,
	}: BootStandardArgs<P>,
) -> Result<(), Error> {
	// Read in pivot binary
	let pivot =
		fs::read(pivot_path.as_ref()).map_err(Error::FailedToReadPivot)?;

	// Create manifest envelope
	let manifest_envelope = read_manifest_envelope(manifest_envelope_path)?;
	let manifest = manifest_envelope.manifest.clone();

	let req = ProtocolMsg::BootStandardRequest {
		manifest_envelope: Box::new(manifest_envelope),
		pivot,
	};
	// Broadcast boot standard instruction and extract the attestation doc from
	// the response.
	let cose_sign1 = match request::post(&uri, &req).unwrap() {
		ProtocolMsg::BootStandardResponse {
			nsm_response: NsmResponse::Attestation { document },
		} => document,
		r => panic!("Unexpected response: {r:?}"),
	};

	let attestation_doc =
		extract_attestation_doc(&cose_sign1, unsafe_skip_attestation, None);

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
		)?;

		// Sanity check the ephemeral key is valid
		let eph_pub_bytes = attestation_doc
			.public_key
			.expect("No ephemeral key in the attestation doc");
		P256Public::from_bytes(&eph_pub_bytes)
			.expect("Ephemeral key not valid public key");
	}

	Ok(())
}

pub(crate) fn get_attestation_doc<P: AsRef<Path>>(
	uri: &str,
	attestation_doc_path: P,
	manifest_envelope_path: P,
) {
	let (cose_sign1, manifest_envelope) =
		match request::post(uri, &ProtocolMsg::LiveAttestationDocRequest) {
			Ok(ProtocolMsg::LiveAttestationDocResponse {
				nsm_response: NsmResponse::Attestation { document },
				manifest_envelope: Some(manifest_envelope),
			}) => (document, manifest_envelope),
			Ok(ProtocolMsg::LiveAttestationDocResponse {
				nsm_response: _,
				manifest_envelope: None,
			}) => panic!(
				"ManifestEnvelope does not exist in enclave - likely waiting for boot instruction"
			),
			r => panic!("Unexpected response: {r:?}"),
		};

	write_with_msg(
		attestation_doc_path.as_ref(),
		&cose_sign1,
		"COSE Sign1 Attestation Doc",
	);
	write_with_msg(
		manifest_envelope_path.as_ref(),
		&borsh::to_vec(&manifest_envelope)
			.expect("manifest enevelope is valid borsh"),
		"Manifest envelope",
	);
}

pub(crate) struct ProxyReEncryptShareArgs<P: AsRef<Path>> {
	pub pair: PairOrYubi,
	pub share_path: P,
	pub attestation_doc_path: P,
	pub approval_path: P,
	pub eph_wrapped_share_path: P,
	pub pcr3_preimage_path: P,
	pub manifest_envelope_path: P,
	pub manifest_set_dir: P,
	pub alias: String,
	pub unsafe_skip_attestation: bool,
	pub unsafe_eph_path_override: Option<String>,
	pub unsafe_auto_confirm: bool,
}

// Verifications in this focus around ensuring
// - the intended manifest is being used
// - the manifest set approved the manifest and is the correct set
// - the enclave belongs to the intended organization (and not an attackers
//   organization)
pub(crate) fn proxy_re_encrypt_share<P: AsRef<Path>>(
	ProxyReEncryptShareArgs {
		mut pair,
		share_path,
		attestation_doc_path,
		approval_path,
		eph_wrapped_share_path,
		pcr3_preimage_path,
		manifest_set_dir,
		manifest_envelope_path,
		alias,
		unsafe_skip_attestation,
		unsafe_eph_path_override,
		unsafe_auto_confirm,
	}: ProxyReEncryptShareArgs<P>,
) -> Result<(), Error> {
	let manifest_envelope = read_manifest_envelope(&manifest_envelope_path)?;
	let attestation_doc =
		read_attestation_doc(&attestation_doc_path, unsafe_skip_attestation)?;
	let encrypted_share = std::fs::read(share_path)
		.map_err(|e| Error::ReadShare(e.to_string()))?;

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
		)?;
	}

	// Pull out the ephemeral key or use the override
	let eph_pub: P256Public = if let Some(eph_path) = unsafe_eph_path_override {
		P256Pair::from_hex_file(eph_path)
			.expect("Could not read ephemeral key override")
			.public_key()
	} else {
		P256Public::from_bytes(
			&attestation_doc
				.public_key
				.expect("No ephemeral key in the attestation doc"),
		)
		.expect("Ephemeral key not valid public key")
	};

	let member = QuorumMember { pub_key: pair.public_key_bytes()?, alias };

	if !proxy_re_encrypt_share_programmatic_verifications(
		&manifest_envelope,
		&get_manifest_set(manifest_set_dir),
		&member,
	) {
		eprintln!("Exiting early without re-encrypting / approving");
		std::process::exit(1);
	}

	if !unsafe_auto_confirm {
		let stdin = io::stdin();
		let stdin_locked = stdin.lock();
		let mut prompter =
			Prompter { reader: stdin_locked, writer: io::stdout() };
		if !proxy_re_encrypt_share_human_verifications(
			&manifest_envelope,
			&pcr3_preimage,
			&mut prompter,
		) {
			eprintln!("Exiting early without re-encrypting / approving");
			std::process::exit(1);
		}
		drop(prompter);
	}

	let share = {
		let plaintext_share = &pair
			.decrypt(&encrypted_share)
			.expect("Failed to decrypt share with personal key.");
		eph_pub.encrypt(plaintext_share).expect("Envelope encryption error")
	};

	let approval = borsh::to_vec(&Approval {
		signature: pair
			.sign(&manifest_envelope.manifest.qos_hash())
			.expect("Failed to sign"),
		member,
	})
	.expect("Could not serialize Approval");

	write_with_msg(approval_path.as_ref(), &approval, "Share Set Approval");

	write_with_msg(
		eph_wrapped_share_path.as_ref(),
		&share,
		"Ephemeral key wrapped share",
	);

	drop(pair);

	Ok(())
}

fn proxy_re_encrypt_share_programmatic_verifications(
	manifest_envelope: &ManifestEnvelope,
	manifest_set: &ManifestSet,
	member: &QuorumMember,
) -> bool {
	if let Err(e) = manifest_envelope.check_approvals() {
		eprintln!("Manifest envelope did not have valid approvals: {e:?}");
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
			"Is this the correct namespace name: {}? (y/n)",
			manifest_envelope.manifest.namespace.name
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check the namespace nonce
	{
		let prompt = format!(
			"Is this the correct namespace nonce: {}? (y/n)",
			manifest_envelope.manifest.namespace.nonce
		);
		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	// Check that the IAM role is correct
	{
		let prompt = format!(
			"Does this AWS IAM role belong to the intended organization: {pcr3_preimage}? (y/n)"
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

		let prompt = format!(
			"The following manifest set members approved:\n{approvers}\nIs this ok? (y/n)"
		);

		if !prompter.prompt_is_yes(&prompt) {
			return false;
		}
	}

	true
}

pub(crate) fn post_share<P: AsRef<Path>>(
	uri: &str,
	eph_wrapped_share_path: P,
	approval_path: P,
) -> Result<(), Error> {
	// Get the ephemeral key wrapped share
	let share = fs::read(eph_wrapped_share_path)
		.map_err(Error::FailedToReadEphWrappedShare)?;
	let approval = read_attestation_approval(&approval_path)?;

	let req = ProtocolMsg::ProvisionRequest { share, approval };
	let is_reconstructed = match request::post(uri, &req).unwrap() {
		ProtocolMsg::ProvisionResponse { reconstructed } => reconstructed,
		r => panic!("Unexpected response: {r:?}"),
	};

	if is_reconstructed {
		println!("The quorum key has been reconstructed.");
	} else {
		println!("The quorum key has *not* been reconstructed.");
	};

	Ok(())
}

#[cfg(feature = "smartcard")]
pub(crate) fn yubikey_sign(hex_payload: &str) -> Result<(), Error> {
	let bytes = qos_hex::decode(hex_payload)?;

	let mut pair = PairOrYubi::from_inputs(true, None, None)?;
	let signature_bytes = pair.sign(&bytes)?;
	let signature = qos_hex::encode(&signature_bytes);

	println!("{signature}");

	Ok(())
}

#[cfg(feature = "smartcard")]
pub(crate) fn yubikey_public() -> Result<(), Error> {
	let mut yubi = crate::yubikey::open_single()?;
	let public = crate::yubikey::pair_public_key(&mut yubi)?;

	let hex = qos_hex::encode(&public);
	println!("{hex}");

	Ok(())
}

pub(crate) fn p256_verify<P: AsRef<Path>>(
	payload_path: P,
	signature_path: P,
	pub_path: P,
) -> Result<(), Error> {
	let payload = fs::read(payload_path)?;
	let public = P256Public::from_hex_file(pub_path)?;
	let signature_bytes = {
		let signature_hex = fs::read_to_string(signature_path)?;

		let signature_hex = signature_hex.trim();
		qos_hex::decode(signature_hex)?
	};

	if let Err(e) = public.verify(&payload, &signature_bytes) {
		println!("Signature not valid: {e:?}");
		Err(e.into())
	} else {
		println!("Valid signature!");
		Ok(())
	}
}

pub(crate) fn p256_sign<P: AsRef<Path>>(
	payload_path: &str,
	signature_path: P,
	master_seed_path: P,
) -> Result<(), Error> {
	let payload = fs::read(payload_path)?;
	let pair = P256Pair::from_hex_file(master_seed_path)?;

	let signature = {
		let signature = pair.sign(&payload)?;
		qos_hex::encode(&signature)
	};
	write_with_msg(
		signature_path.as_ref(),
		signature.as_bytes(),
		"p256 signature",
	);

	Ok(())
}

pub(crate) fn p256_asymmetric_encrypt<P: AsRef<Path>>(
	plaintext_path: P,
	ciphertext_path: P,
	pub_path: P,
) -> Result<(), Error> {
	let public = P256Public::from_hex_file(pub_path)?;
	let plaintext = std::fs::read(plaintext_path.as_ref())?;

	let ciphertext = public.encrypt(&plaintext)?;

	write_with_msg(ciphertext_path.as_ref(), &ciphertext, "Ciphertext");

	Ok(())
}

pub(crate) fn p256_asymmetric_decrypt<P: AsRef<Path>>(
	plaintext_path: P,
	ciphertext_path: P,
	master_seed_path: P,
	output_hex: bool,
) -> Result<(), Error> {
	let pair = P256Pair::from_hex_file(master_seed_path)?;
	let ciphertext = std::fs::read(ciphertext_path.as_ref())?;

	let plaintext = pair.decrypt(&ciphertext)?;
	let file_contents =
		if output_hex { qos_hex::encode_to_vec(&plaintext) } else { plaintext };

	write_with_msg(plaintext_path.as_ref(), &file_contents, "Plaintext");

	Ok(())
}

pub(crate) fn display<P: AsRef<Path>>(
	display_type: &DisplayType,
	file_path: P,
	json: bool,
) -> Result<(), Error> {
	let bytes =
		fs::read(file_path).map_err(|e| Error::ReadShare(e.to_string()))?;
	match *display_type {
		DisplayType::Manifest => {
			let decoded = Manifest::try_from_slice(&bytes)?;
			if json {
				println!("{}", serde_json::to_string(&decoded).unwrap());
			} else {
				println!("{decoded:#?}");
			}
		}
		DisplayType::ManifestEnvelope => {
			let decoded = ManifestEnvelope::try_from_slice(&bytes)?;
			if json {
				println!("{}", serde_json::to_string(&decoded).unwrap());
			} else {
				println!("{decoded:#?}");
			}
		}
		DisplayType::GenesisOutput => {
			let decoded = GenesisOutput::try_from_slice(&bytes)?;
			println!("{decoded:#?}");
		}
	};
	Ok(())
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
	let quorum_pair = P256Pair::generate().expect("Failed P256 key gen");
	let quorum_public_der = quorum_pair.public_key().to_bytes();
	let member = QuorumMember {
		alias: DANGEROUS_DEV_BOOT_MEMBER.to_string(),
		pub_key: quorum_public_der.clone(),
	};

	// Shard it with N=2, K=2
	let shares =
		qos_crypto::shamir::shares_generate(quorum_pair.to_master_seed(), 2, 2)
			.unwrap();
	assert_eq!(
		shares.len(),
		2,
		"Error generating shares - did not get exactly two shares."
	);

	// Read in the pivot
	let pivot = fs::read(&pivot_path).expect("Failed to read pivot binary.");

	let mock_pcr = vec![0; 48];
	// Create a manifest with manifest set of 1
	// everything below is hardcoded except pivot config
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
		pivot: PivotConfig { hash: sha_256(&pivot), restart, args },
		manifest_set: ManifestSet {
			threshold: 1,
			// The only member is the quorum member
			members: vec![member.clone()],
		},
		share_set: ShareSet {
			threshold: 2,
			// The only member is the quorum member
			members: vec![member.clone()],
		},
		patch_set: PatchSet { threshold: 0, members: vec![] },
	};

	// Create and post the boot standard instruction
	let manifest_envelope = {
		let signature =
			quorum_pair.sign(&manifest.qos_hash()).expect("Failed to sign");
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
		} => extract_attestation_doc(&document, true, None),
		r => panic!("Unexpected response: {r:?}"),
	};

	// Pull out the ephemeral key or use the override
	let eph_pub: P256Public = if let Some(eph_path) = unsafe_eph_path_override {
		P256Pair::from_hex_file(eph_path)
			.expect("Could not read ephemeral key override")
			.public_key()
	} else {
		P256Public::from_bytes(
			&attestation_doc
				.public_key
				.expect("No ephemeral key in the attestation doc"),
		)
		.expect("Ephemeral key not valid public key")
	};

	// Create ShareSet approval
	let approval = Approval {
		signature: quorum_pair
			.sign(&manifest_envelope.manifest.qos_hash())
			.expect("Failed to sign"),
		member: QuorumMember {
			pub_key: quorum_pair.public_key().to_bytes(),
			alias: DANGEROUS_DEV_BOOT_MEMBER.to_string(),
		},
	};

	// Post the share a first time. It won't work (1/2 shares aren't enough)
	let req1 = ProtocolMsg::ProvisionRequest {
		share: eph_pub
			.encrypt(&shares[0])
			.expect("Failed to encrypt share to eph key."),
		approval: approval.clone(),
	};
	let resp1 = request::post(uri, &req1).unwrap();
	assert!(
		matches!(
			resp1,
			ProtocolMsg::ProvisionResponse { reconstructed: false }
		),
		"{resp1:?}"
	);

	// Post the second share; expected to reconstruct.
	let req2 = ProtocolMsg::ProvisionRequest {
		share: eph_pub
			.encrypt(&shares[1])
			.expect("Failed to encrypt share to eph key."),
		approval,
	};
	let resp2 = request::post(uri, &req2).unwrap();
	assert!(matches!(
		resp2,
		ProtocolMsg::ProvisionResponse { reconstructed: true }
	));

	println!("Enclave is provisioned!");
}

pub(crate) fn shamir_split(
	secret_path: String,
	total_shares: usize,
	threshold: usize,
	output_dir: &str,
) -> Result<(), Error> {
	let secret = fs::read(&secret_path).map_err(|e| Error::FailedToRead {
		path: secret_path,
		error: e.to_string(),
	})?;
	let shares =
		qos_crypto::shamir::shares_generate(&secret, total_shares, threshold)
			.unwrap();

	for (i, share) in shares.iter().enumerate() {
		let file_name = format!("{}.share", i + 1);
		let file_path = PathBuf::from(&output_dir).join(&file_name);
		write_with_msg(&file_path, share, &file_name);
	}

	Ok(())
}

pub(crate) fn shamir_reconstruct(
	shares: Vec<String>,
	output_path: &str,
) -> Result<(), Error> {
	let shares = shares
		.into_iter()
		.map(|p| {
			fs::read(&p).map_err(|e| Error::FailedToRead {
				path: p,
				error: e.to_string(),
			})
		})
		.collect::<Result<Vec<Vec<u8>>, Error>>()?;

	let secret =
		Zeroizing::new(qos_crypto::shamir::shares_reconstruct(shares).unwrap());

	write_with_msg(output_path.as_ref(), &secret, "Reconstructed secret");

	Ok(())
}

fn find_file_paths<P: AsRef<Path>>(dir: P) -> Vec<PathBuf> {
	assert!(
		dir.as_ref().is_dir(),
		"Not a valid directory: {}",
		dir.as_ref().display()
	);

	fs::read_dir(dir.as_ref())
		.unwrap_or_else(|_| {
			panic!("Failed to read dir {}", dir.as_ref().display())
		})
		.map(|p| p.unwrap().path())
		.collect()
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

			let public = P256Public::from_hex_file(path)
				.expect("Could not read PEM from share_key.pub");
			Some(QuorumMember {
				alias: mem::take(&mut file_name[0]),
				pub_key: public.to_bytes(),
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

			let public = P256Public::from_hex_file(path)
				.expect("Could not read PEM from share_key.pub");
			Some(QuorumMember {
				alias: mem::take(&mut file_name[0]),
				pub_key: public.to_bytes(),
			})
		})
		.collect();

	// We want to try and build the same manifest regardless of the OS.
	members.sort();

	ManifestSet { members, threshold: find_threshold(dir) }
}

fn get_patch_set<P: AsRef<Path>>(dir: P) -> PatchSet {
	let mut members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT) {
				return None;
			};

			let public = P256Public::from_hex_file(path)
				.expect("Could not read public key.");
			Some(MemberPubKey { pub_key: public.to_bytes() })
		})
		.collect();

	// We want to try and build the same manifest regardless of the OS.
	members.sort();

	PatchSet { members, threshold: find_threshold(dir) }
}

fn get_genesis_set<P: AsRef<Path>>(dir: P) -> GenesisSet {
	let mut members: Vec<_> = find_file_paths(&dir)
		.iter()
		.filter_map(|path| {
			let mut file_name = split_file_name(path);
			if file_name.last().map_or(true, |s| s.as_str() != PUB_EXT) {
				return None;
			};

			let public = P256Public::from_hex_file(path)
				.map_err(|e| {
					panic!("Could not read hex from share_key.pub: {path:?}: {e:?}")
				})
				.unwrap();

			Some(QuorumMember {
				alias: mem::take(&mut file_name[0]),
				pub_key: public.to_bytes(),
			})
		})
		.collect();

	// We want to try and build the same manifest regardless of the OS.
	members.sort();

	GenesisSet { members, threshold: find_threshold(dir) }
}

fn find_approvals<P: AsRef<Path>>(
	boot_dir: P,
	manifest: &Manifest,
) -> Vec<Approval> {
	let approvals: Vec<_> = find_file_paths(&boot_dir)
		.iter()
		.filter_map(|path| {
			let file_name = split_file_name(path);
			// Only look at files with the approval extension
			if file_name.last().map_or(true, |s| s.as_str() != APPROVAL_EXT) {
				return None;
			};

			let approval = Approval::try_from_slice(
				&fs::read(path).expect("Failed to read in approval"),
			)
			.expect("Failed to deserialize approval");

			assert!(
				manifest.manifest_set.members.contains(&approval.member),
				"Found approval from member ({:?}) not included in the Manifest Set",
				approval.member.alias
			);

			let pub_key = P256Public::from_bytes(&approval.member.pub_key)
				.expect("Failed to interpret pub key");
			assert!(
				pub_key
					.verify(&manifest.qos_hash(), &approval.signature)
					.is_ok(),
				"Approval signature could not be verified against manifest"
			);

			Some(approval)
		})
		.collect();
	assert!(approvals.len() >= manifest.manifest_set.threshold as usize);

	approvals
}

fn read_manifest<P: AsRef<Path>>(file: P) -> Result<Manifest, Error> {
	let buf = fs::read(file).map_err(Error::FailedToReadManifestFile)?;
	Manifest::try_from_slice(&buf)
		.map_err(|_| Error::FileDidNotHaveValidManifest)
}

fn read_attestation_doc<P: AsRef<Path>>(
	path: P,
	unsafe_skip_attestation: bool,
) -> Result<AttestationDoc, Error> {
	let cose_sign1_der =
		fs::read(path).map_err(Error::FailedToReadAttestationDoc)?;

	Ok(extract_attestation_doc(
		cose_sign1_der.as_ref(),
		unsafe_skip_attestation,
		None,
	))
}

fn read_manifest_envelope<P: AsRef<Path>>(
	file: P,
) -> Result<ManifestEnvelope, Error> {
	let buf =
		fs::read(file).map_err(Error::FailedToReadManifestEnvelopeFile)?;
	ManifestEnvelope::try_from_slice(&buf)
		.map_err(|_| Error::FileDidNotHaveValidManifestEnvelope)
}

fn read_attestation_approval<P: AsRef<Path>>(
	path: P,
) -> Result<Approval, Error> {
	let manifest_envelope =
		fs::read(path).map_err(Error::FailedToReadAttestationApproval)?;

	Approval::try_from_slice(&manifest_envelope)
		.map_err(|_| Error::FileDidNotHaveValidAttestationApproval)
}

fn lines_to_entries<P: AsRef<Path>>(path: P) -> Vec<[String; 2]> {
	let file = File::open(path).expect("failed to open a file");

	let lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<String>, _>>()
		.unwrap();

	lines
		.into_iter()
		.map(|line| {
			let entry: Vec<_> = line.split(' ').map(String::from).collect();
			entry.try_into().expect("Not exactly 2 words in line of file")
		})
		.collect()
}

struct QosPcrs {
	pcr0: Vec<u8>,
	pcr1: Vec<u8>,
	pcr2: Vec<u8>,
}

fn get_entry(
	entries: &[[String; 2]],
	index: usize,
	expected_label: &str,
) -> Vec<u8> {
	let [value, label] = &entries[index];
	assert_eq!(label, expected_label, "Label of entry does not match");
	qos_hex::decode(&value[..])
		.unwrap_or_else(|_| panic!("Invalid hex for {expected_label}"))
}

fn extract_qos_pcrs<P: AsRef<Path>>(qos_release_dir_path: P) -> QosPcrs {
	let pcr_path = PathBuf::from(qos_release_dir_path.as_ref()).join(PCRS_PATH);

	let entries = lines_to_entries(pcr_path);
	QosPcrs {
		pcr0: get_entry(&entries, 0, "PCR0"),
		pcr1: get_entry(&entries, 1, "PCR1"),
		pcr2: get_entry(&entries, 2, "PCR2"),
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

fn extract_pivot_hash<P: AsRef<Path>>(file_path: P) -> Vec<u8> {
	let file = File::open(file_path)
		.expect("failed to open qos build fingerprints file");
	let lines = std::io::BufReader::new(file)
		.lines()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();

	qos_hex::decode(&lines[0]).expect("Failed to decode pivot hash as hex")
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
	// in seconds since unix epoch
	validation_time_override: Option<u64>,
) -> AttestationDoc {
	if unsafe_skip_attestation {
		unsafe_attestation_doc_from_der(cose_sign1_der)
			.expect("Failed to extract attestation doc")
	} else {
		let validation_time = if let Some(t) = validation_time_override {
			t
		} else {
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs()
		};

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
	println!("{item_name} written to: {path_str}");
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
		writeln!(&mut self.writer, "{question}").expect("Unable to write");
		let mut s = String::new();
		let _amt = self.reader.read_line(&mut s).expect("Unable to read");
		s.trim().to_string()
	}

	fn prompt_is_yes(&mut self, question: &str) -> bool {
		// Fixed amount of attempts to avoid a "while true" loop
		let mut attempts = 3;
		// First prompt is the question. Subsequent prompts (if any) are the reminder to answer either yes or no.
		let mut prompt = question;

		while attempts > 0 {
			let answer = self.prompt(prompt);

			if ["yes", "Yes", "YES", "Y", "y"].contains(&answer.as_ref()) {
				return true;
			}

			if ["no", "No", "NO", "N", "n"].contains(&answer.as_ref()) {
				return false;
			}

			attempts -= 1;
			prompt = "Please answer with either \"yes\" (y) or \"no\" (n)";
		}
		false
	}
}

#[cfg(test)]
mod tests {
	use std::vec;

	use qos_core::protocol::{
		services::boot::{
			Approval, Manifest, ManifestEnvelope, ManifestSet, MemberPubKey,
			Namespace, NitroConfig, PatchSet, PivotConfig, QuorumMember,
			RestartPolicy, ShareSet,
		},
		QosHash,
	};
	use qos_nsm::nitro::{cert_from_pem, AWS_ROOT_CERT_PEM};
	use qos_p256::{P256Pair, P256Public};

	use super::{
		approve_manifest_human_verifications,
		approve_manifest_programmatic_verifications,
		proxy_re_encrypt_share_human_verifications,
		proxy_re_encrypt_share_programmatic_verifications, Prompter,
	};

	struct Setup {
		manifest: Manifest,
		manifest_set: ManifestSet,
		share_set: ShareSet,
		nitro_config: NitroConfig,
		pivot_hash: Vec<u8>,
		quorum_key: P256Public,
		manifest_envelope: ManifestEnvelope,
		patch_set: PatchSet,
	}
	fn setup() -> Setup {
		let pairs: Vec<_> =
			(0..3).map(|_| P256Pair::generate().unwrap()).collect();

		let members: Vec<_> = pairs
			.iter()
			.enumerate()
			.map(|(i, pair)| QuorumMember {
				pub_key: pair.public_key().to_bytes(),
				alias: i.to_string(),
			})
			.collect();
		let patch_members = members
			.iter()
			.cloned()
			.map(|m| MemberPubKey { pub_key: m.pub_key })
			.collect();

		let manifest_set =
			ManifestSet { members: members.clone(), threshold: 2 };
		let share_set = ShareSet { members: members.clone(), threshold: 2 };
		let patch_set = PatchSet { members: patch_members, threshold: 2 };
		let nitro_config = NitroConfig {
			pcr0: vec![1; 42],
			pcr1: vec![2; 42],
			pcr2: vec![3; 42],
			pcr3: vec![4; 42],
			qos_commit: "good-qos-commit".to_string(),
			aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap(),
		};
		let pivot_hash = vec![5; 32];
		let quorum_key: P256Public = P256Pair::generate().unwrap().public_key();

		let manifest = Manifest {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 2,
				quorum_key: quorum_key.to_bytes(),
			},
			pivot: PivotConfig {
				hash: pivot_hash.clone().try_into().unwrap(),
				restart: RestartPolicy::Never,
				args: ["--option1", "argument"]
					.into_iter()
					.map(String::from)
					.collect(),
			},
			manifest_set: manifest_set.clone(),
			share_set: share_set.clone(),
			patch_set: patch_set.clone(),
			enclave: nitro_config.clone(),
		};

		let manifest_envelope = ManifestEnvelope {
			manifest: manifest.clone(),
			manifest_set_approvals: std::iter::zip(
				pairs[..2].iter(),
				members.iter(),
			)
			.map(|(pair, member)| Approval {
				signature: pair.sign(&manifest.qos_hash()).unwrap(),
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
			pivot_hash,
			quorum_key,
			manifest_envelope,
			patch_set,
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
				pivot_hash,
				quorum_key,
				patch_set,
				..
			} = setup();

			assert!(approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
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
				pivot_hash,
				quorum_key,
				patch_set,
				..
			} = setup();

			manifest_set.members.get_mut(0).unwrap().alias =
				"vape2live".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_share_set() {
			let Setup {
				manifest,
				manifest_set,
				mut share_set,
				patch_set,
				nitro_config,
				pivot_hash,
				quorum_key,
				..
			} = setup();

			share_set.members.get_mut(0).unwrap().alias =
				"vape2live".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_patch_set() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				mut patch_set,
				nitro_config,
				pivot_hash,
				quorum_key,
				..
			} = setup();

			patch_set.members.get_mut(0).unwrap().pub_key = vec![1; 65];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
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
				pivot_hash,
				quorum_key,
				patch_set,
				..
			} = setup();

			nitro_config.pcr0 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pcr1() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				patch_set,
				mut nitro_config,
				pivot_hash,
				quorum_key,
				..
			} = setup();

			nitro_config.pcr1 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
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
				pivot_hash,
				quorum_key,
				patch_set,
				..
			} = setup();

			nitro_config.pcr2 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
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
				pivot_hash,
				quorum_key,
				patch_set,
				..
			} = setup();

			nitro_config.pcr3 = vec![42; 42];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_qos_commit() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				patch_set,
				mut nitro_config,
				pivot_hash,
				quorum_key,
				..
			} = setup();

			nitro_config.qos_commit = "bad qos commit".to_string();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_pivot_hash() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				patch_set,
				nitro_config,
				pivot_hash: _,
				quorum_key,
				..
			} = setup();

			let pivot_hash = vec![42; 32];

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
				&quorum_key,
			));
		}

		#[test]
		fn rejects_mismatched_quorum_key() {
			let Setup {
				manifest,
				manifest_set,
				share_set,
				patch_set,
				nitro_config,
				pivot_hash,
				..
			} = setup();

			let quorum_key: P256Public =
				P256Pair::generate().unwrap().public_key();

			assert!(!approve_manifest_programmatic_verifications(
				&manifest,
				&manifest_set,
				&share_set,
				&patch_set,
				&nitro_config,
				&pivot_hash,
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
			let vec_in = "No\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!super::approve_manifest_human_verifications(
				&manifest,
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			assert_eq!(
				&output,
				"Is this the correct namespace name: test-namespace? (y/n)\n"
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
				"Is this the correct namespace nonce: 2? (y/n)"
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
				"Is this the correct pivot restart policy: RestartPolicy::Never? (y/n)"
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
			assert_eq!(output[5], "(y/n)");
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
				.alias = "not-a-member".to_string();

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
				pub_key: P256Pair::generate().unwrap().public_key().to_bytes(),
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
		fn accepts_with_some_typos_from_operator() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			// Try all the accepted yes variants: y, yes, Yes, and YES!
			let vec_in = "y\nyes\nyea\ntes\nYes\nYES\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.lines().collect();
			assert_eq!(
				output,
				vec![
				"Is this the correct namespace name: test-namespace? (y/n)",
				"Is this the correct namespace nonce: 2? (y/n)",
				"Does this AWS IAM role belong to the intended organization: pr3? (y/n)",
				"Please answer with either \"yes\" (y) or \"no\" (n)",
				"Please answer with either \"yes\" (y) or \"no\" (n)",
				"The following manifest set members approved:",
				"\talias: 0",
				"\talias: 1",
				"Is this ok? (y/n)",
			]
			);
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
			assert_eq!(
				&output,
				"Is this the correct namespace name: test-namespace? (y/n)\n"
			);
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
			let output: Vec<_> = output.lines().collect();
			assert_eq!(
				output.last().unwrap(),
				&"Is this the correct namespace nonce: 2? (y/n)"
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
			let output: Vec<_> = output.lines().collect();
			assert_eq!(
				output.last().unwrap(),
				&"Does this AWS IAM role belong to the intended organization: pr3? (y/n)"
			);
		}

		#[test]
		fn exits_early_bad_manifest_set_members() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "yes\nyes\nyes\nno".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.lines().collect();

			assert_eq!(
				output[3],
				"The following manifest set members approved:"
			);
			assert_eq!(output[4], "\talias: 0");
			assert_eq!(output[5], "\talias: 1");
			assert_eq!(output[6], "Is this ok? (y/n)");
			assert_eq!(output.len(), 7);
		}

		#[test]
		fn exits_after_three_hesitations() {
			let Setup { manifest_envelope, .. } = setup();

			let mut vec_out: Vec<u8> = vec![];
			let vec_in = "maybe\ndunno\nunsure\n".as_bytes();

			let mut prompter =
				Prompter { reader: vec_in, writer: &mut vec_out };

			assert!(!proxy_re_encrypt_share_human_verifications(
				&manifest_envelope,
				"pr3",
				&mut prompter
			));

			let output = String::from_utf8(vec_out).unwrap();
			let output: Vec<_> = output.lines().collect();

			assert_eq!(
				output,
				vec![
					"Is this the correct namespace name: test-namespace? (y/n)",
					"Please answer with either \"yes\" (y) or \"no\" (n)",
					"Please answer with either \"yes\" (y) or \"no\" (n)",
				]
			);
		}
	}
}

//! CLI Client for interacting with `QuorumOS` enclave and host.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::{
	fs::File,
	io::{BufRead, BufReader},
	path::Path,
};

use qos_p256::P256Pair;

use crate::cli::Error;

/// Yubikey pin prompt
pub const ENTER_PIN_PROMPT: &str = "Enter your pin: ";
/// Yubikey tap message
pub const TAP_MSG: &str = "Tap your YubiKey";

pub mod cli;
#[cfg(feature = "smartcard")]
pub mod yubikey;

/// Host HTTP request helpers.
pub mod request {
	use std::io::Read;

	use borsh::{BorshDeserialize, BorshSerialize};
	use qos_core::protocol::msg::ProtocolMsg;

	const MAX_SIZE: u64 = u32::MAX as u64;

	/// Post a [`qos_core::protocol::msg::ProtocolMsg`] to the given host `url`.
	pub fn post(url: &str, msg: &ProtocolMsg) -> Result<ProtocolMsg, String> {
		let mut buf: Vec<u8> = vec![];

		let response = ureq::post(url)
			.send_bytes(
				&msg.try_to_vec()
					.expect("ProtocolMsg can always be serialized. qed."),
			)
			.map_err(|e| format!("post err: {e:?}"))?;

		response.into_reader().take(MAX_SIZE).read_to_end(&mut buf).map_err(
			|_| {
				"qos_client::request::post: reading response bytes error"
					.to_string()
			},
		)?;

		let decoded_response =
			ProtocolMsg::try_from_slice(&buf).map_err(|_| {
				"qos_client::request::post: deserialization error".to_string()
			})?;

		Ok(decoded_response)
	}

	/// Get the resource at the given host `url`.
	///
	/// # Panics
	///
	/// Panics if the http request fails.
	pub fn get(url: &str) -> Result<String, String> {
		ureq::get(url)
			.call()
			.unwrap()
			.into_string()
			.map_err(|_| format!("GET `{url:?}` failed"))
	}
}

/// Use a P256 key pair or Yubikey for signing operations.
pub enum PairOrYubi {
	#[cfg(feature = "smartcard")]
	/// Yubikey
	Yubi((::yubikey::YubiKey, Vec<u8>)),
	/// P256 key pair
	Pair(P256Pair),
}

impl PairOrYubi {
	/// Create a P256 key pair or yubikey from the given inputs
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

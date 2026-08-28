//! CLI for running an enclave binary.

use std::env;

use qos_nsm::{Nsm, NsmProvider};

use crate::{
	EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE,
	handles::Handles,
	io::SocketAddress,
	parser::{GetParserForOptions, OptionsParser, Parser, Token},
	reaper::Reaper,
};

use crate::io::IOError;

/// "cid"
pub const CID: &str = "cid";
/// "port"
pub const PORT: &str = "port";
/// "usock"
pub const USOCK: &str = "usock";
const MOCK: &str = "mock";
#[cfg(feature = "mock")]
const MOCK_PCRS_OPT: &str = "mock-pcrs";
/// Name for the option to specify the quorum key file.
pub const QUORUM_FILE_OPT: &str = "quorum-file";
/// Name for the option to specify the pivot key file.
pub const PIVOT_FILE_OPT: &str = "pivot-file";
/// Name for the option to specify the ephemeral key file.
pub const EPHEMERAL_FILE_OPT: &str = "ephemeral-file";
/// Name for the option to specify the manifest file.
pub const MANIFEST_FILE_OPT: &str = "manifest-file";
/// Name for the option to specify the maximum `StreamPool` size.
pub const POOL_SIZE: &str = "pool-size";

/// CLI options for starting up the enclave server.
#[derive(Default, Clone, Debug, PartialEq)]
struct EnclaveOpts {
	parsed: Parser,
}

impl EnclaveOpts {
	/// Create a new instance of [`Self`] with some defaults.
	fn new(args: &mut Vec<String>) -> Self {
		let parsed = OptionsParser::<EnclaveParser>::parse(args)
			.expect("Entered invalid CLI args");

		Self { parsed }
	}

	/// Create a new `StreamSocket` for the qos host.
	#[cfg_attr(target_os = "macos", allow(clippy::unnecessary_wraps))]
	fn enclave_socket(&self) -> Result<SocketAddress, IOError> {
		match (
			self.parsed.single(CID),
			self.parsed.single(PORT),
			self.parsed.single(USOCK),
		) {
			#[cfg(not(target_os = "macos"))]
			(Some(c), Some(p), None) => {
				let c =
					c.parse().map_err(|_| IOError::ConnectAddressInvalid)?;
				let p =
					p.parse().map_err(|_| IOError::ConnectAddressInvalid)?;
				Ok(SocketAddress::new_vsock(c, p, crate::io::VMADDR_NO_FLAGS))
			}
			(None, None, Some(u)) => Ok(SocketAddress::new_unix(u.as_str())),
			_ => panic!("Invalid socket opts"),
		}
	}

	/// Get the [`NsmProvider`]
	fn nsm(&self) -> Box<dyn NsmProvider + Send> {
		if self.parsed.flag(MOCK).unwrap_or(false) {
			#[cfg(feature = "mock")]
			{
				let mut nsm = qos_nsm::mock::MockNsm::new();
				if let Some(path) = self.parsed.single(MOCK_PCRS_OPT) {
					nsm = seed_mock_pcrs(nsm, path);
				}
				Box::new(nsm)
			}
			#[cfg(not(feature = "mock"))]
			{
				panic!("\"mock\" feature must be enabled to use `MockNsm`")
			}
		} else {
			Box::new(Nsm)
		}
	}

	/// Defaults to [`QUORUM_FILE`] if not explicitly specified
	fn quorum_file(&self) -> String {
		self.parsed
			.single(QUORUM_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`PIVOT_FILE`] if not explicitly specified
	fn pivot_file(&self) -> String {
		self.parsed
			.single(PIVOT_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	/// Defaults to [`EPHEMERAL_KEY_FILE`] if not explicitly specified
	fn ephemeral_file(&self) -> String {
		self.parsed
			.single(EPHEMERAL_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}

	fn manifest_file(&self) -> String {
		self.parsed
			.single(MANIFEST_FILE_OPT)
			.expect("has a default value.")
			.clone()
	}
}

/// Seed the mock NSM PCR bank from a file with `<hex value> PCR<index>`
/// lines, the same format as the `.pcrs` files in QOS release directories.
/// The seeded values are the mock analog of the image measurements a real
/// Nitro enclave boots with.
///
/// # Panics
///
/// Panics if the file cannot be read or a line is malformed.
#[cfg(feature = "mock")]
fn seed_mock_pcrs(
	mut nsm: qos_nsm::mock::MockNsm,
	path: &str,
) -> qos_nsm::mock::MockNsm {
	let contents = std::fs::read_to_string(path).unwrap_or_else(|e| {
		panic!("failed to read mock PCRs file at {path}: {e}")
	});

	for line in contents.lines() {
		let line = line.trim();
		if line.is_empty() {
			continue;
		}

		let mut parts = line.split_whitespace();
		let (Some(value_hex), Some(label), None) =
			(parts.next(), parts.next(), parts.next())
		else {
			panic!(
				"malformed mock PCRs line (expected `<hex value> PCR<index>`): {line}"
			);
		};
		let index: u16 = label
			.strip_prefix("PCR")
			.and_then(|index| index.parse().ok())
			.unwrap_or_else(|| {
				panic!(
					"malformed mock PCRs label (expected `PCR<index>`): {label}"
				)
			});
		let value = qos_hex::decode(value_hex).unwrap_or_else(|e| {
			panic!("malformed mock PCRs hex value for {label}: {e:?}")
		});

		nsm = nsm.with_pcr(index, value);
	}

	nsm
}

/// Enclave server CLI.
pub struct CLI;
impl CLI {
	/// Execute the enclave server CLI with the environment args using tokio/async
	///
	/// # Panics
	/// If the socket pools cannot be created
	pub async fn execute() {
		let mut args: Vec<String> = env::args().collect();
		let opts = EnclaveOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			// Keep the process alive while Reaper owns runtime cleanup. OCI Reaper
			// observes the same signal and gets its full graceful-stop window.
			let mut reaper = tokio::spawn(async move {
				Reaper::execute(
					&Handles::new(
						opts.ephemeral_file(),
						opts.quorum_file(),
						opts.manifest_file(),
						opts.pivot_file(),
					),
					opts.nsm(),
					opts.enclave_socket()
						.expect("Unable to create enclave socket"),
					None,
				)
				.await;
			});

			eprintln!("qos_core: Reaper running, press ctrl+c to quit");
			tokio::select! {
				_ = &mut reaper => {}
				_ = tokio::signal::ctrl_c() => {
					if tokio::time::timeout(
						std::time::Duration::from_secs(15),
						&mut reaper,
					).await.is_err() {
						reaper.abort();
					}
				}
			}
		}
	}
}

/// Parser for enclave CLI
struct EnclaveParser;
impl GetParserForOptions for EnclaveParser {
	fn parser() -> Parser {
		let parser = Parser::new()
			.token(
				Token::new(CID, "cid of the VSOCK the enclave should listen on.")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(PORT),
			)
			.token(
				Token::new(PORT, "port of the VSOCK the enclave should listen on.")
					.takes_value(true)
					.forbids(vec![USOCK])
					.requires(CID),
			)
			.token(
				Token::new(USOCK, "unix socket (`.sock`) to listen on.")
					.takes_value(true)
					.forbids(vec!["port", "cid"]),
			)
			.token(
				Token::new(MOCK, "include to use the mock Nitro Secure Module; helpful for local dev.")
			)
			.token(
				Token::new(QUORUM_FILE_OPT, "path to file where the Quorum Key secret should be stored. Use default for production.")
					.takes_value(true)
					.default_value(QUORUM_FILE)
			)
			.token(
				Token::new(PIVOT_FILE_OPT, "path to file where the Pivot Binary should be written. Use default for production.")
					.takes_value(true)
					.default_value(PIVOT_FILE),
			)
			.token(
				Token::new(EPHEMERAL_FILE_OPT, "path to file where the Ephemeral Key secret should be written. Use default for production.")
					.takes_value(true)
					.default_value(EPHEMERAL_KEY_FILE)
			)
			.token(
				Token::new(MANIFEST_FILE_OPT, "path to file where the Manifest should be written. Use default for production")
					.takes_value(true)
					.default_value(MANIFEST_FILE)
			);

		#[cfg(feature = "mock")]
		let parser = parser.token(
			Token::new(MOCK_PCRS_OPT, "path to a file with mock PCR seed values (`<hex value> PCR<index>` lines); helpful for local dev.")
				.takes_value(true)
				.requires(MOCK),
		);

		parser
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parse_is_idempotent() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);
		let opts2 = EnclaveOpts::new(&mut args);
		let parsed_args: Vec<_> = vec!["--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();

		assert_eq!(args, parsed_args);
		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
		assert_eq!(*opts2.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts2.parsed.single(PORT).unwrap(), "3999".to_string());
	}

	#[test]
	fn parse_cid_and_port() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(*opts.parsed.single(CID).unwrap(), "6".to_string());
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999".to_string());
	}

	#[test]
	fn parse_usock() {
		let mut args: Vec<_> = vec!["binary", "--usock", "/tmp/usock"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(
			*opts.parsed.single(USOCK).unwrap(),
			"/tmp/usock".to_string()
		);
	}

	#[test]
	fn parse_pivot_file_and_quorum_file() {
		let pivot = "pivot.file";
		let secret = "secret.file";
		let ephemeral = "ephemeral.file";
		let mut args: Vec<_> = vec![
			"binary",
			"--cid",
			"6",
			"--port",
			"3999",
			"--quorum-file",
			secret,
			"--pivot-file",
			pivot,
			"--ephemeral-file",
			ephemeral,
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(*opts.parsed.single(CID).unwrap(), "6");
		assert_eq!(*opts.parsed.single(PORT).unwrap(), "3999");
		assert_eq!(opts.quorum_file(), secret);
		assert_eq!(opts.pivot_file(), pivot);
		assert_eq!(opts.ephemeral_file(), ephemeral);
	}

	#[test]
	fn parse_manifest_file() {
		let mut args: Vec<_> = vec!["binary", "--usock", "./test.sock"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(opts.manifest_file(), MANIFEST_FILE.to_string());

		let mut args: Vec<_> = vec![
			"binary",
			"--usock",
			"./test.sock",
			"--manifest-file",
			"brawndo",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(opts.manifest_file(), "brawndo".to_string());
	}

	#[test]
	#[cfg(feature = "mock")]
	fn mock_nsm_embeds_attestation_request_public_key() {
		let mut args: Vec<_> =
			vec!["binary", "--usock", "./test.sock", "--mock"]
				.into_iter()
				.map(String::from)
				.collect();
		let opts = EnclaveOpts::new(&mut args);
		let public_key = vec![9; 65];

		let response = opts.nsm().nsm_process_request(
			qos_nsm::types::NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: Some(public_key.clone()),
			},
		);

		let qos_nsm::types::NsmResponse::Attestation { document } = response
		else {
			panic!("expected attestation response");
		};
		let doc =
			qos_nsm::nitro::unsafe_attestation_doc_from_der(&document).unwrap();

		assert_eq!(doc.public_key.unwrap().into_vec(), public_key);
	}

	#[test]
	#[cfg(feature = "mock")]
	fn mock_pcrs_seed_the_mock_nsm() {
		let temp_dir = std::env::temp_dir();
		let pcrs_file = temp_dir.join("cli_mock_pcrs_seed_the_mock_nsm.pcrs");
		let pcr0 = vec![7u8; 48];
		let pcr3 = vec![9u8; 48];
		std::fs::write(
			pcrs_file.to_str().unwrap(),
			format!(
				"{} PCR0\n{} PCR3\n",
				qos_hex::encode(&pcr0),
				qos_hex::encode(&pcr3)
			),
		)
		.unwrap();

		let mut args: Vec<_> = vec![
			"binary",
			"--usock",
			"./test.sock",
			"--mock",
			"--mock-pcrs",
			pcrs_file.to_str().unwrap(),
		]
		.into_iter()
		.map(String::from)
		.collect();
		let opts = EnclaveOpts::new(&mut args);

		let response = opts.nsm().nsm_process_request(
			qos_nsm::types::NsmRequest::Attestation {
				user_data: None,
				nonce: None,
				public_key: None,
			},
		);

		let qos_nsm::types::NsmResponse::Attestation { document } = response
		else {
			panic!("expected attestation response");
		};
		let doc =
			qos_nsm::nitro::unsafe_attestation_doc_from_der(&document).unwrap();

		assert_eq!(doc.pcrs.get(&0).unwrap().to_vec(), pcr0);
		assert_eq!(doc.pcrs.get(&3).unwrap().to_vec(), pcr3);

		let _ = std::fs::remove_file(pcrs_file);
	}

	#[test]
	#[cfg(feature = "mock")]
	#[should_panic = "Entered invalid CLI args: MissingInput(\"mock\")"]
	fn panic_on_mock_pcrs_without_mock() {
		let mut args: Vec<_> = vec![
			"binary",
			"--usock",
			"./test.sock",
			"--mock-pcrs",
			"./some.pcrs",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let _opts = EnclaveOpts::new(&mut args);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MutuallyExclusiveInput(\"cid\", \"usock\")"]
	fn panic_on_too_many_opts() {
		let mut args: Vec<_> = vec![
			"binary", "--cid", "6", "--port", "3999", "--usock", "my.sock",
		]
		.into_iter()
		.map(String::from)
		.collect();
		let _opts = EnclaveOpts::new(&mut args);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: MissingInput(\"port\")"]
	fn panic_on_not_enough_opts() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6"]
			.into_iter()
			.map(String::from)
			.collect();
		let _opts = EnclaveOpts::new(&mut args);
	}

	#[test]
	#[cfg(not(target_os = "macos"))]
	fn build_vsock() {
		let mut args: Vec<_> = vec!["binary", "--cid", "6", "--port", "3999"]
			.into_iter()
			.map(String::from)
			.collect();
		let opts = EnclaveOpts::new(&mut args);

		assert_eq!(
			opts.enclave_socket().unwrap(),
			SocketAddress::new_vsock(6, 3999, crate::io::VMADDR_NO_FLAGS)
		);
	}

	#[test]
	#[should_panic = "Entered invalid CLI args: UnexpectedInput(\"--durp\")"]
	fn panic_when_mistyped_cid() {
		let mut args: Vec<_> =
			vec!["--durp"].into_iter().map(String::from).collect();
		let _opts = EnclaveOpts::new(&mut args);
	}
}

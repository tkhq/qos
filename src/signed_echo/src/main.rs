//! Signed echo pivot application binary.

use std::{net::SocketAddr, path::Path, sync::Arc};

use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE};
use qos_nsm::Nsm;
use signed_echo::{
	BootProof, Config, DEFAULT_QUORUM_KEY_PATH, router_with_boot_proof,
};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 3000;

/// Whether to serve this enclave's own cached boot proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootProofMode {
	Off,
	Nsm,
}

#[derive(Debug, PartialEq, Eq)]
struct Cli {
	host: String,
	port: u16,
	quorum_key_path: String,
	boot_proof: BootProofMode,
}

impl Default for Cli {
	fn default() -> Self {
		Self {
			host: DEFAULT_HOST.to_string(),
			port: DEFAULT_PORT,
			quorum_key_path: DEFAULT_QUORUM_KEY_PATH.to_string(),
			boot_proof: BootProofMode::Off,
		}
	}
}

impl Cli {
	fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
		let mut cli = Self::default();
		let mut args = args.into_iter();

		while let Some(arg) = args.next() {
			match arg.as_str() {
				"--host" => cli.host = next_value(&mut args, "--host")?,
				"--port" => {
					cli.port =
						next_value(&mut args, "--port")?.parse().map_err(
							|err| format!("invalid --port value: {err}"),
						)?;
				}
				"--quorum-file" => {
					cli.quorum_key_path =
						next_value(&mut args, "--quorum-file")?;
				}
				"--boot-proof" => {
					cli.boot_proof =
						match next_value(&mut args, "--boot-proof")?.as_str() {
							"off" => BootProofMode::Off,
							"nsm" => BootProofMode::Nsm,
							other => {
								return Err(format!(
									"invalid --boot-proof value: {other}"
								));
							}
						};
				}
				_ => return Err(format!("unknown argument: {arg}")),
			}
		}
		Ok(cli)
	}

	fn addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
		format!("{}:{}", self.host, self.port).parse()
	}

	fn config(&self) -> Config {
		Config::new(&self.quorum_key_path)
	}
}

fn next_value(
	args: &mut impl Iterator<Item = String>,
	name: &str,
) -> Result<String, String> {
	args.next().ok_or_else(|| format!("missing value for {name}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let cli = Cli::parse(std::env::args().skip(1)).map_err(|err| {
		std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
	})?;
	let addr = cli.addr()?;
	if cli.boot_proof == BootProofMode::Off {
		let app = signed_echo::router(cli.config());
		eprintln!("signed_echo listening on {addr}");
		axum::Server::bind(&addr).serve(app.into_make_service()).await?;
		return Ok(());
	}

	// Start with a usable document. Failure exits the pivot; use the manifest's
	// RestartPolicy::Always to have QOS's reaper restart it.
	let (boot_proof, refresh_task) = BootProof::start(
		Arc::new(Nsm),
		Path::new(EPHEMERAL_KEY_FILE),
		Path::new(MANIFEST_FILE),
	)
	.await?;
	eprintln!(
		"signed_echo: attestation certificate expires at {}, valid for {:?}",
		boot_proof.cache().expiry(),
		boot_proof.cache().valid_for(),
	);
	let app = router_with_boot_proof(cli.config(), boot_proof);

	eprintln!("signed_echo listening on {addr}, serving its boot proof");
	serve_with_refresh(
		axum::Server::bind(&addr).serve(app.into_make_service()),
		refresh_task,
	)
	.await
}

// Own both futures so a refresh failure drops the server, and server shutdown
// aborts refresh. The caller exits on error and lets QOS restart the app.
async fn serve_with_refresh<S, E>(
	server: S,
	mut refresh_task: tokio::task::JoinHandle<()>,
) -> Result<(), Box<dyn std::error::Error>>
where
	S: std::future::Future<Output = Result<(), E>>,
	E: std::error::Error + 'static,
{
	tokio::select! {
		completed = server => {
			refresh_task.abort();
			completed?;
			Ok(())
		}
		stopped = &mut refresh_task => {
			match stopped {
				Err(error) => Err(error.into()),
				Ok(()) => Err("attestation refresh task stopped".into()),
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{future::pending, io};
	use tokio::{sync::oneshot, task::JoinError};

	use super::{BootProofMode, Cli, serve_with_refresh};

	#[tokio::test]
	async fn refresh_panic_drops_the_server_and_fails_the_app() {
		let (started, wait_for_server) = oneshot::channel();
		let (server_lifetime, server_dropped) = oneshot::channel::<()>();
		let server = async move {
			let _server_lifetime = server_lifetime;
			started.send(()).unwrap();
			pending::<io::Result<()>>().await
		};
		let refresh = tokio::spawn(async move {
			wait_for_server.await.unwrap();
			panic!("simulate fatal cache-task panic");
		});
		let error = serve_with_refresh(server, refresh).await.unwrap_err();
		assert!(error.downcast_ref::<JoinError>().unwrap().is_panic());
		assert!(
			server_dropped.await.is_err(),
			"the server future must be dropped"
		);
	}

	#[tokio::test]
	async fn unexpected_refresh_completion_is_also_fatal() {
		let error = serve_with_refresh(
			pending::<io::Result<()>>(),
			tokio::spawn(async {}),
		)
		.await
		.unwrap_err();
		assert_eq!(error.to_string(), "attestation refresh task stopped");
	}

	#[tokio::test]
	async fn server_shutdown_or_failure_aborts_refresh() {
		for fail in [false, true] {
			let (refresh_lifetime, refresh_dropped) = oneshot::channel::<()>();
			let refresh = tokio::spawn(async move {
				let _refresh_lifetime = refresh_lifetime;
				pending::<()>().await;
			});
			let server = async move {
				if fail {
					Err(io::Error::other("HTTP server failed"))
				} else {
					Ok(())
				}
			};
			let result = serve_with_refresh(server, refresh).await;
			assert_eq!(result.is_err(), fail);
			assert!(refresh_dropped.await.is_err(), "refresh must be aborted");
		}
	}

	fn parse(args: &[&str]) -> Result<Cli, String> {
		Cli::parse(args.iter().map(ToString::to_string))
	}

	#[test]
	fn boot_proof_is_an_explicit_opt_in() {
		assert_eq!(parse(&[]).unwrap().boot_proof, BootProofMode::Off);
		assert_eq!(
			parse(&["--boot-proof", "off"]).unwrap().boot_proof,
			BootProofMode::Off
		);
		assert_eq!(
			parse(&["--boot-proof", "nsm"]).unwrap().boot_proof,
			BootProofMode::Nsm
		);
	}

	#[test]
	fn unsupported_or_incomplete_arguments_are_rejected() {
		for args in [
			vec!["--boot-proof"],
			vec!["--boot-proof", "qemu"],
			vec!["--boot-proof", "nsm", "--pcr18", "required"],
		] {
			assert!(parse(&args).is_err(), "{args:?}");
		}
	}
}

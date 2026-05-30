//! Signed echo pivot application binary.

use std::net::SocketAddr;

use signed_echo::{Config, DEFAULT_QUORUM_KEY_PATH};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 3000;

#[derive(Debug, PartialEq, Eq)]
struct Cli {
	host: String,
	port: u16,
	quorum_key_path: String,
}

impl Default for Cli {
	fn default() -> Self {
		Self {
			host: DEFAULT_HOST.to_string(),
			port: DEFAULT_PORT,
			quorum_key_path: DEFAULT_QUORUM_KEY_PATH.to_string(),
		}
	}
}

impl Cli {
	fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
		let mut cli = Self::default();
		let mut args = args.into_iter();

		while let Some(arg) = args.next() {
			match arg.as_str() {
				"--host" => {
					cli.host = next_value(&mut args, "--host")?;
				}
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
				_ => {
					return Err(format!("unknown argument: {arg}"));
				}
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
	let app = signed_echo::router(cli.config());

	axum::Server::bind(&addr).serve(app.into_make_service()).await?;
	Ok(())
}

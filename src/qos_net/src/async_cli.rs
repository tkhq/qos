//! Async extension to the CLI
use crate::{
	async_proxy::AsyncProxyServer,
	cli::{ProxyOpts, CLI},
};

impl CLI {
	/// Execute the enclave proxy CLI with the environment args in an async way.
	pub async fn async_execute() {
		use qos_core::async_server::AsyncSocketServer;

		let mut args: Vec<String> = std::env::args().collect();
		let opts = ProxyOpts::new(&mut args);

		if opts.parsed.version() {
			println!("version: {}", env!("CARGO_PKG_VERSION"));
		} else if opts.parsed.help() {
			println!("{}", opts.parsed.info());
		} else {
			let server = AsyncSocketServer::listen_proxy(
				opts.async_pool().expect("unable to create async socket pool"),
			)
			.await
			.expect("unable to get listen join handles");

			match tokio::signal::ctrl_c().await {
				Ok(_) => {
					eprintln!("handling ctrl+c the tokio way");
					server.terminate();
				}
				Err(err) => panic!("{err}"),
			}
		}
	}
}

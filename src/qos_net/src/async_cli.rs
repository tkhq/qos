use crate::{
	async_proxy::AsyncProxy,
	cli::{ProxyOpts, CLI},
};

///! Async extension to the CLI

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
			AsyncSocketServer::listen(opts.addr(), AsyncProxy::new())
				.await
				.unwrap();
		}
	}
}

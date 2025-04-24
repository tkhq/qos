#[cfg(any(feature = "proxy", feature = "async_proxy"))]
use qos_net::cli::CLI;

#[cfg(feature = "proxy")]
pub fn main() {
	CLI::execute();
}

#[cfg(feature = "async_proxy")]
pub fn main() {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("tokio main to run")
		.block_on(async {
			CLI::async_execute().await;
		});
}

#[cfg(not(any(feature = "proxy", feature = "async_proxy")))]
pub fn main() {
	panic!("Cannot run qos_net CLI without proxy feature enabled")
}

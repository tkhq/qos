#[cfg(feature = "async_proxy")]
pub fn main() {
	use qos_net::cli::CLI;

	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("tokio main to run")
		.block_on(async {
			CLI::async_execute().await;
		});
}

#[cfg(not(feature = "async_proxy"))]
pub fn main() {
	panic!("async qos_net invoked without async_proxy feature")
}

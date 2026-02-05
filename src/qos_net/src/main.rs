//! QOS Net proxy binary entry point.

#[cfg(feature = "proxy")]
#[tokio::main]
async fn main() {
	use qos_net::cli::CLI;
	CLI::execute().await;
}

#[cfg(not(any(feature = "proxy")))]
fn main() {
	panic!("Cannot run qos_net CLI without proxy feature enabled")
}

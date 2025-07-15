#[cfg(feature = "proxy")]
#[tokio::main]
pub async fn main() {
	use qos_net::cli::CLI;
	CLI::execute().await;
}

#[cfg(not(any(feature = "proxy")))]
pub fn main() {
	panic!("Cannot run qos_net CLI without proxy feature enabled")
}

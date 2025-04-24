#[cfg(feature = "proxy")]
pub fn main() {
	use qos_net::cli::CLI;
	CLI::execute();
}

#[cfg(not(any(feature = "proxy", feature = "async_proxy")))]
pub fn main() {
	panic!("Cannot run qos_net CLI without proxy feature enabled")
}

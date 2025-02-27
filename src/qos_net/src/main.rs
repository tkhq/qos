#[cfg(feature = "proxy")]
use qos_net::cli::CLI;

#[cfg(feature = "proxy")]
pub fn main() {
	CLI::execute();
}


#[cfg(not(feature = "proxy"))]
pub fn main() {
	panic!("Cannot run qos_net CLI without proxy feature enabled")
}


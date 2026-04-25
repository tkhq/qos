#![no_main]

use libfuzzer_sys::fuzz_target;

// use qos_net::proxy_connection::ProxyConnection;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzIPPort {
	pub ip: String,
	pub port: u16,
}

fuzz_target!(|_data: FuzzIPPort| {
	// Commented out of now as this is an async function that is just returning
	// a future right away without getting polled. The code inside the function
	// (at the time of writing) is strictly std/core or tokio code that might not
	// be worth fuzzing.
	// let _ = ProxyConnection::new_from_ip(data.ip.clone(), data.port);
});

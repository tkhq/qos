#![no_main]

use libfuzzer_sys::fuzz_target;

use qos_net::proxy_connection::ProxyConnection;

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzIPPort {
	pub ip: String,
	pub port: u16,
}

fuzz_target!(|data: FuzzIPPort| {
	let _ = ProxyConnection::new_from_ip(data.ip.clone(), data.port);
});

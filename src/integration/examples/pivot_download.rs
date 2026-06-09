use std::{
	net::SocketAddr,
	time::{Duration, SystemTime},
};

use sha2::Digest;
use ureq::Resolver;

struct FixedResolver {
	ip_addr: SocketAddr,
}

impl Resolver for FixedResolver {
	fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
		Ok(vec![self.ip_addr])
	}
}

// arguments are <url> [ip_override]
//    url - the url of the file to download (GET)
//    ip_override - an optional <ip:port> e.g. 127.0.0.1:80 that is used to avoid dns lookup with the given url if given
fn main() {
	let mut args = std::env::args();
	let url = url::Url::parse(&args.nth(1).expect("no url provided"))
		.expect("invalid url");
	let ip_override = args.next(); // provides ip override if we want to avoid dns

	println!("sleeping 10s before download");
	std::thread::sleep(std::time::Duration::from_secs(10));

	let client_builder = if let Some(ip) = ip_override {
		let ip_addr = ip.parse().expect("invalid override ip");
		let base_url = url.host_str().expect("no host in url");

		println!("using override ip of {ip} for base url {base_url}");

		ureq::builder().resolver(FixedResolver { ip_addr })
	} else {
		ureq::builder()
	};

	let client = client_builder.timeout(Duration::from_mins(1)).build();

	println!("starting download of {url}");
	let request = client.get(url.as_ref());

	let start = SystemTime::now();
	let dl = request.call().expect("unable to download");

	let status = dl.status();
	let bytes: Vec<u8> = dl.into_string().unwrap().bytes().collect();

	let size = bytes.len();
	let ss = sha2::Sha256::digest(bytes);

	println!(
		"download complete\n\tstatus: {}\n\tsize: {}\n\tduration: {:?}\n\tsha256sum:{:x}",
		status,
		size,
		SystemTime::now().duration_since(start).unwrap(),
		ss,
	);
}

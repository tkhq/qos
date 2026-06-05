use std::time::{Duration, SystemTime};

use sha2::Digest;

fn main() {
	let mut args = std::env::args();
	let url = url::Url::parse(&args.nth(1).expect("no url provided"))
		.expect("invalid url");
	let ip_override = args.next(); // provides ip override if we want to avoid dns

	println!("sleeping 10s before download");
	std::thread::sleep(std::time::Duration::from_secs(10));

	let client_builder = if let Some(ip) = ip_override {
		let addr = ip.parse().expect("invalid override ip");
		let base_url = url.host_str().expect("no host in url");

		println!("using override ip of {ip} for base url {base_url}");

		reqwest::blocking::ClientBuilder::new()
			.resolve_to_addrs(base_url, &[addr])
	} else {
		reqwest::blocking::ClientBuilder::new()
	};

	let client = client_builder.build().unwrap();

	println!("starting download of {url}");
	let request = client
		.get(url)
		.timeout(Duration::from_secs(300))
		.build()
		.expect("unable to build request");

	let start = SystemTime::now();
	let dl = client.execute(request).expect("unable to download");

	let status = dl.status();
	let bytes = dl.bytes().unwrap();
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

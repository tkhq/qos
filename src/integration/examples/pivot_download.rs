use std::{
	net::SocketAddr,
	time::{Duration, SystemTime},
};

use axum::{Json, Router, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use ureq::{
	Agent,
	config::Config,
	http::Uri,
	unversioned::{
		resolver::{ResolvedSocketAddrs, Resolver},
		transport::{DefaultConnector, NextTimeout},
	},
};

#[derive(Debug)]
struct FixedResolver {
	ip_addr: SocketAddr,
}

// download request
#[derive(Debug, Deserialize)]
struct DlRequest {
	url: url::Url,
	ip_override: Option<String>,
}

#[derive(Debug, Serialize)]
struct DlResponse {
	status: u16,
	size: usize,
	duration: Duration,
	sha256sum: String,
	error: Option<String>,
}

impl DlResponse {
	pub fn error(status: u16, error: String) -> Self {
		Self {
			status,
			size: 0,
			duration: Duration::ZERO,
			sha256sum: String::new(),
			error: Some(error),
		}
	}
}

impl Resolver for FixedResolver {
	fn resolve(
		&self,
		_uri: &Uri,
		_config: &Config,
		_timeout: NextTimeout,
	) -> Result<ResolvedSocketAddrs, ureq::Error> {
		let mut addrs = self.empty();
		addrs.push(self.ip_addr);
		Ok(addrs)
	}
}

async fn serve() {
	// build our application with a single route
	let app = Router::new().route("/", axum::routing::post(download));

	println!("axum server running, listening on http://127.0.0.1:3000");
	// run it with hyper on localhost:3000
	let listener =
		tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
	axum::serve(listener, app).await.unwrap();
}

async fn download(
	Json(DlRequest { url, ip_override }): Json<DlRequest>,
) -> impl IntoResponse {
	let response = tokio::task::spawn_blocking(move || {
		let config = Agent::config_builder()
			.timeout_global(Some(Duration::from_mins(1)))
			.build();
		let client = if let Some(ip) = ip_override {
			let ip_addr = ip.parse().expect("invalid override ip");
			let base_url = url.host_str().expect("no host in url");

			println!("using override ip of {ip} for base url {base_url}");

			Agent::with_parts(
				config,
				DefaultConnector::new(),
				FixedResolver { ip_addr },
			)
		} else {
			config.new_agent()
		};

		println!("starting download of {url}");
		let request = client.get(url.as_ref());

		let start = SystemTime::now();
		let dl = match request.call() {
			Ok(r) => r,
			Err(ureq::Error::StatusCode(code)) => return (StatusCode::from_u16(code).unwrap(), DlResponse::error(code, format!("status {code}"))),
			Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, DlResponse::error(500, e.to_string()))
		};

		let status = dl.status().as_u16();
		let bytes: Vec<u8> = dl.into_body().read_to_string().unwrap().bytes().collect();

		let size = bytes.len();
		let sha256sum = sha2::Sha256::digest(bytes);
		let duration = SystemTime::now().duration_since(start).unwrap();

		println!(
			"download complete\n\tstatus: {}\n\tsize: {}\n\tduration: {:?}\n\tsha256sum:{:x}",
			status,
			size,
			duration,
			sha256sum,
		);

		(StatusCode::OK, DlResponse {
			status,
			size,
			duration,
			sha256sum: format!("{sha256sum:x}"),
			error: None,
		})
	}).await.expect("unable to join blocking task");

	(response.0, Json(response.1))
}

#[tokio::main]
async fn main() {
	serve().await
}

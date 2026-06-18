use std::{
	net::SocketAddr,
	time::{Duration, SystemTime},
};

use axum::{Json, Router, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use ureq::Resolver;

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
	pub fn unexpected_response(code: u16, r: ureq::Response) -> Self {
		Self {
			status: code,
			size: 0,
			duration: Duration::ZERO,
			sha256sum: String::new(),
			error: Some(r.status_text().to_string()),
		}
	}

	pub fn transport_error(t: ureq::Transport) -> Self {
		Self {
			status: 500,
			size: 0,
			duration: Duration::ZERO,
			sha256sum: String::new(),
			error: Some(t.message().unwrap_or("unknown error").to_string()),
		}
	}
}

impl Resolver for FixedResolver {
	fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
		Ok(vec![self.ip_addr])
	}
}

async fn serve() {
	// build our application with a single route
	let app = Router::new().route("/", axum::routing::post(download));

	println!("axum server running, listening on http://127.0.0.1:3000");
	// run it with hyper on localhost:3000
	axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
		.serve(app.into_make_service())
		.await
		.unwrap();
}

async fn download(
	Json(DlRequest { url, ip_override }): Json<DlRequest>,
) -> impl IntoResponse {
	let response = tokio::task::spawn_blocking(move || {
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
		let dl = match request.call() {
			Ok(r) => r,
			Err(ureq::Error::Status(code, r)) => return (StatusCode::from_u16(code).unwrap(), DlResponse::unexpected_response(code, r)),
			Err(ureq::Error::Transport(e)) => return (StatusCode::INTERNAL_SERVER_ERROR, DlResponse::transport_error(e))
		};

		let status = dl.status();
		let bytes: Vec<u8> = dl.into_string().unwrap().bytes().collect();

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

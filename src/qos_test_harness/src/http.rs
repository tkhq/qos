use std::{
	io::{Read, Write},
	net::{TcpStream, ToSocketAddrs},
	time::Duration,
};

use thiserror::Error;

use crate::{HttpResponse, RunnerError};

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum HttpClientError {
	#[error("unsupported URL `{0}`")]
	UnsupportedUrl(String),
	#[error("invalid URL `{0}`")]
	InvalidUrl(String),
	#[error("io error: {0}")]
	Io(String),
	#[error("invalid HTTP response: {0}")]
	InvalidResponse(String),
}

impl From<HttpClientError> for RunnerError {
	fn from(value: HttpClientError) -> Self {
		Self::new(value.to_string())
	}
}

impl From<std::io::Error> for HttpClientError {
	fn from(value: std::io::Error) -> Self {
		Self::Io(value.to_string())
	}
}

pub fn http_get(url: &str) -> Result<HttpResponse, HttpClientError> {
	request("GET", url, &[])
}

pub fn http_post(
	url: &str,
	body: &[u8],
) -> Result<HttpResponse, HttpClientError> {
	request("POST", url, body)
}

fn request(
	method: &str,
	url: &str,
	body: &[u8],
) -> Result<HttpResponse, HttpClientError> {
	let parsed = ParsedUrl::parse(url)?;
	let addr = format!("{}:{}", parsed.host, parsed.port);
	let socket_addr = addr
		.to_socket_addrs()?
		.next()
		.ok_or_else(|| HttpClientError::InvalidUrl(url.to_string()))?;
	let mut stream = TcpStream::connect_timeout(&socket_addr, HTTP_TIMEOUT)?;
	stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
	stream.set_write_timeout(Some(HTTP_TIMEOUT))?;

	let request = format!(
		"{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
		parsed.path,
		parsed.host,
		body.len()
	);
	stream.write_all(request.as_bytes())?;
	stream.write_all(body)?;

	let mut response = Vec::new();
	stream.read_to_end(&mut response)?;
	parse_response(&response)
}

fn parse_response(bytes: &[u8]) -> Result<HttpResponse, HttpClientError> {
	let split = bytes
		.windows(4)
		.position(|window| window == b"\r\n\r\n")
		.ok_or_else(|| {
			HttpClientError::InvalidResponse("missing header terminator".into())
		})?;
	let headers = std::str::from_utf8(&bytes[..split])
		.map_err(|err| HttpClientError::InvalidResponse(err.to_string()))?;
	let status = headers
		.lines()
		.next()
		.and_then(|line| line.split_whitespace().nth(1))
		.and_then(|status| status.parse::<u16>().ok())
		.ok_or_else(|| {
			HttpClientError::InvalidResponse("missing status code".into())
		})?;
	Ok(HttpResponse::new(status, bytes[split + 4..].to_vec()))
}

struct ParsedUrl {
	host: String,
	port: u16,
	path: String,
}

impl ParsedUrl {
	fn parse(url: &str) -> Result<Self, HttpClientError> {
		let rest = url
			.strip_prefix("http://")
			.ok_or_else(|| HttpClientError::UnsupportedUrl(url.to_string()))?;
		let (authority, path) = match rest.split_once('/') {
			Some((authority, path)) => (authority, format!("/{path}")),
			None => (rest, "/".to_string()),
		};
		if authority.is_empty() {
			return Err(HttpClientError::InvalidUrl(url.to_string()));
		}

		let (host, port) = match authority.rsplit_once(':') {
			Some((host, port)) => {
				let port = port.parse::<u16>().map_err(|_| {
					HttpClientError::InvalidUrl(url.to_string())
				})?;
				(host.to_string(), port)
			}
			None => (authority.to_string(), 80),
		};

		Ok(Self { host, port, path })
	}
}

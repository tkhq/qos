use std::{
	io::{Read, Write},
	net::{Shutdown, TcpListener, TcpStream},
	time::{SystemTime, UNIX_EPOCH},
};

use qos_p256::P256Pair;
use qos_test_harness::{SignedEchoResponse, signed_echo_payload};

fn main() {
	let opts = Opts::parse();
	let addr = format!("{}:{}", opts.host, opts.port);
	let listener = TcpListener::bind(&addr)
		.unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));
	let key = P256Pair::generate().expect("failed to generate P-256 key");

	for stream in listener.incoming() {
		match stream {
			Ok(stream) => handle_connection(stream, &key),
			Err(err) => eprintln!("failed to accept connection: {err}"),
		}
	}
}

fn handle_connection(mut stream: TcpStream, key: &P256Pair) {
	let mut request = vec![0_u8; 64 * 1024];
	let read = match stream.read(&mut request) {
		Ok(read) => read,
		Err(err) => {
			eprintln!("failed to read request: {err}");
			return;
		}
	};
	request.truncate(read);

	let response = match parse_request(&request) {
		Some(Request { method, path, body: _ })
			if method == "GET" && path == "/health" =>
		{
			http_response(200, b"ok".to_vec())
		}
		Some(Request { method, path, body })
			if method == "POST" && path == "/echo" =>
		{
			signed_echo_response(key, &body)
		}
		_ => http_response(404, b"not found".to_vec()),
	};

	if let Err(err) = stream.write_all(&response) {
		eprintln!("failed to write response: {err}");
	}
	let _ = stream.shutdown(Shutdown::Both);
}

fn signed_echo_response(key: &P256Pair, body: &[u8]) -> Vec<u8> {
	let message = match std::str::from_utf8(body) {
		Ok(message) => message,
		Err(_) => {
			return http_response(400, b"request body must be utf-8".to_vec());
		}
	};
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system clock before unix epoch")
		.as_secs();
	let payload = signed_echo_payload(time, message);
	let signature = key.sign(&payload).expect("failed to sign echo payload");
	let response = SignedEchoResponse {
		time,
		message: message.to_string(),
		signed_payload_hex: qos_hex::encode(&payload),
		signature_hex: qos_hex::encode(&signature),
		public_key_hex: qos_hex::encode(&key.public_key().to_bytes()),
	};
	let body =
		serde_json::to_vec(&response).expect("signed echo response is json");
	http_response(200, body)
}

fn http_response(status: u16, body: Vec<u8>) -> Vec<u8> {
	let reason = match status {
		200 => "OK",
		400 => "Bad Request",
		404 => "Not Found",
		_ => "Internal Server Error",
	};
	let headers = format!(
		"HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
		body.len()
	);
	[headers.into_bytes(), body].concat()
}

struct Request {
	method: String,
	path: String,
	body: Vec<u8>,
}

fn parse_request(bytes: &[u8]) -> Option<Request> {
	let split = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
	let headers = std::str::from_utf8(&bytes[..split]).ok()?;
	let mut lines = headers.lines();
	let request_line = lines.next()?;
	let mut parts = request_line.split_whitespace();
	let method = parts.next()?.to_string();
	let path = parts.next()?.to_string();
	let content_len = lines
		.find_map(|line| {
			let (name, value) = line.split_once(':')?;
			name.eq_ignore_ascii_case("content-length")
				.then(|| value.trim().parse::<usize>().ok())
				.flatten()
		})
		.unwrap_or(0);
	let body_start = split + 4;
	let body_end = body_start + content_len.min(bytes.len() - body_start);

	Some(Request { method, path, body: bytes[body_start..body_end].to_vec() })
}

struct Opts {
	host: String,
	port: u16,
}

impl Opts {
	fn parse() -> Self {
		let mut host = "0.0.0.0".to_string();
		let mut port = 3000;
		let mut args = std::env::args().skip(1);
		while let Some(arg) = args.next() {
			match arg.as_str() {
				"--host" => {
					host = args.next().expect("--host requires a value");
				}
				"--port" => {
					port = args
						.next()
						.expect("--port requires a value")
						.parse()
						.expect("--port must be a u16");
				}
				_ => panic!("unknown argument {arg}"),
			}
		}
		Self { host, port }
	}
}

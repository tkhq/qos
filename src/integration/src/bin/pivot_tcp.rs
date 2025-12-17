use integration::PIVOT_TCP_SUCCESS_FILE;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
};

#[tokio::main]
async fn main() {
	let tcp_listener = TcpListener::bind("127.0.0.1:3000")
		.await
		.expect("unable to bind localhost:3000");

	loop {
		let (mut stream, _) = tcp_listener
			.accept()
			.await
			.expect("failed to accept tcp connection");

		tokio::spawn(async move {
			// read the message body
			let mut buf = vec![0u8; 32];
			let size = stream
				.read(&mut buf)
				.await
				.expect("failed to read message body");

			stream
				.write_all(&buf[..size])
				.await
				.expect("unable to write tcp reply");

			// final msg received, exit
			if &buf[..size] == b"done" {
				std::process::exit(0);
			}

			// we don't want to force "fs" into tokio so we just use std/sync here
			std::fs::write(PIVOT_TCP_SUCCESS_FILE, &buf[..size])
				.expect("unable to write tcp pivot success file");
		})
		.await
		.expect("unable to join worker");
	}
}

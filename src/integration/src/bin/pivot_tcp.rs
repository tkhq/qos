use integration::PIVOT_TCP_SUCCESS_FILE;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
};

#[tokio::main]
async fn main() {
	let port: u16 = std::env::args()
		.nth(1)
		.expect("no port provided")
		.parse()
		.expect("invalid port specified");
	let host_addr = format!("127.0.0.1:{port}");

	let tcp_listener = TcpListener::bind(&host_addr)
		.await
		.expect("unable to bind {host_addr}");

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

			// probably connect check
			if size == 0 {
				return;
			}

			stream
				.write_all(&buf[..size])
				.await
				.expect("unable to write tcp reply");

			// final msg received, exit
			if &buf[..size] == b"done" {
				stream.shutdown().await.expect("unable to shutdown cleanly");

				// we don't want to force "fs" into tokio so we just use std/sync here
				std::fs::write(PIVOT_TCP_SUCCESS_FILE, "finished")
					.expect("unable to write tcp pivot success file");
				std::process::exit(0);
			}
		});
	}
}

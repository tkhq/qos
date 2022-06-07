#[tokio::main]
async fn main() {
	// Development quick start
	// ```
	// `cargo run --bin qos-host -- \
	// 		--usock tk.sock \
	// 		--host-port 3000 \
	// 		--host-ip 0.0.0.0 \
	// ```
	qos_host::CLI::execute().await;
}

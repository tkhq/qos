//! QOS bridge binary entry point for ingress bridge.

use qos_bridge::cli;

#[tokio::main]
async fn main() {
	// Development quick start
	// ```
	// cargo run --bin ingress -- \
	//      --usock /tmp/usock.sock \
	// ```
	cli::Cli::execute_ingress().await;
}

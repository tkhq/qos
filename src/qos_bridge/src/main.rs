//! QOS bridge binary entry point.

mod cli;
mod host;

#[tokio::main]
async fn main() {
	// Development quick start
	// ```
	// cargo run --bin qos_bridge -- \
	//      --usock /tmp/usock.sock \
	//      --control-url http://localhost:3001/qos
	// ```
	cli::Cli::execute().await;
}

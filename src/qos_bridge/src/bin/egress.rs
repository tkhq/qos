//! QOS bridge binary entry point for egress bridge.

use qos_bridge::cli;

fn main() {
	// Development quick start
	// ```
	// cargo run --bin egress -- \
	//      --cid 16
	// ```
	cli::Cli::execute_egress();
}

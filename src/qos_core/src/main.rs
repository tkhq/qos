use qos_core::cli::CLI;

#[tokio::main]
async fn main() {
	CLI::execute().await;
}

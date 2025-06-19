use qos_core::cli::CLI;

#[tokio::main]
async fn main() {
	CLI::async_execute().await;
}

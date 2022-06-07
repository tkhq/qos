#[tokio::main]
async fn main() {
	qos_host::cli::CLI::execute().await;
}

use reshard_host::cli::CLI;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	CLI::execute().await;

	Ok(())
}

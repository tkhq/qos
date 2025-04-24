use qos_core::cli::CLI;

fn main() {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("tokio main to run")
		.block_on(async {
			CLI::async_execute();
		});
}

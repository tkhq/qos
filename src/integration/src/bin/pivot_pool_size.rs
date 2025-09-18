use integration::PIVOT_POOL_SIZE_SUCCESS_FILE;

fn main() {
	if std::env::var("POOL_SIZE").is_err() {
		panic!("invalid pool size specified")
	}

	integration::Cli::execute(PIVOT_POOL_SIZE_SUCCESS_FILE);
}

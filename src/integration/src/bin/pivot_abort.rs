fn main() {
	for i in 0..3 {
		std::thread::sleep(std::time::Duration::from_millis(i));
	}

	std::process::abort();
}

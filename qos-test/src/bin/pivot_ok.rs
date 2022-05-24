use qos_test::PIVOT_OK_SUCCESS_FILE;

fn main() {
	for i in 0..3 {
		println!("Pivot OK Binary. Iteration #{}", i);
	}

	println!("writing to file");
	std::fs::write(qos_test::PIVOT_OK_SUCCESS_FILE, b"contents").unwrap();
}

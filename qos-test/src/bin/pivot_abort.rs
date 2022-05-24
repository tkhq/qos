fn main() {
	for i in 0..3 {
		println!("Pivot ABORT Binary. Iteration #{}", i);
	}

	std::process::abort();
}

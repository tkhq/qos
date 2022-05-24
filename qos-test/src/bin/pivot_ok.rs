fn main() {
	for i in 0..3 {
		println!("Pivot OK Binary. Iteration #{}", i);
	}

	std::fs::write("./pivot_ok_works", b"contents").unwrap();
}

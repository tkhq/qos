fn main() {
	for i in 0..3 {
		println!("Pivot PANIC Binary. Iteration #{}", i);
	}

	panic!("Pivot PANIC Binary is ... panicking");
}

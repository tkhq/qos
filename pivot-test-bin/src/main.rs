use rand::Rng;

fn main() {
	for _ in 0..100 {
		let mut rng = rand::thread_rng();

		let n: u64 = rng.gen();
		if n % u8::MAX as u64 == 0 {
			// Randomly panic sometimes
			panic!("The pivot binary is panicking")
		}
	}
}

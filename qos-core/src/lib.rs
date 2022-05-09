#![forbid(unsafe_code)]

pub mod client;
pub mod io;
pub mod protocol;
pub mod server;

#[cfg(test)]
mod tests {
	#[test]
	fn it_works() {
		let result = 2 + 2;
		assert_eq!(result, 4);
	}
}

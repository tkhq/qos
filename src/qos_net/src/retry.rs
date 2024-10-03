use std::thread::sleep;
use std::time::Duration;

pub fn retry_with_backoff<T, E, F>(
	mut operation: F,
	retry_count: u32,
) -> Result<T, E>
where
	F: FnMut() -> Result<T, E>,
{
	let mut attempts = 0;

	loop {
		match operation() {
			Ok(result) => return Ok(result),
			Err(_) if attempts < retry_count => {
				attempts += 1;
				let backoff_duration =
					Duration::from_millis(2_u64.pow(attempts) * 100); // Exponential backoff
				sleep(backoff_duration);
			}
			Err(e) => return Err(e),
		}
	}
}

#[cfg(test)]
mod test {

	use std::cell::RefCell;

	use super::*;

    #[test]
	fn test_retry_with_backoff_success_after_retries() {
		// This mock will fail the first 2 attempts, and succeed on the 3rd attempt.
		let attempt_counter = RefCell::new(0);
		let operation = || {
			let mut attempts = attempt_counter.borrow_mut();
			*attempts += 1;
			if *attempts <= 2 {
				Err("fail")
			} else {
				Ok("success")
			}
		};

		// Retry 3 times
		let result: Result<&str, &str> = retry_with_backoff(operation, 3);

		assert_eq!(result, Ok("success"));
		assert_eq!(*attempt_counter.borrow(), 3);
	}

	#[test]
	fn test_retry_with_backoff_failure_after_max_retries() {
		// This mock will always fail.
		let attempt_counter = RefCell::new(0);
		let operation = || {
			let mut attempts = attempt_counter.borrow_mut();
			*attempts += 1;
			Err("fail")
		};

		// Retry 3 times
		let result: Result<&str, &str> = retry_with_backoff(operation, 3);

		assert_eq!(result, Err("fail"));
		assert_eq!(*attempt_counter.borrow(), 4); // 1 initial try + 3 retries
	}

	#[test]
	fn test_retry_with_backoff_no_retries() {
		// This mock will fail the first time and there will be no retries.
		let attempt_counter = RefCell::new(0);
		let operation = || {
			let mut attempts = attempt_counter.borrow_mut();
			*attempts += 1;
			Err("fail")
		};

		// Retry 0 times
		let result: Result<&str, &str> = retry_with_backoff(operation, 0);

		assert_eq!(result, Err("fail"));
		assert_eq!(*attempt_counter.borrow(), 1); // Only 1 attempt
	}
}
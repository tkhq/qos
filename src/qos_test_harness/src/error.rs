use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct RunnerError {
	message: String,
}

impl RunnerError {
	#[must_use]
	pub fn new(message: impl Into<String>) -> Self {
		Self { message: message.into() }
	}

	#[must_use]
	pub fn message(&self) -> &str {
		&self.message
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TestError {
	#[error("runner step {step} failed: {source}")]
	Runner {
		step: &'static str,
		#[source]
		source: RunnerError,
	},

	#[error("{message}")]
	Assertion { message: String },

	#[error("test failed with `{test_error}` and cleanup failed: {source}")]
	CleanupAfterFailure {
		test_error: Box<TestError>,
		#[source]
		source: RunnerError,
	},

	#[error("cleanup failed after passing test: {source}")]
	CleanupAfterPass {
		#[source]
		source: RunnerError,
	},
}

impl TestError {
	#[must_use]
	pub fn assertion(message: impl Into<String>) -> Self {
		Self::Assertion { message: message.into() }
	}

	#[must_use]
	pub fn runner(step: &'static str, source: RunnerError) -> Self {
		Self::Runner { step, source }
	}

	#[must_use]
	pub fn cleanup_after_failure(
		test_error: TestError,
		source: RunnerError,
	) -> Self {
		Self::CleanupAfterFailure { test_error: Box::new(test_error), source }
	}

	#[must_use]
	pub fn cleanup_after_pass(source: RunnerError) -> Self {
		Self::CleanupAfterPass { source }
	}
}

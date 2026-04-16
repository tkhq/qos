//! Wall-clock access for Unix time inside QOS.

use std::{fmt, time::SystemTime};

/// Error returned when reading wall-clock time fails or overflows `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockError {
	/// Converting between time units failed.
	TimeConversionFailed,
	/// The system clock was before the Unix epoch.
	TimeBeforeUnixEpoch,
	/// The returned value did not fit in `u64`.
	TimeOverflow,
}

impl fmt::Display for WallClockError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TimeConversionFailed => {
				write!(f, "system clock conversion failed")
			}
			Self::TimeBeforeUnixEpoch => {
				write!(f, "system clock was before the Unix epoch")
			}
			Self::TimeOverflow => {
				write!(f, "system clock value overflowed u64")
			}
		}
	}
}

/// Source of Unix wall-clock time for expiry and freshness checks.
pub trait WallClock: Send + Sync {
	/// Returns Unix time in whole milliseconds.
	fn unix_time_millis(&self) -> Result<u64, WallClockError>;

	/// Returns Unix time in whole seconds.
	fn unix_time_seconds(&self) -> Result<u64, WallClockError> {
		self.unix_time_millis()?
			.checked_div(1_000)
			.ok_or(WallClockError::TimeConversionFailed)
	}
}

/// Wall clock backed by the host operating system.
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
	fn unix_time_millis(&self) -> Result<u64, WallClockError> {
		let duration = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.map_err(|_| WallClockError::TimeBeforeUnixEpoch)?;

		u64::try_from(duration.as_millis())
			.map_err(|_| WallClockError::TimeOverflow)
	}
}

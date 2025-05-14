use nix::sys::time::TimeVal;
use tokio::sync::{Mutex, MutexGuard};

use super::{AsyncListener, AsyncStream, IOError, SocketAddress};

/// Socket Pool Errors
#[derive(Debug)]
pub enum PoolError {
	/// No addresses were provided in the pool constructor
	NoAddressesSpecified,
}

/// Generic Async pool using tokio Mutex
struct AsyncPool<T> {
	handles: Vec<Mutex<T>>,
}

/// Specialization of [AsyncPool] with [AsyncStream] and connection/liste logic.
pub struct AsyncStreamPool {
	addresses: Vec<SocketAddress>,
	pool: AsyncPool<AsyncStream>,
}

impl AsyncStreamPool {
	/// Create a new [AsyncStreamPool] which will contain all the known addresses but no connections yet.
	pub fn new(addresses: impl IntoIterator<Item = SocketAddress>) -> Self {
		let pool = AsyncPool::empty();
		Self { addresses: addresses.into_iter().collect(), pool }
	}

	/// Gets the next available [AsyncStream] behind a [MutexGuard]
	pub async fn get(&self) -> MutexGuard<AsyncStream> {
		self.pool.get().await
	}

	/// Connect all the addresses
	pub async fn connect(&mut self, timeout: TimeVal) -> Result<(), IOError> {
		let mut handles = Vec::new();
		for addr in &self.addresses {
			let handle = AsyncStream::connect(&addr, timeout).await?;
			handles.push(Mutex::new(handle));
		}

		if handles.is_empty() {
			Err(PoolError::NoAddressesSpecified.into())
		} else {
			self.pool.handles = handles;
			Ok(())
		}
	}

	/// Listen for a new connection on all the addresses, deconstructs the pool for server
	/// side operation.
	pub async fn listen(self) -> Result<Vec<AsyncListener>, IOError> {
		let mut listeners = Vec::new();

		for addr in self.addresses {
			let listener = AsyncListener::listen(addr).await?;

			listeners.push(listener);
		}

		Ok(listeners)
	}
}

impl<T> AsyncPool<T> {
	fn empty() -> Self {
		Self { handles: Vec::new() }
	}

	/// Get a [AsyncStream] behind a [MutexGuard] for use in a [AsyncStream::call]
	/// Will wait (async) if all connections are locked until one becomes available
	async fn get(&self) -> MutexGuard<T> {
		let iter = self.handles.iter().map(|h| {
			let l = h.lock();
			Box::pin(l)
		});

		// find a unlock stream
		let (stream, _, _) = futures::future::select_all(iter).await;

		stream
	}
}

#[cfg(test)]
mod test {
	use super::*;

	// constructor for basic i32 with repeating 0 values for testing
	impl AsyncPool<i32> {
		fn test(count: usize) -> Self {
			Self {
				handles: std::iter::repeat(0)
					.take(count)
					.map(Mutex::new)
					.collect(),
			}
		}
	}

	// tests if basic pool works with still-available connections
	#[tokio::test]
	async fn test_async_pool_available() {
		let pool = AsyncPool::test(2);

		let first = pool.get().await;
		assert_eq!(*first, 0);
		let second = pool.get().await;
		assert_eq!(*second, 0);

		// this would hang (wait) if we didn't drop one of the previous ones
		drop(first);
		let third = pool.get().await;
		assert_eq!(*third, 0);
	}
}

use std::sync::Arc;

use nix::sys::time::TimeVal;
use tokio::sync::{Mutex, MutexGuard, RwLock};

use super::{AsyncListener, AsyncStream, IOError, SocketAddress};

/// Socket Pool Errors
#[derive(Debug)]
pub enum PoolError {
	/// No addresses were provided in the pool constructor
	NoAddressesSpecified,
}

/// Generic Async pool using tokio Mutex
#[derive(Debug)]
struct AsyncPool<T> {
	handles: Vec<Mutex<T>>,
}

/// Specialization of `AsyncPool` with `AsyncStream` and connection/liste logic.
#[derive(Debug)]
pub struct AsyncStreamPool {
	addresses: Vec<SocketAddress>, // local copy used for `listen` only TODO: refactor listeners out of pool
	pool: AsyncPool<AsyncStream>,
}

/// Helper type to wrap `AsyncStreamPool` in `Arc` and `RwLock`. Used to allow multiple processors to run across IO
/// await points without locking the whole set.
pub type SharedAsyncStreamPool = Arc<RwLock<AsyncStreamPool>>;

impl AsyncStreamPool {
	/// Create a new `AsyncStreamPool` which will contain all the known addresses but no connections yet.
	/// Includes the connect timeout which gets used in case `get` gets called.
	pub fn new(
		addresses: impl IntoIterator<Item = SocketAddress>,
		timeout: TimeVal,
	) -> Self {
		let addresses: Vec<SocketAddress> = addresses.into_iter().collect();

		// TODO: DEBUG remove
		for addr in &addresses {
			println!("pool address: {:?}", addr.debug_info());
		}

		let streams: Vec<AsyncStream> =
			addresses.iter().map(|a| AsyncStream::new(a, timeout)).collect();

		let pool = AsyncPool::from(streams);

		Self { addresses, pool }
	}

	/// Helper function to get the Arc and Mutex wrapping
	#[must_use]
	pub fn shared(self) -> SharedAsyncStreamPool {
		Arc::new(RwLock::new(self))
	}

	/// Returns number of expected sockets/connections
	#[must_use]
	pub fn len(&self) -> usize {
		self.addresses.len()
	}

	/// Returns true if pool is empty
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Gets the next available `AsyncStream` behind a `MutexGuard`
	pub async fn get(&self) -> MutexGuard<AsyncStream> {
		self.pool.get().await
	}

	/// Create a new pool by listening new connection on all the addresses
	pub fn listen(self) -> Result<Vec<AsyncListener>, IOError> {
		let mut listeners = Vec::new();

		for addr in self.addresses {
			let listener = AsyncListener::listen(&addr)?;

			listeners.push(listener);
		}

		Ok(listeners)
	}
}

impl<T> AsyncPool<T> {
	/// Get a `AsyncStream` behind a `MutexGuard` for use in a `AsyncStream::call`
	/// Will wait (async) if all connections are locked until one becomes available
	async fn get(&self) -> MutexGuard<T> {
		// TODO: make this into an error
		if self.handles.is_empty() {
			panic!("empty handles in AsyncPool. Bad init?");
		}

		let iter = self.handles.iter().map(|h| {
			let l = h.lock();
			Box::pin(l)
		});

		// find a unlock stream
		let (stream, _, _) = futures::future::select_all(iter).await;

		stream
	}
}

impl<T> From<Vec<T>> for AsyncPool<T> {
	fn from(value: Vec<T>) -> Self {
		let handles: Vec<Mutex<T>> =
			value.into_iter().map(|val| Mutex::new(val)).collect();

		Self { handles }
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

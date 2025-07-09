use std::{path::Path, sync::Arc};

use nix::sys::{socket::UnixAddr, time::TimeVal};
use tokio::sync::{Mutex, MutexGuard, RwLock};

use super::{AsyncListener, AsyncStream, IOError, SocketAddress};

/// Socket Pool Errors
#[derive(Debug)]
pub enum PoolError {
	/// No addresses were provided in the pool constructor
	NoAddressesSpecified,
	/// Invalid source address specified for `next_address` call, usually due to `path` missing in `UnixSock`.
	InvalidSourceAddress,
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
	timeout: TimeVal,
}

/// Helper type to wrap `AsyncStreamPool` in `Arc` and `RwLock`. Used to allow multiple processors to run across IO
/// await points without locking the whole set.
pub type SharedAsyncStreamPool = Arc<RwLock<AsyncStreamPool>>;

impl AsyncStreamPool {
	/// Create a new `AsyncStreamPool` with given starting `SocketAddress`, timout and number of addresses to populate.
	pub fn new(
		start_address: SocketAddress,
		timeout: TimeVal,
		mut count: u32,
	) -> Result<Self, IOError> {
		eprintln!(
			"AsyncStreamPool start address: {:?}",
			start_address.debug_info()
		);

		let mut addresses = Vec::new();
		let mut addr = start_address;
		while count > 0 {
			addresses.push(addr.clone());
			count -= 1;

			if count == 0 {
				break; // early break to prevent needless address creation
			}
			addr = addr.next_address()?;
		}

		Ok(Self::with_addresses(addresses, timeout))
	}

	/// Create a new `AsyncStreamPool` which will contain all the provided addresses but no connections yet.
	/// Includes the connect timeout which gets used in case `get` gets called.
	#[must_use]
	fn with_addresses(
		addresses: impl IntoIterator<Item = SocketAddress>,
		timeout: TimeVal,
	) -> Self {
		let addresses: Vec<SocketAddress> = addresses.into_iter().collect();

		let streams: Vec<AsyncStream> =
			addresses.iter().map(|a| AsyncStream::new(a, timeout)).collect();

		let pool = AsyncPool::from(streams);

		Self { addresses, pool, timeout }
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
	pub fn listen(&self) -> Result<Vec<AsyncListener>, IOError> {
		let mut listeners = Vec::new();

		for addr in &self.addresses {
			let listener = AsyncListener::listen(addr)?;

			listeners.push(listener);
		}

		Ok(listeners)
	}

	/// Expands the pool with new addresses using `SocketAddress::next_address`
	pub fn expand_to(&mut self, size: u32) -> Result<(), IOError> {
		eprintln!("expanding async pool to {size}");
		let size = size as usize;

		if let Some(last_address) = self.addresses.last().cloned() {
			let mut next = last_address;
			let count = self.addresses.len();
			for _ in count..size {
				next = next.next_address()?;

				self.pool.push(AsyncStream::new(&next, self.timeout));
				self.addresses.push(next.clone());
			}
		}

		Ok(())
	}

	/// Listen to new connections on added sockets on top of existing listeners, returning the list of new `AsyncListener`
	pub fn listen_to(
		&mut self,
		size: u32,
	) -> Result<Vec<AsyncListener>, IOError> {
		eprintln!("listening async pool to {size}");
		let size = size as usize;
		let mut listeners = Vec::new();

		if let Some(last_address) = self.addresses.last().cloned() {
			let mut next = last_address;
			let count = self.addresses.len();
			for _ in count..size {
				next = next.next_address()?;
				eprintln!("adding listener on {}", next.debug_info());

				self.addresses.push(next.clone());
				let listener = AsyncListener::listen(&next)?;

				listeners.push(listener);
			}
		}

		Ok(listeners)
	}
}

impl<T> AsyncPool<T> {
	/// Get a `AsyncStream` behind a `MutexGuard` for use in a `AsyncStream::call`
	/// Will wait (async) if all connections are locked until one becomes available
	async fn get(&self) -> MutexGuard<T> {
		// TODO: make this into an error
		assert!(
			!self.handles.is_empty(),
			"empty handles in AsyncPool. Bad init?"
		);

		let iter = self.handles.iter().map(|h| {
			let l = h.lock();
			Box::pin(l)
		});

		// find a unlock stream
		let (stream, _, _) = futures::future::select_all(iter).await;

		stream
	}

	fn push(&mut self, value: T) {
		self.handles.push(Mutex::new(value));
	}
}

impl<T> From<Vec<T>> for AsyncPool<T> {
	fn from(value: Vec<T>) -> Self {
		let handles: Vec<Mutex<T>> =
			value.into_iter().map(|val| Mutex::new(val)).collect();

		Self { handles }
	}
}

/// Provide the "next" usock path. Given a `"*_X"` where X is a number, this function
/// will return `"*_X+1"`. If there is no `"_X"` suffix a `"_0"` will be appended instead.
fn next_usock_path(path: &Path) -> Result<String, IOError> {
	let path =
		path.as_os_str().to_str().ok_or(IOError::ConnectAddressInvalid)?;
	if let Some(underscore_index) = path.rfind('_') {
		let num_str = &path[underscore_index + 1..];
		let num = num_str.parse::<usize>();
		Ok(match num {
			Ok(index) => {
				format!("{}_{}", &path[0..underscore_index], index + 1)
			}
			Err(_) => format!("{path}_0"), // non-numerical _X, just add _0
		})
	} else {
		Ok(format!("{path}_0"))
	}
}

impl SocketAddress {
	/// Creates and returns the "following" `SocketAddress`. In case of VSOCK we increment the port from the source by 1.
	/// In case of USOCK we increment the postfix of the path if present, or add a `"_0"` at the end.
	///
	/// This is mostly used by the `AsyncSocketPool`.
	pub(crate) fn next_address(&self) -> Result<Self, IOError> {
		match self {
			Self::Unix(usock) => match usock.path() {
				Some(path) => {
					let path: &str = &next_usock_path(path)?;
					let addr = UnixAddr::new(path)?;
					Ok(Self::Unix(addr))
				}
				None => {
					Err(IOError::PoolError(PoolError::InvalidSourceAddress))
				}
			},
			#[cfg(feature = "vm")]
			Self::Vsock(vsock) => Ok(Self::new_vsock(
				vsock.cid(),
				vsock.port() + 1,
				super::stream::vsock_svm_flags(*vsock),
			)),
		}
	}
}

#[cfg(test)]
mod test {
	use std::path::PathBuf;

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

	#[test]
	fn next_usock_path_works() {
		assert_eq!(
			next_usock_path(&PathBuf::from("basic")).unwrap(),
			"basic_0"
		);
		assert_eq!(next_usock_path(&PathBuf::from("")).unwrap(), "_0");
		assert_eq!(
			next_usock_path(&PathBuf::from("with_underscore_elsewhere"))
				.unwrap(),
			"with_underscore_elsewhere_0"
		);
		assert_eq!(
			next_usock_path(&PathBuf::from("with_underscore_at_end_")).unwrap(),
			"with_underscore_at_end__0"
		);
		assert_eq!(
			next_usock_path(&PathBuf::from("good_num_2")).unwrap(),
			"good_num_3"
		);
		assert_eq!(
			next_usock_path(&PathBuf::from("good_num_34")).unwrap(),
			"good_num_35"
		);
		assert_eq!(
			next_usock_path(&PathBuf::from("good_num_999")).unwrap(),
			"good_num_1000"
		);
	}
}

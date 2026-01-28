use std::{path::Path, sync::Arc};

use nix::sys::socket::UnixAddr;
use tokio::sync::{Mutex, MutexGuard, RwLock};

use super::{IOError, Listener, SocketAddress, Stream};

/// Socket Pool Errors
#[derive(Debug)]
pub enum PoolError {
	/// No addresses were provided in the pool constructor
	NoAddressesSpecified,
	/// Invalid source address specified for `next_address` call, usually due to `path` missing in `UnixSock`.
	InvalidSourceAddress,
}

/// `MutexGuard` newtype to allow logging of releases.
#[derive(Debug)]
pub struct PoolGuard<'item> {
	value: MutexGuard<'item, Stream>,
}

/// Specialization of `AsyncPool` with `Stream` and connection/list logic.
#[derive(Debug)]
pub struct StreamPool {
	addresses: Vec<SocketAddress>, // local copy used for `listen` only TODO: refactor listeners out of pool
	handles: Vec<Mutex<Stream>>,
}

/// Helper type to wrap `StreamPool` in `Arc` and `RwLock`. Used to allow multiple processors to run across IO
/// await points without locking the whole set.
/// Ensures that `Stream` instances get reset when returned to the pool.
pub type SharedStreamPool = Arc<RwLock<StreamPool>>;

impl Drop for PoolGuard<'_> {
	fn drop(&mut self) {
		// ensure we clean up
		self.value.reset();
	}
}

impl<'item> PoolGuard<'item> {
	/// Create a new `PoolGuard` from the given `MutexGuard` and `index` value.
	#[must_use]
	pub fn new(value: MutexGuard<'item, Stream>) -> Self {
		Self { value }
	}
}

impl std::ops::Deref for PoolGuard<'_> {
	type Target = Stream;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl std::ops::DerefMut for PoolGuard<'_> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.value
	}
}

impl StreamPool {
	/// Create a new `StreamPool` with given starting `SocketAddress`, timeout and number of addresses to populate.
	pub fn new(
		start_address: SocketAddress,
		mut count: u8,
	) -> Result<Self, IOError> {
		if count == 0 {
			return Err(IOError::PoolError(PoolError::NoAddressesSpecified));
		}

		println!("StreamPool start address: {start_address}");

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

		Ok(Self::with_addresses(addresses))
	}

	/// Create a single address pool.
	pub fn single(address: SocketAddress) -> Result<Self, IOError> {
		Self::new(address, 1)
	}

	/// Create a new `StreamPool` which will contain all the provided addresses but no connections yet.
	#[must_use]
	fn with_addresses(
		addresses: impl IntoIterator<Item = SocketAddress>,
	) -> Self {
		let addresses: Vec<SocketAddress> = addresses.into_iter().collect();

		let streams: Vec<Stream> = addresses.iter().map(Stream::new).collect();

		let handles = streams.into_iter().map(Mutex::new).collect();

		Self { addresses, handles }
	}

	/// Helper function to get the Arc and Mutex wrapping
	#[must_use]
	pub fn shared(self) -> SharedStreamPool {
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

	/// Gets the next available `Stream` behind a `MutexGuard`
	///
	/// # Panics
	/// Panics if list of addresses provided was empty.
	pub async fn get(&self) -> PoolGuard {
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
		let (guard, _, _) = futures::future::select_all(iter).await;

		PoolGuard::new(guard)
	}

	/// Create a new pool by listening for new connection on all the addresses
	pub fn listen(&self) -> Result<Vec<Listener>, IOError> {
		let mut listeners = Vec::new();

		for addr in &self.addresses {
			let listener = Listener::listen(addr)?;

			listeners.push(listener);
		}

		Ok(listeners)
	}

	/// Expands the pool with new addresses using `SocketAddress::next_address`
	pub fn expand_to(&mut self, size: u8) -> Result<(), IOError> {
		println!("StreamPool: expanding async pool to {size}");
		let size = size as usize;

		if let Some(last_address) = self.addresses.last().cloned() {
			let mut next = last_address;
			let count = self.addresses.len();
			for _ in count..size {
				next = next.next_address()?;

				self.handles.push(Mutex::new(Stream::new(&next)));
				self.addresses.push(next.clone());
			}
		}

		Ok(())
	}

	/// Listen to new connections on added sockets on top of existing listeners, returning the list of new `Listener`
	pub fn listen_to(&mut self, size: u8) -> Result<Vec<Listener>, IOError> {
		println!("StreamPool: listening async pool to {size}");
		let size = size as usize;
		let mut listeners = Vec::new();

		if let Some(last_address) = self.addresses.last().cloned() {
			let mut next = last_address;
			let count = self.addresses.len();
			for _ in count..size {
				next = next.next_address()?;

				self.addresses.push(next.clone());
				let listener = Listener::listen(&next)?;

				listeners.push(listener);
			}
		}

		Ok(listeners)
	}

	/// Deconstruct the pool into all contained `Stream` objects.
	pub fn to_streams(self) -> Vec<Stream> {
		self.handles.into_iter().map(|m| m.into_inner()).collect()
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
	/// This is mostly used by the `SocketPool`.
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
				super::vsock_svm_flags(*vsock),
			)),
		}
	}
}

#[cfg(test)]
mod test {
	use std::path::PathBuf;

	use super::*;

	// tests if basic pool works with still-available connections
	#[tokio::test]
	async fn test_async_pool_available() {
		let start_addr = SocketAddress::new_unix("/tmp/never.sock");
		let pool = StreamPool::new(start_addr, 2).unwrap();

		let first = pool.get().await;
		let second = pool.get().await;

		// this would hang (wait) if we didn't drop one of the previous ones
		drop(first);
		let third = pool.get().await;

		let result = tokio::time::timeout(
			std::time::Duration::from_millis(200),
			async {
				let _fourth = pool.get().await;
			},
		)
		.await;
		drop(third);
		drop(second);

		assert!(result.is_err()); // Elapsed is not constructible
	}

	// We need to ensure that Socket stream is ALWAYS reset when it returns to the pool, no matter
	// if we had an error, panic or any kind of other escape-hatch situation (e.g. task cancel).
	#[tokio::test]
	async fn test_pool_guard_hatch() {
		let server_addr =
			SocketAddress::new_unix("/tmp/test_pool_guard_hatch.sock");
		let server = Listener::listen(&server_addr).unwrap();

		let server_task = tokio::task::spawn(async move {
			let _stream = server.accept().await.unwrap();
			// give the call time to connect and hang
			tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
		});

		let pool = StreamPool::new(server_addr, 1).unwrap().shared();
		let pool_clone = pool.clone();

		// fire of a call on the stream that we will cancel before timeout is handled
		let client_task = tokio::task::spawn(async move {
			let borrowed_pool = pool_clone.read().await;
			let mut stream = borrowed_pool.get().await;
			let _ = stream.call(&[1]).await;
		});

		// give the call time to connect and hang on send
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;

		// escape-hatch the task away
		client_task.abort();

		// check if the stream has been returned to the pool
		let borrowed_pool = pool.read().await;
		let stream = borrowed_pool.get().await;

		// checkk if the stream has been reset properly
		assert!(!stream.is_connected());

		// clean up the server
		server_task.abort();
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

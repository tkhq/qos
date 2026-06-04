//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod host_bridge;
mod pool;
mod stream;
use std::{
	net::{IpAddr, SocketAddr},
	path::Path,
};

pub use host_bridge::*;
pub use pool::*;
pub use stream::*;

#[cfg(not(target_os = "macos"))]
use nix::sys::socket::VsockAddr;
use nix::sys::socket::{AddressFamily, SockaddrLike, UnixAddr};
pub use nix::sys::time::{TimeVal, TimeValLike};

/// QOS I/O error
#[derive(Debug)]
pub enum IOError {
	/// `std::io::Error` wrapper.
	StdIoError(std::io::Error),
	/// `nix::Error` wrapper.
	NixError(nix::Error),
	/// Arithmetic operation saturated.
	ArithmeticSaturation,
	/// Unknown error.
	UnknownError,
	/// Stream was not connected when expected to be connected.
	DisconnectedStream,
	/// Connect address invalid
	ConnectAddressInvalid,
	/// Timed out while claling `connect` over a socket.
	ConnectTimeout,
	/// Timed out while calling `recv` over a socket.
	RecvTimeout,
	/// The `recv` system call was interrupted while receiving over a socket.
	RecvInterrupted,
	/// Receive was called on a closed connection.
	RecvConnectionClosed,
	/// Client could not connect at the given socket address.
	ConnectNixError(nix::Error),
	/// A nix error encountered while calling `send`.
	SendNixError(nix::Error),
	/// A nix error encountered while calling `recv`.
	RecvNixError(nix::Error),
	/// Reading the response size resulted in a size which exceeds the max payload size.
	OversizedPayload(usize),
	/// An async socket pool error during pool operations.
	PoolError(PoolError),
	/// Proxy connection unexpected, e.g. connected after accepting
	UnexpectedProxyConnection,
	/// Proxy connection expected, e.g. not connected after processing
	MissingProxyConnection,
}

impl From<nix::Error> for IOError {
	fn from(err: nix::Error) -> Self {
		Self::NixError(err)
	}
}

impl From<std::io::Error> for IOError {
	fn from(err: std::io::Error) -> Self {
		Self::StdIoError(err)
	}
}

impl From<PoolError> for IOError {
	fn from(value: PoolError) -> Self {
		Self::PoolError(value)
	}
}
/// Socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketAddress {
	/// VSOCK address.
	#[cfg(not(target_os = "macos"))]
	Vsock(VsockAddr),
	/// Unix address.
	Unix(UnixAddr),
	/// TCP address.
	Tcp(SocketAddr),
}

/// VSOCK flag for talking to host if we deploy multiple enclave "horizontally" on the same VM.
pub const VMADDR_FLAG_TO_HOST: u8 = 0x01;
/// Don't specify any flags for a VSOCK.
pub const VMADDR_NO_FLAGS: u8 = 0x00;

impl SocketAddress {
	/// Create a new Unix socket.
	///
	/// # Panics
	///
	/// Panics if `nix::sys::socket::UnixAddr::new` panics.
	#[must_use]
	pub fn new_unix<P: AsRef<Path>>(path: P) -> Self {
		let addr = UnixAddr::new(path.as_ref()).unwrap();
		Self::Unix(addr)
	}

	/// Create a new TCP socket.
	#[must_use]
	pub fn new_tcp(ip: IpAddr, port: u16) -> Self {
		Self::Tcp(SocketAddr::new(ip, port))
	}

	/// Create a new Vsock socket.
	///
	/// For flags see: [Add flags field in the vsock address](<https://lkml.org/lkml/2020/12/11/249>).
	#[cfg(not(target_os = "macos"))]
	#[must_use]
	pub fn new_vsock(cid: u32, port: u32, flags: u8) -> Self {
		Self::Vsock(Self::new_vsock_raw(cid, port, flags))
	}

	/// Create a new raw `VsockAddr`.
	///
	/// For flags see: [Add flags field in the vsock address](<https://lkml.org/lkml/2020/12/11/249>).
	///
	/// # Panics
	///
	/// Panics if `VsockAddr::from_raw` cannot construct a valid address from
	/// the provided fields (should be unreachable for well-formed `cid` /
	/// `port` / `flags`).
	#[cfg(not(target_os = "macos"))]
	#[allow(unsafe_code)]
	#[must_use]
	pub fn new_vsock_raw(cid: u32, port: u32, flags: u8) -> VsockAddr {
		let vsock_addr = SockAddrVm {
			svm_family: AddressFamily::Vsock as libc::sa_family_t,
			svm_reserved1: 0,
			svm_cid: cid,
			svm_port: port,
			svm_flags: flags,
			svm_zero: [0; 3],
		};
		let vsock_addr_len = libc::socklen_t::try_from(size_of::<SockAddrVm>())
			.expect("SockAddrVm size fits in socklen_t");
		// SAFETY: `vsock_addr` is a valid, fully-initialized `SockAddrVm`
		// (the layout-compatible struct corresponding to a vsock sockaddr),
		// and we pass the matching size. `VsockAddr::from_raw` returns
		// `Some` iff the address family is `AF_VSOCK`, which we set above.
		unsafe {
			VsockAddr::from_raw(
				std::ptr::from_ref(&vsock_addr).cast::<libc::sockaddr>(),
				Some(vsock_addr_len),
			)
			.expect("constructed vsock sockaddr is valid")
		}
	}

	/// Get the `AddressFamily` of the socket.
	#[must_use]
	pub fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(_) => AddressFamily::Vsock,
			Self::Unix(_) => AddressFamily::Unix,
			Self::Tcp(addr) => {
				if addr.is_ipv4() {
					AddressFamily::Inet
				} else {
					AddressFamily::Inet6
				}
			}
		}
	}

	/// Convenience method for accessing the wrapped address.
	///
	/// # Panics
	///
	/// Panics for TCP addresses, which are handled by Tokio directly and do
	/// not have a nix [`SockaddrLike`] wrapper in this API.
	#[must_use]
	pub fn addr(&self) -> Box<dyn SockaddrLike> {
		match *self {
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(vsa) => Box::new(vsa),
			Self::Unix(ua) => Box::new(ua),
			Self::Tcp(_) => {
				panic!("tcp addresses do not expose a nix sockaddr accessor")
			}
		}
	}

	/// Returns the `UnixAddr` if this is a USOCK `SocketAddress`, panics otherwise
	///
	/// # Panics
	///
	/// Panics if the underlying `SocketAddress` is not a `Unix` variant.
	#[must_use]
	pub fn usock(&self) -> &UnixAddr {
		match self {
			Self::Unix(usock) => usock,
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(_) => panic!("invalid socket address requested"),
			Self::Tcp(_) => panic!("invalid socket address requested"),
		}
	}

	/// Returns the `VsockAddr` if this is a VSOCK `SocketAddress`, panics otherwise
	///
	/// # Panics
	///
	/// Panics if the underlying `SocketAddress` is not a `Vsock` variant.
	#[must_use]
	#[cfg(not(target_os = "macos"))]
	pub fn vsock(&self) -> &VsockAddr {
		match self {
			Self::Vsock(vsock) => vsock,
			Self::Unix(_) | Self::Tcp(_) => {
				panic!("invalid socket address requested")
			}
		}
	}

	/// Returns the TCP address if this is a TCP `SocketAddress`, panics otherwise.
	///
	/// # Panics
	///
	/// Panics if the underlying `SocketAddress` is not a `Tcp` variant.
	#[must_use]
	pub fn tcp(&self) -> SocketAddr {
		match self {
			Self::Tcp(addr) => *addr,
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(_) | Self::Unix(_) => {
				panic!("invalid socket address requested")
			}
			#[cfg(target_os = "macos")]
			Self::Unix(_) => panic!("invalid socket address requested"),
		}
	}

	/// Returns a new `SocketAddress` depending on socket type:
	/// If VSOCK, the same CID is used with the provided port.
	/// If USOCK, the "<port>.appsock" suffix is added.
	///
	/// # Errors
	///
	/// Returns [`IOError::ConnectAddressInvalid`] if the Unix socket path
	/// cannot be resolved.
	#[allow(unused)]
	pub fn with_port(&self, port: u16) -> Result<SocketAddress, IOError> {
		match self {
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(vsa) => Ok(Self::new_vsock(
				vsa.cid(),
				port.into(),
				vsock_svm_flags(*vsa),
			)),
			Self::Unix(ua) => {
				let mut path = ua
					.path()
					.ok_or(IOError::ConnectAddressInvalid)?
					.as_os_str()
					.to_owned();

				path.push(format!(".{port}.appsock"));

				Ok(Self::new_unix(
					path.to_str().ok_or(IOError::ConnectAddressInvalid)?,
				))
			}
			Self::Tcp(addr) => Ok(Self::Tcp(SocketAddr::new(addr.ip(), port))),
		}
	}
}

impl std::fmt::Display for SocketAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			#[cfg(not(target_os = "macos"))]
			Self::Vsock(vsock) => {
				write!(f, "vsock cid: {} port: {}", vsock.cid(), vsock.port())
			}
			Self::Unix(usock) => {
				write!(
					f,
					"usock path: {}",
					usock
						.path()
						.unwrap_or(&std::path::PathBuf::from("unknown/error"))
						.as_os_str()
						.to_str()
						.unwrap_or("unable to procure")
				)
			}
			Self::Tcp(addr) => {
				write!(f, "tcp addr: {addr}")
			}
		}
	}
}

/// Extract `svm_flags` field value from existing VSOCK.
#[cfg(not(target_os = "macos"))]
#[allow(unsafe_code)]
#[must_use]
pub fn vsock_svm_flags(vsock: VsockAddr) -> u8 {
	// SAFETY: `SockAddrVm` is `repr(C)` and laid out identically to the
	// kernel `sockaddr_vm` structure that backs `nix`'s `VsockAddr`, so the
	// reinterpret is well-defined for the purpose of reading the
	// `svm_flags` byte.
	unsafe {
		let cast: SockAddrVm = std::mem::transmute(vsock);
		cast.svm_flags
	}
}

#[cfg(not(target_os = "macos"))]
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct SockAddrVm {
	svm_family: libc::sa_family_t,
	svm_reserved1: libc::c_ushort,
	svm_port: libc::c_uint,
	svm_cid: libc::c_uint,
	// Field added [here](https://github.com/torvalds/linux/commit/3a9c049a81f6bd7c78436d7f85f8a7b97b0821e6)
	// but not yet in a version of libc we can use.
	svm_flags: u8,
	svm_zero: [u8; 3],
}

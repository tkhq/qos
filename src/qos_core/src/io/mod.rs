//! Abstractions for low level I/O.
//!
//! NOTE TO MAINTAINERS: Interaction with any sys calls should be contained
//! within this module.

mod pool;
mod stream;
pub use pool::*;
pub use stream::*;

#[cfg(feature = "vm")]
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
	/// A async socket pool error during pool operations.
	PoolError(PoolError),
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
	#[cfg(feature = "vm")]
	Vsock(VsockAddr),
	/// Unix address.
	Unix(UnixAddr),
}

/// VSOCK flag for talking to host.
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
	pub fn new_unix(path: &str) -> Self {
		let addr = UnixAddr::new(path).unwrap();
		Self::Unix(addr)
	}

	/// Create a new Vsock socket.
	///
	/// For flags see: [Add flags field in the vsock address](<https://lkml.org/lkml/2020/12/11/249>).
	#[cfg(feature = "vm")]
	pub fn new_vsock(cid: u32, port: u32, flags: u8) -> Self {
		Self::Vsock(Self::new_vsock_raw(cid, port, flags))
	}

	/// Create a new raw VsockAddr.
	///
	/// For flags see: [Add flags field in the vsock address](<https://lkml.org/lkml/2020/12/11/249>).
	#[cfg(feature = "vm")]
	#[allow(unsafe_code)]
	pub fn new_vsock_raw(cid: u32, port: u32, flags: u8) -> VsockAddr {
		let vsock_addr = SockAddrVm {
			svm_family: AddressFamily::Vsock as libc::sa_family_t,
			svm_reserved1: 0,
			svm_cid: cid,
			svm_port: port,
			svm_flags: flags,
			svm_zero: [0; 3],
		};
		let vsock_addr_len = size_of::<SockAddrVm>() as libc::socklen_t;
		let addr = unsafe {
			VsockAddr::from_raw(
				&vsock_addr as *const SockAddrVm as *const libc::sockaddr,
				Some(vsock_addr_len),
			)
			.unwrap()
		};
		addr
	}

	/// Get the `AddressFamily` of the socket.
	#[must_use]
	pub fn family(&self) -> AddressFamily {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(_) => AddressFamily::Vsock,
			Self::Unix(_) => AddressFamily::Unix,
		}
	}

	/// Convenience method for accessing the wrapped address
	#[must_use]
	pub fn addr(&self) -> Box<dyn SockaddrLike> {
		match *self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsa) => Box::new(vsa),
			Self::Unix(ua) => Box::new(ua),
		}
	}

	/// Shows socket debug info
	#[must_use]
	pub fn debug_info(&self) -> String {
		match self {
			#[cfg(feature = "vm")]
			Self::Vsock(vsock) => {
				format!("vsock cid: {} port: {}", vsock.cid(), vsock.port())
			}
			Self::Unix(usock) => {
				format!(
					"usock path: {}",
					usock
						.path()
						.unwrap_or(&std::path::PathBuf::from("unknown/error"))
						.as_os_str()
						.to_str()
						.unwrap_or("unable to procure")
				)
			}
		}
	}

	/// Returns the `UnixAddr` if this is a USOCK `SocketAddress`, panics otherwise
	#[must_use]
	pub fn usock(&self) -> &UnixAddr {
		match self {
			Self::Unix(usock) => usock,
			#[cfg(feature = "vm")]
			_ => panic!("invalid socket address requested"),
		}
	}

	/// Returns the `UnixAddr` if this is a USOCK `SocketAddress`, panics otherwise
	#[must_use]
	#[cfg(feature = "vm")]
	pub fn vsock(&self) -> &VsockAddr {
		match self {
			Self::Vsock(vsock) => vsock,
			_ => panic!("invalid socket address requested"),
		}
	}
}

/// Extract svm_flags field value from existing VSOCK.
#[cfg(feature = "vm")]
#[allow(unsafe_code)]
pub fn vsock_svm_flags(vsock: VsockAddr) -> u8 {
	unsafe {
		let cast: SockAddrVm = std::mem::transmute(vsock);
		cast.svm_flags
	}
}

#[cfg(feature = "vm")]
#[repr(C)]
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

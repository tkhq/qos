//! Utilities for reading and writing buffers against raw file descriptors.
// This code is largely adapted from Veracruz - zeke

use std::{mem::size_of, os::unix::io::RawFd, vec::Vec};

use nix::sys::socket::{recv, send, MsgFlags};

use super::IOError;

// TODO: test payloads that are u64::MAX length

/// Send `buf`, a buffer of data to`fd`, a file descriptor.
pub fn send_buf(fd: RawFd, buf: &Vec<u8>) -> Result<(), IOError> {
	let len = buf.len();

	// First, send the length of the buffer
	{
		let len_buf: [u8; size_of::<u64>()] = (len as u64).to_le_bytes();

		// First, sent the length of the buffer
		let mut sent_bytes = 0;
		while sent_bytes < len_buf.len() {
			sent_bytes += match send(
				fd,
				&len_buf[sent_bytes..len_buf.len()],
				MsgFlags::empty(),
			) {
				Ok(size) => size,
				// Err(nix::Error::EINTR) => 0,
				Err(err) => return Err(IOError::NixError(err)),
			};
		}
	}

	// Then, send the contents of the buffer
	{
		let mut sent_bytes = 0;
		while sent_bytes < len {
			sent_bytes +=
				match send(fd, &buf[sent_bytes..len], MsgFlags::empty()) {
					Ok(size) => size,
					Err(nix::Error::EINTR) => 0,
					Err(err) => return Err(IOError::NixError(err)),
				}
		}
	}

	Ok(())
}

/// Receive a buffer of data at `fd`, a file descriptor.
pub fn recv_buf(fd: RawFd) -> Result<Vec<u8>, IOError> {
	// First, read the length
	let length: usize = {
		{
			let mut buf = [0u8; size_of::<u64>()];
			let len = buf.len();
			std::debug_assert!(buf.len() == 8);

			let mut received_bytes = 0;
			while received_bytes < len {
				received_bytes += match recv(
					fd,
					&mut buf[received_bytes..len],
					MsgFlags::empty(),
				) {
					Ok(size) => size,
					// https://stackoverflow.com/questions/1674162/how-to-handle-eintr-interrupted-system-call#1674348
					// Not necessarily actually an error, just the syscall was
					// interrupted while in progress.
					Err(nix::Error::EINTR) => 0,
					Err(err) => return Err(IOError::NixError(err)),
				};
			}

			u64::from_le_bytes(buf)
				.try_into()
				// Should only be possible if we are on 32bit architecture
				.map_err(|_| IOError::ArithmeticSaturation)?
		}
	};

	// Then, read the buffer
	let mut buf = Vec::with_capacity(length);
	{
		let mut received_bytes = 0;
		while received_bytes < length {
			received_bytes += match recv(
				fd,
				&mut buf[received_bytes..length],
				MsgFlags::empty(),
			) {
				Ok(size) => size,
				Err(nix::Error::EINTR) => 0,
				Err(err) => return Err(IOError::NixError(err)),
			}
		}
	}

	Ok(buf)
}

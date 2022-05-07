// use std::os::unix::io::AsRawFd;

// use crate::io::{self, vsock::VsockSocket};

// pub struct ClientServer {
// 	vsock: VsockSocket,
// }

// impl ClientServer {
// 	pub fn try_connect(cid: u32, port: u32) -> Result<Self, io::IOError> {
// 		Ok(Self {
// 			vsock: VsockSocket::try_connect(cid, port)
// 				.map_err(|e| io::IOError::NixError(e))?,
// 		})
// 	}

// 	pub fn send_buf(&self, buf: &Vec<u8>) -> Result<(), io::IOError> {
// 		io::raw_fd::send_buf(self.vsock.as_raw_fd(), buf)
// 	}

// 	pub fn recv_buf(&self) -> Result<Vec<u8>, io::IOError> {
// 		io::raw_fd::recv_buf(self.vsock.as_raw_fd())
// 	}

// 	pub fn try_serve(cid: u32, port: u32) -> Result<(), io::IOError> {
// 		let server = Self {
// 			vsock: VsockSocket::try_listen(cid, port)
// 				.map_err(|e| io::IOError::NixError(e))?,
// 		};

// 		loop {
// 			if let Ok(mut req) = server.recv_buf() {
// 				println!("APECLAVE received {:#?}", req);

// 				// Extend the request to ack we recieved
// 				req.extend(b" - signed by APECLAVE".iter());

// 				// Echo back, but with the extended request
// 				server.send_buf(&req)?;
// 			}
// 		}

// 		// Ok(server)
// 	}
// }

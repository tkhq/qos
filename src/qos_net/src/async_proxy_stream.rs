//! Contains an abstraction to implement the standard library's Read/Write
//! traits with `ProxyMsg`s.
use std::{io::ErrorKind, pin::Pin, task::Poll};

use borsh::BorshDeserialize;
use qos_core::io::AsyncStream;
use tokio::{
	io::{AsyncRead, AsyncWrite},
	sync::MutexGuard,
};

use crate::{error::QosNetError, proxy_msg::ProxyMsg};

/// Struct representing a remote connection
/// This is going to be used by enclaves, on the other side of a socket
/// and plugged into the tokio-rustls via the AsyncWrite and AsyncRead traits
pub struct AsyncProxyStream<'pool> {
	/// AsyncStream we hold for this connection
	stream: MutexGuard<'pool, AsyncStream>,
	/// StreamState for when we're in request
	stream_state: StreamState,
	/// Sending out request bytes still needed to be pushed out
	request_bytes: Vec<u8>,
	/// Receiving data size (from header)
	response_size: u64,
	/// Receiving data for running request
	response_bytes: Vec<u8>,
	/// Once a connection is established (successful `ConnectByName` or
	/// ConnectByIp request), this connection ID is set the u32 in
	/// `ConnectResponse`.
	pub connection_id: u32,
	/// The remote host this connection points to
	pub remote_hostname: Option<String>,
	/// The remote IP this connection points to
	pub remote_ip: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
	None,
	Requesting,
	Receiving, // expected size of raw msg (if 0, no header processed yet)
}

impl<'pool> AsyncProxyStream<'pool> {
	/// Create a new AsyncProxyStream by targeting a hostname
	///
	/// # Arguments
	///
	/// * `pool` - the AsyncStreamPool to pick a USOCK/VSOCK out of
	///   to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `hostname` - the hostname to connect to (the remote qos_net proxy will
	///   resolve DNS)
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	/// * `dns_resolvers` - array of resolvers to use to resolve `hostname`
	/// * `dns_port` - DNS port to use while resolving DNS (typically: 53 or
	///   853)
	pub async fn connect_by_name(
		mut stream: MutexGuard<'pool, AsyncStream>,
		hostname: String,
		port: u16,
		dns_resolvers: Vec<String>,
		dns_port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByNameRequest {
			hostname: hostname.clone(),
			port,
			dns_resolvers,
			dns_port,
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { connection_id, remote_ip } => {
					Ok(Self {
						stream,
						connection_id,
						stream_state: StreamState::None,
						request_bytes: Vec::new(),
						response_size: 0,
						response_bytes: Vec::new(),
						remote_ip,
						remote_hostname: Some(hostname),
					})
				}
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Create a new ProxyStream by targeting an IP address directly.
	///
	/// # Arguments
	/// * `addr` - the USOCK or VSOCK to connect to (this socket should be bound
	///   to a qos_net proxy) `timeout` is the timeout applied to the socket
	/// * `timeout` - the timeout to connect with
	/// * `ip` - the IP the remote qos_net proxy should connect to
	/// * `port` - the port the remote qos_net proxy should connect to
	///   (typically: 80 or 443 for http/https)
	pub async fn connect_by_ip(
		mut stream: MutexGuard<'pool, AsyncStream>,
		ip: String,
		port: u16,
	) -> Result<Self, QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::ConnectByIpRequest { ip, port })
			.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::ConnectResponse { connection_id, remote_ip } => {
					Ok(Self {
						stream,
						stream_state: StreamState::None,
						request_bytes: Vec::new(),
						response_size: 0,
						response_bytes: Vec::new(),
						connection_id,
						remote_ip,
						remote_hostname: None,
					})
				}
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}

	/// Close the remote connection
	pub async fn close(&mut self) -> Result<(), QosNetError> {
		let req = borsh::to_vec(&ProxyMsg::CloseRequest {
			connection_id: self.connection_id,
		})
		.expect("ProtocolMsg can always be serialized.");
		let resp_bytes = self.stream.call(&req).await?;

		match ProxyMsg::try_from_slice(&resp_bytes) {
			Ok(resp) => match resp {
				ProxyMsg::CloseResponse { connection_id: _ } => Ok(()),
				_ => Err(QosNetError::InvalidMsg),
			},
			Err(_) => Err(QosNetError::InvalidMsg),
		}
	}
}

impl AsyncWrite for AsyncProxyStream<'_> {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, std::io::Error>> {
		// make a clone since we need to set it to new values inside the match (IIRC rust 1.84+ fixes this?)
		let old_stream_state = self.stream_state.clone();

		let result = match old_stream_state {
			StreamState::None => {
				// new read, we need to send a ReadRequest to the other side
				self.request_bytes =
					raw_proxy_msg_bytes(ProxyMsg::WriteRequest {
						connection_id: self.connection_id,
						data: Vec::from(buf),
					});

				send_proxy_req(self, cx)
			}
			StreamState::Requesting => send_proxy_req(self, cx),
			StreamState::Receiving => get_proxy_resp(self, cx),
		};

		match result {
			Poll::Pending => Poll::Pending,
			Poll::Ready(proxy_msg_result) => match proxy_msg_result {
				Err(err) => Poll::Ready(Err(err)),
				Ok(proxy_msg) => match proxy_msg {
					ProxyMsg::WriteResponse { connection_id: _, size } => {
						Poll::Ready(Ok(size))
					}

					ProxyMsg::ProxyError(e) => {
						Poll::Ready(Err(std::io::Error::new(
							ErrorKind::InvalidData,
							format!("Proxy error: {e:?}"),
						)))
					}
					_ => Poll::Ready(Err(std::io::Error::new(
						ErrorKind::InvalidData,
						"unexpected response",
					))),
				},
			},
		}
	}

	fn poll_flush(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		// make a clone since we need to set it to new values inside the match (IIRC rust 1.84+ fixes this?)
		let old_stream_state = self.stream_state.clone();

		let result = match old_stream_state {
			StreamState::None => {
				// new read, we need to send a ReadRequest to the other side
				self.request_bytes =
					raw_proxy_msg_bytes(ProxyMsg::FlushRequest {
						connection_id: self.connection_id,
					});

				send_proxy_req(self, cx)
			}
			StreamState::Requesting => send_proxy_req(self, cx),
			StreamState::Receiving => get_proxy_resp(self, cx),
		};

		match result {
			Poll::Pending => Poll::Pending,
			Poll::Ready(proxy_msg_result) => match proxy_msg_result {
				Err(err) => Poll::Ready(Err(err)),
				Ok(proxy_msg) => match proxy_msg {
					ProxyMsg::FlushResponse { connection_id: _ } => {
						Poll::Ready(Ok(()))
					}

					ProxyMsg::ProxyError(e) => {
						Poll::Ready(Err(std::io::Error::new(
							ErrorKind::InvalidData,
							format!("Proxy error: {e:?}"),
						)))
					}
					_ => Poll::Ready(Err(std::io::Error::new(
						ErrorKind::InvalidData,
						"unexpected response",
					))),
				},
			},
		}
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		let stream: &mut AsyncStream = &mut self.stream;
		Pin::new(stream).poll_shutdown(cx)
	}
}

impl AsyncRead for AsyncProxyStream<'_> {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		// make a clone since we need to set it to new values inside the match (IIRC rust 1.84+ fixes this?)
		let old_stream_state = self.stream_state.clone();

		let result = match old_stream_state {
			StreamState::None => {
				// new read, we need to send a ReadRequest to the other side
				self.request_bytes =
					raw_proxy_msg_bytes(ProxyMsg::ReadRequest {
						connection_id: self.connection_id,
						size: buf.capacity(),
					});

				send_proxy_req(self, cx)
			}
			StreamState::Requesting => send_proxy_req(self, cx),
			StreamState::Receiving => get_proxy_resp(self, cx),
		};

		match result {
			Poll::Pending => Poll::Pending,
			Poll::Ready(proxy_msg_result) => match proxy_msg_result {
				Err(err) => Poll::Ready(Err(err)),
				Ok(proxy_msg) => match proxy_msg {
					ProxyMsg::ReadResponse { connection_id: _, size, data } => {
						if size == 0 {
							// EOF
							return Poll::Ready(Ok(()));
						}
						if data.is_empty() {
							// this is not EOF, shouldn't happen
							return Poll::Ready(Err(std::io::Error::new(
								ErrorKind::Interrupted,
								"empty Read",
							)));
						}
						if data.len() > buf.capacity() {
							return Poll::Ready(Err(std::io::Error::new(
								ErrorKind::InvalidData,
								format!(
											"overflow: cannot read {} bytes into a buffer of {} bytes",
											data.len(),
											buf.capacity()
										),
							)));
						}

						// Copy data into buffer
						buf.put_slice(&data);
						Poll::Ready(Ok(()))
					}
					ProxyMsg::ProxyError(e) => {
						Poll::Ready(Err(std::io::Error::new(
							ErrorKind::InvalidData,
							format!("Proxy error: {e:?}"),
						)))
					}
					_ => Poll::Ready(Err(std::io::Error::new(
						ErrorKind::InvalidData,
						"unexpected response",
					))),
				},
			},
		}
	}
}

// creates Vec<u8> containing the borsch encoded ProxyMsg with the u64 header for raw sends
fn raw_proxy_msg_bytes(msg: ProxyMsg) -> Vec<u8> {
	let req =
		borsh::to_vec(&msg).expect("ProtocolMsg can always be serialized.");
	let len = req.len();
	// First the length of the buffer
	let mut buf: Vec<u8> = (len as u64).to_le_bytes().into();
	// then the request bytes
	buf.extend_from_slice(&req);

	buf
}

// send bytes of a proxy ReadRequest or WriteRequest, or partial bytes thereof into the stream and keep state
fn send_proxy_req(
	mut ps: std::pin::Pin<&mut AsyncProxyStream>,
	cx: &mut std::task::Context<'_>,
) -> std::task::Poll<std::io::Result<ProxyMsg>> {
	let to_send = ps.request_bytes.len();
	let bytes = ps.request_bytes.clone(); // TODO: this is silly, due to pin
	let stream: &mut AsyncStream = &mut ps.stream;
	let written = Pin::new(stream).poll_write(cx, &bytes);

	// since writes can end up being partial, we need to ensure we keep state
	match written {
		// nothing was written, go Pending
		Poll::Pending => {
			ps.stream_state = StreamState::Requesting;
			Poll::Pending
		}
		// we wrote something out
		Poll::Ready(resp) => match resp {
			Ok(sent_bytes) => {
				// we didn't write everything, stay in Requesting state and continue
				if sent_bytes < to_send {
					ps.request_bytes.drain(..sent_bytes);
					ps.stream_state = StreamState::Requesting;
					Poll::Pending // re-do continuing for the rest of the read-request
				} else {
					// everything was sent out, we can go to receiving
					ps.stream_state = StreamState::Receiving;
					ps.response_size = 0; // unknown yet
					ps.response_bytes = Vec::new(); // reset the receiving buffer
					get_proxy_resp(ps, cx)
				}
			}
			Err(err) => Poll::Ready(Err(err)),
		},
	}
}

// read bytes of a proxy ReadResponse or WriteResponse, or partial bytes thereof out of the stream and keep state
fn get_proxy_resp(
	mut ps: std::pin::Pin<&mut AsyncProxyStream>,
	cx: &mut std::task::Context<'_>,
) -> std::task::Poll<std::io::Result<ProxyMsg>> {
	const HEADER_BYTES: usize = size_of::<u64>();

	let mut inner_buf = [0u8; 65535]; // minimum is HEADER_BYTES + 1 to even to make sense
	let mut read_buf = tokio::io::ReadBuf::new(&mut inner_buf);

	loop {
		let stream: &mut AsyncStream = &mut ps.stream;
		let read = Pin::new(stream).poll_read(cx, &mut read_buf);

		match read {
			Poll::Pending => return Poll::Pending,

			Poll::Ready(result) => match result {
				Ok(_) => {
					let filled = read_buf.filled();

					// if we didn't get the "header" yet, we need to pick that out
					let skip_bytes = if ps.response_size == 0 {
						if filled.len() < HEADER_BYTES {
							continue; // we need to read more
						}

						ps.response_size = u64::from_le_bytes(
							read_buf.filled()[..HEADER_BYTES]
								.try_into()
								.expect("wrong size by programmer"),
						)
						.try_into()
						// Should only be possible if we are on 32bit architecture
						.expect("32bit architecture not supported");
						HEADER_BYTES
					} else {
						0
					};

					let filled_slice = &filled[skip_bytes..];
					ps.response_bytes.extend_from_slice(filled_slice);

					// we filled out read_buf, all data is now in read_vec so it's safe to clear
					if read_buf.remaining() == 0 {
						read_buf.clear();
					}

					if ps.response_bytes.len() as u64 == ps.response_size {
						// EOF, we should be done
						let result =
							ProxyMsg::try_from_slice(&ps.response_bytes);
						ps.stream_state = StreamState::None; // reset for new read
						return Poll::Ready(result);
					}
					// otherwise just keep reading
				}
				Err(err) => return Poll::Ready(Err(err)),
			},
		}
	}
}

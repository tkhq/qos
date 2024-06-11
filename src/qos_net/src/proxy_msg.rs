use crate::error::QosNetError;

/// Message types to use with the remote proxy.
#[derive(Debug, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProxyMsg {
	/// A error from executing the protocol.
	ProxyError(QosNetError),

	/// Request the status of the proxy server.
	StatusRequest,
	/// Response for [`Self::StatusRequest`], contains the number of opened
	/// connections
	StatusResponse(usize),

	/// Request from the enclave app to open a TCP connection to a remote host,
	/// by name This results in DNS resolution and new remote connection saved
	/// in protocol state
	ConnectByNameRequest {
		/// The hostname to connect to, e.g. "www.googleapis.com"
		hostname: String,
		/// e.g. 443
		port: u16,
		/// An array of DNS resolvers e.g. ["8.8.8.8", "8.8.4.4"]
		dns_resolvers: Vec<String>,
		/// Port number to perform DNS resolution, e.g. 53
		dns_port: u16,
	},
	/// Request from the enclave app to open a TCP connection to a remote host,
	/// by IP This results in a new remote connection saved in protocol state
	ConnectByIpRequest {
		/// The IP to connect to, e.g. "1.2.3.4"
		ip: String,
		/// e.g. 443
		port: u16,
	},
	/// Response for `ConnectByNameRequest` and `ConnectByIpRequest`
	ConnectResponse {
		/// Connection ID to reference the opened connection in later messages
		/// (`Read`, `Write`, `Flush`)
		connection_id: u32,
		/// The remote host IP, e.g. "1.2.3.4"
		remote_ip: String,
	},
	/// Read from a remote connection
	ReadRequest {
		/// A connection ID from `ConnectResponse`
		connection_id: u32,
		/// number of bytes to read
		size: usize,
	},
	/// Response to `ReadRequest` containing read data
	ReadResponse {
		/// A connection ID from `ConnectResponse`
		connection_id: u32,
		/// number of bytes read
		data: Vec<u8>,
		/// buffer after mutation from `read`. The first `size` bytes contain
		/// the result of the `read` call
		size: usize,
	},
	/// Write to a remote connection
	WriteRequest {
		/// A connection ID from `ConnectResponse`
		connection_id: u32,
		/// Data to be sent
		data: Vec<u8>,
	},
	/// Response to `WriteRequest` containing the number of successfully
	/// written bytes.
	WriteResponse {
		/// Connection ID from `ConnectResponse`
		connection_id: u32,
		/// Number of bytes written successfully
		size: usize,
	},
	/// Write to a remote connection
	FlushRequest {
		/// A connection ID from `ConnectResponse`
		connection_id: u32,
	},
	/// Response to `FlushRequest`
	/// The response only contains the connection ID. Success is implicit: if
	/// the flush response fails, a `ProxyError` will be sent instead.
	FlushResponse {
		/// Connection ID from `ConnectResponse`
		connection_id: u32,
	},
}

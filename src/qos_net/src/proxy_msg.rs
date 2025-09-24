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
		/// The remote host IP, e.g. "1.2.3.4"
		remote_ip: String,
	},
}

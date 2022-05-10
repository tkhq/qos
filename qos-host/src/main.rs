use qos_core::io::SocketAddress;
use qos_host::HostServer;

#[tokio::main]
async fn main() {
	let addr = SocketAddress::new_unix("./dev.sock");
	let port = 3000;

	let server = HostServer::new(addr, [127, 0, 0, 1], port);
	let _ = server.serve().await.map_err(|e| eprintln!("server: {:?}", e));
}

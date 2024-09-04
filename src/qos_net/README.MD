# QOS Net

This crate contains a proxy server and utilities to work with it. This server is a socket proxy: it listens on a socket (USOCK or VSOCK) and opens TCP connections to the outside. By sending `Proxy::*` messages over the socket, clients of the proxy can read/write/flush the TCP connections.

When the proxy is run outside of an enclave and listening on a VSOCK port, the enclave process running on the inside can thus communicate with the outside and execute any protocol on top of a TCP connection by:
* Opening a connection to a target hostname (`Proxy::ConnectByName`) or IP (`ProxyMsg::ConnectByIp`): this returns a connection ID for subsequent messages.
* Sending `ProxyMsg::Read`, `ProxyMsg::Write` or `ProxyMsg::Flush` using the connection ID

Libraries like [`rustls`](https://github.com/rustls/rustls) are built generically to let users run the TLS protocol over any struct which implements [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html) and [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) traits.

These traits are implemented in the `ProxyStream` struct: its `read`, `write`, and `flush` methods send `ProxyMsg` to a socket instead of manipulating a local socket or file descriptor.

Binaries running in enclaves can thus open connections to the outside world by importing and using `ProxyStream`. See the following integration test: [src/integration/tests/remote_tls.rs](../integration/tests/remote_tls.rs).
